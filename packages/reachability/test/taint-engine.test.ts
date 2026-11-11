import { describe, it, expect, beforeAll } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import type { NormalizedFinding } from '@secureship/contracts';
import {
  TreeSitterLoader,
  TaintCatalog,
  TaintEngine,
  ImportGraph,
  SastReachabilityAnalyzer,
} from '../src/index.js';

describe('Taint Engine & Source-to-Sink Data-Flow Suite (Blocker 4)', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  describe('TaintCatalog', () => {
    it('accurately identifies HTTP sources across frameworks', () => {
      expect(TaintCatalog.matchSource('req.query.id')).not.toBeNull();
      expect(TaintCatalog.matchSource('req.body.name')).not.toBeNull();
      expect(TaintCatalog.matchSource('request.args.get("x")')).not.toBeNull();
      expect(TaintCatalog.matchSource('r.URL.Query()')).not.toBeNull();
      expect(TaintCatalog.matchSource('c.Query("id")')).not.toBeNull();
      expect(TaintCatalog.matchSource('Request.Query["id"]')).not.toBeNull();
    });

    it('accurately identifies dangerous sinks across categories', () => {
      expect(TaintCatalog.matchSink('db.query')).not.toBeNull();
      expect(TaintCatalog.matchSink('prisma.$queryRawUnsafe')).not.toBeNull();
      expect(TaintCatalog.matchSink('exec')).not.toBeNull();
      expect(TaintCatalog.matchSink('child_process.execSync')).not.toBeNull();
      expect(TaintCatalog.matchSink('os.system')).not.toBeNull();
      expect(TaintCatalog.matchSink('subprocess.run')).not.toBeNull();
      expect(TaintCatalog.matchSink('eval')).not.toBeNull();
      expect(TaintCatalog.matchSink('fs.readFile')).not.toBeNull();
    });

    it('identifies sanitizers that neutralize taint', () => {
      expect(TaintCatalog.isSanitized('parseInt(req.query.id)', 'SQL_QUERY')).toBe(true);
      expect(TaintCatalog.isSanitized('Number(req.query.id)', 'COMMAND_INJECTION')).toBe(true);
      expect(TaintCatalog.isSanitized('encodeURIComponent(val)', 'XSS')).toBe(true);
      expect(TaintCatalog.isSanitized('val + 1', 'SQL_QUERY')).toBe(false);
    });
  });

  describe('TaintEngine Source-to-Sink Tracking', () => {
    it('detects direct taint flow from HTTP input into Command Injection sink', () => {
      const code = `
import { exec } from 'child_process';

export function handleRequest(req, res) {
  const userCmd = req.query.cmd;
  exec(userCmd);
}
`;
      const result = TaintEngine.analyze({
        filePath: 'server.js',
        fileContent: code,
        findingLine: 6, // exec(userCmd)
      });

      expect(result.hasTaintFlow).toBe(true);
      expect(result.isConstantSink).toBe(false);
      expect(result.taintDetail).toBeDefined();
      expect(result.taintDetail!.sinkType).toBe('COMMAND_INJECTION');
      expect(result.taintDetail!.sourceType).toBe('HTTP_QUERY');
      expect(result.taintDetail!.taintSteps.length).toBeGreaterThanOrEqual(2);
      expect(result.notes).toContain('Confirmed exploit taint flow');
    });

    it('detects propagated taint flow via string concatenation into SQL sink', () => {
      const code = `
import { db } from './db.js';

export function getUser(req, res) {
  const username = req.body.username;
  const sql = "SELECT * FROM users WHERE name = '" + username + "'";
  db.query(sql);
}
`;
      const result = TaintEngine.analyze({
        filePath: 'user-service.ts',
        fileContent: code,
        findingLine: 7, // db.query(sql)
      });

      expect(result.hasTaintFlow).toBe(true);
      expect(result.taintDetail).toBeDefined();
      expect(result.taintDetail!.sinkType).toBe('SQL_QUERY');
      expect(result.taintDetail!.sourceType).toBe('HTTP_BODY');
      expect(result.taintDetail!.sourceLine).toBe(5);
      expect(result.taintDetail!.sinkLine).toBe(7);
    });

    it('identifies safe compile-time static constant arguments as constant sink', () => {
      const code = `
import { execSync } from 'child_process';

export function getVersion() {
  const output = execSync('git --version');
  return output.toString();
}
`;
      const result = TaintEngine.analyze({
        filePath: 'utils.js',
        fileContent: code,
        findingLine: 5, // execSync('git --version')
      });

      expect(result.hasTaintFlow).toBe(false);
      expect(result.isConstantSink).toBe(true);
      expect(result.notes).toContain('compile-time static constant arguments');
    });

    it('neutralizes taint when input is parsed via integer sanitizer', () => {
      const code = `
import { db } from './db.js';

export function getById(req, res) {
  const id = parseInt(req.query.id);
  const sql = "SELECT * FROM items WHERE id = " + id;
  db.query(sql);
}
`;
      const result = TaintEngine.analyze({
        filePath: 'item-service.js',
        fileContent: code,
        findingLine: 6, // db.query(sql)
      });

      expect(result.hasTaintFlow).toBe(false);
      expect(result.isConstantSink).toBe(false);
    });

    it('tracks Python Flask request.args to os.system sink', () => {
      const code = `
import os
from flask import request

def run_backup():
    target = request.args.get('target')
    os.system(target)
`;
      const result = TaintEngine.analyze({
        filePath: 'backup.py',
        fileContent: code,
        findingLine: 7, // os.system(target)
      });

      expect(result.hasTaintFlow).toBe(true);
      expect(result.taintDetail).toBeDefined();
      expect(result.taintDetail!.sinkType).toBe('COMMAND_INJECTION');
      expect(result.taintDetail!.sourceType).toBe('HTTP_QUERY');
    });

    it('tracks destructured object parameters from req.query', () => {
      const code = `
export function runScript(req, res) {
  const { code } = req.query;
  eval(code);
}
`;
      const result = TaintEngine.analyze({
        filePath: 'executor.js',
        fileContent: code,
        findingLine: 4, // eval(code)
      });

      expect(result.hasTaintFlow).toBe(true);
      expect(result.taintDetail!.sinkType).toBe('EVAL_CODE');
      expect(result.taintDetail!.sourceType).toBe('HTTP_QUERY');
    });
  });

  describe('SastReachabilityAnalyzer with Taint Integration', () => {
    it('elevates verdict from REACHABLE_IMPORT to REACHABLE_CALL_PATH on confirmed taint flow', async () => {
      const testDir = path.join(os.tmpdir(), `secureship-taint-e2e-${Date.now()}`);
      fs.mkdirSync(testDir, { recursive: true });

      try {
        const vulnerableFile = path.join(testDir, 'index.js');
        fs.writeFileSync(
          vulnerableFile,
          `import { exec } from 'child_process';
export function run(req, res) {
  const target = req.query.host;
  exec("ping " + target);
}
run();
`
        );

        const graph = await ImportGraph.build(testDir, { noCache: true });

        const finding: NormalizedFinding = {
          id: 'test-finding-1',
          fingerprint: 'a'.repeat(64),
          ruleId: 'SS-SAST-js-exec',
          scannerName: 'opengrep',
          category: 'SAST',
          severity: 'HIGH',
          title: 'Command Injection Sink',
          description: 'Untrusted input reaches exec()',
          reachability: 'UNKNOWN',
          location: {
            filePath: 'index.js',
            startLine: 4,
            endLine: 4,
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

        // Blocker 4 core proof: Verdict is REACHABLE_CALL_PATH, evidence is TAINT_FLOW!
        expect(detail.verdict).toBe('REACHABLE_CALL_PATH');
        expect(detail.evidence.kind).toBe('TAINT_FLOW');
        expect(detail.evidence.taintFlow).toBeDefined();
        expect(detail.evidence.taintFlow!.isExploitable).toBe(true);
        expect(detail.evidence.taintFlow!.sinkType).toBe('COMMAND_INJECTION');
        expect(detail.evidence.taintFlow!.sourceType).toBe('HTTP_QUERY');
        expect(detail.evidence.notes).toContain('Confirmed exploit taint flow');
      } finally {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    });

    it('preserves REACHABLE_IMPORT with static constant note when sink uses safe literal', async () => {
      const testDir = path.join(os.tmpdir(), `secureship-constant-e2e-${Date.now()}`);
      fs.mkdirSync(testDir, { recursive: true });

      try {
        const safeFile = path.join(testDir, 'index.js');
        fs.writeFileSync(
          safeFile,
          `import { exec } from 'child_process';
export function status() {
  exec("git status");
}
status();
`
        );

        const graph = await ImportGraph.build(testDir, { noCache: true });

        const finding: NormalizedFinding = {
          id: 'test-finding-2',
          fingerprint: 'b'.repeat(64),
          ruleId: 'SS-SAST-js-exec',
          scannerName: 'opengrep',
          category: 'SAST',
          severity: 'HIGH',
          title: 'Command Execution Sink',
          description: 'exec call site',
          reachability: 'UNKNOWN',
          location: {
            filePath: 'index.js',
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

        expect(detail.verdict).toBe('REACHABLE_IMPORT');
        expect(detail.evidence.notes).toContain('compile-time static constant arguments');
      } finally {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    });
  });
});
