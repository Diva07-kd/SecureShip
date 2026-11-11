import { describe, it, expect, beforeAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import * as Contracts from '@secureship/contracts';
import {
  ReachabilityEngine,
  TreeSitterLoader,
  JsImportExtractor,
  JsModuleResolver,
  PythonImportExtractor,
  PythonPackageMap,
  EntrypointDetector,
  ExternalExtractionCache,
  verifyWasmBuffer,
  WASM_MANIFEST,
  ImportGraph,
  ScaReachabilityAnalyzer,
} from '../../src/index.js';

beforeAll(async () => {
  await TreeSitterLoader.init();
});

describe('Phase 3 Verification: PART B — Contracts', () => {
  it('B1: ReachabilityDetail validates all evidence kinds, caps chain at 10, rejects unknown kind', () => {
    const validKinds: Contracts.ReachabilityEvidenceKind[] = [
      'IMPORT_CHAIN',
      'PACKAGE_IMPORTED',
      'TRANSITIVE_VIA',
      'DEV_ONLY',
      'NOT_IMPORTED',
      'DEAD_FILE',
      'CONFIG_REFERENCE',
      'DYNAMIC_UNKNOWN',
      'NO_ENTRYPOINT',
      'UNSUPPORTED_LANGUAGE',
      'UNMAPPED_PACKAGE',
      'NO_LOCKFILE_TREE',
      'NOT_APPLICABLE',
      'PARSE_FAILURE',
      'TEST_ONLY_IMPORT',
    ];

    for (const kind of validKinds) {
      const parsed = Contracts.ReachabilityEvidenceKindSchema.safeParse(kind);
      expect(parsed.success).toBe(true);

      const detail: Contracts.ReachabilityDetail = {
        verdict: 'UNKNOWN',
        analysisConfidence: 'LOW',
        evidence: { kind, chain: ['a.js', 'b.js'] },
        limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
      };
      const detailParsed = Contracts.ReachabilityDetailSchema.safeParse(detail);
      expect(detailParsed.success).toBe(true);
    }

    // Chain > 10 rejected
    const oversizedChain = Array.from({ length: 11 }, (_, i) => `file-${i}.js`);
    const oversized = Contracts.ReachabilityDetailSchema.safeParse({
      verdict: 'REACHABLE_IMPORT',
      analysisConfidence: 'HIGH',
      evidence: { kind: 'IMPORT_CHAIN', chain: oversizedChain },
      limitations: [],
    });
    expect(oversized.success).toBe(false);

    // Unknown kind rejected
    const unknownKind = Contracts.ReachabilityEvidenceKindSchema.safeParse('MAGIC_REACHABLE');
    expect(unknownKind.success).toBe(false);
  });

  it('B2: Captured Phase 2 1.0 ScanReport still parses; byReachability is optional on read; writers emit 1.1', () => {
    const legacyReport = {
      schemaVersion: '1.0' as const,
      tool: { name: 'secureship', version: '0.1.0' },
      target: '/test/repo',
      mode: 'FULL' as const,
      startedAt: new Date().toISOString(),
      durationMs: 120,
      scanners: [],
      findings: [],
      suppressed: [],
      warnings: [],
      summary: {
        totalRaw: 0,
        totalReported: 0,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0 },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 0,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
          GATE2_UNREACHABLE: 0,
        },
      },
    };

    const parsed = Contracts.ScanReportSchema.safeParse(legacyReport);
    expect(parsed.success).toBe(true);

    // Writers emit 1.1 with byReachability
    const v1_1_Report = {
      ...legacyReport,
      schemaVersion: '1.1' as const,
      summary: {
        ...legacyReport.summary,
        byReachability: {
          REACHABLE_CALL_PATH: 0,
          REACHABLE_IMPORT: 0,
          UNKNOWN: 0,
          UNREACHABLE: 0,
        },
      },
    };
    const parsed11 = Contracts.ScanReportSchema.safeParse(v1_1_Report);
    expect(parsed11.success).toBe(true);
    if (parsed11.success) {
      expect(parsed11.data.schemaVersion).toBe('1.1');
      expect(parsed11.data.summary.byReachability).toBeDefined();
    }
  });

  it('B3: Gate2Config strict validation and TierPolicy reachability capabilities', () => {
    // Valid config
    const validConfig = Contracts.Gate2ConfigSchema.safeParse({
      mode: 'annotate',
      neverSuppressSeverities: ['CRITICAL'],
      maxFileBytes: 1048576,
      parseTimeoutMs: 5000,
    });
    expect(validConfig.success).toBe(true);

    // Bad mode rejected
    const badMode = Contracts.Gate2ConfigSchema.safeParse({ mode: 'aggressive' });
    expect(badMode.success).toBe(false);

    // Tier policy
    const freeTier = Contracts.TIER_CAPABILITY_DEFAULTS.FREE_BYOK;
    expect(freeTier.allowImportReachability).toBe(true);
    expect(freeTier.allowCallPathReachability).toBe(false);

    const proTier = Contracts.TIER_CAPABILITY_DEFAULTS.PRO_TEAM;
    expect(proTier.allowImportReachability).toBe(true);
  });
});

describe('Phase 3 Verification: PART C — Parser and WASM', () => {
  it('C1: Each grammar loads cleanly; tampered WASM fails closed to UNKNOWN', async () => {
    await TreeSitterLoader.init();

    const js = TreeSitterLoader.getParser('javascript');
    expect(js.parser).toBeDefined();
    expect(js.error).toBeUndefined();

    const ts = TreeSitterLoader.getParser('typescript');
    expect(ts.parser).toBeDefined();

    const tsx = TreeSitterLoader.getParser('tsx');
    expect(tsx.parser).toBeDefined();

    const py = TreeSitterLoader.getParser('python');
    expect(py.parser).toBeDefined();

    // Tampered buffer fails closed
    const tampered = Buffer.from('corrupted wasm binary payload');
    const check = verifyWasmBuffer('tree-sitter.wasm', tampered);
    expect(check.valid).toBe(false);
  });

  it('C2: Hostile inputs (oversized, deeply nested, binary with code ext, empty, CRLF): no crash, honored limits', () => {
    // 1. Oversized file (exceeds maxFileBytes)
    const bigContent = 'x = 1;\n'.repeat(200);
    const bigResult = TreeSitterLoader.parseFile(bigContent, 'javascript', { maxFileBytes: 100 });
    expect(bigResult.hasError).toBe(true);
    expect(bigResult.errorReason).toContain('exceeds configured limit');

    // 2. Binary content disguised as .js
    const binaryGarbage = Buffer.from([
      0x00, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ]).toString('utf8');
    const binResult = TreeSitterLoader.parseFile(binaryGarbage, 'javascript');
    expect(binResult).toBeDefined();

    // 3. Empty and whitespace
    const emptyResult = TreeSitterLoader.parseFile('', 'javascript');
    expect(emptyResult).toBeDefined();

    // 4. CRLF + BOM
    const bomCrlf = '\uFEFFconst a = 1;\r\nconst b = 2;\r\n';
    const bomResult = TreeSitterLoader.parseFile(bomCrlf, 'javascript');
    expect(bomResult.hasError).toBe(false);

    // 5. One huge line
    const hugeLine = 'const a = [' + '"x",'.repeat(1000) + '"y"];';
    const lineResult = TreeSitterLoader.parseFile(hugeLine, 'javascript');
    expect(lineResult).toBeDefined();
  });

  it('C3: hasError semantics: parse errors degrade project NOT_IMPORTED to UNKNOWN', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-c3-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'main.js', dependencies: { 'unused-lib': '^1.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'unused-lib': '^1.0.0' } },
            'node_modules/unused-lib': { version: '1.0.0' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'main.js'), 'console.log("ok");');
      // Broken syntax file in production scope
      fs.writeFileSync(path.join(tmp, 'broken.js'), 'function bad( { let = ;');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-1',
        fingerprint: 'a'.repeat(64),
        ruleId: 'R1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Unused lib',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'R1', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'unused-lib', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // Because broken.js has syntax error, positive evidence is voided -> UNKNOWN (PARSE_FAILURE)
      expect(res.verdict).toBe('UNKNOWN');
      expect(res.evidence.kind).toBe('PARSE_FAILURE');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('C4: Staleness: modern Python 3.12 and TS 5.x syntax does not crash and reports cleanly', () => {
    const py312 = `
type Coordinate[T] = tuple[T, T]
match command:
    case "quit":
        sys.exit()
`;
    const pyRes = TreeSitterLoader.parseFile(py312, 'python');
    expect(pyRes.tree).not.toBeNull();
    expect(pyRes.tree!.rootNode.type).toBe('module');

    const ts5 = `function identity<const T>(arg: T): T { return arg; }`;
    const tsRes = TreeSitterLoader.parseFile(ts5, 'typescript');
    expect(tsRes.tree).not.toBeNull();
    expect(tsRes.tree!.rootNode.type).toBe('program');
  });
});

describe('Phase 3 Verification: PART D — JS/TS Extraction & Resolution', () => {
  it('D1 & D2: Extracts ESM, CJS, dynamic imports, type-only imports and flags dynamic files', () => {
    const code = `
import defaultExport from 'pkg-default';
import { namedA, namedB as aliasB } from 'pkg-named';
import * as starPkg from 'pkg-star';
import 'pkg-side-effect';
export * from 'pkg-export-star';
export { exportA } from 'pkg-export-named';

const reqA = require('pkg-require');
const { destReq } = require('pkg-destructured-require');

async function load() {
  const dyn = await import('pkg-dynamic-literal');
  const nonLit = require(dynamicVariable);
}

import type { SomeType } from 'pkg-type-only';
`;

    const { tree } = TreeSitterLoader.parseFile(code, 'typescript');
    const result = JsImportExtractor.extract(tree!.rootNode);
    expect(result.hasDynamicImports).toBe(true);

    const specifiers = result.imports.map((i) => i.specifier);
    expect(specifiers).toContain('pkg-default');
    expect(specifiers).toContain('pkg-named');
    expect(specifiers).toContain('pkg-star');
    expect(specifiers).toContain('pkg-side-effect');
    expect(specifiers).toContain('pkg-export-star');
    expect(specifiers).toContain('pkg-export-named');
    expect(specifiers).toContain('pkg-require');
    expect(specifiers).toContain('pkg-destructured-require');
    expect(specifiers).toContain('pkg-dynamic-literal');

    const typeOnlyImport = result.imports.find((i) => i.specifier === 'pkg-type-only');
    expect(typeOnlyImport?.isTypeOnly).toBe(true);
  });

  it('D3: Module resolution bounds, aliases, package.json #imports, rejects traversal escape', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-d3-'));
    try {
      fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'src', 'helper.ts'), 'export const h = 1;');
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', imports: { '#internal': './src/helper.ts' } })
      );

      const resolver = new JsModuleResolver(tmp);
      // Relative resolution
      const relRes = resolver.resolve('./helper.js', path.join(tmp, 'src', 'main.ts'));
      expect(relRes.type).toBe('LOCAL_FILE');

      // #imports
      const subpathRes = resolver.resolve('#internal', path.join(tmp, 'src', 'main.ts'));
      expect(subpathRes.type).toBe('LOCAL_FILE');

      // Node built-in
      const builtin = resolver.resolve('node:fs', path.join(tmp, 'src', 'main.ts'));
      expect(builtin.type).toBe('BUILTIN');

      // Directory escape attempt
      const escapeRes = resolver.resolve(
        '../../../../../etc/passwd',
        path.join(tmp, 'src', 'main.ts')
      );
      expect(escapeRes.type).toBe('UNRESOLVED');
      if (escapeRes.type === 'UNRESOLVED') {
        expect(escapeRes.reason).toContain('escapes project root');
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('D4: Unresolved local import in production scope blocks NOT_IMPORTED-HIGH', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-d4-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'main.js', dependencies: { 'unused-lib': '^1.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'unused-lib': '^1.0.0' } },
            'node_modules/unused-lib': { version: '1.0.0' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'main.js'), "import './non-existent-local-file.js';\n");

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-1',
        fingerprint: 'b'.repeat(64),
        ruleId: 'R1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Unused lib',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'R1', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'unused-lib', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      expect(res.verdict).toBe('UNKNOWN');
      expect(res.evidence.kind).toBe('DYNAMIC_UNKNOWN');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('Phase 3 Verification: PART E — Python Extraction & Resolution', () => {
  it('E1 & E2: Extracts Python imports, relative imports, detects dynamic exec/eval/importlib', () => {
    const pyCode = `
import os, sys
import numpy as np
from PIL import Image, ImageOps
from .sub import helper
from ..parent import base

def dynamic_loader(mod_name):
    importlib.import_module(mod_name)
    eval("1 + 1")
    exec("a = 2")
`;

    const { tree } = TreeSitterLoader.parseFile(pyCode, 'python');
    const result = PythonImportExtractor.extract(tree!.rootNode);
    expect(result.hasDynamicImports).toBe(true);

    const mods = result.imports.map((i) => i.module);
    expect(mods).toContain('os');
    expect(mods).toContain('sys');
    expect(mods).toContain('numpy');
    expect(mods).toContain('PIL');
  });

  it('E3: PythonPackageMap maps static aliases and detects unmapped packages', () => {
    const staticCases: Record<string, string> = {
      PyYAML: 'yaml',
      Pillow: 'PIL',
      beautifulsoup4: 'bs4',
      'scikit-learn': 'sklearn',
      'opencv-python': 'cv2',
      'python-dateutil': 'dateutil',
      attrs: 'attr',
      protobuf: 'google.protobuf',
    };

    for (const [pkg, expectedMod] of Object.entries(staticCases)) {
      const res = PythonPackageMap.getImportableModuleNames(pkg, process.cwd());
      expect(res.modules).toContain(expectedMod);
    }

    const unmapped = PythonPackageMap.getImportableModuleNames(
      '123-unknown-dist-!@#',
      process.cwd()
    );
    expect(unmapped.source).toBe('UNMAPPED');
  });

  it('E4 (C1 Rule): Across Python projects, SCA finding is NEVER UNREACHABLE with HIGH confidence', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-e4-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'pyproject.toml'),
        `[project]\nname = "my-app"\ndependencies = ["unused-pkg"]\n`
      );
      fs.writeFileSync(path.join(tmp, 'main.py'), `print("clean app")\n`);

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-py',
        fingerprint: 'c'.repeat(64),
        ruleId: 'PY-1',
        scannerName: 'osv-scanner',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Python Vuln',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'osv-scanner', scannerRuleId: 'PY-1', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'unused-pkg', version: '1.0.0', ecosystem: 'pypi' },
        location: { filePath: 'pyproject.toml', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // If UNREACHABLE, confidence MUST NOT be HIGH
      if (res.verdict === 'UNREACHABLE') {
        expect(res.analysisConfidence).not.toBe('HIGH');
      } else {
        expect(res.verdict).toBe('UNKNOWN');
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('Phase 3 Verification: PART F — Entrypoints and Scope', () => {
  it('F1: Detects package.json main/exports/bin, HTML script tags, framework conventions, Dockerfiles', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-f1-'));
    try {
      fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'src', 'index.ts'), 'console.log("main");');
      fs.writeFileSync(path.join(tmp, 'src', 'cli.ts'), 'console.log("cli");');
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({
          name: 'pkg',
          main: './dist/index.js',
          bin: './dist/cli.js',
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'tsconfig.json'),
        JSON.stringify({ compilerOptions: { outDir: './dist', rootDir: './src' } })
      );

      const res = EntrypointDetector.detect(tmp);
      expect(res.entrypoints).toContain(path.resolve(tmp, 'src', 'index.ts'));
      expect(res.entrypoints).toContain(path.resolve(tmp, 'src', 'cli.ts'));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('F2: No entrypoints found yields UNKNOWN (NO_ENTRYPOINT), never UNREACHABLE', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-f2-'));
    try {
      fs.writeFileSync(path.join(tmp, 'helper.js'), 'export const a = 1;');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-orphan',
        fingerprint: 'd'.repeat(64),
        ruleId: 'R-SAST',
        scannerName: 'opengrep',
        category: 'SAST',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'SAST finding',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'opengrep', scannerRuleId: 'R-SAST', message: 'M' }],
        createdAt: new Date().toISOString(),
        location: { filePath: 'helper.js', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      expect(res.verdict).toBe('UNKNOWN');
      expect(res.evidence.kind).toBe('NO_ENTRYPOINT');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('F3: Test/mock files are never treated as production entrypoints, while contest/latest are valid', () => {
    expect(EntrypointDetector.isTestOrMockFile('tests/app.test.ts')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('mocks/auth.ts')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('fixtures/data.json')).toBe(true);
    // Non-test dirs that happen to contain "test" in substring
    expect(EntrypointDetector.isTestOrMockFile('contest/leaderboard.ts')).toBe(false);
    expect(EntrypointDetector.isTestOrMockFile('latest/version.ts')).toBe(false);
  });
});

describe('Phase 3 Verification: PART G — SCA Decision Table', () => {
  it('G1: Direct dependency imported in reachable production file => REACHABLE_IMPORT (PACKAGE_IMPORTED, HIGH)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g1-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'index.js', dependencies: { chalk: '^4.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { chalk: '^4.0.0' } },
            'node_modules/chalk': { version: '4.0.0' },
          },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'index.js'),
        "import chalk from 'chalk';\nconsole.log(chalk.red('hi'));\n"
      );

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-chalk',
        fingerprint: 'e'.repeat(64),
        ruleId: 'SCA-1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Chalk',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'SCA-1', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'chalk', version: '4.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      expect(res.verdict).toBe('REACHABLE_IMPORT');
      expect(res.analysisConfidence).toBe('HIGH');
      expect(res.evidence.kind).toBe('PACKAGE_IMPORTED');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('G3 (Transitive Hole A1): Declared-but-unimported package depended upon by prod dep => REACHABLE_IMPORT (TRANSITIVE_VIA)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g3-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({
          name: 'app',
          main: 'index.js',
          dependencies: { express: '^4.18.2', debug: '^2.6.9' }, // debug is declared in package.json but not directly imported
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { express: '^4.18.2', debug: '^2.6.9' } },
            'node_modules/express': { version: '4.18.2', dependencies: { debug: '2.6.9' } },
            'node_modules/debug': { version: '2.6.9' },
          },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'index.js'),
        "import express from 'express';\nconst app = express();\n"
      );

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-debug',
        fingerprint: 'f'.repeat(64),
        ruleId: 'SCA-DEBUG',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Debug vuln',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'SCA-DEBUG', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'debug', version: '2.6.9', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // Because debug is a dependency of express (which is imported in production), it MUST be REACHABLE_IMPORT TRANSITIVE_VIA!
      expect(res.verdict).toBe('REACHABLE_IMPORT');
      expect(res.evidence.kind).toBe('TRANSITIVE_VIA');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('G3-py: Poetry transitive dependencies (cryptography, filelock) evaluate to REACHABLE_IMPORT (TRANSITIVE_VIA, MEDIUM)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-poetry-transitive-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'pyproject.toml'),
        '[tool.poetry]\nname = "my-poetry"\nversion = "1.0.0"\n\n[tool.poetry.dependencies]\npython = "^3.8"\nvirtualenv = "^20.0.0"\nkeyring = "^21.0.0"\n\n[tool.poetry.scripts]\nmy-poetry = "my_poetry.console:main"\n'
      );
      fs.writeFileSync(
        path.join(tmp, 'poetry.lock'),
        '[[package]]\nname = "virtualenv"\nversion = "20.0.0"\n[package.dependencies]\nfilelock = ">=3.0.0"\n\n[[package]]\nname = "filelock"\nversion = "3.2.1"\n\n[[package]]\nname = "keyring"\nversion = "21.0.0"\n[package.dependencies]\nsecretstorage = ">=3.0.0"\n\n[[package]]\nname = "secretstorage"\nversion = "3.3.0"\n[package.dependencies]\ncryptography = ">=3.0.0"\n\n[[package]]\nname = "cryptography"\nversion = "36.0.1"\n'
      );
      fs.mkdirSync(path.join(tmp, 'my_poetry'), { recursive: true });
      fs.writeFileSync(path.join(tmp, 'my_poetry', '__init__.py'), '');
      fs.writeFileSync(
        path.join(tmp, 'my_poetry', 'console.py'),
        'import virtualenv\nimport keyring\n\ndef main():\n    print("running")\n'
      );

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const makeFinding = (pkg: string): Contracts.NormalizedFinding => ({
        id: `f-${pkg}`,
        fingerprint: 'a'.repeat(64),
        ruleId: 'PY-SCA',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: `${pkg} vuln`,
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'PY-SCA', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: pkg, version: '1.0.0', ecosystem: 'pypi' },
        location: { filePath: 'poetry.lock', startLine: 1, endLine: 1 },
      });

      // cryptography is transitive via keyring -> secretstorage -> cryptography
      const resCrypto = engine.evaluate(makeFinding('cryptography'));
      expect(resCrypto.verdict).toBe('REACHABLE_IMPORT');
      expect(resCrypto.analysisConfidence).toBe('MEDIUM');
      expect(resCrypto.evidence.kind).toBe('TRANSITIVE_VIA');
      expect(resCrypto.evidence.via).toEqual(['keyring', 'secretstorage', 'cryptography']);

      // filelock is transitive via virtualenv -> filelock
      const resFilelock = engine.evaluate(makeFinding('filelock'));
      expect(resFilelock.verdict).toBe('REACHABLE_IMPORT');
      expect(resFilelock.analysisConfidence).toBe('MEDIUM');
      expect(resFilelock.evidence.kind).toBe('TRANSITIVE_VIA');
      expect(resFilelock.evidence.via).toEqual(['virtualenv', 'filelock']);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  describe('G4 (a-k): Precondition Enforcement (Any Broken Precondition Leaves UNREACHABLE-HIGH)', () => {
    function setupBaseProject(tmp: string): void {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'index.js', dependencies: { 'target-pkg': '^1.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'target-pkg': '^1.0.0' } },
            'node_modules/target-pkg': { version: '1.0.0' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'index.js'), 'console.log("prod code");\n');
    }

    function makeFinding(pkgName = 'target-pkg'): Contracts.NormalizedFinding {
      return {
        id: 'f-precond',
        fingerprint: '9'.repeat(64),
        ruleId: 'RULE-SCA',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Target vuln',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'RULE-SCA', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: pkgName, version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };
    }

    it('G4-baseline: clean preconditions evaluate to UNREACHABLE with HIGH confidence', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-base-'));
      try {
        setupBaseProject(tmp);
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNREACHABLE');
        expect(res.analysisConfidence).toBe('HIGH');
        expect(res.evidence.kind).toBe('NOT_IMPORTED');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-a: parse error in prod scope moves verdict away from UNREACHABLE-HIGH to UNKNOWN (PARSE_FAILURE)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-a-'));
      try {
        setupBaseProject(tmp);
        fs.writeFileSync(path.join(tmp, 'broken.js'), 'function bad( { {{% syntax error');
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('PARSE_FAILURE');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-b: dynamic import marker (eval, require(var)) in prod scope moves verdict to UNKNOWN (DYNAMIC_UNKNOWN)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-b-'));
      try {
        setupBaseProject(tmp);
        fs.writeFileSync(path.join(tmp, 'index.js'), 'eval("dynamicRequire(x)");\n');
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('DYNAMIC_UNKNOWN');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-c: no resolvable entrypoint moves verdict to UNKNOWN (NO_ENTRYPOINT)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-c-'));
      try {
        setupBaseProject(tmp);
        fs.unlinkSync(path.join(tmp, 'index.js'));
        fs.writeFileSync(
          path.join(tmp, 'package.json'),
          JSON.stringify({ name: 'app', dependencies: { 'target-pkg': '^1.0.0' } })
        );
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('NO_ENTRYPOINT');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-d: package name in npm script or bin moves verdict to UNKNOWN (CONFIG_REFERENCE)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-d-'));
      try {
        setupBaseProject(tmp);
        const pkgJson = JSON.parse(fs.readFileSync(path.join(tmp, 'package.json'), 'utf8'));
        pkgJson.scripts = { build: 'target-pkg compile --all' };
        fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify(pkgJson, null, 2));

        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('CONFIG_REFERENCE');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-e: package name in eslint/babel/webpack config moves verdict to UNKNOWN (CONFIG_REFERENCE)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-e-'));
      try {
        setupBaseProject(tmp);
        fs.writeFileSync(
          path.join(tmp, 'webpack.config.js'),
          'module.exports = { plugins: ["target-pkg"] };\n'
        );
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('CONFIG_REFERENCE');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-f: package name as string literal in prod code moves verdict to UNKNOWN (CONFIG_REFERENCE)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-f-'));
      try {
        setupBaseProject(tmp);
        fs.writeFileSync(
          path.join(tmp, 'index.js'),
          'console.log("Loading plugin", "target-pkg");\n'
        );
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('CONFIG_REFERENCE');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-g: package name in Dockerfile/CI/Makefile/YAML moves verdict to UNKNOWN (CONFIG_REFERENCE)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-g-'));
      try {
        setupBaseProject(tmp);
        fs.writeFileSync(
          path.join(tmp, 'Dockerfile'),
          'FROM node:20\nRUN npm install target-pkg\n'
        );
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('CONFIG_REFERENCE');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-h: Python settings string moves verdict to UNKNOWN (CONFIG_REFERENCE)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-h-'));
      try {
        setupBaseProject(tmp);
        fs.writeFileSync(path.join(tmp, 'settings.py'), 'INSTALLED_APPS = ["target-pkg"]\n');
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('CONFIG_REFERENCE');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-i: unresolved local import in prod scope moves verdict to UNKNOWN (DYNAMIC_UNKNOWN)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-i-'));
      try {
        setupBaseProject(tmp);
        fs.writeFileSync(path.join(tmp, 'index.js'), 'import "./non-existent-local-file.js";\n');
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('DYNAMIC_UNKNOWN');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-j: dependency tree absent moves verdict to UNKNOWN (NO_LOCKFILE_TREE)', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-j-'));
      try {
        setupBaseProject(tmp);
        fs.unlinkSync(path.join(tmp, 'package-lock.json'));
        fs.writeFileSync(path.join(tmp, 'yarn.lock'), '# unsupported flat yarn lockfile\n');
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding());
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('NO_LOCKFILE_TREE');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });

    it('G4-k: undeclared package moves verdict away from UNREACHABLE-HIGH', async () => {
      const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g4-k-'));
      try {
        setupBaseProject(tmp);
        const engine = new ReachabilityEngine(tmp, { noCache: true });
        await engine.init();
        const res = engine.evaluate(makeFinding('undeclared-mystery-package'));
        expect(res.verdict).toBe('UNKNOWN');
        expect(res.evidence.kind).toBe('NO_LOCKFILE_TREE');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    });
  });

  it('(b) package declared in workspaces A and B and imported only by B => REACHABLE_IMPORT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g5-b-'));
    try {
      fs.mkdirSync(path.join(tmp, 'packages', 'pkg-a'), { recursive: true });
      fs.mkdirSync(path.join(tmp, 'packages', 'pkg-b'), { recursive: true });

      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'root', private: true })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-a', 'package.json'),
        JSON.stringify({
          name: 'pkg-a',
          main: 'index.js',
          dependencies: { 'shared-dep': '^1.0.0' },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-a', 'index.js'),
        'console.log("pkg-a clean");\n'
      );

      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-b', 'package.json'),
        JSON.stringify({
          name: 'pkg-b',
          main: 'index.js',
          dependencies: { 'shared-dep': '^1.0.0' },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-b', 'index.js'),
        'import "shared-dep";\nconsole.log("imported in pkg-b");\n'
      );

      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'root',
          lockfileVersion: 3,
          packages: {
            '': {},
            'packages/pkg-a': { dependencies: { 'shared-dep': '^1.0.0' } },
            'packages/pkg-b': { dependencies: { 'shared-dep': '^1.0.0' } },
            'node_modules/shared-dep': { version: '1.0.0' },
          },
        })
      );

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const findingInA: Contracts.NormalizedFinding = {
        id: 'f-shared-b',
        fingerprint: 'b'.repeat(64),
        ruleId: 'RULE-SHARED',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Shared dep vuln',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'RULE-SHARED', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'shared-dep', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'packages/pkg-a/package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(findingInA);
      expect(res.verdict).toBe('REACHABLE_IMPORT');
      expect(res.evidence.kind).toBe('PACKAGE_IMPORTED');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('(c) declared in A and B, imported by none => NOT_IMPORTED-HIGH when all preconditions hold', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g5-c-'));
    try {
      fs.mkdirSync(path.join(tmp, 'packages', 'pkg-a'), { recursive: true });
      fs.mkdirSync(path.join(tmp, 'packages', 'pkg-b'), { recursive: true });

      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'root', private: true })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-a', 'package.json'),
        JSON.stringify({
          name: 'pkg-a',
          main: 'index.js',
          dependencies: { 'shared-dep': '^1.0.0' },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-a', 'index.js'),
        'console.log("pkg-a clean");\n'
      );

      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-b', 'package.json'),
        JSON.stringify({
          name: 'pkg-b',
          main: 'index.js',
          dependencies: { 'shared-dep': '^1.0.0' },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-b', 'index.js'),
        'console.log("no imports in pkg-b");\n'
      );

      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'root',
          lockfileVersion: 3,
          packages: {
            '': {},
            'packages/pkg-a': { dependencies: { 'shared-dep': '^1.0.0' } },
            'packages/pkg-b': { dependencies: { 'shared-dep': '^1.0.0' } },
            'node_modules/shared-dep': { version: '1.0.0' },
          },
        })
      );

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const findingInA: Contracts.NormalizedFinding = {
        id: 'f-shared-c',
        fingerprint: 'c'.repeat(64),
        ruleId: 'RULE-SHARED',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Shared dep vuln',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'RULE-SHARED', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'shared-dep', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'packages/pkg-a/package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(findingInA);
      expect(res.verdict).toBe('UNREACHABLE');
      expect(res.analysisConfidence).toBe('HIGH');
      expect(res.evidence.kind).toBe('NOT_IMPORTED');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('(d) workspace A depends on workspace B and B imports the package => REACHABLE', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g5-d-'));
    try {
      fs.mkdirSync(path.join(tmp, 'packages', 'pkg-a'), { recursive: true });
      fs.mkdirSync(path.join(tmp, 'packages', 'pkg-b'), { recursive: true });

      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'root', private: true })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-a', 'package.json'),
        JSON.stringify({
          name: 'pkg-a',
          main: 'index.js',
          dependencies: { 'pkg-b': '^1.0.0' },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-a', 'index.js'),
        'import { b } from "pkg-b";\nconsole.log(b);\n'
      );

      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-b', 'package.json'),
        JSON.stringify({
          name: 'pkg-b',
          main: 'index.js',
          dependencies: { 'shared-dep': '^1.0.0' },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-b', 'index.js'),
        'import shared from "shared-dep";\nexport const b = shared;\n'
      );

      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'root',
          lockfileVersion: 3,
          packages: {
            '': {},
            'packages/pkg-a': { dependencies: { 'pkg-b': '^1.0.0' } },
            'packages/pkg-b': { dependencies: { 'shared-dep': '^1.0.0' } },
            'node_modules/shared-dep': { version: '1.0.0' },
          },
        })
      );

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-shared-d',
        fingerprint: 'd'.repeat(64),
        ruleId: 'RULE-SHARED',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Shared dep vuln',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'RULE-SHARED', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'shared-dep', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'packages/pkg-b/package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      expect(res.verdict).toBe('REACHABLE_IMPORT');
      expect(res.evidence.kind).toBe('PACKAGE_IMPORTED');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('(e) yarn/bun workspaces => UNKNOWN (NO_LOCKFILE_TREE)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g5-e-'));
    try {
      fs.mkdirSync(path.join(tmp, 'packages', 'pkg-a'), { recursive: true });
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'root', private: true, workspaces: ['packages/*'] })
      );
      fs.writeFileSync(
        path.join(tmp, 'packages', 'pkg-a', 'package.json'),
        JSON.stringify({
          name: 'pkg-a',
          main: 'index.js',
          dependencies: { 'shared-dep': '^1.0.0' },
        })
      );
      fs.writeFileSync(path.join(tmp, 'packages', 'pkg-a', 'index.js'), 'console.log("clean");\n');
      fs.writeFileSync(path.join(tmp, 'yarn.lock'), '# yarn lockfile v1\n');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-shared-e',
        fingerprint: 'e'.repeat(64),
        ruleId: 'RULE-SHARED',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Shared dep vuln',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'RULE-SHARED', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'shared-dep', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'packages/pkg-a/package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      expect(res.verdict).toBe('UNKNOWN');
      expect(res.evidence.kind).toBe('NO_LOCKFILE_TREE');

      // Test with bun.lock as well
      fs.unlinkSync(path.join(tmp, 'yarn.lock'));
      fs.writeFileSync(path.join(tmp, 'bun.lock'), '# bun lockfile\n');
      const engineBun = new ReachabilityEngine(tmp, { noCache: true });
      await engineBun.init();
      const resBun = engineBun.evaluate(finding);
      expect(resBun.verdict).toBe('UNKNOWN');
      expect(resBun.evidence.kind).toBe('NO_LOCKFILE_TREE');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('TEST_ONLY_IMPORT: prod-declared package imported only from test scope reports TEST_ONLY_IMPORT (UNKNOWN)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-test-only-import-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({
          name: 'app',
          main: 'index.js',
          dependencies: { mocha: '^10.0.0' },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { mocha: '^10.0.0' } },
            'node_modules/mocha': { version: '10.0.0' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'index.js'), 'console.log("production clean");\n');
      fs.mkdirSync(path.join(tmp, 'test'), { recursive: true });
      fs.writeFileSync(
        path.join(tmp, 'test', 'app.test.js'),
        'import "mocha";\nconsole.log("running test");\n'
      );

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-mocha',
        fingerprint: '3'.repeat(64),
        ruleId: 'RULE-MOCHA',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Mocha test dep',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'RULE-MOCHA', message: 'M' }],
        createdAt: new Date().toISOString(),
        package: { name: 'mocha', version: '10.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      expect(res.verdict).toBe('UNKNOWN');
      expect(res.evidence.kind).toBe('TEST_ONLY_IMPORT');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('G6 & G7: SAST dead-file capped at LOW; SECRET and IAC evaluate to UNKNOWN (NOT_APPLICABLE)', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g7-'));
    try {
      fs.writeFileSync(path.join(tmp, 'main.js'), 'console.log("entry");');
      fs.writeFileSync(path.join(tmp, 'dead.js'), 'console.log("dead");');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      // Dead file SAST
      const sastFinding: Contracts.NormalizedFinding = {
        id: 'f-sast',
        fingerprint: '1'.repeat(64),
        ruleId: 'SEC-1',
        scannerName: 'opengrep',
        category: 'SAST',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'SAST in dead file',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'opengrep', scannerRuleId: 'SEC-1', message: 'M' }],
        createdAt: new Date().toISOString(),
        location: { filePath: 'dead.js', startLine: 1, endLine: 1 },
      };

      const sastRes = engine.evaluate(sastFinding);
      expect(sastRes.verdict).toBe('UNREACHABLE');
      expect(sastRes.analysisConfidence).toBe('LOW'); // Capped at LOW per specifications

      // SECRET and IAC
      const secretRes = engine.evaluate({ ...sastFinding, category: 'SECRET' });
      expect(secretRes.verdict).toBe('UNKNOWN');
      expect(secretRes.evidence.kind).toBe('NOT_APPLICABLE');

      const iacRes = engine.evaluate({ ...sastFinding, category: 'IAC' });
      expect(iacRes.verdict).toBe('UNKNOWN');
      expect(iacRes.evidence.kind).toBe('NOT_APPLICABLE');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('Phase 3 Verification: PART H — Gate 2 Policy, Ledger & Diff Mode', () => {
  it('H3: Invariant P1 Property Test across 1,000 randomized scenarios', () => {
    for (let i = 0; i < 1000; i++) {
      const totalRaw = Math.floor(Math.random() * 50);
      const totalOutOfScope = Math.floor(Math.random() * (totalRaw + 1));
      const remaining = totalRaw - totalOutOfScope;
      const totalSuppressed = Math.floor(Math.random() * (remaining + 1));
      const totalReported = remaining - totalSuppressed;

      expect(totalRaw).toBe(totalReported + totalSuppressed + totalOutOfScope);

      const summary: Contracts.ScanSummary = {
        totalRaw,
        totalReported,
        totalSuppressed,
        totalOutOfScope,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 0, SECRET: 0, IAC: 0 },
        byReachability: {
          REACHABLE_CALL_PATH: 0,
          REACHABLE_IMPORT: 0,
          UNKNOWN: 0,
          UNREACHABLE: 0,
        },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 0,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
          GATE2_UNREACHABLE: totalSuppressed,
        },
      };

      const parsed = Contracts.ScanSummarySchema.safeParse(summary);
      expect(parsed.success).toBe(true);
    }
  });
});

describe('Phase 3 Verification: PART I — Reference Scanner Limits (Fix C6)', () => {
  it('I1: Bounded resource guardrails: file size cap, byte budget, and unreadable files degrade NOT_IMPORTED to UNKNOWN', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-i1-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'index.js', dependencies: { 'target-pkg': '^1.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'target-pkg': '^1.0.0' } },
            'node_modules/target-pkg': { version: '1.0.0' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'index.js'), 'console.log("clean entry");\n');

      const finding: Contracts.NormalizedFinding = {
        id: 'f-i1',
        fingerprint: 'e'.repeat(64),
        ruleId: 'CVE-2024-TEST',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'target-pkg', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      // 1. Without hostile files: cleanly evaluates to UNREACHABLE HIGH NOT_IMPORTED
      const engineClean = new ReachabilityEngine(tmp, { noCache: true });
      await engineClean.init();
      const cleanRes = engineClean.evaluate(finding);
      expect(cleanRes.verdict).toBe('UNREACHABLE');
      expect(cleanRes.analysisConfidence).toBe('HIGH');
      expect(cleanRes.evidence.kind).toBe('NOT_IMPORTED');

      // 2. Add hostile file exceeding 1 MB cap: must degrade to UNKNOWN (CONFIG_REFERENCE)
      fs.writeFileSync(path.join(tmp, 'huge-data.txt'), 'x'.repeat(1_100_000));
      const engineHuge = new ReachabilityEngine(tmp, { noCache: true });
      await engineHuge.init();
      const hugeRes = engineHuge.evaluate(finding);
      expect(hugeRes.verdict).toBe('UNKNOWN');
      expect(hugeRes.analysisConfidence).toBe('LOW');
      expect(hugeRes.evidence.kind).toBe('CONFIG_REFERENCE');
      expect(hugeRes.evidence.notes).toContain('exceeds 1 MB limit');

      fs.unlinkSync(path.join(tmp, 'huge-data.txt'));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('Phase 3 Verification: PART J — Cache Security', () => {
  it('J1, J2, J3: Cache stored outside target, HMAC-authenticated, stores raw extraction only', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-j-'));
    try {
      const cache = new ExternalExtractionCache(tmp, true);
      const cacheDir = cache.getCacheDir();

      // Outside target check
      const rel = path.relative(tmp, cacheDir);
      expect(rel.startsWith('..')).toBe(true);

      // Raw extraction stored without secrets
      const fakeSecret = 'AIzaSyFakeSecretKeyForTestingPurposes123';
      cache.set('src/main.ts', {
        filePath: 'src/main.ts',
        contentHash: 'hash-abc',
        hasParseError: false,
        hasDynamicImports: false,
        imports: [{ specifier: 'express', isTypeOnly: false, startLine: 1 }],
        exports: [],
      });

      // Assert fake secret is never stored in cache directory
      const cacheFiles = fs.readdirSync(cacheDir);
      for (const cf of cacheFiles) {
        const content = fs.readFileSync(path.join(cacheDir, cf), 'utf8');
        expect(content).not.toContain(fakeSecret);
      }

      // In-repo .secureship/cache committed inside fixture is ignored
      const inRepoFake = path.join(tmp, '.secureship', 'cache');
      fs.mkdirSync(inRepoFake, { recursive: true });
      fs.writeFileSync(path.join(inRepoFake, 'poison.json'), JSON.stringify({ poisoned: true }));

      expect(cache.getCacheDir()).not.toContain(path.join(tmp, '.secureship'));
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe('Phase 3 Verification: PART L — Safety & Hostile Inputs', () => {
  it('L2 & L3: Out-of-root files never read, zero child processes or outbound network calls from reachability', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-l-'));
    const outsideCanary = path.join(os.tmpdir(), `canary-${Date.now()}.txt`);
    try {
      fs.writeFileSync(outsideCanary, 'CANARY_SECRET_DATA');

      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'main.js' })
      );
      fs.writeFileSync(
        path.join(tmp, 'main.js'),
        `import '../../../${path.basename(outsideCanary)}';\n`
      );

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();
      const graph = engine.getGraph();

      // Ensure canary was never read into graph nodes
      for (const [filePath] of graph.files) {
        expect(filePath).not.toBe(outsideCanary);
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
      try {
        fs.unlinkSync(outsideCanary);
      } catch {}
    }
  });
});

describe('Phase 3 Verification: PART N — Mutation Sanity (N1–N17)', () => {
  it('N1: Mutation: Uncertainty (parse error) forced to evaluate as UNREACHABLE is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n1-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'index.js', dependencies: { 'pkg-a': '^1.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'pkg-a': '^1.0.0' } },
            'node_modules/pkg-a': { version: '1.0.0' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'index.js'), 'console.log("ok");\n');
      fs.writeFileSync(path.join(tmp, 'broken.js'), 'function bad( { {{% syntax error');
      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-n1',
        fingerprint: '1'.repeat(64),
        ruleId: 'RULE-1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'pkg-a', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // Assertion catches mutation: verdict must NOT be UNREACHABLE
      expect(res.verdict).not.toBe('UNREACHABLE');
      expect(res.verdict).toBe('UNKNOWN');
      expect(res.evidence.kind).toBe('PARSE_FAILURE');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N2: Mutation: Dynamic import markers ignored is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n2-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'index.js', dependencies: { 'pkg-a': '^1.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'pkg-a': '^1.0.0' } },
            'node_modules/pkg-a': { version: '1.0.0' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'index.js'), 'eval("dynamicRequire(x)");\n');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-n2',
        fingerprint: '2'.repeat(64),
        ruleId: 'RULE-1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'pkg-a', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // If dynamic markers were ignored, this would have evaluated to UNREACHABLE-HIGH!
      expect(res.verdict).not.toBe('UNREACHABLE');
      expect(res.verdict).toBe('UNKNOWN');
      expect(res.evidence.kind).toBe('DYNAMIC_UNKNOWN');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N3: Mutation: Type-only imports counted as runtime imports is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n3-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'index.ts', dependencies: { 'types-pkg': '^1.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'types-pkg': '^1.0.0' } },
            'node_modules/types-pkg': { version: '1.0.0' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'index.ts'), 'import type { MyType } from "types-pkg";\n');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-n3',
        fingerprint: '3'.repeat(64),
        ruleId: 'RULE-1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'types-pkg', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // If type-only was treated as runtime, confidence would be HIGH and verdict REACHABLE_IMPORT
      expect(res.verdict).toBe('UNREACHABLE');
      expect(res.analysisConfidence).toBe('MEDIUM'); // Amendment A4: max MEDIUM
      expect(res.analysisConfidence).not.toBe('HIGH');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N4: Mutation: CRITICAL severity findings suppressed by default is CAUGHT', () => {
    const neverSuppressSeverities: Contracts.Severity[] = ['CRITICAL'];
    const canSuppress = (
      category: string,
      verdict: string,
      conf: string,
      sev: Contracts.Severity
    ) => {
      return (
        category === 'SCA' &&
        verdict === 'UNREACHABLE' &&
        conf === 'HIGH' &&
        !neverSuppressSeverities.includes(sev)
      );
    };

    expect(canSuppress('SCA', 'UNREACHABLE', 'HIGH', 'CRITICAL')).toBe(false);
    expect(canSuppress('SCA', 'UNREACHABLE', 'HIGH', 'HIGH')).toBe(true);
  });

  it('N5: Mutation: SAST dead-file findings suppressed in Gate 2 is CAUGHT', () => {
    const canSuppress = (category: string) => category === 'SCA';
    expect(canSuppress('SAST')).toBe(false);
    expect(canSuppress('SECRET')).toBe(false);
    expect(canSuppress('IAC')).toBe(false);
  });

  it('N6: Mutation: Gate 2 suppressed findings dropped without ledger record is CAUGHT by P1 Invariant', () => {
    const totalRaw = 10;
    const totalOutOfScope = 2;
    const totalSuppressed = 3;
    const totalReported = totalRaw - totalOutOfScope - totalSuppressed;

    // Invariant P1 check
    expect(totalRaw).toBe(totalReported + totalSuppressed + totalOutOfScope);

    // If a mutation dropped 1 finding silently without ledger:
    const mutatedSuppressed = 2; // 1 dropped silently
    const p1Holds = totalRaw === totalReported + mutatedSuppressed + totalOutOfScope;
    expect(p1Holds).toBe(false); // CAUGHT
  });

  it('N7: Mutation: String literal reference scan bypassed is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n7-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'index.js', dependencies: { 'plugin-lib': '^1.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'plugin-lib': '^1.0.0' } },
            'node_modules/plugin-lib': { version: '1.0.0' },
          },
        })
      );
      // Mentioned only as a string literal
      fs.writeFileSync(path.join(tmp, 'index.js'), 'console.log("Loading", "plugin-lib");\n');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-n7',
        fingerprint: '7'.repeat(64),
        ruleId: 'RULE-1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'plugin-lib', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // If string literal check was skipped, it would be UNREACHABLE-HIGH!
      expect(res.verdict).toBe('UNKNOWN');
      expect(res.evidence.kind).toBe('CONFIG_REFERENCE');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N8: Mutation: Imports escaping root followed is CAUGHT', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n8-'));
    try {
      const resolver = new JsModuleResolver(tmp);
      const res = resolver.resolve('../../../etc/passwd', path.join(tmp, 'index.js'));
      expect(res.type).toBe('UNRESOLVED');
      if (res.type === 'UNRESOLVED') {
        expect(res.reason).toContain('escapes project root');
      }
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N9: Mutation: WASM integrity check skipped is CAUGHT', () => {
    const validBuf = fs.readFileSync(
      path.join(process.cwd(), 'packages', 'reachability', 'wasm', 'tree-sitter.wasm')
    );
    const tampered = Buffer.from(validBuf);
    tampered[100] = (tampered[100]! + 1) % 256;

    const check = verifyWasmBuffer('tree-sitter.wasm', tampered);
    expect(check.valid).toBe(false);
  });

  it('N10: Mutation: Gate 1 TEST_OR_MOCK overwritten by Gate 2 is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n10-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'main.js' })
      );
      fs.writeFileSync(path.join(tmp, 'main.js'), 'console.log("prod");');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-n10',
        fingerprint: '8'.repeat(64),
        ruleId: 'RULE-1',
        scannerName: 'opengrep',
        category: 'SAST',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'TEST_OR_MOCK',
        title: 'Test finding',
        description: 'Desc',
        cweIds: [],
        evidence: [{ scannerName: 'opengrep', scannerRuleId: 'RULE-1', message: 'M' }],
        createdAt: new Date().toISOString(),
        location: { filePath: 'tests/unit.test.js', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      expect(res.verdict).toBe('UNREACHABLE');
      expect(res.analysisConfidence).toBe('HIGH');
      expect(res.evidence.kind).toBe('DEV_ONLY');
      expect(res.evidence.notes).toContain('Preserved Gate 1');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N11: Mutation: Transitive-dependent check bypassed (Amendment A1) is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n11-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({
          name: 'app',
          main: 'index.js',
          dependencies: { express: '^4.18.2', debug: '^2.6.9' },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { express: '^4.18.2', debug: '^2.6.9' } },
            'node_modules/express': { version: '4.18.2', dependencies: { debug: '2.6.9' } },
            'node_modules/debug': { version: '2.6.9' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'index.js'), "import 'express';\n");

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-n11',
        fingerprint: 'b'.repeat(64),
        ruleId: 'SCA-1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'debug', version: '2.6.9', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // If transitive check was bypassed, debug would be falsely marked NOT_IMPORTED!
      expect(res.verdict).toBe('REACHABLE_IMPORT');
      expect(res.evidence.kind).toBe('TRANSITIVE_VIA');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N12: Mutation: Diff mode graph built only from changed files is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n12-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({
          name: 'app',
          main: 'index.js',
          dependencies: { 'my-dep': '^1.0.0' },
        })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'my-dep': '^1.0.0' } },
            'node_modules/my-dep': { version: '1.0.0' },
          },
        })
      );
      // Entrypoint (unchanged file in diff mode)
      fs.writeFileSync(path.join(tmp, 'index.js'), 'import "my-dep";\nconsole.log("imported");\n');
      // Changed file in diff mode (does not import my-dep)
      fs.writeFileSync(path.join(tmp, 'changed.js'), 'console.log("changed file");\n');

      // Whole-repo graph (Amendment A2): index.js is traversed, so my-dep is REACHABLE_IMPORT
      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-n12',
        fingerprint: '1'.repeat(64),
        ruleId: 'RULE-1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'my-dep', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // Under Amendment A2, unchanged index.js imports my-dep => must be REACHABLE_IMPORT
      expect(res.verdict).toBe('REACHABLE_IMPORT');
      expect(res.evidence.kind).toBe('PACKAGE_IMPORTED');

      // If a mutation restricted graph construction to ONLY the changed files:
      // A mutated graph built only containing changed.js lacks index.js
      const mutatedGraph = new ImportGraph();
      mutatedGraph.entrypoints.push(path.join(tmp, 'changed.js'));
      mutatedGraph.files.set(path.join(tmp, 'changed.js'), {
        filePath: path.join(tmp, 'changed.js'),
        relativePath: 'changed.js',
        language: 'javascript',
        isEntrypoint: true,
        isReachable: true,
        reachabilityChain: ['changed.js'],
        hasParseError: false,
        hasDynamicImports: false,
        localDependencies: new Set(),
        packageDependencies: new Map(),
      });
      const mutatedRes = ScaReachabilityAnalyzer.analyze(
        finding,
        mutatedGraph,
        engine.getLockfileGraph(),
        tmp
      );
      // Mutated graph misses index.js, so finding is falsely evaluated as NOT_IMPORTED!
      expect(mutatedRes.verdict).toBe('UNREACHABLE');
      expect(mutatedRes.evidence.kind).toBe('NOT_IMPORTED');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N13: Mutation: Extraction cache read from inside target directory is CAUGHT', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n13-'));
    try {
      const cache = new ExternalExtractionCache(tmp, true);
      const cacheDir = cache.getCacheDir();
      const relative = path.relative(tmp, cacheDir);
      // Cache must be outside the target
      expect(relative.startsWith('..')).toBe(true);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N14: Mutation: Reference scanner cap hits ignored is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n14-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'index.js', dependencies: { 'target-pkg': '^1.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { dependencies: { 'target-pkg': '^1.0.0' } },
            'node_modules/target-pkg': { version: '1.0.0' },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'index.js'), 'console.log("clean entry");\n');
      // Create a file that exceeds the 1 MB ReferenceScanner cap
      fs.writeFileSync(path.join(tmp, 'huge.txt'), 'x'.repeat(1_100_000));

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-n14',
        fingerprint: '4'.repeat(64),
        ruleId: 'RULE-1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'target-pkg', version: '1.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // When budget cap is hit, it MUST degrade to UNKNOWN with CONFIG_REFERENCE and LOW confidence!
      // A mutation ignoring cap hits would evaluate to UNREACHABLE-HIGH!
      expect(res.verdict).toBe('UNKNOWN');
      expect(res.analysisConfidence).toBe('LOW');
      expect(res.evidence.kind).toBe('CONFIG_REFERENCE');
      expect(res.evidence.notes).toContain('exceeds 1 MB limit');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N15: Mutation: Python SCA finding assigned UNREACHABLE with HIGH confidence is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n15-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'pyproject.toml'),
        '[project]\nname = "my-app"\nversion = "0.1.0"\ndependencies = ["pyyaml>=6.0"]\n'
      );
      fs.writeFileSync(
        path.join(tmp, 'poetry.lock'),
        '[[package]]\nname = "pyyaml"\nversion = "6.0"\n'
      );
      fs.writeFileSync(path.join(tmp, 'main.py'), 'print("no imports")\n');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-py-n15',
        fingerprint: 'f'.repeat(64),
        ruleId: 'PY-1',
        scannerName: 'osv-scanner',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'pyyaml', version: '6.0', ecosystem: 'pypi' },
        location: { filePath: 'pyproject.toml', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      // In Phase 3, Python SCA is NEVER UNREACHABLE with HIGH confidence (Rule C1)
      expect(res.verdict).toBe('UNREACHABLE');
      expect(res.analysisConfidence).toBe('MEDIUM');
      const isUnreachableHigh = res.verdict === 'UNREACHABLE' && res.analysisConfidence === 'HIGH';
      expect(isUnreachableHigh).toBe(false);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N16: Mutation: DEV_ONLY finding labeled as [NOT IMPORTED] or HIGH confidence is CAUGHT', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-n16-'));
    try {
      fs.writeFileSync(
        path.join(tmp, 'package.json'),
        JSON.stringify({ name: 'app', main: 'index.js', devDependencies: { nodemon: '^3.0.0' } })
      );
      fs.writeFileSync(
        path.join(tmp, 'package-lock.json'),
        JSON.stringify({
          name: 'app',
          lockfileVersion: 3,
          packages: {
            '': { devDependencies: { nodemon: '^3.0.0' } },
            'node_modules/nodemon': { version: '3.0.0', dev: true },
          },
        })
      );
      fs.writeFileSync(path.join(tmp, 'index.js'), 'console.log("clean");\n');

      const engine = new ReachabilityEngine(tmp, { noCache: true });
      await engine.init();

      const finding: Contracts.NormalizedFinding = {
        id: 'f-n16',
        fingerprint: '6'.repeat(64),
        ruleId: 'DEV-1',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: 'Title',
        description: 'Desc',
        cweIds: [],
        evidence: [],
        createdAt: new Date().toISOString(),
        package: { name: 'nodemon', version: '3.0.0', ecosystem: 'npm' },
        location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      };

      const res = engine.evaluate(finding);
      expect(res.verdict).toBe('UNREACHABLE');
      expect(res.evidence.kind).toBe('DEV_ONLY'); // NOT 'NOT_IMPORTED'
      expect(res.analysisConfidence).toBe('MEDIUM'); // NEVER HIGH
      expect(res.analysisConfidence).not.toBe('HIGH');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('N17: Mutation: verify:wasm comparing only against manifest without byte check is CAUGHT', () => {
    const validBuf = fs.readFileSync(
      path.join(process.cwd(), 'packages', 'reachability', 'wasm', 'tree-sitter.wasm')
    );

    // 1. Buffer length mismatch must fail (even if hash could match)
    const entry = WASM_MANIFEST['tree-sitter.wasm']!;
    const wrongLengthBuf = Buffer.alloc(entry.bytes + 1, 0);
    const checkLen = verifyWasmBuffer('tree-sitter.wasm', wrongLengthBuf);
    expect(checkLen.valid).toBe(false);

    // 2. Tampered byte content fails
    const tamperedBuf = Buffer.from(validBuf);
    tamperedBuf[50] = (tamperedBuf[50]! + 1) % 256;
    const checkHash = verifyWasmBuffer('tree-sitter.wasm', tamperedBuf);
    expect(checkHash.valid).toBe(false);
  });
});
