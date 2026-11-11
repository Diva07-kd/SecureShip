import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type { NormalizedFinding } from '@secureship/contracts';
import { ReachabilityEngine } from '../src/reachability-engine.js';

describe('ReachabilityEngine Full Suite', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(
      os.tmpdir(),
      `secureship-engine-test-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  function createMockFinding(overrides: Partial<NormalizedFinding>): NormalizedFinding {
    return {
      id: 'f-1',
      fingerprint: 'a'.repeat(64),
      ruleId: 'test-rule',
      scannerName: 'osv-scanner',
      category: 'SCA',
      severity: 'HIGH',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      scopeTag: 'PRODUCTION',
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      location: { filePath: 'package.json', startLine: 1, endLine: 1 },
      title: 'Test',
      description: 'Desc',
      cweIds: [],
      evidence: [{ scannerName: 'osv-scanner', scannerRuleId: 'R1', message: 'M' }],
      createdAt: new Date().toISOString(),
      ...overrides,
    };
  }

  it('evaluates direct production imports as REACHABLE_IMPORT (PACKAGE_IMPORTED, HIGH)', async () => {
    // Setup repository with index.ts importing express
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'app',
        main: 'src/index.ts',
        dependencies: { express: '^4.18.2' },
      })
    );
    fs.writeFileSync(
      path.join(tmpDir, 'package-lock.json'),
      JSON.stringify({
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { express: '^4.18.2' } },
          'node_modules/express': { version: '4.18.2' },
        },
      })
    );
    fs.writeFileSync(
      path.join(tmpDir, 'src', 'index.ts'),
      "import express from 'express';\nconst app = express();\n"
    );

    const engine = new ReachabilityEngine(tmpDir, { noCache: true });
    await engine.init();

    const finding = createMockFinding({
      category: 'SCA',
      package: { ecosystem: 'npm', name: 'express', version: '4.18.2' },
    });

    const detail = engine.evaluate(finding);
    expect(detail.verdict).toBe('REACHABLE_IMPORT');
    expect(detail.analysisConfidence).toBe('HIGH');
    expect(detail.evidence.kind).toBe('PACKAGE_IMPORTED');
  });

  it('evaluates type-only imports as UNREACHABLE with MEDIUM confidence (Amendment A4)', async () => {
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'app',
        main: 'src/index.ts',
        dependencies: { 'type-fest': '^4.0.0' },
      })
    );
    fs.writeFileSync(
      path.join(tmpDir, 'package-lock.json'),
      JSON.stringify({
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { 'type-fest': '^4.0.0' } },
          'node_modules/type-fest': { version: '4.0.0' },
        },
      })
    );
    fs.writeFileSync(
      path.join(tmpDir, 'src', 'index.ts'),
      "import type { JsonObject } from 'type-fest';\nexport const x = 1;\n"
    );

    const engine = new ReachabilityEngine(tmpDir, { noCache: true });
    await engine.init();

    const finding = createMockFinding({
      category: 'SCA',
      package: { ecosystem: 'npm', name: 'type-fest', version: '4.0.0' },
    });

    const detail = engine.evaluate(finding);
    expect(detail.verdict).toBe('UNREACHABLE');
    expect(detail.analysisConfidence).toBe('MEDIUM'); // Amendment A4: never HIGH
    expect(detail.evidence.kind).toBe('DEV_ONLY');
  });

  it('evaluates transitive dependency of production import as REACHABLE_IMPORT (TRANSITIVE_VIA, MEDIUM)', async () => {
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'app',
        main: 'src/index.ts',
        dependencies: { express: '^4.18.2' },
      })
    );
    fs.writeFileSync(
      path.join(tmpDir, 'package-lock.json'),
      JSON.stringify({
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { express: '^4.18.2' } },
          'node_modules/express': {
            version: '4.18.2',
            dependencies: { 'nested-dep': '1.0.0' },
          },
          'node_modules/nested-dep': { version: '1.0.0' },
        },
      })
    );
    fs.writeFileSync(path.join(tmpDir, 'src', 'index.ts'), "import express from 'express';\n");

    const engine = new ReachabilityEngine(tmpDir, { noCache: true });
    await engine.init();

    const finding = createMockFinding({
      category: 'SCA',
      package: { ecosystem: 'npm', name: 'nested-dep', version: '1.0.0' },
    });

    const detail = engine.evaluate(finding);
    expect(detail.verdict).toBe('REACHABLE_IMPORT');
    expect(detail.analysisConfidence).toBe('MEDIUM');
    expect(detail.evidence.kind).toBe('TRANSITIVE_VIA');
    expect(detail.evidence.via).toContain('express');
  });

  it('evaluates unused leaf direct dependency meeting all criteria as UNREACHABLE (NOT_IMPORTED, HIGH)', async () => {
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'app',
        main: 'src/index.ts',
        dependencies: {
          express: '^4.18.2',
          unusedlib: '^1.0.0',
        },
      })
    );
    fs.writeFileSync(
      path.join(tmpDir, 'package-lock.json'),
      JSON.stringify({
        name: 'app',
        lockfileVersion: 3,
        packages: {
          '': {
            dependencies: { express: '^4.18.2', unusedlib: '^1.0.0' },
          },
          'node_modules/express': { version: '4.18.2' },
          'node_modules/unusedlib': { version: '1.0.0' },
        },
      })
    );
    fs.writeFileSync(path.join(tmpDir, 'src', 'index.ts'), "import express from 'express';\n");

    const engine = new ReachabilityEngine(tmpDir, { noCache: true });
    await engine.init();

    const finding = createMockFinding({
      category: 'SCA',
      package: { ecosystem: 'npm', name: 'unusedlib', version: '1.0.0' },
    });

    const detail = engine.evaluate(finding);
    expect(detail.verdict).toBe('UNREACHABLE');
    expect(detail.analysisConfidence).toBe('HIGH');
    expect(detail.evidence.kind).toBe('NOT_IMPORTED');
  });

  it('evaluates SAST findings with dead files as UNREACHABLE with LOW confidence', async () => {
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'app', main: 'src/index.ts' })
    );
    fs.writeFileSync(path.join(tmpDir, 'src', 'index.ts'), "console.log('main');\n");
    fs.writeFileSync(path.join(tmpDir, 'src', 'dead.ts'), "eval('unreachable dead code');\n");

    const engine = new ReachabilityEngine(tmpDir, { noCache: true });
    await engine.init();

    const finding = createMockFinding({
      category: 'SAST',
      location: { filePath: 'src/dead.ts', startLine: 1, endLine: 1 },
    });

    const detail = engine.evaluate(finding);
    expect(detail.verdict).toBe('UNREACHABLE');
    expect(detail.analysisConfidence).toBe('LOW'); // Low confidence ensures dead files are never auto-suppressed
    expect(detail.evidence.kind).toBe('DEAD_FILE');
  });

  it('preserves Gate 1 TEST_OR_MOCK scopeTag as UNREACHABLE (DEV_ONLY, HIGH)', async () => {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({ name: 'app', main: 'index.js' })
    );
    fs.writeFileSync(path.join(tmpDir, 'index.js'), "console.log('hello');\n");

    const engine = new ReachabilityEngine(tmpDir, { noCache: true });
    await engine.init();

    const finding = createMockFinding({
      category: 'SAST',
      scopeTag: 'TEST_OR_MOCK',
      location: { filePath: 'test/suite.test.ts', startLine: 1, endLine: 1 },
    });

    const detail = engine.evaluate(finding);
    expect(detail.verdict).toBe('UNREACHABLE');
    expect(detail.analysisConfidence).toBe('HIGH');
    expect(detail.evidence.kind).toBe('DEV_ONLY');
  });

  it('Principle G8: SECRET and IAC findings always evaluate to UNKNOWN (NOT_APPLICABLE)', async () => {
    const engine = new ReachabilityEngine(tmpDir, { noCache: true });
    await engine.init();

    const secretFinding = createMockFinding({ category: 'SECRET' });
    const secretDetail = engine.evaluate(secretFinding);
    expect(secretDetail.verdict).toBe('UNKNOWN');
    expect(secretDetail.evidence.kind).toBe('NOT_APPLICABLE');

    const iacFinding = createMockFinding({ category: 'IAC' });
    const iacDetail = engine.evaluate(iacFinding);
    expect(iacDetail.verdict).toBe('UNKNOWN');
    expect(iacDetail.evidence.kind).toBe('NOT_APPLICABLE');
  });

  it('throws an error if evaluate is called before init()', () => {
    const engine = new ReachabilityEngine(tmpDir, { noCache: true });
    expect(() => engine.evaluate(createMockFinding({ category: 'SAST' }))).toThrow(
      'ReachabilityEngine.init() must be awaited'
    );
  });

  it('returns lockfile graph from getLockfileGraph() and handles unknown category fallback', async () => {
    const engine = new ReachabilityEngine(tmpDir, { noCache: true });
    await engine.init();
    expect(engine.getLockfileGraph()).toBeNull();

    const fallbackFinding = createMockFinding({
      category: 'UNKNOWN_CAT' as unknown as import('@secureship/contracts').FindingCategory,
    });
    const res = engine.evaluate(fallbackFinding);
    expect(res.verdict).toBe('UNKNOWN');
    expect(res.evidence.kind).toBe('NOT_APPLICABLE');
    expect(res.evidence.notes).toContain('Unsupported finding category');
  });
});
