import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ReachabilityEngine } from '@secureship/reachability';
import type { NormalizedFinding } from '@secureship/contracts';

describe('Gate 2 Metamorphic Mutation Test Suite (Amendment A15)', () => {
  let tempDir: string;

  const targetPkg = 'target-pkg';
  const finding: NormalizedFinding = {
    id: 'sca-meta-1',
    fingerprint: 'a'.repeat(64),
    scannerName: 'trivy',
    ruleId: 'CVE-2024-META',
    category: 'SCA',
    severity: 'HIGH',
    confidence: 'HIGH',
    reachability: 'UNKNOWN',
    upstreamValidationStatus: 'UNKNOWN',
    verificationStatus: 'UNVERIFIED',
    scopeTag: 'PRODUCTION',
    title: 'Test vulnerability',
    description: 'Test vulnerability',
    cweIds: [],
    evidence: [{ scannerName: 'trivy', scannerRuleId: 'CVE-2024-META', message: 'Test vuln' }],
    createdAt: new Date().toISOString(),
    package: {
      name: targetPkg,
      version: '1.0.0',
      ecosystem: 'npm',
    },
    location: {
      filePath: 'package.json',
      startLine: 1,
      endLine: 1,
    },
  };

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-meta-'));
    // Setup initial baseline project where target-pkg is UNREACHABLE with HIGH confidence
    fs.writeFileSync(
      path.join(tempDir, 'package.json'),
      JSON.stringify(
        {
          name: 'meta-project',
          main: 'index.js',
          dependencies: {
            [targetPkg]: '^1.0.0',
          },
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      path.join(tempDir, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'meta-project',
          lockfileVersion: 3,
          packages: {
            '': {
              dependencies: {
                [targetPkg]: '^1.0.0',
              },
            },
            [`node_modules/${targetPkg}`]: {
              version: '1.0.0',
            },
          },
        },
        null,
        2
      )
    );

    fs.writeFileSync(
      path.join(tempDir, 'index.js'),
      `console.log("Safe production code with no imports");\n`
    );
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  async function evaluateTarget(): Promise<ReturnType<ReachabilityEngine['evaluate']>> {
    const engine = new ReachabilityEngine(tempDir, {
      parseTimeoutMs: 5000,
      maxFileBytes: 1_048_576,
    });
    await engine.init();
    return engine.evaluate(finding);
  }

  it('confirms baseline project produces UNREACHABLE with HIGH confidence', async () => {
    const baseline = await evaluateTarget();
    expect(baseline.verdict).toBe('UNREACHABLE');
    expect(baseline.analysisConfidence).toBe('HIGH');
    expect(baseline.evidence.kind).toBe('NOT_IMPORTED');
  });

  it('mutation 1: adding a config entry naming the package flips verdict away from UNREACHABLE-HIGH', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'rollup.config.js'),
      `module.exports = { external: ['${targetPkg}'] };\n`
    );
    const mutated = await evaluateTarget();
    expect(mutated.verdict).toBe('UNKNOWN');
    expect(mutated.evidence.kind).toBe('CONFIG_REFERENCE');
  });

  it('mutation 2: adding a string literal in prod code flips verdict away from UNREACHABLE-HIGH', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'index.js'),
      `console.log("Loading plugin", "${targetPkg}");\n`
    );
    const mutated = await evaluateTarget();
    expect(mutated.verdict).toBe('UNKNOWN');
    expect(mutated.evidence.kind).toBe('CONFIG_REFERENCE');
  });

  it('mutation 3: adding an npm script using its bin flips verdict away from UNREACHABLE-HIGH', async () => {
    const pkgJson = JSON.parse(fs.readFileSync(path.join(tempDir, 'package.json'), 'utf8'));
    pkgJson.scripts = { build: `${targetPkg} compile --src src` };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(pkgJson, null, 2));

    const mutated = await evaluateTarget();
    expect(mutated.verdict).toBe('UNKNOWN');
    expect(mutated.evidence.kind).toBe('CONFIG_REFERENCE');
  });

  it('mutation 4: adding a syntax-error file flips verdict away from UNREACHABLE-HIGH', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'broken.js'),
      `function invalidSyntax( { {{{ %%%%% not valid js`
    );
    const mutated = await evaluateTarget();
    expect(mutated.verdict).toBe('UNKNOWN');
    expect(mutated.evidence.kind).toBe('PARSE_FAILURE');
  });

  it('mutation 5: adding dynamic require/eval in prod code flips verdict away from UNREACHABLE-HIGH', async () => {
    fs.writeFileSync(path.join(tempDir, 'index.js'), `const mod = eval('require("something")');\n`);
    const mutated = await evaluateTarget();
    expect(mutated.verdict).toBe('UNKNOWN');
    expect(mutated.evidence.kind).toBe('DYNAMIC_UNKNOWN');
  });

  it('mutation 6: deleting the only entrypoint flips verdict away from UNREACHABLE-HIGH', async () => {
    fs.unlinkSync(path.join(tempDir, 'index.js'));
    const mutated = await evaluateTarget();
    expect(mutated.verdict).toBe('UNKNOWN');
    expect(mutated.evidence.kind).toBe('NO_ENTRYPOINT');
  });

  it('mutation 7: adding a production import flips verdict to REACHABLE_IMPORT with HIGH confidence', async () => {
    fs.writeFileSync(
      path.join(tempDir, 'index.js'),
      `import '${targetPkg}';\nconsole.log("now imported");\n`
    );
    const mutated = await evaluateTarget();
    expect(mutated.verdict).toBe('REACHABLE_IMPORT');
    expect(mutated.analysisConfidence).toBe('HIGH');
    expect(mutated.evidence.kind).toBe('PACKAGE_IMPORTED');
  });
});
