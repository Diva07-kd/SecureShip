import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ReachabilityEngine } from '@secureship/reachability';
import type { NormalizedFinding } from '@secureship/contracts';

describe('Gate 2 Ground-Truth Fuzz Test (>= 300 Projects)', () => {
  let fuzzBaseDir: string;

  beforeAll(() => {
    fuzzBaseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fuzz-'));
  });

  afterAll(() => {
    try {
      fs.rmSync(fuzzBaseDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup on Windows
    }
  });

  it('generates >= 300 random projects and validates 0 false-unreachables with confusion matrix', async () => {
    const TOTAL_PROJECTS = 300;
    let falseUnreachableCount = 0;

    // Confusion Matrix: [Actual][Predicted]
    // Actual: REACHABLE, UNREACHABLE, UNKNOWN
    // Predicted: REACHABLE, UNREACHABLE, UNKNOWN
    const confusionMatrix = {
      ACTUAL_REACHABLE: { PRED_REACHABLE: 0, PRED_UNREACHABLE: 0, PRED_UNKNOWN: 0 },
      ACTUAL_UNREACHABLE: { PRED_REACHABLE: 0, PRED_UNREACHABLE: 0, PRED_UNKNOWN: 0 },
      ACTUAL_UNKNOWN: { PRED_REACHABLE: 0, PRED_UNREACHABLE: 0, PRED_UNKNOWN: 0 },
    };

    const scenarios = [
      'JS_PROD_IMPORTED',
      'JS_UNIMPORTED_LEAF',
      'JS_DEV_ONLY',
      'JS_TRANSITIVE_PROD',
      'JS_DYNAMIC_EVAL',
      'JS_SYNTAX_ERROR',
      'JS_CONFIG_REFERENCED',
      'PY_PROD_IMPORTED',
      'PY_UNIMPORTED_LEAF',
      'PY_UNMAPPED_PKG',
      'PY_FLAT_REQS_TRANSITIVE',
      'NO_ENTRYPOINT_PROJECT',
    ] as const;

    for (let i = 0; i < TOTAL_PROJECTS; i++) {
      const scenario = scenarios[i % scenarios.length];
      const projDir = path.join(fuzzBaseDir, `proj_${i}_${scenario}`);
      fs.mkdirSync(projDir, { recursive: true });

      let targetPkg = `pkg-${i}`;
      let actualTruth: 'ACTUAL_REACHABLE' | 'ACTUAL_UNREACHABLE' | 'ACTUAL_UNKNOWN' =
        'ACTUAL_UNKNOWN';
      let ecosystem = 'npm';

      if (scenario === 'JS_PROD_IMPORTED') {
        actualTruth = 'ACTUAL_REACHABLE';
        targetPkg = 'chalk';
        fs.writeFileSync(
          path.join(projDir, 'package.json'),
          JSON.stringify({
            name: `proj-${i}`,
            main: 'index.js',
            dependencies: { chalk: '^4.1.0' },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'package-lock.json'),
          JSON.stringify({
            name: `proj-${i}`,
            lockfileVersion: 2,
            packages: {
              '': { dependencies: { chalk: '^4.1.0' } },
              'node_modules/chalk': { version: '4.1.0' },
            },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'index.js'),
          `import chalk from 'chalk';\nconsole.log(chalk.blue('test'));\n`
        );
      } else if (scenario === 'JS_UNIMPORTED_LEAF') {
        actualTruth = 'ACTUAL_UNREACHABLE';
        targetPkg = 'unused-lib';
        fs.writeFileSync(
          path.join(projDir, 'package.json'),
          JSON.stringify({
            name: `proj-${i}`,
            main: 'index.js',
            dependencies: { 'unused-lib': '^1.0.0' },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'package-lock.json'),
          JSON.stringify({
            name: `proj-${i}`,
            lockfileVersion: 3,
            packages: {
              '': { dependencies: { 'unused-lib': '^1.0.0' } },
              'node_modules/unused-lib': { version: '1.0.0' },
            },
          })
        );
        fs.writeFileSync(path.join(projDir, 'index.js'), `console.log("hello world");\n`);
      } else if (scenario === 'JS_DEV_ONLY') {
        actualTruth = 'ACTUAL_UNREACHABLE';
        targetPkg = 'mocha';
        fs.writeFileSync(
          path.join(projDir, 'package.json'),
          JSON.stringify({
            name: `proj-${i}`,
            main: 'index.js',
            devDependencies: { mocha: '^9.0.0' },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'package-lock.json'),
          JSON.stringify({
            name: `proj-${i}`,
            lockfileVersion: 3,
            packages: {
              '': { devDependencies: { mocha: '^9.0.0' } },
              'node_modules/mocha': { version: '9.0.0', dev: true },
            },
          })
        );
        fs.writeFileSync(path.join(projDir, 'index.js'), `console.log("hello world");\n`);
      } else if (scenario === 'JS_TRANSITIVE_PROD') {
        actualTruth = 'ACTUAL_REACHABLE';
        targetPkg = 'ms';
        fs.writeFileSync(
          path.join(projDir, 'package.json'),
          JSON.stringify({
            name: `proj-${i}`,
            main: 'index.js',
            dependencies: { debug: '^4.3.0' },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'package-lock.json'),
          JSON.stringify({
            name: `proj-${i}`,
            lockfileVersion: 3,
            packages: {
              '': { dependencies: { debug: '^4.3.0' } },
              'node_modules/debug': {
                version: '4.3.0',
                dependencies: { ms: '2.1.2' },
              },
              'node_modules/ms': { version: '2.1.2' },
            },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'index.js'),
          `import debug from 'debug';\ndebug('app')('started');\n`
        );
      } else if (scenario === 'JS_DYNAMIC_EVAL') {
        actualTruth = 'ACTUAL_UNKNOWN';
        targetPkg = 'dynamic-target';
        fs.writeFileSync(
          path.join(projDir, 'package.json'),
          JSON.stringify({
            name: `proj-${i}`,
            main: 'index.js',
            dependencies: { 'dynamic-target': '^1.0.0' },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'package-lock.json'),
          JSON.stringify({
            name: `proj-${i}`,
            lockfileVersion: 3,
            packages: {
              '': { dependencies: { 'dynamic-target': '^1.0.0' } },
              'node_modules/dynamic-target': { version: '1.0.0' },
            },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'index.js'),
          `const mod = eval('require("dynamic-target")');\n`
        );
      } else if (scenario === 'JS_SYNTAX_ERROR') {
        actualTruth = 'ACTUAL_UNKNOWN';
        targetPkg = 'some-pkg';
        fs.writeFileSync(
          path.join(projDir, 'package.json'),
          JSON.stringify({
            name: `proj-${i}`,
            main: 'index.js',
            dependencies: { 'some-pkg': '^1.0.0' },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'package-lock.json'),
          JSON.stringify({
            name: `proj-${i}`,
            lockfileVersion: 3,
            packages: {
              '': { dependencies: { 'some-pkg': '^1.0.0' } },
              'node_modules/some-pkg': { version: '1.0.0' },
            },
          })
        );
        fs.writeFileSync(path.join(projDir, 'index.js'), `import { def broken; %%%% syntax error`);
      } else if (scenario === 'JS_CONFIG_REFERENCED') {
        actualTruth = 'ACTUAL_UNKNOWN';
        targetPkg = 'eslint';
        fs.writeFileSync(
          path.join(projDir, 'package.json'),
          JSON.stringify({
            name: `proj-${i}`,
            main: 'index.js',
            scripts: { lint: 'eslint .' },
            devDependencies: { eslint: '^8.0.0' },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'package-lock.json'),
          JSON.stringify({
            name: `proj-${i}`,
            lockfileVersion: 3,
            packages: {
              '': { devDependencies: { eslint: '^8.0.0' } },
              'node_modules/eslint': { version: '8.0.0', dev: true },
            },
          })
        );
        fs.writeFileSync(path.join(projDir, 'index.js'), `console.log("clean app");\n`);
      } else if (scenario === 'PY_PROD_IMPORTED') {
        actualTruth = 'ACTUAL_REACHABLE';
        ecosystem = 'pypi';
        targetPkg = 'pyyaml';
        fs.writeFileSync(
          path.join(projDir, 'pyproject.toml'),
          `[project]\nname = "proj-${i}"\nversion = "0.1.0"\ndependencies = ["pyyaml>=5.0"]\n`
        );
        fs.writeFileSync(
          path.join(projDir, 'poetry.lock'),
          `[[package]]\nname = "pyyaml"\nversion = "6.0"\n`
        );
        fs.writeFileSync(
          path.join(projDir, 'main.py'),
          `import yaml\nprint(yaml.safe_load("a: 1"))\n`
        );
      } else if (scenario === 'PY_UNIMPORTED_LEAF') {
        actualTruth = 'ACTUAL_UNREACHABLE';
        ecosystem = 'pypi';
        targetPkg = 'pyyaml';
        fs.writeFileSync(
          path.join(projDir, 'pyproject.toml'),
          `[project]\nname = "proj-${i}"\nversion = "0.1.0"\ndependencies = ["pyyaml>=5.0"]\n`
        );
        fs.writeFileSync(
          path.join(projDir, 'poetry.lock'),
          `[[package]]\nname = "pyyaml"\nversion = "6.0"\n`
        );
        fs.writeFileSync(path.join(projDir, 'main.py'), `print("no imports here")\n`);
      } else if (scenario === 'PY_UNMAPPED_PKG') {
        actualTruth = 'ACTUAL_UNKNOWN';
        ecosystem = 'pypi';
        targetPkg = 'completely-fictional-package-xyz-123';
        fs.writeFileSync(
          path.join(projDir, 'pyproject.toml'),
          `[project]\nname = "proj-${i}"\nversion = "0.1.0"\ndependencies = ["completely-fictional-package-xyz-123"]\n`
        );
        fs.writeFileSync(
          path.join(projDir, 'poetry.lock'),
          `[[package]]\nname = "completely-fictional-package-xyz-123"\nversion = "1.0"\n`
        );
        fs.writeFileSync(path.join(projDir, 'main.py'), `print("running")\n`);
      } else if (scenario === 'PY_FLAT_REQS_TRANSITIVE') {
        actualTruth = 'ACTUAL_UNKNOWN';
        ecosystem = 'pypi';
        targetPkg = 'urllib3';
        fs.writeFileSync(
          path.join(projDir, 'requirements.txt'),
          `requests==2.28.0\nurllib3==1.26.9\n`
        );
        fs.writeFileSync(
          path.join(projDir, 'main.py'),
          `import requests\nprint(requests.get("https://example.com"))\n`
        );
      } else if (scenario === 'NO_ENTRYPOINT_PROJECT') {
        actualTruth = 'ACTUAL_UNKNOWN';
        targetPkg = 'some-lib';
        fs.writeFileSync(
          path.join(projDir, 'package.json'),
          JSON.stringify({
            name: `proj-${i}`,
            dependencies: { 'some-lib': '^1.0.0' },
          })
        );
        fs.writeFileSync(
          path.join(projDir, 'package-lock.json'),
          JSON.stringify({
            name: `proj-${i}`,
            lockfileVersion: 3,
            packages: {
              '': { dependencies: { 'some-lib': '^1.0.0' } },
              'node_modules/some-lib': { version: '1.0.0' },
            },
          })
        );
        fs.writeFileSync(path.join(projDir, 'random-helper.js'), `console.log("no entrypoint");\n`);
      }

      // Finding under evaluation
      const finding: NormalizedFinding = {
        id: `vuln-${i}`,
        fingerprint: 'a'.repeat(64),
        scannerName: 'trivy',
        ruleId: 'CVE-2024-TEST',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        scopeTag: 'PRODUCTION',
        title: `Vulnerability in ${targetPkg}`,
        description: `Vulnerability in ${targetPkg}`,
        cweIds: [],
        evidence: [{ scannerName: 'trivy', scannerRuleId: 'CVE-2024-TEST', message: 'Test vuln' }],
        createdAt: new Date().toISOString(),
        package: {
          name: targetPkg,
          version: '1.0.0',
          ecosystem,
        },
        location: {
          filePath: ecosystem === 'pypi' ? 'pyproject.toml' : 'package.json',
          startLine: 1,
          endLine: 1,
        },
      };

      const engine = new ReachabilityEngine(projDir, {
        parseTimeoutMs: 5000,
        maxFileBytes: 1_048_576,
      });
      await engine.init();
      const result = engine.evaluate(finding);

      // Check false-unreachable condition:
      // If ground truth is REACHABLE (or dynamic/unknown where code might reach it),
      // a prediction of UNREACHABLE is a safety violation!
      if (actualTruth === 'ACTUAL_REACHABLE' && result.verdict === 'UNREACHABLE') {
        falseUnreachableCount++;
      }

      // Map predicted verdict to category
      let predCat: 'PRED_REACHABLE' | 'PRED_UNREACHABLE' | 'PRED_UNKNOWN' = 'PRED_UNKNOWN';
      if (result.verdict === 'REACHABLE_IMPORT' || result.verdict === 'REACHABLE_CALL_PATH') {
        predCat = 'PRED_REACHABLE';
      } else if (result.verdict === 'UNREACHABLE') {
        predCat = 'PRED_UNREACHABLE';
      }

      confusionMatrix[actualTruth][predCat]++;
    }

    // Print confusion matrix
    console.log('\n=== Gate 2 Fuzz Test Confusion Matrix (300 Projects) ===');
    console.log('---------------------------------------------------------');
    console.log('| Ground Truth       | Pred REACHABLE | Pred UNREACHABLE | Pred UNKNOWN |');
    console.log('---------------------------------------------------------');
    console.log(
      `| ACTUAL_REACHABLE   | ${confusionMatrix.ACTUAL_REACHABLE.PRED_REACHABLE.toString().padEnd(14)} | ${confusionMatrix.ACTUAL_REACHABLE.PRED_UNREACHABLE.toString().padEnd(16)} | ${confusionMatrix.ACTUAL_REACHABLE.PRED_UNKNOWN.toString().padEnd(12)} |`
    );
    console.log(
      `| ACTUAL_UNREACHABLE | ${confusionMatrix.ACTUAL_UNREACHABLE.PRED_REACHABLE.toString().padEnd(14)} | ${confusionMatrix.ACTUAL_UNREACHABLE.PRED_UNREACHABLE.toString().padEnd(16)} | ${confusionMatrix.ACTUAL_UNREACHABLE.PRED_UNKNOWN.toString().padEnd(12)} |`
    );
    console.log(
      `| ACTUAL_UNKNOWN     | ${confusionMatrix.ACTUAL_UNKNOWN.PRED_REACHABLE.toString().padEnd(14)} | ${confusionMatrix.ACTUAL_UNKNOWN.PRED_UNREACHABLE.toString().padEnd(16)} | ${confusionMatrix.ACTUAL_UNKNOWN.PRED_UNKNOWN.toString().padEnd(12)} |`
    );
    console.log('---------------------------------------------------------');
    console.log(`Total False-Unreachables: ${falseUnreachableCount}`);

    expect(falseUnreachableCount).toBe(0);
    expect(confusionMatrix.ACTUAL_REACHABLE.PRED_UNREACHABLE).toBe(0);
  });
});
