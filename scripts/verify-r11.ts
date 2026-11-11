/* eslint-disable @typescript-eslint/no-explicit-any */
import { tmpdir } from 'node:os';
import path from 'node:path';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { SafeProcessRunner } from '../packages/core-engine/dist/index.js';
import { ScanReportSchema } from '../packages/contracts/dist/index.js';

async function runR11() {
  console.log('=== STARTING R11 END-TO-END PROOF WITH REAL SCANNERS ===\n');

  const cliEntry = path.resolve('packages/cli/dist/index.js');
  const tempFixtureDir = mkdtempSync(path.join(tmpdir(), 'secureship-r11-fixture-'));

  try {
    // Setup fixture structure
    mkdirSync(path.join(tempFixtureDir, 'src'), { recursive: true });
    mkdirSync(path.join(tempFixtureDir, 'tests'), { recursive: true });

    // 1. Prod AWS secret & Test AWS secret
    writeFileSync(
      path.join(tempFixtureDir, 'src/config.js'),
      '// Production config\nexport const AWS_KEY = "AKIAI44QH8DHBEJ78901";\n'
    );
    writeFileSync(
      path.join(tempFixtureDir, 'tests/config.test.js'),
      '// Test mock config\nexport const TEST_AWS_KEY = "AKIAI44QH8DHBEJ78901";\n'
    );

    // 2. SAST: JS dynamic eval
    writeFileSync(
      path.join(tempFixtureDir, 'src/app.js'),
      'function handleInput(userInput) {\n  return eval(userInput);\n}\n'
    );

    // 3. SAST: Python pickle loads
    writeFileSync(
      path.join(tempFixtureDir, 'app.py'),
      'import pickle\ndef load_data(raw_data):\n    return pickle.loads(raw_data)\n'
    );

    // 4. SCA: package.json + package-lock.json with vulnerable lodash 4.17.15
    writeFileSync(
      path.join(tempFixtureDir, 'package.json'),
      JSON.stringify(
        {
          name: 'vulnerable-app',
          version: '1.0.0',
          dependencies: {
            lodash: '4.17.15',
          },
        },
        null,
        2
      )
    );

    writeFileSync(
      path.join(tempFixtureDir, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'vulnerable-app',
          version: '1.0.0',
          lockfileVersion: 2,
          packages: {
            '': {
              name: 'vulnerable-app',
              version: '1.0.0',
              dependencies: {
                lodash: '4.17.15',
              },
            },
            'node_modules/lodash': {
              version: '4.17.15',
              resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz',
              integrity:
                'sha512-8xOcRHvCjnocdS5cpwXQXVzcnhFIeTQ56MS626Yqnmh8GtKBgPFEzJ443gh749ABagNF8fMrYYS6zgXYOMCWzw==',
            },
          },
          dependencies: {
            lodash: {
              version: '4.17.15',
              resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz',
              integrity:
                'sha512-8xOcRHvCjnocdS5cpwXQXVzcnhFIeTQ56MS626Yqnmh8GtKBgPFEzJ443gh749ABagNF8fMrYYS6zgXYOMCWzw==',
            },
          },
        },
        null,
        2
      )
    );

    // 5. IaC: Dockerfile with obvious misconfigurations
    writeFileSync(
      path.join(tempFixtureDir, 'Dockerfile'),
      'FROM alpine:latest\nUSER root\nENTRYPOINT ["/bin/sh"]\n'
    );

    // 6. IaC: Terraform open security group
    writeFileSync(
      path.join(tempFixtureDir, 'main.tf'),
      `resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`
    );

    console.log(`Fixture created successfully at: ${tempFixtureDir}\n`);

    // --- STEP 1: scan <fixture> ---
    console.log('----------------------------------------------------');
    console.log('STEP 1: scan <fixture>');
    console.log('----------------------------------------------------');
    const step1 = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir],
      {
        timeoutMs: 120_000,
      }
    );
    console.log(`Exit Code: ${step1.exitCode} (timedOut: ${step1.timedOut})`);
    console.log(`Stdout:\n${step1.stdout}`);
    if (step1.stderr) console.log(`Stderr:\n${step1.stderr}`);

    // --- STEP 2: scan <fixture> --json ---
    console.log('----------------------------------------------------');
    console.log('STEP 2: scan <fixture> --json');
    console.log('----------------------------------------------------');
    const step2 = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--json'],
      { timeoutMs: 120_000 }
    );
    console.log(`Exit Code: ${step2.exitCode} (timedOut: ${step2.timedOut})`);
    let parsedReport: any = null;
    try {
      parsedReport = JSON.parse(step2.stdout);
      const validation = ScanReportSchema.safeParse(parsedReport);
      console.log(
        `Schema Validation: ${validation.success ? 'PASSED (ScanReportSchema)' : 'FAILED'}`
      );
      console.log(`Total Findings Reported: ${parsedReport.findings.length}`);
      console.log(`Total Findings Suppressed: ${parsedReport.suppressed.length}`);
      console.log(
        `Scanners Statuses: ${parsedReport.scanners.map((s: any) => `${s.name}=${s.status}`).join(', ')}`
      );
    } catch (e: any) {
      console.error('Failed to parse JSON:', e.message);
      console.log('Raw output was:\n', step2.stdout);
    }

    // --- STEP 3: scan <fixture> --sarif out.sarif ---
    console.log('----------------------------------------------------');
    console.log('STEP 3: scan <fixture> --sarif out.sarif');
    console.log('----------------------------------------------------');
    const sarifPath = path.join(tempFixtureDir, 'out.sarif');
    const step3 = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--sarif', sarifPath],
      { timeoutMs: 120_000 }
    );
    console.log(`Exit Code: ${step3.exitCode}`);
    console.log(`SARIF File Exists: ${existsSync(sarifPath)}`);
    if (existsSync(sarifPath)) {
      const sarifContent = JSON.parse(readFileSync(sarifPath, 'utf-8'));
      console.log(`SARIF Version: ${sarifContent.version}`);
      console.log(`SARIF Schema: ${sarifContent.$schema}`);
      console.log(`SARIF Runs Count: ${sarifContent.runs?.length}`);
      const resultCount = sarifContent.runs?.[0]?.results?.length ?? 0;
      console.log(`SARIF Results Count: ${resultCount}`);
    }

    // --- STEP 4: Confirm Policy & Merged Evidences ---
    console.log('----------------------------------------------------');
    console.log('STEP 4: Confirm Policy & Merged Findings');
    console.log('----------------------------------------------------');
    if (parsedReport) {
      const prodSecret = parsedReport.findings.find(
        (f: any) => f.category === 'SECRET' && f.location.filePath.includes('src/config.js')
      );
      const testSecretInReported = parsedReport.findings.find(
        (f: any) => f.category === 'SECRET' && f.location.filePath.includes('tests/config.test.js')
      );
      const testSecretInSuppressed = parsedReport.suppressed.find(
        (s: any) =>
          s.finding.category === 'SECRET' &&
          s.finding.location.filePath.includes('tests/config.test.js')
      );

      console.log(`Prod secret reported: ${Boolean(prodSecret)} (Rule: ${prodSecret?.ruleId})`);
      if (testSecretInReported) {
        console.log(
          `Test-dir secret status: KEPT IN REPORTED findings because Gate 1 provider-secret policy applies (keepProviderSecrets: true preserves active AWS provider secrets with non-placeholder values even in test folders).`
        );
      } else if (testSecretInSuppressed) {
        console.log(
          `Test-dir secret status: SUPPRESSED in ledger as ${testSecretInSuppressed.reasonCode ?? testSecretInSuppressed.reason} (${testSecretInSuppressed.detail})`
        );
      } else {
        console.log(`Test-dir secret: not detected`);
      }

      // Check SCA findings and evidence merge
      const scaFindings = parsedReport.findings.filter((f: any) => f.category === 'SCA');
      console.log(`Total SCA findings: ${scaFindings.length}`);
      for (const sca of scaFindings) {
        console.log(`  - Finding: ${sca.ruleId} (${sca.title})`);
        console.log(`    Evidence Count: ${sca.evidence?.length}`);
        const scannerNames = sca.evidence?.map((e: any) => e.scannerName);
        console.log(`    Scanners Contributing Evidence: ${scannerNames.join(', ')}`);
      }
    }

    // --- STEP 5: scan <fixture> --offline ---
    console.log('----------------------------------------------------');
    console.log('STEP 5: scan <fixture> --offline');
    console.log('----------------------------------------------------');
    const step5 = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--offline'],
      { timeoutMs: 120_000 }
    );
    console.log(`Exit Code: ${step5.exitCode}`);
    console.log(`Stdout:\n${step5.stdout}`);

    // --- STEP 6: Stripped PATH (No scanners found) ---
    console.log('----------------------------------------------------');
    console.log('STEP 6: Stripped PATH -> expect NOT SCANNED & exit 3');
    console.log('----------------------------------------------------');
    const missingCfg = path.join(tempFixtureDir, 'missing.config.json');
    writeFileSync(
      missingCfg,
      JSON.stringify({
        binaryOverrides: {
          gitleaks: 'C:/missing/gitleaks.exe',
          opengrep: 'C:/missing/opengrep.exe',
          trivy: 'C:/missing/trivy.exe',
          'osv-scanner': 'C:/missing/osv.exe',
          checkov: 'C:/missing/checkov.exe',
        },
      })
    );
    const step6 = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--config', missingCfg],
      { timeoutMs: 15_000 }
    );
    console.log(`Exit Code: ${step6.exitCode}`);
    console.log(`Stdout:\n${step6.stdout}`);
    if (step6.stderr) console.log(`Stderr:\n${step6.stderr}`);

    // --- STEP 7: --fail-on CRITICAL and --fail-on NONE exit codes ---
    console.log('----------------------------------------------------');
    console.log('STEP 7: --fail-on CRITICAL vs --fail-on NONE exit codes');
    console.log('----------------------------------------------------');
    const step7Crit = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--fail-on', 'CRITICAL'],
      { timeoutMs: 120_000 }
    );
    console.log(`--fail-on CRITICAL Exit Code: ${step7Crit.exitCode}`);

    const step7None = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--fail-on', 'NONE'],
      { timeoutMs: 120_000 }
    );
    console.log(`--fail-on NONE Exit Code: ${step7None.exitCode}`);

    // --- STEP 8: scan <fixture> --diff in two-commit repo, plus --staged ---
    console.log('----------------------------------------------------');
    console.log('STEP 8: --diff against real 2-commit git repo, plus --staged');
    console.log('----------------------------------------------------');
    await SafeProcessRunner.run('git', ['init'], { cwd: tempFixtureDir });
    await SafeProcessRunner.run('git', ['config', 'user.name', 'SecureShip Bot'], {
      cwd: tempFixtureDir,
    });
    await SafeProcessRunner.run('git', ['config', 'user.email', 'bot@secureship.local'], {
      cwd: tempFixtureDir,
    });
    await SafeProcessRunner.run('git', ['add', '.'], { cwd: tempFixtureDir });
    await SafeProcessRunner.run('git', ['commit', '-m', 'Initial commit with all files'], {
      cwd: tempFixtureDir,
    });

    // Make commit 2: modify src/app.js
    writeFileSync(
      path.join(tempFixtureDir, 'src/app.js'),
      '// Commit 2 modification\nfunction handleInput(userInput) {\n  return eval(userInput);\n}\n'
    );
    await SafeProcessRunner.run('git', ['add', 'src/app.js'], { cwd: tempFixtureDir });
    await SafeProcessRunner.run('git', ['commit', '-m', 'Commit 2 modifying app.js'], {
      cwd: tempFixtureDir,
    });

    // Run --diff HEAD~1
    const step8Diff = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--diff', 'HEAD~1'],
      { timeoutMs: 120_000 }
    );
    console.log(`--diff HEAD~1 Exit Code: ${step8Diff.exitCode}`);
    console.log(`--diff HEAD~1 Output:\n${step8Diff.stdout}`);

    // Modify a file and stage it for --staged test
    writeFileSync(
      path.join(tempFixtureDir, 'src/new-staged.js'),
      'export function runCmd(cmd) { return eval(cmd); }\n'
    );
    await SafeProcessRunner.run('git', ['add', 'src/new-staged.js'], { cwd: tempFixtureDir });

    const step8Staged = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--staged'],
      { timeoutMs: 120_000 }
    );
    console.log(`--staged Exit Code: ${step8Staged.exitCode}`);
    console.log(`--staged Output:\n${step8Staged.stdout}`);

    // --- STEP 9: Baseline update, rescan BASELINE_KNOWN, add new vulnerable file ---
    console.log('----------------------------------------------------');
    console.log('STEP 9: Baseline workflow (update-baseline -> rescan -> new file)');
    console.log('----------------------------------------------------');
    const step9Update = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--update-baseline'],
      { timeoutMs: 120_000 }
    );
    console.log(`--update-baseline Exit Code: ${step9Update.exitCode}`);
    console.log(
      `Baseline file created: ${existsSync(path.join(tempFixtureDir, '.secureship/baseline.json'))}`
    );

    const step9Rescan = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--json'],
      { timeoutMs: 120_000 }
    );
    console.log(`Rescan Exit Code: ${step9Rescan.exitCode}`);
    const rescanReport = JSON.parse(step9Rescan.stdout);
    console.log(`Reported findings after baseline: ${rescanReport.findings.length}`);
    console.log(
      `Suppressed baseline findings: ${rescanReport.summary.suppressedByReason.BASELINE_KNOWN}`
    );

    // Now add new vulnerable file
    writeFileSync(
      path.join(tempFixtureDir, 'src/brand-new-vuln.js'),
      'function execEval(input) { eval(input); }\n'
    );

    const step9NewFile = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', tempFixtureDir, '--json'],
      { timeoutMs: 120_000 }
    );
    console.log(`New File Scan Exit Code: ${step9NewFile.exitCode}`);
    const newFileReport = JSON.parse(step9NewFile.stdout);
    console.log(`Newly reported findings count: ${newFileReport.findings.length}`);
    for (const f of newFileReport.findings) {
      console.log(`  - Newly reported: ${f.ruleId} at ${f.location.filePath}`);
    }
  } finally {
    // Delete fixture programmatically
    try {
      rmSync(tempFixtureDir, { recursive: true, force: true });
      console.log(`\nTemp fixture cleaned up at: ${tempFixtureDir}`);
    } catch (e: any) {
      console.warn('Could not remove temp fixture:', e.message);
    }
  }

  console.log('\n=== R11 END-TO-END PROOF COMPLETE ===');
}

runR11().catch((err) => {
  console.error('R11 execution failed:', err);
  process.exit(1);
});
