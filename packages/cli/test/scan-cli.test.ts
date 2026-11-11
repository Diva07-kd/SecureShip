import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { SafeProcessRunner } from '@secureship/core-engine';
import { ScanReportSchema } from '@secureship/contracts';
import { resolveReachabilityLabel } from '../src/commands/scan.js';

describe('CLI E2E Scan Suite', () => {
  const cliEntry = path.resolve('packages/cli/dist/index.js');
  const fixtureDir = path.resolve('packages/core-engine/test/fixtures');

  it('runs scan --json and outputs pure parseable JSON validating against ScanReportSchema', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'gitleaks', '--json'],
      { timeoutMs: 30_000 }
    );

    expect(res.exitCode).toBe(0);
    expect(res.stdout.trim()).not.toBe('');
    let parsed: unknown;
    expect(() => {
      parsed = JSON.parse(res.stdout);
    }).not.toThrow();

    const parseResult = ScanReportSchema.safeParse(parsed);
    expect(parseResult.success).toBe(true);

    const report = parseResult.data!;
    expect(report.tool.name).toBe('secureship');
    expect(report.mode).toBe('FULL');
    expect(report.summary.totalRaw).toBe(
      report.summary.totalReported + report.summary.totalSuppressed + report.summary.totalOutOfScope
    );
  }, 35_000);

  it('Amendment 2: --update-baseline combined with --diff exits 2 with a clear message', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--diff', 'main', '--update-baseline'],
      { timeoutMs: 10_000 }
    );

    expect(res.exitCode).toBe(2);
    const combinedOutput = res.stdout + res.stderr;
    expect(combinedOutput).toContain('Cannot update baseline in incremental diff');
  });

  it('Git Safety: --diff with leading dash ref exits 2 with option injection error', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--diff', '--upload-pack=pwned'],
      { timeoutMs: 10_000 }
    );

    expect(res.exitCode).toBe(2);
    const combinedOutput = res.stdout + res.stderr;
    expect(combinedOutput).toContain("starting with '-' are disallowed");
  });

  it('R10: scan . --diff HEAD~1 on a single-commit repo exits 2 with Unknown git ref', async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'r10-single-commit-'));
    try {
      await SafeProcessRunner.run('git', ['init'], { cwd: tempDir });
      await SafeProcessRunner.run('git', ['config', 'user.name', 'SecureShip Bot'], {
        cwd: tempDir,
      });
      await SafeProcessRunner.run('git', ['config', 'user.email', 'bot@secureship.local'], {
        cwd: tempDir,
      });
      writeFileSync(path.join(tempDir, 'file.txt'), 'initial commit\n');
      await SafeProcessRunner.run('git', ['add', '.'], { cwd: tempDir });
      await SafeProcessRunner.run('git', ['commit', '-m', 'commit 1'], { cwd: tempDir });

      const res = await SafeProcessRunner.run(
        'node',
        [cliEntry, 'scan', tempDir, '--diff', 'HEAD~1'],
        { timeoutMs: 15_000 }
      );

      expect(res.exitCode).toBe(2);
      expect(res.stderr + res.stdout).toContain(
        "Unknown git ref 'HEAD~1' (the repository may have too few commits)"
      );
    } finally {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it('R2: when NO scanner completes with SUCCESS, exits 3 and displays NOT SCANNED warning', async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'r2-all-missing-'));
    const cfg = path.join(tempDir, 'secureship.config.json');
    writeFileSync(
      cfg,
      JSON.stringify({
        binaryOverrides: {
          gitleaks: 'C:/nonexistent/gitleaks.exe',
          opengrep: 'C:/nonexistent/opengrep.exe',
          trivy: 'C:/nonexistent/trivy.exe',
          'osv-scanner': 'C:/nonexistent/osv.exe',
          checkov: 'C:/nonexistent/checkov.exe',
        },
      })
    );

    try {
      // 1. Human terminal mode
      const resHuman = await SafeProcessRunner.run(
        'node',
        [cliEntry, 'scan', tempDir, '--config', cfg],
        { timeoutMs: 15_000 }
      );
      expect(resHuman.exitCode).toBe(3);
      expect(resHuman.stderr + resHuman.stdout).toContain('⚠ NOT SCANNED: no scanner completed');
      expect(resHuman.stderr + resHuman.stdout).not.toContain(
        '✔ Clean: No security findings reported'
      );

      // 2. JSON mode adds warning to report
      const resJson = await SafeProcessRunner.run(
        'node',
        [cliEntry, 'scan', tempDir, '--config', cfg, '--json'],
        { timeoutMs: 15_000 }
      );
      expect(resJson.exitCode).toBe(3);
      const parsed = JSON.parse(resJson.stdout);
      expect(parsed.warnings.some((w: string) => w.includes('NOT SCANNED'))).toBe(true);
    } finally {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it('R2: when SOME scanners are missing, displays Clean for scanners that ran never bare Clean', async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'r2-partial-missing-'));
    const cfg = path.join(tempDir, 'secureship.config.json');
    writeFileSync(
      cfg,
      JSON.stringify({
        binaryOverrides: {
          opengrep: 'C:/nonexistent/opengrep.exe',
        },
      })
    );

    try {
      const res = await SafeProcessRunner.run(
        'node',
        [cliEntry, 'scan', tempDir, '--config', cfg, '--scanners', 'gitleaks,opengrep'],
        { timeoutMs: 20_000 }
      );
      expect(res.exitCode).toBe(0);
      expect(res.stdout).toContain(
        'Clean for scanners that ran: SecureShip Secret. NOT scanned: SecureShip SAST.'
      );
      expect(res.stdout).not.toContain(
        '✔ Clean: No security findings reported at or above threshold.'
      );
    } finally {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it('R3: status column padding in --no-color mode exactly aligns with colored output', async () => {
    const resColor = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'gitleaks'],
      { timeoutMs: 20_000 }
    );
    const resNoColor = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'gitleaks', '--no-color'],
      { timeoutMs: 20_000 }
    );

    expect(resColor.exitCode).toBe(0);
    expect(resNoColor.exitCode).toBe(0);

    const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');
    const headerColor = resColor.stdout
      .split('\n')
      .find((l) => l.includes('Scanner') && l.includes('Status'));
    const headerNoColor = resNoColor.stdout
      .split('\n')
      .find((l) => l.includes('Scanner') && l.includes('Status'));
    expect(headerColor).toBeDefined();
    expect(headerNoColor).toBeDefined();
    expect(headerNoColor).toBe(stripAnsi(headerColor!));

    // Verify row status index alignment
    const rowColor = resColor.stdout.split('\n').find((l) => l.includes('SecureShip Secret'));
    const rowNoColor = resNoColor.stdout.split('\n').find((l) => l.includes('SecureShip Secret'));
    expect(rowColor).toBeDefined();
    expect(rowNoColor).toBeDefined();

    const strippedRowColor = stripAnsi(rowColor!);
    expect(strippedRowColor.indexOf('SUCCESS')).toBe(rowNoColor!.indexOf('SUCCESS'));
    expect(strippedRowColor.indexOf('8.30.1')).toBe(rowNoColor!.indexOf('8.30.1'));
  });

  it('--strict mode exits 3 when scanners are missing or fail', async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'strict-missing-'));
    const cfg = path.join(tempDir, 'secureship.config.json');
    writeFileSync(
      cfg,
      JSON.stringify({
        binaryOverrides: {
          opengrep: 'C:/nonexistent/opengrep.exe',
        },
      })
    );

    try {
      const res = await SafeProcessRunner.run(
        'node',
        [cliEntry, 'scan', tempDir, '--config', cfg, '--strict', '--scanners', 'gitleaks,opengrep'],
        { timeoutMs: 20_000 }
      );

      // Should fail with infrastructure error code 3
      expect(res.exitCode).toBe(3);
    } finally {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it('rejects unknown scanners with exit code 2 and helpful error', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'unknown_scanner'],
      { timeoutMs: 10_000 }
    );

    expect(res.exitCode).toBe(2);
    expect(res.stderr + res.stdout).toContain('Unknown scanner(s) specified');
  });

  it('honors --output and --sarif flags to export files', async () => {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'cli-export-test-'));
    const jsonOut = path.join(tempDir, 'report.json');
    const sarifOut = path.join(tempDir, 'report.sarif');

    try {
      const res = await SafeProcessRunner.run(
        'node',
        [
          cliEntry,
          'scan',
          fixtureDir,
          '--scanners',
          'gitleaks',
          '--output',
          jsonOut,
          '--sarif',
          sarifOut,
        ],
        { timeoutMs: 20_000 }
      );

      expect(res.exitCode).toBe(0);
      const fs = await import('node:fs');
      expect(fs.existsSync(jsonOut)).toBe(true);
      expect(fs.existsSync(sarifOut)).toBe(true);

      const parsedJson = JSON.parse(fs.readFileSync(jsonOut, 'utf-8'));
      expect(parsedJson.schemaVersion).toBe('1.3');

      const parsedSarif = JSON.parse(fs.readFileSync(sarifOut, 'utf-8'));
      expect(parsedSarif.version).toBe('2.1.0');
    } finally {
      try {
        rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it('Amendment 4: honors --no-color flag and outputs unformatted plain text without ANSI codes', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'gitleaks', '--no-color'],
      { timeoutMs: 20_000 }
    );

    expect(res.exitCode).toBe(0);
    // Should NOT contain ANSI escape sequences (\x1b[...)
    expect(res.stdout).not.toMatch(/\x1b\[[0-9;]*m/);
    expect(res.stdout).toContain('SecureShip Security Scan Report');
    expect(res.stdout).toContain('Scanner Execution Status:');
  });

  it('Defect K1-01: scan --gate2 with invalid mode exits 2 with error and does not run scan', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--gate2', 'invalidMode'],
      { timeoutMs: 10_000 }
    );

    expect(res.exitCode).toBe(2);
    const combinedOutput = res.stdout + res.stderr;
    expect(combinedOutput).toContain('Invalid --gate2 mode "invalidMode"');
    expect(combinedOutput).toContain('Allowed modes: off, annotate, suppress');
  });

  it('R5: --gate2 off contract: no reachabilityDetail, no tags, no reachability summary line, no disclaimer, no byReachability', async () => {
    // 1. JSON output check
    const jsonRes = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'gitleaks', '--gate2', 'off', '--json'],
      { timeoutMs: 20_000 }
    );
    expect(jsonRes.exitCode).toBe(0);
    const jsonParsed = JSON.parse(jsonRes.stdout);
    expect(jsonParsed.summary.byReachability).toBeUndefined();
    expect(jsonParsed.summary.unknownByEvidence).toBeUndefined();
    for (const f of jsonParsed.findings) {
      expect(f.reachabilityDetail).toBeUndefined();
    }

    // 2. Human output check
    const humanRes = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', fixtureDir, '--scanners', 'gitleaks', '--gate2', 'off', '--no-color'],
      { timeoutMs: 20_000 }
    );
    expect(humanRes.exitCode).toBe(0);
    expect(humanRes.stdout).not.toContain('Reachability:');
    expect(humanRes.stdout).not.toContain('Import-level analysis only');
    expect(humanRes.stdout).not.toContain('[UNKNOWN]');
    expect(humanRes.stdout).not.toContain('[IMPORTED]');
    expect(humanRes.stdout).not.toContain('[NOT IMPORTED]');
  });

  describe('R6: Table-driven reachability human labels', () => {
    const cases = [
      {
        name: 'DEAD_FILE evidence kind maps to [NOT REACHED FROM ENTRYPOINT]',
        finding: {
          reachability: 'UNREACHABLE' as const,
          reachabilityDetail: {
            verdict: 'UNREACHABLE' as const,
            analysisConfidence: 'HIGH' as const,
            evidence: { kind: 'DEAD_FILE', notes: 'Unreachable' },
          },
        },
        expectedTag: '[NOT REACHED FROM ENTRYPOINT]',
        expectedCountKey: 'not reached from entrypoint',
      },
      {
        name: 'NOT_IMPORTED evidence kind maps to [NOT IMPORTED]',
        finding: {
          reachability: 'UNREACHABLE' as const,
          reachabilityDetail: {
            verdict: 'UNREACHABLE' as const,
            analysisConfidence: 'HIGH' as const,
            evidence: { kind: 'NOT_IMPORTED', notes: 'Never imported' },
          },
        },
        expectedTag: '[NOT IMPORTED]',
        expectedCountKey: 'not imported',
      },
      {
        name: 'DEV_ONLY evidence kind maps to [DEV/TEST ONLY]',
        finding: {
          reachability: 'UNREACHABLE' as const,
          reachabilityDetail: {
            verdict: 'UNREACHABLE' as const,
            analysisConfidence: 'MEDIUM' as const,
            evidence: { kind: 'DEV_ONLY', notes: 'Dev dependency only' },
          },
        },
        expectedTag: '[DEV/TEST ONLY]',
        expectedCountKey: 'dev/test only',
      },
      {
        name: 'type-only notes map to [TYPE-ONLY IMPORT]',
        finding: {
          reachability: 'UNREACHABLE' as const,
          reachabilityDetail: {
            verdict: 'UNREACHABLE' as const,
            analysisConfidence: 'MEDIUM' as const,
            evidence: {
              kind: 'DEV_ONLY',
              notes: 'Package is imported strictly via TypeScript type-only imports',
            },
          },
        },
        expectedTag: '[TYPE-ONLY IMPORT]',
        expectedCountKey: 'type-only import',
      },
      {
        name: 'TEST_ONLY_IMPORT evidence kind maps to [TEST-ONLY IMPORT]',
        finding: {
          reachability: 'UNREACHABLE' as const,
          reachabilityDetail: {
            verdict: 'UNREACHABLE' as const,
            analysisConfidence: 'HIGH' as const,
            evidence: { kind: 'TEST_ONLY_IMPORT', notes: 'Imported only in tests' },
          },
        },
        expectedTag: '[TEST-ONLY IMPORT]',
        expectedCountKey: 'test-only import',
      },
      {
        name: 'REACHABLE_CALL_PATH maps to [IMPORTED]',
        finding: {
          reachability: 'REACHABLE_CALL_PATH' as const,
          reachabilityDetail: {
            verdict: 'REACHABLE_CALL_PATH' as const,
            analysisConfidence: 'HIGH' as const,
            evidence: { kind: 'ENTRYPOINT_REACHABLE', notes: 'Call path exists' },
          },
        },
        expectedTag: '[IMPORTED]',
        expectedCountKey: 'imported',
      },
      {
        name: 'REACHABLE_IMPORT maps to [IMPORTED]',
        finding: {
          reachability: 'REACHABLE_IMPORT' as const,
          reachabilityDetail: {
            verdict: 'REACHABLE_IMPORT' as const,
            analysisConfidence: 'HIGH' as const,
            evidence: { kind: 'PACKAGE_IMPORTED', notes: 'Directly imported' },
          },
        },
        expectedTag: '[IMPORTED]',
        expectedCountKey: 'imported',
      },
      {
        name: 'UNREACHABLE default maps to [NOT IMPORTED]',
        finding: {
          reachability: 'UNREACHABLE' as const,
          reachabilityDetail: {
            verdict: 'UNREACHABLE' as const,
            analysisConfidence: 'HIGH' as const,
            evidence: { kind: 'SOME_OTHER_KIND', notes: 'Unreachable' },
          },
        },
        expectedTag: '[NOT IMPORTED]',
        expectedCountKey: 'not imported',
      },
      {
        name: 'UNKNOWN verdict maps to [UNKNOWN]',
        finding: {
          reachability: 'UNKNOWN' as const,
          reachabilityDetail: {
            verdict: 'UNKNOWN' as const,
            analysisConfidence: 'LOW' as const,
            evidence: { kind: 'DYNAMIC_UNKNOWN', notes: 'Uncertain' },
          },
        },
        expectedTag: '[UNKNOWN]',
        expectedCountKey: 'unknown',
      },
    ];

    for (const tc of cases) {
      it(tc.name, () => {
        const dummyFinding = {
          ruleId: 'test-rule',
          title: 'Test Finding',
          category: 'SAST' as const,
          severity: 'HIGH' as const,
          location: { filePath: 'src/app.ts', startLine: 1 },
          ...tc.finding,
        };
        const res = resolveReachabilityLabel(
          dummyFinding as unknown as Parameters<typeof resolveReachabilityLabel>[0]
        );
        expect(res.tag).toBe(tc.expectedTag);
        expect(res.countKey).toBe(tc.expectedCountKey);
      });
    }
  });
});
