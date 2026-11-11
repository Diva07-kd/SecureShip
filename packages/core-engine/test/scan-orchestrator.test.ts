import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { ScanOrchestrator } from '../src/orchestrator/scan-orchestrator.js';
import { ReachabilityEngine } from '@secureship/reachability';
import type { IScannerAdapter, ScanExecutionResult, ScanOptions } from '@secureship/contracts';

describe('ScanOrchestrator Integration & Isolation Suite', () => {
  let tempWorkspace: string;

  beforeEach(() => {
    tempWorkspace = mkdtempSync(path.join(tmpdir(), 'orchestrator-test-'));
    // Create package.json and a source file
    writeFileSync(
      path.join(tempWorkspace, 'package.json'),
      JSON.stringify({ name: 'test-app', version: '1.0.0' }),
      'utf-8'
    );
    writeFileSync(path.join(tempWorkspace, 'app.ts'), 'console.log("hello");\n', 'utf-8');
  });

  afterEach(() => {
    try {
      rmSync(tempWorkspace, { recursive: true, force: true });
    } catch {}
  });

  function createMockAdapter(
    name: 'gitleaks' | 'opengrep' | 'trivy' | 'osv-scanner' | 'checkov',
    behavior: 'success' | 'crash' | 'timeout' | 'missing',
    findingsCount = 0
  ): IScannerAdapter {
    return {
      name,
      category: name === 'gitleaks' ? 'SECRET' : name === 'opengrep' ? 'SAST' : 'SCA',
      version: async () => '1.0.0',
      isAvailable: async () => behavior !== 'missing',
      supportsProject: () => true,
      scan: async (_targetDir: string, options: ScanOptions = {}): Promise<ScanExecutionResult> => {
        if (behavior === 'missing') {
          return {
            scannerName: name,
            status: 'TOOL_MISSING',
            findings: [],
            durationMs: 10,
            exitCode: null,
            timedOut: false,
            errorMessage: 'Tool missing',
          };
        }
        if (behavior === 'crash') {
          return {
            scannerName: name,
            status: 'ERROR',
            findings: [],
            durationMs: 50,
            exitCode: 1,
            timedOut: false,
            errorMessage: 'Unexpected scanner crash',
          };
        }
        if (behavior === 'timeout') {
          return {
            scannerName: name,
            status: 'TIMEOUT',
            findings: [],
            durationMs: options.timeoutMs ?? 100,
            exitCode: null,
            timedOut: true,
            errorMessage: 'Scanner timed out',
          };
        }

        const findings = [];
        for (let i = 0; i < findingsCount; i++) {
          findings.push({
            id: `f-${name}-${i}`,
            fingerprint: `${name}-${i}`.padEnd(64, '0'),
            ruleId: `rule-${name}-${i}`,
            scannerName: name,
            category: name === 'gitleaks' ? ('SECRET' as const) : ('SAST' as const),
            severity: 'HIGH' as const,
            confidence: 'HIGH' as const,
            reachability: 'UNKNOWN' as const,
            location: { filePath: 'app.ts', startLine: 1, endLine: 1 },
            upstreamValidationStatus: 'UNKNOWN' as const,
            verificationStatus: 'UNVERIFIED' as const,
            scopeTag: 'PRODUCTION' as const,
            title: `Finding from ${name}`,
            description: `Description from ${name}`,
            cweIds: [],
            evidence: [{ scannerName: name, scannerRuleId: `rule-${name}-${i}`, message: 'Found' }],
            createdAt: new Date().toISOString(),
          });
        }

        return {
          scannerName: name,
          status: 'SUCCESS',
          findings,
          durationMs: 25,
          exitCode: 0,
          timedOut: false,
        };
      },
    };
  }

  it('P3 Failure Isolation: one scanner crashing and another timing out never aborts the successful scanner', async () => {
    const crashingAdapter = createMockAdapter('gitleaks', 'crash');
    const timingOutAdapter = createMockAdapter('trivy', 'timeout');
    const successfulAdapter = createMockAdapter('opengrep', 'success', 2);

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [crashingAdapter, timingOutAdapter, successfulAdapter],
      timeoutMs: 1000,
    });

    expect(report.scanners).toHaveLength(3);

    const gitleaksSummary = report.scanners.find((s) => s.name === 'gitleaks');
    const trivySummary = report.scanners.find((s) => s.name === 'trivy');
    const opengrepSummary = report.scanners.find((s) => s.name === 'opengrep');

    expect(gitleaksSummary?.status).toBe('ERROR');
    expect(trivySummary?.status).toBe('TIMEOUT');
    expect(opengrepSummary?.status).toBe('SUCCESS');

    // Findings from successful adapter are preserved
    expect(report.findings).toHaveLength(2);
    expect(report.summary.totalReported).toBe(2);
    expect(report.summary.totalRaw).toBe(2);
  });

  it('Strict mode records warning if any scanner fails', async () => {
    const missingAdapter = createMockAdapter('checkov', 'missing');
    const successfulAdapter = createMockAdapter('opengrep', 'success', 0);

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [missingAdapter, successfulAdapter],
      strict: true,
    });

    expect(report.warnings.some((w) => w.includes('Strict mode enabled'))).toBe(true);
  });

  it('throws error when --update-baseline is combined with --diff or --staged', async () => {
    const adapter = createMockAdapter('opengrep', 'success');

    await expect(
      ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [adapter],
        diffRef: 'HEAD~1',
        updateBaseline: true, // Illegal combination!
      })
    ).rejects.toThrow(/Cannot update baseline in incremental diff/);
  });

  it('respects config.scanners toggles and supportsProject filters', async () => {
    const opengrepAdapter = createMockAdapter('opengrep', 'success', 0);
    const gitleaksAdapter = createMockAdapter('gitleaks', 'success', 0);
    const unsupportedAdapter: IScannerAdapter = {
      ...createMockAdapter('checkov', 'success', 0),
      supportsProject: () => false,
    };

    const configPath = path.join(tempWorkspace, 'secureship.config.json');
    writeFileSync(
      configPath,
      JSON.stringify({
        scanners: {
          opengrep: true,
          gitleaks: false, // Disabled in config
        },
      }),
      'utf-8'
    );

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      configPath,
      adapters: [opengrepAdapter, gitleaksAdapter, unsupportedAdapter],
    });

    const ranNames = report.scanners.map((s) => s.name);
    expect(ranNames).toContain('opengrep');
    expect(ranNames).not.toContain('gitleaks');
    expect(ranNames).not.toContain('checkov');
  });

  it('handles AbortSignal cleanly and records cancellation', async () => {
    const adapter = createMockAdapter('opengrep', 'success', 0);
    const controller = new AbortController();
    controller.abort(); // Pre-aborted

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [adapter],
      signal: controller.signal,
    });

    expect(report.scanners[0]!.errorMessage).toContain('Scan aborted');
  });

  it('updates baseline file on full scan when updateBaseline is set', async () => {
    const adapter = createMockAdapter('opengrep', 'success', 2);
    const baselineFile = path.join(tempWorkspace, '.secureship-baseline.json');

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [adapter],
      updateBaseline: true,
      baselinePath: baselineFile,
    });

    expect(report.summary.totalReported).toBe(2);
    const fs = await import('node:fs');
    expect(fs.existsSync(baselineFile)).toBe(true);
    const baselineDoc = JSON.parse(fs.readFileSync(baselineFile, 'utf-8'));
    expect(baselineDoc.findings).toHaveLength(2);
  });

  it('filters executed scanners using explicit scanners array', async () => {
    const opengrepAdapter = createMockAdapter('opengrep', 'success', 0);
    const gitleaksAdapter = createMockAdapter('gitleaks', 'success', 0);

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [opengrepAdapter, gitleaksAdapter],
      scanners: ['gitleaks'],
    });

    expect(report.scanners).toHaveLength(1);
    expect(report.scanners[0]!.name).toBe('gitleaks');
  });

  it('routes findings through ignore rules, baseline, and reported streams in orchestrator', async () => {
    const adapter = createMockAdapter('opengrep', 'success', 3);

    // 1. Write config with ignore rule for finding 0
    const configPath = path.join(tempWorkspace, 'ignore-test.config.json');
    writeFileSync(
      configPath,
      JSON.stringify({
        ignore: [
          {
            ruleId: 'rule-opengrep-0',
            reason: 'Accepted security risk for legacy testing component',
            expires: '2026-12-31',
          },
        ],
      }),
      'utf-8'
    );

    // 2. Write baseline document containing fingerprint for finding 1
    const baselinePath = path.join(tempWorkspace, 'existing-baseline.json');
    const fp1 = 'opengrep-1'.padEnd(64, '0');
    writeFileSync(
      baselinePath,
      JSON.stringify({
        schemaVersion: '1.0',
        createdAt: '2026-01-01T00:00:00.000Z',
        findings: [
          {
            fingerprint: fp1,
            ruleId: 'rule-opengrep-1',
            filePath: 'app.ts',
            firstSeen: '2026-01-01T00:00:00.000Z',
          },
        ],
      }),
      'utf-8'
    );

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [adapter],
      configPath,
      baselinePath,
    });

    expect(report.summary.totalRaw).toBe(3);
    expect(report.summary.totalReported).toBe(1);
    expect(report.summary.totalSuppressed).toBe(2);
    expect(report.summary.suppressedByReason.USER_IGNORE_RULE).toBe(1);
    expect(report.summary.suppressedByReason.BASELINE_KNOWN).toBe(1);
    expect(report.findings[0]!.ruleId).toBe('rule-opengrep-2');
  });

  it('routes out-of-diff findings to totalOutOfScope and test code to Gate 1 suppression', async () => {
    const customAdapter: IScannerAdapter = {
      name: 'opengrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async () => ({
        scannerName: 'opengrep',
        status: 'SUCCESS',
        findings: [
          {
            id: 'f-prod-outside',
            fingerprint: 'a'.repeat(64),
            ruleId: 'rule-prod',
            scannerName: 'opengrep',
            category: 'SAST',
            severity: 'HIGH',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'src/untouched.ts', startLine: 1, endLine: 1 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'PRODUCTION',
            title: 'Outside finding',
            description: 'Outside diff scope',
            cweIds: [],
            evidence: [
              { scannerName: 'opengrep', scannerRuleId: 'rule-prod', message: 'Outside diff' },
            ],
            createdAt: new Date().toISOString(),
          },
          {
            id: 'f-test-inside',
            fingerprint: 'b'.repeat(64),
            ruleId: 'rule-test-eval',
            scannerName: 'opengrep',
            category: 'SAST',
            severity: 'HIGH',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'test/sample.test.ts', startLine: 5, endLine: 5 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'TEST_OR_MOCK',
            title: 'Test code finding',
            description: 'Inside modified test file',
            cweIds: [],
            evidence: [
              {
                scannerName: 'opengrep',
                scannerRuleId: 'rule-test-eval',
                message: 'Test eval found',
              },
            ],
            createdAt: new Date().toISOString(),
          },
        ],
        durationMs: 20,
        exitCode: 0,
        timedOut: false,
      }),
    };

    // Initialize git repo in tempWorkspace
    const { SafeProcessRunner } = await import('../src/sandbox/safe-process-runner.js');
    await SafeProcessRunner.run('git', ['init'], { cwd: tempWorkspace });
    await SafeProcessRunner.run('git', ['config', 'user.email', 'test@secureship.dev'], {
      cwd: tempWorkspace,
    });
    await SafeProcessRunner.run('git', ['config', 'user.name', 'SecureShip Tester'], {
      cwd: tempWorkspace,
    });

    // Initial commit
    const testFile = path.join(tempWorkspace, 'test', 'sample.test.ts');
    const fs = await import('node:fs');
    fs.mkdirSync(path.join(tempWorkspace, 'test'), { recursive: true });
    fs.writeFileSync(testFile, 'const testVar = 1;\n', 'utf-8');
    await SafeProcessRunner.run('git', ['add', '.'], { cwd: tempWorkspace });
    await SafeProcessRunner.run('git', ['commit', '-m', 'Initial commit'], { cwd: tempWorkspace });

    // Modify test file and stage it
    fs.writeFileSync(testFile, 'const testVar = 2;\n', 'utf-8');
    await SafeProcessRunner.run('git', ['add', '.'], { cwd: tempWorkspace });

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [customAdapter],
      staged: true, // Incremental staged mode
    });

    expect(report.summary.totalRaw).toBe(2);
    // f-prod-outside was outside staged diff -> totalOutOfScope
    expect(report.summary.totalOutOfScope).toBe(1);
    // f-test-inside was inside staged diff -> suppressed by Gate 1
    expect(report.summary.totalSuppressed).toBe(1);
    expect(report.summary.totalReported).toBe(0);
    expect(report.summary.suppressedByReason.GATE1_TEST_OR_MOCK).toBe(1);

    // Invariant P1 verification
    expect(report.summary.totalRaw).toBe(
      report.summary.totalReported + report.summary.totalSuppressed + report.summary.totalOutOfScope
    );
  });

  it('Amendment 1: finding that is both suppressible (Gate 1 / test code) and out-of-scope lands in totalOutOfScope and NEVER enters ledger', async () => {
    const customAdapter: IScannerAdapter = {
      name: 'opengrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async () => ({
        scannerName: 'opengrep',
        status: 'SUCCESS',
        findings: [
          {
            id: 'f-test-outside',
            fingerprint: 'e'.repeat(64),
            ruleId: 'rule-test-eval',
            scannerName: 'opengrep',
            category: 'SAST',
            severity: 'HIGH',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            // Located in test directory -> would be suppressed by Gate 1 if evaluated
            location: { filePath: 'test/untouched.test.ts', startLine: 10, endLine: 10 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'TEST_OR_MOCK',
            title: 'Test code finding outside diff',
            description: 'This finding is both suppressible and out-of-scope',
            cweIds: [],
            evidence: [
              { scannerName: 'opengrep', scannerRuleId: 'rule-test-eval', message: 'Test eval' },
            ],
            createdAt: new Date().toISOString(),
          },
        ],
        durationMs: 15,
        exitCode: 0,
        timedOut: false,
      }),
    };

    // Initialize git repo in tempWorkspace
    const { SafeProcessRunner } = await import('../src/sandbox/safe-process-runner.js');
    await SafeProcessRunner.run('git', ['init'], { cwd: tempWorkspace });
    await SafeProcessRunner.run('git', ['config', 'user.email', 'test@secureship.dev'], {
      cwd: tempWorkspace,
    });
    await SafeProcessRunner.run('git', ['config', 'user.name', 'SecureShip Tester'], {
      cwd: tempWorkspace,
    });

    const testFile = path.join(tempWorkspace, 'test', 'untouched.test.ts');
    const appFile = path.join(tempWorkspace, 'src', 'app.ts');
    const fs = await import('node:fs');
    fs.mkdirSync(path.join(tempWorkspace, 'test'), { recursive: true });
    fs.mkdirSync(path.join(tempWorkspace, 'src'), { recursive: true });
    fs.writeFileSync(testFile, 'describe("test", () => {});\n', 'utf-8');
    fs.writeFileSync(appFile, 'export const a = 1;\n', 'utf-8');

    await SafeProcessRunner.run('git', ['add', '.'], { cwd: tempWorkspace });
    await SafeProcessRunner.run('git', ['commit', '-m', 'Initial commit'], { cwd: tempWorkspace });

    // Modify ONLY src/app.ts and stage it. test/untouched.test.ts is untouched (out-of-scope).
    fs.writeFileSync(appFile, 'export const a = 2;\n', 'utf-8');
    await SafeProcessRunner.run('git', ['add', 'src/app.ts'], { cwd: tempWorkspace });

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [customAdapter],
      staged: true,
    });

    // P1 Precedence Rule: Diff scoping evaluated FIRST.
    // Finding is out-of-scope -> lands in totalOutOfScope, NEVER enters the ledger.
    expect(report.summary.totalRaw).toBe(1);
    expect(report.summary.totalOutOfScope).toBe(1);
    expect(report.summary.totalSuppressed).toBe(0);
    expect(report.summary.totalReported).toBe(0);
    expect(report.summary.suppressedByReason.GATE1_TEST_OR_MOCK).toBe(0);
    expect(report.suppressed).toHaveLength(0);
    expect(report.findings).toHaveLength(0);

    // Invariant holds: totalRaw === totalReported + totalSuppressed + totalOutOfScope
    expect(report.summary.totalRaw).toBe(
      report.summary.totalReported + report.summary.totalSuppressed + report.summary.totalOutOfScope
    );
  });

  it('sorts findings deterministically by severity, reachability verdict, file path, and line', async () => {
    const customAdapter: IScannerAdapter = {
      name: 'opengrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async () => ({
        scannerName: 'opengrep',
        status: 'SUCCESS',
        findings: [
          {
            id: 'f-high-b-10',
            fingerprint: '1'.repeat(64),
            ruleId: 'rule-1',
            scannerName: 'opengrep',
            category: 'SAST',
            severity: 'HIGH',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'src/b.ts', startLine: 10, endLine: 10 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'PRODUCTION',
            title: 'High B',
            description: 'Desc',
            cweIds: [],
            evidence: [{ scannerName: 'opengrep', scannerRuleId: 'rule-1', message: 'High B' }],
            createdAt: new Date().toISOString(),
          },
          {
            id: 'f-high-a-20',
            fingerprint: '2'.repeat(64),
            ruleId: 'rule-2',
            scannerName: 'opengrep',
            category: 'SAST',
            severity: 'HIGH',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'src/a.ts', startLine: 20, endLine: 20 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'PRODUCTION',
            title: 'High A Line 20',
            description: 'Desc',
            cweIds: [],
            evidence: [{ scannerName: 'opengrep', scannerRuleId: 'rule-2', message: 'High A 20' }],
            createdAt: new Date().toISOString(),
          },
          {
            id: 'f-high-a-10',
            fingerprint: '3'.repeat(64),
            ruleId: 'rule-3',
            scannerName: 'opengrep',
            category: 'SAST',
            severity: 'HIGH',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'src/a.ts', startLine: 10, endLine: 10 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'PRODUCTION',
            title: 'High A Line 10',
            description: 'Desc',
            cweIds: ['CWE-79'],
            evidence: [{ scannerName: 'opengrep', scannerRuleId: 'rule-3', message: 'High A 10' }],
            createdAt: new Date().toISOString(),
          },
          {
            id: 'f-crit-c-1',
            fingerprint: '4'.repeat(64),
            ruleId: 'rule-4',
            scannerName: 'opengrep',
            category: 'SAST',
            severity: 'CRITICAL',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'src/c.ts', startLine: 1, endLine: 1 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'PRODUCTION',
            title: 'Crit C Line 1',
            description: 'Desc',
            cweIds: [],
            evidence: [{ scannerName: 'opengrep', scannerRuleId: 'rule-4', message: 'Crit C 1' }],
            createdAt: new Date().toISOString(),
          },
        ],
        durationMs: 10,
        exitCode: 0,
        timedOut: false,
      }),
    };

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [customAdapter],
      gate2Mode: 'annotate',
    });

    expect(report.findings).toHaveLength(4);
    // CRITICAL should come first
    expect(report.findings[0]?.id).toBe('f-crit-c-1');
    // HIGH findings sorted by filePath then line: src/a.ts:10, src/a.ts:20, src/b.ts:10
    expect(report.findings[1]?.id).toBe('f-high-a-10');
    expect(report.findings[2]?.id).toBe('f-high-a-20');
    expect(report.findings[3]?.id).toBe('f-high-b-10');
  });

  it('handles reachEngine.evaluate error gracefully and records PARSE_FAILURE UNKNOWN', async () => {
    const customAdapter: IScannerAdapter = {
      name: 'opengrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async () => ({
        scannerName: 'opengrep',
        status: 'SUCCESS',
        findings: [
          {
            id: 'f-err',
            fingerprint: 'e'.repeat(64),
            ruleId: 'rule-err',
            scannerName: 'opengrep',
            category: 'SAST',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'app.ts', startLine: 1, endLine: 1 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'PRODUCTION',
            title: 'Error test',
            description: 'Desc',
            cweIds: [],
            evidence: [{ scannerName: 'opengrep', scannerRuleId: 'rule-err', message: 'Err test' }],
            createdAt: new Date().toISOString(),
          },
        ],
        durationMs: 10,
        exitCode: 0,
        timedOut: false,
      }),
    };

    const spy = vi.spyOn(ReachabilityEngine.prototype, 'evaluate').mockImplementationOnce(() => {
      throw new Error('Simulated evaluator explosion');
    });

    try {
      const report = await ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [customAdapter],
        gate2Mode: 'annotate',
      });

      expect(report.findings).toHaveLength(1);
      const detail = report.findings[0]?.reachabilityDetail;
      expect(detail?.verdict).toBe('UNKNOWN');
      expect(detail?.evidence.kind).toBe('PARSE_FAILURE');
      expect(detail?.evidence.notes).toContain('Simulated evaluator explosion');
    } finally {
      spy.mockRestore();
    }
  });

  it('filters adapters based on config.scanners settings', async () => {
    const adapter1 = createMockAdapter('opengrep', 'success', 0);
    const adapter2 = createMockAdapter('gitleaks', 'success', 0);

    const configFile = path.join(tempWorkspace, 'secureship.config.json');
    writeFileSync(
      configFile,
      JSON.stringify({
        scanners: {
          opengrep: false,
          gitleaks: true,
        },
      }),
      'utf-8'
    );

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [adapter1, adapter2],
      configPath: configFile,
    });

    const scannerNames = report.scanners.map((s) => s.name);
    expect(scannerNames).toContain('gitleaks');
    expect(scannerNames).not.toContain('opengrep');
  });

  it('handles reachEngine.init failure gracefully and records warning', async () => {
    const adapter = createMockAdapter('opengrep', 'success', 0);
    const spy = vi
      .spyOn(ReachabilityEngine.prototype, 'init')
      .mockRejectedValueOnce(new Error('Init exploded'));

    try {
      const report = await ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [adapter],
        gate2Mode: 'annotate',
      });
      expect(
        report.warnings.some((w) => w.includes('Gate 2 reachability engine initialization failed'))
      ).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it('suppresses qualifying unreachable SCA findings in suppress mode, but preserves CRITICAL findings', async () => {
    const customAdapter: IScannerAdapter = {
      name: 'trivy',
      category: 'SCA',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async () => ({
        scannerName: 'trivy',
        status: 'SUCCESS',
        findings: [
          {
            id: 'f-sca-high',
            fingerprint: '1'.repeat(64),
            ruleId: 'SCA-1',
            scannerName: 'trivy',
            category: 'SCA',
            severity: 'HIGH',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'package.json', startLine: 1, endLine: 1 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'PRODUCTION',
            title: 'SCA High',
            description: 'Desc',
            cweIds: [],
            evidence: [{ scannerName: 'trivy', scannerRuleId: 'SCA-1', message: 'SCA' }],
            createdAt: new Date().toISOString(),
            package: { name: 'unused-dep', version: '1.0.0', ecosystem: 'npm' },
          },
          {
            id: 'f-sca-crit',
            fingerprint: '2'.repeat(64),
            ruleId: 'SCA-2',
            scannerName: 'trivy',
            category: 'SCA',
            severity: 'CRITICAL',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'package.json', startLine: 1, endLine: 1 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'PRODUCTION',
            title: 'SCA Crit',
            description: 'Desc',
            cweIds: [],
            evidence: [{ scannerName: 'trivy', scannerRuleId: 'SCA-2', message: 'SCA' }],
            createdAt: new Date().toISOString(),
            package: { name: 'unused-dep-2', version: '1.0.0', ecosystem: 'npm' },
          },
          {
            id: 'f-sast-dead',
            fingerprint: '3'.repeat(64),
            ruleId: 'SAST-1',
            scannerName: 'opengrep',
            category: 'SAST',
            severity: 'HIGH',
            confidence: 'HIGH',
            reachability: 'UNKNOWN',
            location: { filePath: 'src/dead.ts', startLine: 1, endLine: 1 },
            upstreamValidationStatus: 'UNKNOWN',
            verificationStatus: 'UNVERIFIED',
            scopeTag: 'PRODUCTION',
            title: 'SAST Dead File',
            description: 'Desc',
            cweIds: [],
            evidence: [{ scannerName: 'opengrep', scannerRuleId: 'SAST-1', message: 'SAST' }],
            createdAt: new Date().toISOString(),
          },
        ],
        durationMs: 10,
        exitCode: 0,
        timedOut: false,
      }),
    };

    const spy = vi.spyOn(ReachabilityEngine.prototype, 'evaluate').mockImplementation((f) => ({
      verdict: 'UNREACHABLE',
      analysisConfidence: 'HIGH',
      evidence: {
        kind: 'NOT_IMPORTED',
        notes: f.id === 'f-sca-high' ? undefined : 'Custom notes',
      },
      limitations: [],
    }));

    try {
      const report = await ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [customAdapter],
        gate2Mode: 'suppress',
      });

      // f-sca-high is suppressed because it is HIGH severity SCA
      expect(report.summary.totalSuppressed).toBe(1);
      expect(report.suppressed).toHaveLength(1);
      expect(report.suppressed[0]?.reasonCode).toBe('GATE2_UNREACHABLE');
      expect(report.suppressed[0]?.finding.id).toBe('f-sca-high');

      // f-sca-crit (CRITICAL) and f-sast-dead (SAST dead-file) are NOT suppressed
      expect(report.summary.totalReported).toBe(2);
      expect(report.findings).toHaveLength(2);
      expect(report.findings.some((f) => f.id === 'f-sca-crit')).toBe(true);
      expect(report.findings.some((f) => f.id === 'f-sast-dead')).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it('rejects invalid gate2Mode with clear error', async () => {
    await expect(
      ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [],
        gate2Mode: 'invalid-mode' as unknown as import('@secureship/contracts').Gate2Mode,
      })
    ).rejects.toThrow('Invalid gate2 mode "invalid-mode"');
  });

  it('resolves default baseline path when not provided in options or config', async () => {
    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [],
    });
    expect(report.summary.totalRaw).toBe(0);
  });
});
