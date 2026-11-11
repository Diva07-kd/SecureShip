import { describe, it, expect, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  type NormalizedFinding,
  type ScanReport,
  ScanReportSchema,
  type Severity,
  type FindingCategory,
  type Reachability,
} from '@secureship/contracts';
import { SuppressionLedger } from '../src/suppression/ledger.js';
import { ReportBuilder } from '../src/report/report-builder.js';
import { ScanOrchestrator } from '../src/orchestrator/scan-orchestrator.js';
import type { IScannerAdapter, ScanExecutionResult } from '@secureship/contracts';

function makeMockFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  const id = overrides.id ?? `f-${Math.random().toString(36).substring(2, 9)}`;
  const fp = (overrides.fingerprint ?? id.padEnd(64, '0')).slice(0, 64);
  return {
    id,
    fingerprint: fp,
    ruleId: overrides.ruleId ?? 'MOCK_RULE',
    scannerName: 'generic',
    category: overrides.category ?? 'SCA',
    severity: overrides.severity ?? 'HIGH',
    confidence: 'HIGH',
    reachability: overrides.reachability ?? 'UNKNOWN',
    reachabilityDetail: overrides.reachabilityDetail,
    location: overrides.location ?? {
      filePath: 'package.json',
      startLine: 1,
      endLine: 1,
    },
    scopeTag: overrides.scopeTag ?? 'PRODUCTION',
    upstreamValidationStatus: overrides.upstreamValidationStatus ?? 'UNKNOWN',
    verificationStatus: overrides.verificationStatus ?? 'UNVERIFIED',
    cweIds: overrides.cweIds ?? [],
    title: overrides.title ?? 'Mock Finding',
    description: 'Mock Description',
    evidence: [
      {
        scannerName: 'generic',
        scannerRuleId: 'MOCK_RULE',
        message: 'Mock evidence message',
      },
    ],
    createdAt: new Date().toISOString(),
    package: overrides.package ?? {
      ecosystem: 'npm',
      name: 'foo-pkg',
      version: '1.0.0',
    },
    ...overrides,
  };
}

describe('Gate 2 SuppressionLedger & Accounting Invariant P1', () => {
  it('enforces P1 invariant with GATE2_UNREACHABLE suppressions across >= 1000 generated scenarios', () => {
    const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const categories: FindingCategory[] = ['SAST', 'SCA', 'SECRET', 'IAC'];
    const reachabilities: Reachability[] = [
      'REACHABLE_CALL_PATH',
      'REACHABLE_IMPORT',
      'UNKNOWN',
      'UNREACHABLE',
    ];

    for (let i = 0; i < 1000; i++) {
      const ledger = new SuppressionLedger();
      const nRaw = Math.floor(Math.random() * 20);
      ledger.recordRaw(nRaw);

      let allocated = 0;
      // Randomly allocate to outOfScope, reported, gate1, user_ignore, baseline, gate2
      const nOutOfScope = Math.min(nRaw - allocated, Math.floor(Math.random() * 5));
      ledger.recordOutOfScope(nOutOfScope);
      allocated += nOutOfScope;

      while (allocated < nRaw) {
        const choice = Math.floor(Math.random() * 6);
        const f = makeMockFinding({
          severity: severities[Math.floor(Math.random() * severities.length)],
          category: categories[Math.floor(Math.random() * categories.length)],
          reachability: reachabilities[Math.floor(Math.random() * reachabilities.length)],
        });

        if (choice === 0) {
          ledger.addReported(f);
        } else if (choice === 1) {
          ledger.suppress(f, 'GATE1_TEST_OR_MOCK', 'Test code', 'Gate 1');
        } else if (choice === 2) {
          ledger.suppress(f, 'USER_IGNORE_RULE', 'User rule', 'Ignore');
        } else if (choice === 3) {
          ledger.suppress(f, 'BASELINE_KNOWN', 'Baseline entry', 'Baseline');
        } else if (choice === 4) {
          ledger.suppress(f, 'GATE2_UNREACHABLE', 'Unreachable package', 'Gate 2');
        } else {
          ledger.addReported(f);
        }
        allocated++;
      }

      // Assert invariant P1 holds
      expect(() => ledger.verifyInvariant()).not.toThrow();
      const summary = ledger.computeSummary();
      expect(summary.totalRaw).toBe(
        summary.totalReported + summary.totalSuppressed + summary.totalOutOfScope
      );
      expect(summary.suppressedByReason.GATE2_UNREACHABLE).toBeGreaterThanOrEqual(0);
      expect(summary.byReachability).toBeDefined();
    }
  });
});

describe('ReportBuilder & Backward Compatibility (Amendment A10)', () => {
  it('emits schemaVersion 1.3 by default with byReachability summary', () => {
    const ledger = new SuppressionLedger();
    ledger.recordRaw(2);
    const f1 = makeMockFinding({
      severity: 'HIGH',
      reachability: 'REACHABLE_IMPORT',
    });
    const f2 = makeMockFinding({
      severity: 'CRITICAL',
      reachability: 'UNREACHABLE',
    });
    ledger.addReported(f1);
    ledger.addReported(f2);

    const report = ReportBuilder.build({
      targetDir: process.cwd(),
      mode: 'FULL',
      startedAt: new Date().toISOString(),
      durationMs: 100,
      scanners: [],
      ledger,
    });

    expect(report.schemaVersion).toBe('1.3');
    expect(report.summary.byReachability).toEqual({
      REACHABLE_CALL_PATH: 0,
      REACHABLE_IMPORT: 1,
      UNREACHABLE: 1,
      UNKNOWN: 0,
    });
  });

  it('accepts and parses real Phase 2 ScanReport without byReachability (1.0 report compatibility)', () => {
    const legacyReport10 = {
      schemaVersion: '1.0',
      tool: {
        name: 'secureship',
        version: '0.1.0-alpha',
      },
      target: process.cwd(),
      mode: 'FULL',
      startedAt: new Date().toISOString(),
      durationMs: 120,
      scanners: [],
      findings: [],
      suppressed: [],
      summary: {
        totalRaw: 1,
        totalReported: 1,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 0, SCA: 1, SECRET: 0, IAC: 0 },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 0,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
          GATE2_UNREACHABLE: 0,
        },
      },
      warnings: [],
    };

    const parsed = ScanReportSchema.parse(legacyReport10);
    expect(parsed.schemaVersion).toBe('1.0');
    expect(parsed.summary.byReachability).toBeUndefined();
  });
});

describe('ScanOrchestrator Gate 2 Integration', () => {
  const tmpDirs: string[] = [];

  function createTestProject(files: Record<string, string>): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-g2-test-'));
    tmpDirs.push(dir);
    for (const [relPath, content] of Object.entries(files)) {
      const fullPath = path.join(dir, relPath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, content, 'utf8');
    }
    return dir;
  }

  afterEach(() => {
    for (const d of tmpDirs) {
      try {
        fs.rmSync(d, { recursive: true, force: true });
      } catch {
        // ignore cleanup errors
      }
    }
    tmpDirs.length = 0;
  });

  it('in annotate mode: attaches reachabilityDetail and sorts reported findings deterministically', async () => {
    const projectDir = createTestProject({
      'package.json': JSON.stringify({
        name: 'test-app',
        main: 'src/index.js',
        dependencies: {
          'used-pkg': '^1.0.0',
          'unused-pkg': '^1.0.0',
        },
      }),
      'package-lock.json': JSON.stringify({
        name: 'test-app',
        lockfileVersion: 3,
        packages: {
          '': {
            dependencies: { 'used-pkg': '^1.0.0', 'unused-pkg': '^1.0.0' },
          },
          'node_modules/used-pkg': { version: '1.0.0' },
          'node_modules/unused-pkg': { version: '1.0.0' },
        },
      }),
      'src/index.js': `const used = require('used-pkg');\nconsole.log(used);`,
    });

    const mockAdapter: IScannerAdapter = {
      name: 'trivy',
      category: 'SCA',
      version: async () => '0.50.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async (): Promise<ScanExecutionResult> => ({
        scannerName: 'trivy',
        status: 'SUCCESS',
        durationMs: 50,
        exitCode: 0,
        timedOut: false,
        findings: [
          makeMockFinding({
            id: 'find-unused',
            severity: 'HIGH',
            category: 'SCA',
            package: { ecosystem: 'npm', name: 'unused-pkg', version: '1.0.0' },
            location: { filePath: 'package.json', startLine: 6, endLine: 6 },
          }),
          makeMockFinding({
            id: 'find-used',
            severity: 'HIGH',
            category: 'SCA',
            package: { ecosystem: 'npm', name: 'used-pkg', version: '1.0.0' },
            location: { filePath: 'package.json', startLine: 5, endLine: 5 },
          }),
        ],
      }),
    };

    const report: ScanReport = await ScanOrchestrator.scan({
      targetDir: projectDir,
      adapters: [mockAdapter],
      gate2Mode: 'annotate',
      noCache: true,
    });

    expect(report.summary.totalReported).toBe(2);
    expect(report.summary.totalSuppressed).toBe(0);

    const fUsed = report.findings.find((f) => f.package?.name === 'used-pkg');
    const fUnused = report.findings.find((f) => f.package?.name === 'unused-pkg');

    expect(fUsed?.reachabilityDetail?.verdict).toBe('REACHABLE_IMPORT');
    expect(fUnused?.reachabilityDetail?.verdict).toBe('UNREACHABLE');

    // Deterministic sort: REACHABLE_IMPORT must precede UNREACHABLE for same severity
    expect(report.findings[0]!.package?.name).toBe('used-pkg');
    expect(report.findings[1]!.package?.name).toBe('unused-pkg');
  });

  it('in suppress mode: suppresses qualifying non-critical SCA findings into GATE2_UNREACHABLE', async () => {
    const projectDir = createTestProject({
      'package.json': JSON.stringify({
        name: 'test-app',
        main: 'src/index.js',
        dependencies: {
          'unused-pkg': '^1.0.0',
          'critical-unused': '^1.0.0',
        },
      }),
      'package-lock.json': JSON.stringify({
        name: 'test-app',
        lockfileVersion: 3,
        packages: {
          '': {
            dependencies: { 'unused-pkg': '^1.0.0', 'critical-unused': '^1.0.0' },
          },
          'node_modules/unused-pkg': { version: '1.0.0' },
          'node_modules/critical-unused': { version: '1.0.0' },
        },
      }),
      'src/index.js': `console.log("hello world");`,
    });

    const mockAdapter: IScannerAdapter = {
      name: 'trivy',
      category: 'SCA',
      version: async () => '0.50.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async (): Promise<ScanExecutionResult> => ({
        scannerName: 'trivy',
        status: 'SUCCESS',
        durationMs: 50,
        exitCode: 0,
        timedOut: false,
        findings: [
          makeMockFinding({
            id: 'find-unused-high',
            severity: 'HIGH',
            category: 'SCA',
            package: { ecosystem: 'npm', name: 'unused-pkg', version: '1.0.0' },
          }),
          makeMockFinding({
            id: 'find-unused-critical',
            severity: 'CRITICAL',
            category: 'SCA',
            package: { ecosystem: 'npm', name: 'critical-unused', version: '1.0.0' },
          }),
        ],
      }),
    };

    const report: ScanReport = await ScanOrchestrator.scan({
      targetDir: projectDir,
      adapters: [mockAdapter],
      gate2Mode: 'suppress',
      noCache: true,
    });

    // CRITICAL is never suppressed by default; HIGH is suppressed
    expect(report.summary.totalReported).toBe(1);
    expect(report.summary.totalSuppressed).toBe(1);
    expect(report.summary.suppressedByReason.GATE2_UNREACHABLE).toBe(1);
    expect(report.findings[0]!.package?.name).toBe('critical-unused');
    expect(report.suppressed[0]!.finding.package?.name).toBe('unused-pkg');
    expect(report.suppressed[0]!.reasonCode).toBe('GATE2_UNREACHABLE');
  });

  it('in gate2Mode off: skips reachability evaluation completely', async () => {
    const projectDir = createTestProject({
      'package.json': JSON.stringify({
        name: 'test-app',
        dependencies: { 'unused-pkg': '^1.0.0' },
      }),
    });

    const mockAdapter: IScannerAdapter = {
      name: 'trivy',
      category: 'SCA',
      version: async () => '0.50.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async (): Promise<ScanExecutionResult> => ({
        scannerName: 'trivy',
        status: 'SUCCESS',
        durationMs: 50,
        exitCode: 0,
        timedOut: false,
        findings: [
          makeMockFinding({
            id: 'find-1',
            severity: 'HIGH',
            category: 'SCA',
            package: { ecosystem: 'npm', name: 'unused-pkg', version: '1.0.0' },
          }),
        ],
      }),
    };

    const report: ScanReport = await ScanOrchestrator.scan({
      targetDir: projectDir,
      adapters: [mockAdapter],
      gate2Mode: 'off',
    });

    expect(report.summary.totalReported).toBe(1);
    expect(report.findings[0]!.reachabilityDetail).toBeUndefined();
  });

  it('Amendment A2: --staged/--diff builds graph from whole repo, so package in changed lockfile imported by unchanged file is REACHABLE', async () => {
    const { SafeProcessRunner } = await import('../src/sandbox/safe-process-runner.js');

    const projectDir = createTestProject({
      'package.json': JSON.stringify({
        name: 'test-app',
        main: 'src/index.js',
        dependencies: {
          lodash: '^4.17.21',
        },
      }),
      'package-lock.json': JSON.stringify({
        name: 'test-app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { lodash: '^4.17.20' } },
          'node_modules/lodash': { version: '4.17.20' },
        },
      }),
      'src/index.js': `const lodash = require('lodash');\nconsole.log(lodash.map);`,
    });

    // Initialize git repository
    await SafeProcessRunner.run('git', ['init'], { cwd: projectDir });
    await SafeProcessRunner.run('git', ['config', 'user.email', 'test@secureship.dev'], {
      cwd: projectDir,
    });
    await SafeProcessRunner.run('git', ['config', 'user.name', 'SecureShip Tester'], {
      cwd: projectDir,
    });
    await SafeProcessRunner.run('git', ['add', '.'], { cwd: projectDir });
    await SafeProcessRunner.run('git', ['commit', '-m', 'Initial commit'], { cwd: projectDir });

    // Now modify package-lock.json only (simulate bumping or updating dependency)
    fs.writeFileSync(
      path.join(projectDir, 'package-lock.json'),
      JSON.stringify({
        name: 'test-app',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { lodash: '^4.17.21' } },
          'node_modules/lodash': { version: '4.17.21' },
        },
      }),
      'utf8'
    );
    // Stage package-lock.json
    await SafeProcessRunner.run('git', ['add', 'package-lock.json'], { cwd: projectDir });

    // Mock scanner reports an SCA finding on package-lock.json (the changed file)
    const mockAdapter: IScannerAdapter = {
      name: 'osv-scanner',
      category: 'SCA',
      version: async () => '1.7.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async (): Promise<ScanExecutionResult> => ({
        scannerName: 'osv-scanner',
        status: 'SUCCESS',
        durationMs: 50,
        exitCode: 0,
        timedOut: false,
        findings: [
          makeMockFinding({
            id: 'find-lodash',
            severity: 'HIGH',
            category: 'SCA',
            package: { ecosystem: 'npm', name: 'lodash', version: '4.17.21' },
            location: { filePath: 'package-lock.json', startLine: 1, endLine: 1 },
          }),
        ],
      }),
    };

    // Run orchestrator with staged=true
    const report: ScanReport = await ScanOrchestrator.scan({
      targetDir: projectDir,
      adapters: [mockAdapter],
      staged: true,
      gate2Mode: 'annotate',
      noCache: true,
    });

    // Finding is in changed file (package-lock.json) so it's in scope.
    // The graph built from whole repo discovers src/index.js (UNCHANGED file) imports lodash!
    expect(report.summary.totalReported).toBe(1);
    expect(report.findings[0]!.package?.name).toBe('lodash');
    expect(report.findings[0]!.reachabilityDetail?.verdict).toBe('REACHABLE_IMPORT');
    expect(report.findings[0]!.reachabilityDetail?.evidence.kind).toBe('PACKAGE_IMPORTED');
  });
});
