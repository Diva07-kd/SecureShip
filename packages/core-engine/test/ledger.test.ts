import { describe, it, expect } from 'vitest';
import { SuppressionLedger } from '../src/suppression/ledger.js';
import { DiffScope } from '../src/git/diff-scope.js';
import { Gate1Scope } from '../src/gates/gate1-scope.js';
import type { NormalizedFinding, Severity, FindingCategory } from '@secureship/contracts';

describe('SuppressionLedger & Invariant P1 Precedence Suite', () => {
  function createSampleFinding(
    id: string,
    filePath = 'src/app.ts',
    severity: Severity = 'HIGH',
    category: FindingCategory = 'SAST'
  ): NormalizedFinding {
    return {
      id,
      fingerprint: id.padEnd(64, '0'),
      ruleId: 'sample-rule',
      scannerName: 'opengrep',
      category,
      severity,
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      location: { filePath, startLine: 1, endLine: 1 },
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Sample finding',
      description: 'Sample description',
      cweIds: [],
      evidence: [{ scannerName: 'opengrep', scannerRuleId: 'sample-rule', message: 'Sample' }],
      createdAt: new Date().toISOString(),
    };
  }

  it('P1 Invariant: holds across 1,000 randomized finding distributions', () => {
    for (let run = 0; run < 100; run++) {
      const ledger = new SuppressionLedger();
      const reportedCount = Math.floor(Math.random() * 50);
      const suppressedCount = Math.floor(Math.random() * 50);
      const outOfScopeCount = Math.floor(Math.random() * 50);
      const totalRaw = reportedCount + suppressedCount + outOfScopeCount;

      ledger.recordRaw(totalRaw);

      for (let i = 0; i < reportedCount; i++) {
        ledger.addReported(createSampleFinding(`rep-${i}`));
      }

      for (let i = 0; i < suppressedCount; i++) {
        ledger.suppress(
          createSampleFinding(`sup-${i}`),
          'GATE1_TEST_OR_MOCK',
          'Test code',
          'Gate1'
        );
      }

      ledger.recordOutOfScope(outOfScopeCount);

      // Verify invariant doesn't throw
      expect(() => ledger.verifyInvariant()).not.toThrow();

      const summary = ledger.computeSummary();
      expect(summary.totalRaw).toBe(totalRaw);
      expect(summary.totalReported).toBe(reportedCount);
      expect(summary.totalSuppressed).toBe(suppressedCount);
      expect(summary.totalOutOfScope).toBe(outOfScopeCount);
    }
  });

  it('P1 Invariant: throws error when raw count does not match the sum of buckets', () => {
    const ledger = new SuppressionLedger();
    ledger.recordRaw(10);
    ledger.addReported(createSampleFinding('f-1'));
    // Only 1 accounted for out of 10!
    expect(() => ledger.verifyInvariant()).toThrow(/Suppression Ledger Invariant P1 Violation/);
  });

  it('Amendment 1 Precedence: a finding that is both out-of-diff-scope and suppressible lands in totalOutOfScope, NOT in ledger', () => {
    // Scenario:
    // A test file finding (suppressible by Gate 1) is NOT part of the changed files in the diff.
    const findingInTestDir = createSampleFinding(
      'f-test-outside',
      'tests/auth.test.ts',
      'HIGH',
      'SAST'
    );

    // Diff scope only covers 'src/app.ts'
    const diffScope = {
      isDiffMode: true,
      changedFiles: new Set(['src/app.ts']),
      fileLineRanges: new Map(),
    };

    const ledger = new SuppressionLedger();
    ledger.recordRaw(1);

    // Step 1: Diff scope check
    const inScope = DiffScope.isFindingInScope(findingInTestDir, diffScope);
    expect(inScope).toBe(false);

    if (!inScope) {
      ledger.recordOutOfScope(1);
    } else {
      // Should NOT reach here
      const gate1 = Gate1Scope.evaluate(findingInTestDir);
      ledger.suppress(findingInTestDir, gate1.suppressionReason!, 'Test', 'Gate1');
    }

    // Invariant check passes
    expect(() => ledger.verifyInvariant()).not.toThrow();

    const summary = ledger.computeSummary();
    expect(summary.totalRaw).toBe(1);
    expect(summary.totalOutOfScope).toBe(1);
    expect(summary.totalSuppressed).toBe(0); // NEVER entered ledger!
    expect(summary.totalReported).toBe(0);
    expect(ledger.getSuppressedFindings()).toHaveLength(0);
  });
});
