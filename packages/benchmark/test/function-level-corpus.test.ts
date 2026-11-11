import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import type { NormalizedFinding } from '@secureship/contracts';
import { ReachabilityEngine } from '@secureship/reachability';

describe('Function-Level Benchmark Corpus Suite (62 Hand-Labeled Fixtures)', () => {
  const corpusDir = path.resolve('packages/benchmark/corpus/function-level');

  it('evaluates all 62 function-level corpus fixtures with ZERO false-unreachables', async () => {
    const caseDirs = fs
      .readdirSync(corpusDir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => path.join(corpusDir, d.name))
      .sort();

    expect(caseDirs.length).toBeGreaterThanOrEqual(60);

    let falseUninvokedCount = 0;
    let referencedTP = 0;
    let referencedFN = 0;
    let escapesTP = 0;
    let escapesFN = 0;
    let prunedHighCount = 0;
    let prunedMediumCount = 0;
    let prunedLowCount = 0;
    let totalDirectEvaluated = 0;
    const blockedReasonCounts: Record<string, number> = {};

    for (const caseDir of caseDirs) {
      const expectedPath = path.join(caseDir, 'reachability-expected.json');
      expect(fs.existsSync(expectedPath)).toBe(true);

      const exp = JSON.parse(fs.readFileSync(expectedPath, 'utf8'));

      const engine = new ReachabilityEngine(caseDir, {
        noCache: true,
        functionLevel: true,
        datasetIntegrityVerified: exp.simulateTamper ? false : true,
        symbolDataset: exp.customDataset ?? undefined,
      });
      await engine.init();

      const finding: NormalizedFinding = {
        id: `f-${exp.id}`,
        fingerprint: '0'.repeat(64),
        ruleId: exp.ruleId ?? 'CVE-2021-23337',
        scannerName: 'trivy',
        category: 'SCA',
        severity: 'HIGH',
        confidence: 'HIGH',
        reachability: 'UNKNOWN',
        location: {
          filePath: fs.existsSync(path.join(caseDir, 'requirements.txt'))
            ? 'requirements.txt'
            : 'package.json',
          startLine: 1,
          endLine: 1,
        },
        scopeTag: 'PRODUCTION',
        upstreamValidationStatus: 'UNKNOWN',
        verificationStatus: 'UNVERIFIED',
        title: exp.id,
        description: exp.description ?? exp.id,
        cweIds: [],
        evidence: [
          {
            scannerName: 'trivy',
            scannerRuleId: exp.ruleId ?? 'CVE-2021-23337',
            message: exp.description ?? 'Test',
          },
        ],
        createdAt: new Date().toISOString(),
        package: exp.package
          ? {
              ecosystem: exp.ecosystem ?? 'npm',
              name: exp.package,
              version: '1.0.0',
            }
          : undefined,
      };

      const detail = engine.evaluate(finding);
      totalDirectEvaluated++;

      // 1. False Uninvoked Soundness Check
      // If ground truth is "used" (groundTruthUsed === true), predicted CANNOT be UNINVOKED_SYMBOL
      if (exp.groundTruthUsed && detail.evidence.kind === 'UNINVOKED_SYMBOL') {
        falseUninvokedCount++;
      }

      // 2. Recall tracking
      if (exp.expectedKind === 'SYMBOL_REFERENCED' || exp.expectedKind === 'SYMBOL_CALL_PATH') {
        if (
          detail.evidence.kind === 'SYMBOL_REFERENCED' ||
          detail.evidence.kind === 'SYMBOL_CALL_PATH'
        ) {
          referencedTP++;
        } else {
          referencedFN++;
        }
      }

      if (exp.expectedKind === 'NAMESPACE_ESCAPES') {
        if (detail.evidence.kind === 'NAMESPACE_ESCAPES') {
          escapesTP++;
        } else {
          escapesFN++;
        }
      }

      // 3. Noise reduction counts
      if (detail.verdict === 'UNREACHABLE' && detail.evidence.kind === 'UNINVOKED_SYMBOL') {
        if (detail.analysisConfidence === 'HIGH') {
          prunedHighCount++;
        } else if (detail.analysisConfidence === 'MEDIUM') {
          prunedMediumCount++;
        } else {
          prunedLowCount++;
        }
      }

      // 4. Blocked reasons tracking
      if (detail.evidence.blockedBy) {
        blockedReasonCounts[detail.evidence.blockedBy] =
          (blockedReasonCounts[detail.evidence.blockedBy] ?? 0) + 1;
      }

      // Assert Verdict
      expect(
        detail.verdict,
        `Case ${exp.id}: Expected verdict ${exp.expectedVerdict}, received ${detail.verdict} (reason: ${detail.evidence.kind}, blockedBy: ${detail.evidence.blockedBy})`
      ).toBe(exp.expectedVerdict);

      // Assert Kind
      expect(
        detail.evidence.kind,
        `Case ${exp.id}: Expected kind ${exp.expectedKind}, received ${detail.evidence.kind}`
      ).toBe(exp.expectedKind);

      // Assert Confidence if specified
      if (exp.expectedConfidence) {
        expect(
          detail.analysisConfidence,
          `Case ${exp.id}: Expected confidence ${exp.expectedConfidence}, received ${detail.analysisConfidence}`
        ).toBe(exp.expectedConfidence);
      }

      // Assert BlockedBy if specified
      if (exp.expectedBlockedBy) {
        expect(detail.evidence.blockedBy).toBe(exp.expectedBlockedBy);
      }
    }

    // Hard Threshold Verification
    expect(falseUninvokedCount).toBe(0); // Zero unsound false unreachables
    expect(referencedFN).toBe(0); // 100% referenced recall
    expect(escapesFN).toBe(0); // 100% escape recall

    console.log('\n--- 62-Case Function-Level Corpus Evaluation Metrics ---');
    console.log(`Total Cases Evaluated   : ${totalDirectEvaluated}`);
    console.log(`False-Uninvoked Count   : ${falseUninvokedCount} (PASS - Threshold 0)`);
    console.log(`Referenced Recall       : 100% (${referencedTP}/${referencedTP})`);
    console.log(`Escape Detection Recall : 100% (${escapesTP}/${escapesTP})`);
    console.log(`Pruned to UNREACHABLE (HIGH)   : ${prunedHighCount}`);
    console.log(`Pruned to UNREACHABLE (MEDIUM) : ${prunedMediumCount}`);
    console.log(`Pruned to UNREACHABLE (LOW)    : ${prunedLowCount}`);
    console.log('Blocked By Precondition Breakdown:', blockedReasonCounts);
  });
});
