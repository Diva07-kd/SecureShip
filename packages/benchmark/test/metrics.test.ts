import { describe, it, expect } from 'vitest';
import { MetricsCalculator, ReachabilityMetricsCalculator } from '../src/metrics.js';

describe('Benchmark Metrics Calculator Unit Suite', () => {
  it('computes precision, recall, F1, and suppression-recall against hand-computed values', () => {
    // Example: TP = 8, FP = 2, FN = 2, wronglySuppressed = 1
    // Precision = 8 / (8 + 2) = 0.8
    // Recall = 8 / (8 + 2) = 0.8
    // F1 = 2 * (0.8 * 0.8) / (0.8 + 0.8) = 0.8
    // SuppressionRecall = 8 / (8 + 1) = 8 / 9 ≈ 0.8889
    const m = MetricsCalculator.calculate(8, 2, 2, 1);

    expect(m.truePositives).toBe(8);
    expect(m.falsePositives).toBe(2);
    expect(m.falseNegatives).toBe(2);
    expect(m.precision).toBe(0.8);
    expect(m.recall).toBe(0.8);
    expect(m.f1).toBe(0.8);
    expect(m.suppressionRecall).toBe(0.8889);
  });

  it('handles division by zero safeguards cleanly', () => {
    // When no findings exist (hasCases: false per R7)
    const mEmpty = MetricsCalculator.calculate(0, 0, 0, 0);
    expect(mEmpty.hasCases).toBe(false);
    expect(mEmpty.precision).toBe(0.0);
    expect(mEmpty.recall).toBe(0.0);
    expect(mEmpty.f1).toBe(0.0);
    expect(mEmpty.suppressionRecall).toBe(1.0);

    // When TP = 0 and FP > 0
    const mZeroTP = MetricsCalculator.calculate(0, 5, 5, 0);
    expect(mZeroTP.hasCases).toBe(true);
    expect(mZeroTP.precision).toBe(0.0);
    expect(mZeroTP.recall).toBe(0.0);
    expect(mZeroTP.f1).toBe(0.0);
  });

  it('evaluates threshold satisfaction accurately', () => {
    const thresholds = {
      minPrecision: 0.85,
      minRecall: 0.8,
      minF1: 0.8,
      minSuppressionRecall: 0.9,
    };

    // Passing metrics
    const mPassing = MetricsCalculator.calculate(10, 1, 1, 0);
    // Precision: 10/11 = 0.909, Recall: 10/11 = 0.909, F1: 0.909, SuppRecall: 10/10 = 1.0
    const resPassing = MetricsCalculator.satisfiesThresholds(mPassing, thresholds);
    expect(resPassing.passed).toBe(true);
    expect(resPassing.violations).toHaveLength(0);

    // Failing metrics (precision drops below 0.85)
    const mFailing = MetricsCalculator.calculate(6, 4, 1, 2);
    // Precision: 6/10 = 0.60, SuppRecall: 6/8 = 0.75
    const resFailing = MetricsCalculator.satisfiesThresholds(mFailing, thresholds);
    expect(resFailing.passed).toBe(false);
    expect(resFailing.violations.length).toBeGreaterThan(0);
    expect(resFailing.violations.some((v) => v.includes('Suppression recall'))).toBe(true);
  });

  it('ReachabilityMetricsCalculator: computes falseUnreachableCount, accuracies, and noiseReductionPercent', () => {
    const evals = [
      { predicted: 'REACHABLE_IMPORT', truth: 'REACHABLE_IMPORT', reportedBeforeGate2: true },
      {
        predicted: 'UNREACHABLE',
        truth: 'UNREACHABLE',
        suppressed: true,
        reportedBeforeGate2: true,
      },
      { predicted: 'UNKNOWN', truth: 'UNKNOWN', reportedBeforeGate2: true },
      { predicted: 'UNKNOWN', truth: 'UNREACHABLE', reportedBeforeGate2: true },
    ];

    const m = ReachabilityMetricsCalculator.calculate(evals);
    expect(m.totalFindings).toBe(4);
    expect(m.falseUnreachableCount).toBe(0);
    expect(m.unknownCount).toBe(2);
    expect(m.unknownRate).toBe(0.5);
    expect(m.reachabilityAccuracy.reachable).toBe(1.0);
    expect(m.noiseReductionPercent).toBe(25.0);
  });

  it('ReachabilityMetricsCalculator: detects false-unreachable (CRITICAL failure flag)', () => {
    const evals = [{ predicted: 'UNREACHABLE', truth: 'REACHABLE_IMPORT' }];
    const m = ReachabilityMetricsCalculator.calculate(evals);
    expect(m.falseUnreachableCount).toBe(1);
  });

  it('ReachabilityMetricsCalculator: handles empty evaluations with null noiseReductionPercent (Amendment A15)', () => {
    const mEmpty = ReachabilityMetricsCalculator.calculate([]);
    expect(mEmpty.totalFindings).toBe(0);
    expect(mEmpty.noiseReductionPercent).toBeNull();
    expect(mEmpty.reachabilityAccuracy.reachable).toBeNull();
    expect(mEmpty.reachabilityAccuracy.unreachable).toBeNull();
    expect(mEmpty.reachabilityAccuracy.unknown).toBeNull();
  });

  it('Spec Gap M2: returns null (N/A) for accuracy when a specific class has 0 cases', () => {
    // Only reachable cases present
    const evals = [
      { predicted: 'REACHABLE_IMPORT', truth: 'REACHABLE_IMPORT' },
      { predicted: 'REACHABLE_IMPORT', truth: 'REACHABLE_IMPORT' },
    ];
    const m = ReachabilityMetricsCalculator.calculate(evals);
    expect(m.reachabilityAccuracy.reachable).toBe(1.0);
    expect(m.reachabilityAccuracy.unreachable).toBeNull(); // 0 unreachable truth cases
    expect(m.reachabilityAccuracy.unknown).toBeNull(); // 0 unknown truth cases
  });
});
