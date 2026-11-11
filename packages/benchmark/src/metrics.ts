export interface BenchmarkMetrics {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
  suppressionRecall: number;
  hasCases: boolean;
}

export class MetricsCalculator {
  /**
   * Computes precision, recall, and F1 score with division-by-zero safeguards.
   * If total cases (tp + fp + fn) is 0, hasCases is marked false.
   */
  public static calculate(
    tp: number,
    fp: number,
    fn: number,
    wronglySuppressed = 0
  ): BenchmarkMetrics {
    const hasCases = tp + fp + fn > 0;

    const precision = !hasCases ? 0.0 : tp + fp === 0 ? 1.0 : tp / (tp + fp);
    const recall = !hasCases ? 0.0 : tp + fn === 0 ? 1.0 : tp / (tp + fn);
    const f1 = precision + recall === 0 ? 0.0 : (2 * precision * recall) / (precision + recall);

    const suppressionRecall =
      !hasCases || tp + wronglySuppressed === 0 ? 1.0 : tp / (tp + wronglySuppressed);

    return {
      truePositives: tp,
      falsePositives: fp,
      falseNegatives: fn,
      precision: parseFloat(precision.toFixed(4)),
      recall: parseFloat(recall.toFixed(4)),
      f1: parseFloat(f1.toFixed(4)),
      suppressionRecall: parseFloat(suppressionRecall.toFixed(4)),
      hasCases,
    };
  }

  /**
   * Checks whether benchmark metrics satisfy configured threshold limits.
   * Categories with hasCases === false are explicitly ignored.
   */
  public static satisfiesThresholds(
    metrics: BenchmarkMetrics,
    thresholds: {
      minPrecision: number;
      minRecall: number;
      minF1: number;
      minSuppressionRecall: number;
    }
  ): { passed: boolean; violations: string[] } {
    if (!metrics.hasCases) {
      return { passed: true, violations: [] };
    }

    const violations: string[] = [];

    if (metrics.precision < thresholds.minPrecision) {
      violations.push(
        `Precision ${metrics.precision} is below minimum threshold ${thresholds.minPrecision}`
      );
    }

    if (metrics.recall < thresholds.minRecall) {
      violations.push(
        `Recall ${metrics.recall} is below minimum threshold ${thresholds.minRecall}`
      );
    }

    if (metrics.f1 < thresholds.minF1) {
      violations.push(`F1 score ${metrics.f1} is below minimum threshold ${thresholds.minF1}`);
    }

    if (metrics.suppressionRecall < thresholds.minSuppressionRecall) {
      violations.push(
        `Suppression recall ${metrics.suppressionRecall} is below minimum threshold ${thresholds.minSuppressionRecall}`
      );
    }

    return {
      passed: violations.length === 0,
      violations,
    };
  }
}

export interface ReachabilityEvaluationItem {
  predicted: string;
  truth: string;
  suppressed?: boolean;
  reportedBeforeGate2?: boolean;
}

export interface ReachabilityMetrics {
  totalFindings: number;
  falseUnreachableCount: number; // Hard requirement: 0
  unknownCount: number;
  unknownRate: number; // unknownCount / totalFindings
  reachabilityAccuracy: {
    reachable: number | null;
    unreachable: number | null;
    unknown: number | null;
    overall: number;
  };
  noiseReductionPercent: number | null; // Suppressed qualifying findings / total reported before Gate 2 * 100, null if no findings
}

export class ReachabilityMetricsCalculator {
  /**
   * Computes reachability metrics against ground truth.
   * falseUnreachable: verdict is UNREACHABLE when ground truth is REACHABLE (CRITICAL FAILURE).
   */
  public static calculate(evaluations: ReachabilityEvaluationItem[]): ReachabilityMetrics {
    const total = evaluations.length;
    if (total === 0) {
      return {
        totalFindings: 0,
        falseUnreachableCount: 0,
        unknownCount: 0,
        unknownRate: 0,
        reachabilityAccuracy: { reachable: null, unreachable: null, unknown: null, overall: 1.0 },
        noiseReductionPercent: null, // N/A on empty classes
      };
    }

    let falseUnreachableCount = 0;
    let unknownCount = 0;
    let correctCount = 0;
    let reachableTruthCount = 0;
    let reachableCorrect = 0;
    let unreachableTruthCount = 0;
    let unreachableCorrect = 0;
    let unknownTruthCount = 0;
    let unknownCorrect = 0;

    let suppressedCount = 0;
    let reportedBeforeGate2Count = 0;

    for (const ev of evaluations) {
      const pred = ev.predicted;
      const truth = ev.truth;

      if (pred === 'UNKNOWN') unknownCount++;
      if (ev.suppressed) suppressedCount++;
      if (ev.reportedBeforeGate2) reportedBeforeGate2Count++;

      // False unreachable: predicted UNREACHABLE but ground truth is REACHABLE (or REACHABLE_IMPORT / REACHABLE_CALL_PATH)
      if (pred === 'UNREACHABLE' && truth.startsWith('REACHABLE')) {
        falseUnreachableCount++;
      }

      const match =
        pred === truth || (pred.startsWith('REACHABLE') && truth.startsWith('REACHABLE'));
      if (match) correctCount++;

      if (truth.startsWith('REACHABLE')) {
        reachableTruthCount++;
        if (pred.startsWith('REACHABLE')) reachableCorrect++;
      } else if (truth === 'UNREACHABLE') {
        unreachableTruthCount++;
        if (pred === 'UNREACHABLE') unreachableCorrect++;
      } else {
        unknownTruthCount++;
        if (pred === 'UNKNOWN') unknownCorrect++;
      }
    }

    const reachAcc = reachableTruthCount > 0 ? reachableCorrect / reachableTruthCount : null;
    const unreachAcc =
      unreachableTruthCount > 0 ? unreachableCorrect / unreachableTruthCount : null;
    const unkAcc = unknownTruthCount > 0 ? unknownCorrect / unknownTruthCount : null;
    const overallAcc = total > 0 ? correctCount / total : 1.0;

    // Amendment A15: Define noiseReductionPercent precisely:
    // (suppressed qualifying findings / total reported-before-Gate-2) * 100
    // Show null (N/A) for empty classes, never 100%.
    const noiseReductionPercent =
      reportedBeforeGate2Count > 0
        ? parseFloat(((suppressedCount / reportedBeforeGate2Count) * 100).toFixed(2))
        : null;

    return {
      totalFindings: total,
      falseUnreachableCount,
      unknownCount,
      unknownRate: parseFloat((unknownCount / total).toFixed(4)),
      reachabilityAccuracy: {
        reachable: reachAcc !== null ? parseFloat(reachAcc.toFixed(4)) : null,
        unreachable: unreachAcc !== null ? parseFloat(unreachAcc.toFixed(4)) : null,
        unknown: unkAcc !== null ? parseFloat(unkAcc.toFixed(4)) : null,
        overall: overallAcc !== null ? parseFloat(overallAcc.toFixed(4)) : 1.0,
      },
      noiseReductionPercent,
    };
  }
}
