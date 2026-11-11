import type {
  AiVerdict,
  FindingCategory,
  NormalizedFinding,
  Reachability,
  ScanSummary,
  Severity,
  SuppressedFinding,
  SuppressionReasonCode,
} from '@secureship/contracts';

export class SuppressionLedger {
  private readonly suppressedList: SuppressedFinding[] = [];
  private readonly reportedList: NormalizedFinding[] = [];
  private outOfScopeCount = 0;
  private rawCount = 0;

  /**
   * Records a raw finding increment.
   */
  public recordRaw(count = 1): void {
    this.rawCount += count;
  }

  /**
   * Records a finding that is outside the incremental diff scope.
   */
  public recordOutOfScope(count = 1): void {
    this.outOfScopeCount += count;
  }

  /**
   * Adds a finding to the reported findings list.
   */
  public addReported(finding: NormalizedFinding): void {
    this.reportedList.push(finding);
  }

  /**
   * Suppresses a finding with an auditable reason code and detail.
   */
  public suppress(
    finding: NormalizedFinding,
    reasonCode: SuppressionReasonCode,
    detail: string,
    source: string
  ): void {
    this.suppressedList.push({
      finding,
      reasonCode,
      detail,
      source,
    });
  }

  public getReportedFindings(): NormalizedFinding[] {
    return [...this.reportedList];
  }

  public sortReported(comparator: (a: NormalizedFinding, b: NormalizedFinding) => number): void {
    this.reportedList.sort(comparator);
  }

  public getSuppressedFindings(): SuppressedFinding[] {
    return [...this.suppressedList];
  }

  /**
   * Verifies Invariant P1: totalRaw === totalReported + totalSuppressed + totalOutOfScope
   */
  public verifyInvariant(): void {
    const totalReported = this.reportedList.length;
    const totalSuppressed = this.suppressedList.length;
    const totalOutOfScope = this.outOfScopeCount;
    const calculated = totalReported + totalSuppressed + totalOutOfScope;

    if (this.rawCount !== calculated) {
      throw new Error(
        `Suppression Ledger Invariant P1 Violation: totalRaw (${this.rawCount}) does not match totalReported (${totalReported}) + totalSuppressed (${totalSuppressed}) + totalOutOfScope (${totalOutOfScope}) = ${calculated}`
      );
    }
  }

  /**
   * Generates a fully aggregated ScanSummary object.
   */
  public computeSummary(
    includeReachability = true,
    functionLevelOptions?: { skippedTier?: number }
  ): ScanSummary {
    this.verifyInvariant();

    const bySeverity: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    const byCategory: Record<FindingCategory, number> = {
      SAST: 0,
      SCA: 0,
      SECRET: 0,
      IAC: 0,
      SUPPLY_CHAIN: 0,
    };

    const byReachability: Record<Reachability, number> = {
      REACHABLE_CALL_PATH: 0,
      REACHABLE_IMPORT: 0,
      UNREACHABLE: 0,
      UNKNOWN: 0,
    };

    const unknownByEvidence: Record<string, number> = {};

    const byAiVerdict: Record<AiVerdict, number> = {
      LIKELY_TRUE_POSITIVE: 0,
      LIKELY_FALSE_POSITIVE: 0,
      NEEDS_HUMAN_REVIEW: 0,
    };
    let hasAiVerdict = false;

    for (const f of this.reportedList) {
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
      if (includeReachability) {
        const reach = f.reachabilityDetail?.verdict ?? f.reachability ?? 'UNKNOWN';
        byReachability[reach] = (byReachability[reach] ?? 0) + 1;
        if (reach === 'UNKNOWN') {
          const kind = f.reachabilityDetail?.evidence?.kind ?? 'NO_REACHABILITY_DETAIL';
          unknownByEvidence[kind] = (unknownByEvidence[kind] ?? 0) + 1;
        }
      }
      if (f.aiTriage?.verdict) {
        byAiVerdict[f.aiTriage.verdict] = (byAiVerdict[f.aiTriage.verdict] ?? 0) + 1;
        hasAiVerdict = true;
      }
    }

    const suppressedByReason: Record<SuppressionReasonCode, number> = {
      GATE1_TEST_OR_MOCK: 0,
      GATE1_EXAMPLE: 0,
      GATE1_DOCUMENTATION: 0,
      USER_IGNORE_RULE: 0,
      BASELINE_KNOWN: 0,
      GATE2_UNREACHABLE: 0,
      GATE3_LIKELY_FALSE_POSITIVE: 0,
      SUPPLY_CHAIN_ALLOWLISTED: 0,
    };

    for (const s of this.suppressedList) {
      suppressedByReason[s.reasonCode] = (suppressedByReason[s.reasonCode] ?? 0) + 1;
    }

    const summary: ScanSummary = {
      totalRaw: this.rawCount,
      totalReported: this.reportedList.length,
      totalSuppressed: this.suppressedList.length,
      totalOutOfScope: this.outOfScopeCount,
      bySeverity,
      byCategory,
      suppressedByReason,
    };

    if (includeReachability) {
      summary.byReachability = byReachability;
      if (Object.keys(unknownByEvidence).length > 0) {
        summary.unknownByEvidence = unknownByEvidence;
      }
    }

    if (hasAiVerdict) {
      summary.byAiVerdict = byAiVerdict;
    }

    // Function-Level Reachability Summary (Phase B)
    let flEvaluated = 0;
    let flNoSymbolData = 0;
    let flSymbolReferenced = 0;
    let flCallPathProven = 0;
    let flUninvoked = 0;
    let flEscapedOrUnknown = 0;
    const flBlockedByReason: Record<string, number> = {};

    const allFindings = [...this.reportedList, ...this.suppressedList.map((s) => s.finding)];

    for (const f of allFindings) {
      const ev = f.reachabilityDetail?.evidence;
      if (!ev) continue;

      if (ev.kind === 'SYMBOL_CALL_PATH') {
        flCallPathProven++;
        flEvaluated++;
      } else if (ev.kind === 'SYMBOL_REFERENCED') {
        flSymbolReferenced++;
        flEvaluated++;
      } else if (ev.kind === 'UNINVOKED_SYMBOL') {
        flUninvoked++;
        flEvaluated++;
      } else if (ev.kind === 'NAMESPACE_ESCAPES') {
        flEscapedOrUnknown++;
        flEvaluated++;
      } else if (
        ev.kind === 'PACKAGE_IMPORTED' &&
        typeof ev.notes === 'string' &&
        ev.notes.includes('symbol data unavailable')
      ) {
        flNoSymbolData++;
        flEvaluated++;
      }

      if (ev.blockedBy) {
        flBlockedByReason[ev.blockedBy] = (flBlockedByReason[ev.blockedBy] ?? 0) + 1;
      }
    }

    const skippedTierCount = functionLevelOptions?.skippedTier ?? 0;
    if (includeReachability && (flEvaluated > 0 || skippedTierCount > 0)) {
      summary.functionLevel = {
        evaluated: flEvaluated,
        noSymbolData: flNoSymbolData,
        symbolReferenced: flSymbolReferenced,
        callPathProven: flCallPathProven,
        uninvoked: flUninvoked,
        escapedOrUnknown: flEscapedOrUnknown,
        skippedTier: skippedTierCount,
        blockedByReason: flBlockedByReason,
      };
    }

    return summary;
  }
}
