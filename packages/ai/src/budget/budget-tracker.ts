import type { AiExecutionSummary, AiPayloadDetail } from '@secureship/contracts';

export class BudgetTracker {
  private readonly maxFindings: number;
  private readonly budgetTokens: number;

  private findingsConsideredCount = 0;
  private findingsSentCount = 0;
  private skippedReasons: Map<string, number> = new Map();
  private totalTokensIn = 0;
  private totalTokensOut = 0;
  private truncatedSliceCount = 0;
  private cacheHitCount = 0;
  private readonly filesSentSet = new Set<string>();
  private readonly warningList: string[] = [];

  constructor(maxFindings = 25, budgetTokens = 200_000) {
    this.maxFindings = maxFindings;
    this.budgetTokens = budgetTokens;
  }

  private findingsEligibleCount = 0;

  public recordConsidered(count = 1): void {
    this.findingsConsideredCount += count;
  }

  public recordEligible(count = 1): void {
    this.findingsEligibleCount += count;
  }

  public recordSkip(reason: string, count = 1): void {
    const current = this.skippedReasons.get(reason) || 0;
    this.skippedReasons.set(reason, current + count);
  }

  public recordFindingSent(): void {
    this.findingsSentCount++;
  }

  public recordCacheHit(): void {
    this.cacheHitCount++;
  }

  public recordTruncatedSlice(): void {
    this.truncatedSliceCount++;
  }

  public recordFiles(files: string[]): void {
    for (const f of files) {
      this.filesSentSet.add(f);
    }
  }

  public recordTokens(inTokens: number, outTokens: number): void {
    this.totalTokensIn += inTokens;
    this.totalTokensOut += outTokens;
  }

  public addWarning(warning: string): void {
    this.warningList.push(warning);
  }

  public canSendFinding(): boolean {
    if (this.findingsSentCount >= this.maxFindings) {
      return false;
    }
    if (this.totalTokensIn + this.totalTokensOut >= this.budgetTokens) {
      return false;
    }
    return true;
  }

  public toExecutionSummary(
    provider: string,
    model: string,
    host: string,
    deterministic: boolean,
    dryRun?: boolean,
    estimate?: boolean,
    dryRunPayloads?: AiPayloadDetail[]
  ): AiExecutionSummary {
    const findingsSkipped = Array.from(this.skippedReasons.entries()).map(([reason, count]) => ({
      reason,
      count,
    }));

    return {
      provider,
      model,
      host,
      deterministic,
      findingsConsidered: this.findingsConsideredCount,
      findingsEligible: this.findingsEligibleCount,
      findingsSent: this.findingsSentCount,
      findingsSkipped,
      tokensIn: this.totalTokensIn,
      tokensOut: this.totalTokensOut,
      filesSent: Array.from(this.filesSentSet).sort(),
      truncatedSlices: this.truncatedSliceCount,
      cacheHits: this.cacheHitCount,
      warnings: [...this.warningList],
      dryRun,
      estimate,
      dryRunPayloads,
    };
  }
}
