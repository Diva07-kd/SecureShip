import { FreshnessResult, OfflineGenerationManifest } from './types.js';

export interface FreshnessOptions {
  maxStaleDays?: number;
  maxExpiredDays?: number;
  now?: () => Date;
}

export const DEFAULT_MAX_STALE_DAYS = 7;
export const DEFAULT_MAX_EXPIRED_DAYS = 30;

export class FreshnessEvaluator {
  private readonly nowFn: () => Date;

  constructor(nowFn: () => Date = () => new Date()) {
    this.nowFn = nowFn;
  }

  /**
   * Pure evaluation of offline database freshness against an injected clock.
   */
  public evaluate(
    manifest: OfflineGenerationManifest,
    options: FreshnessOptions = {}
  ): FreshnessResult {
    const now = (options.now ?? this.nowFn)();
    const maxStale = options.maxStaleDays ?? DEFAULT_MAX_STALE_DAYS;
    const maxExpired = options.maxExpiredDays ?? DEFAULT_MAX_EXPIRED_DAYS;

    // Determine representative timestamp: latest upstreamUpdatedAt among components,
    // falling back to manifest createdAt or importedAt.
    let refTimestamp = manifest.createdAt || manifest.importedAt;
    for (const comp of manifest.components) {
      if (comp.upstreamUpdatedAt && comp.upstreamUpdatedAt > refTimestamp) {
        refTimestamp = comp.upstreamUpdatedAt;
      }
    }

    const refDate = new Date(refTimestamp);
    const diffMs = Math.max(0, now.getTime() - refDate.getTime());
    const ageDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    const isExpired = ageDays > maxExpired;
    const isStale = ageDays > maxStale;

    let status: 'FRESH' | 'STALE' | 'EXPIRED' = 'FRESH';
    if (isExpired) {
      status = 'EXPIRED';
    } else if (isStale) {
      status = 'STALE';
    }

    return {
      ageDays,
      isStale,
      isExpired,
      status,
      evaluatedTimestamp: refTimestamp,
    };
  }
}
