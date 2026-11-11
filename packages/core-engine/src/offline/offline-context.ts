import { resolveDbDir } from '../paths/index.js';
import { DbLocator } from './db-locator.js';
import { FreshnessEvaluator } from './freshness-evaluator.js';
import { OfflineContext, OfflineDatabaseProvenance } from './types.js';

export interface CreateOfflineContextOptions {
  offline?: boolean;
  strict?: boolean;
  dbDir?: string;
  now?: () => Date;
  maxStaleDays?: number;
  maxExpiredDays?: number;
}

export function createOfflineContext(options: CreateOfflineContextOptions = {}): OfflineContext {
  const isOffline = options.offline ?? false;
  if (!isOffline) {
    return {
      enabled: false,
      completeness: 'COMPLETE',
      databases: [],
      warnings: [],
    };
  }

  const targetDbDir = options.dbDir ?? resolveDbDir();
  const activeGen = DbLocator.getActiveGeneration(targetDbDir);

  if (!activeGen) {
    const missingMessage = `No offline vulnerability database installed in '${targetDbDir}'.`;
    if (options.strict) {
      throw new Error(
        `[Offline Security Violation] ${missingMessage} Under --strict, scanning cannot proceed without a valid offline database.`
      );
    }

    return {
      enabled: true,
      completeness: 'DEGRADED',
      databases: [],
      warnings: [
        `[Warning] ${missingMessage} Vulnerability scanning is operating in degraded mode. Run 'secureship import-offline <bundle>' to install an offline database.`,
      ],
      error: missingMessage,
    };
  }

  const evaluator = new FreshnessEvaluator(options.now ?? (() => new Date()));
  const freshness = evaluator.evaluate(activeGen.manifest, {
    maxStaleDays: options.maxStaleDays,
    maxExpiredDays: options.maxExpiredDays,
  });

  const warnings: string[] = [];
  let completeness: 'COMPLETE' | 'DEGRADED' = 'COMPLETE';

  if (freshness.isExpired) {
    const expiredMsg = `Offline vulnerability database generation '${activeGen.id}' is ${freshness.ageDays} days old (exceeds ${options.maxExpiredDays ?? 30} days strict threshold).`;
    if (options.strict) {
      throw new Error(
        `[Offline Security Violation] ${expiredMsg} Under --strict, scanning cannot proceed with an expired database.`
      );
    }
    completeness = 'DEGRADED';
    warnings.push(`[Warning] ${expiredMsg} Scan completeness is DEGRADED.`);
  } else if (freshness.isStale) {
    warnings.push(
      `[Warning] Offline vulnerability database generation '${activeGen.id}' is ${freshness.ageDays} days old (> ${options.maxStaleDays ?? 7} days). Consider updating with a newer offline bundle.`
    );
  }

  const databases: OfflineDatabaseProvenance[] = activeGen.manifest.components
    .filter((c) => c.kind === 'db')
    .map((c) => ({
      id: c.id,
      version: c.version,
      upstreamUpdatedAt: c.upstreamUpdatedAt,
      importedAt: activeGen.manifest.importedAt,
      ageDays: freshness.ageDays,
      trust: activeGen.manifest.trust,
      generationId: activeGen.id,
      bundleId: activeGen.manifest.bundleId,
    }));

  return {
    enabled: true,
    completeness,
    generationId: activeGen.id,
    generationDir: activeGen.dir,
    trivyCacheDir: DbLocator.getTrivyCacheDir(activeGen.dir),
    osvDbDir: DbLocator.getOsvDbDir(activeGen.dir),
    databases,
    warnings,
  };
}
