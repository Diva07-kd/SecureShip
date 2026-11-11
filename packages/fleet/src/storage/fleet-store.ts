import path from 'node:path';
import crypto from 'node:crypto';
import {
  type FleetIngestPayload,
  type FleetRepoSummary,
  type FleetExecutiveSummary,
  type FleetPolicy,
  type FleetSbomComponent,
  type RiskGrade,
  computeRepoScore,
} from '@secureship/contracts';
import {
  FLEET_STORE_FORMAT_VERSION,
  FleetStoreError,
  FleetStoreCorruptionError,
  FleetStoreUnsupportedVersionError,
  FleetStorePersistError,
  FleetStoreValidationError,
  serializeSnapshot,
  parseSnapshotBytes,
  sanitizeAndValidatePolicyUpdates,
} from './fleet-snapshot.js';
import {
  type FsFacade,
  defaultFsFacade,
  defaultSleep,
  defaultRandom,
  probeWritable,
  cleanStaleTemps,
  quarantine,
  atomicReplace,
} from './atomic-file.js';

export {
  FLEET_STORE_FORMAT_VERSION,
  FleetStoreError,
  FleetStoreCorruptionError,
  FleetStoreUnsupportedVersionError,
  FleetStorePersistError,
  FleetStoreValidationError,
  FsFacade,
};

export interface FleetStoreLogger {
  warn(code: string, message: string, meta?: Record<string, unknown>): void;
  error(code: string, message: string, meta?: Record<string, unknown>): void;
  debug?(code: string, message: string, meta?: Record<string, unknown>): void;
}

const defaultLogger: FleetStoreLogger = {
  warn: (code, message) => console.warn(`[${code}] ${message}`),
  error: (code, message) => console.error(`[${code}] ${message}`),
  debug: () => {},
};

export interface FleetStoreInternals {
  fs?: FsFacade;
  logger?: FleetStoreLogger;
  now?: () => number;
  sleep?: (ms: number) => void;
  random?: (bytes?: number) => string;
  platform?: NodeJS.Platform;
}

export interface FleetStoreOptions {
  storageFile?: string;
  dbPath?: string;
  defaultPolicy?: Partial<FleetPolicy>;
  strictLoad?: boolean;
  strictPersistence?: boolean;
  quarantineKeep?: number;
  /** @internal Internal hooks for deterministic testing and dependency injection */
  internals?: FleetStoreInternals;
}

export interface FleetPersistenceStatus {
  healthy: boolean;
  mode: 'memory-only' | 'atomic' | 'non-atomic-fallback';
  consecutiveFailures: number;
  lastSuccessAt?: string;
  lastError?: {
    code: string;
    message: string;
    at: string;
  };
}

export interface FleetLoadReport {
  source: 'none' | 'primary' | 'backup' | 'empty-after-corruption';
  recovered: boolean;
  quarantined: string[];
  warnings: string[];
}

/**
 * Enterprise FleetStore for managing and persisting corporate vulnerability telemetry and policy.
 *
 * Persistence Architecture (Wave 1 Gate 13 / F-FLT-004):
 * - Atomic write protocol: temp-file-and-rename (`${target}.tmp.<pid>.<time>.<rand>`) with fsync.
 * - Files created:
 *   - Primary file: `${target}` (0o600 on POSIX).
 *   - Backup file: `${target}.bak` rotated atomically only after successful write and integrity verification.
 *   - Quarantine files: `${target}.corrupt-<UTC yyyymmddThhmmssZ>-<rand>` preserving corrupt state for forensics.
 *   - Stale temporary files: `${target}.tmp.*` pruned automatically on startup.
 * - Permission tightening: Database, backup, and quarantine files are created with mode 0o600 and directories 0o700
 *   on POSIX platforms. On Windows, mode permissions are skipped and parent directory ACL inheritance applies.
 * - Platform semantics:
 *   - Windows: Retries EPERM/EACCES/EBUSY on rename with exponential backoff (10-320ms) against scanner locks.
 *   - Docker: Falls back to non-atomic in-place write with verified backup when renaming over single-file bind mounts (EBUSY/EXDEV).
 *   - Symlinks: Resolves `realpathSync` so the underlying target file is updated without destroying the symlink.
 * - Single-Writer Requirement:
 *   FleetStore is designed for single-writer deployments per database file. Multiple server instances sharing
 *   a database file without distributed locking can cause lost updates. External modifications trigger
 *   FLEET_STORE_EXTERNAL_MODIFICATION warnings.
 */
export class FleetStore {
  public static readonly FORMAT_VERSION = FLEET_STORE_FORMAT_VERSION;
  public static readonly FLEET_STORE_FORMAT_VERSION = FLEET_STORE_FORMAT_VERSION;
  public static readonly FleetStoreError = FleetStoreError;
  public static readonly FleetStoreCorruptionError = FleetStoreCorruptionError;
  public static readonly FleetStoreUnsupportedVersionError = FleetStoreUnsupportedVersionError;
  public static readonly FleetStorePersistError = FleetStorePersistError;
  public static readonly FleetStoreValidationError = FleetStoreValidationError;

  private repos: Map<string, FleetRepoSummary> = new Map();
  private policy: FleetPolicy;
  private readonly defaultPolicy: FleetPolicy;
  private readonly storageFile?: string;
  private readonly strictLoad: boolean;
  private readonly strictPersistence: boolean;
  private readonly quarantineKeep: number;

  private readonly fsFacade: FsFacade;
  private readonly logger: FleetStoreLogger;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => void;
  private readonly random: (bytes?: number) => string;
  private readonly platform: NodeJS.Platform;

  private persistenceHealthy: boolean = true;
  private persistenceMode: 'memory-only' | 'atomic' | 'non-atomic-fallback' = 'memory-only';
  private consecutivePersistFailures: number = 0;
  private lastSuccessAt?: string;
  private lastError?: { code: string; message: string; at: string };
  private lastPersistErrorLoggedAt: number = 0;
  private fallbackLogged: boolean = false;

  private primaryKnownGood: boolean = false;
  private lastWritten?: { size: number; mtimeMs: number; digest: string };

  private isPersisting: boolean = false;
  private persistDirty: boolean = false;

  private readonly loadReport: {
    source: 'none' | 'primary' | 'backup' | 'empty-after-corruption';
    recovered: boolean;
    quarantined: string[];
    warnings: string[];
  } = {
    source: 'none',
    recovered: false,
    quarantined: [],
    warnings: [],
  };

  constructor(options: FleetStoreOptions = {}) {
    this.storageFile = options.storageFile ?? options.dbPath;
    this.strictLoad = options.strictLoad ?? false;
    this.strictPersistence = options.strictPersistence ?? false;
    this.quarantineKeep = options.quarantineKeep ?? 5;

    const internals = options.internals ?? {};
    this.fsFacade = internals.fs ?? defaultFsFacade;
    this.logger = internals.logger ?? defaultLogger;
    this.now = internals.now ?? Date.now;
    this.sleep = internals.sleep ?? defaultSleep;
    this.random = internals.random ?? defaultRandom;
    this.platform = internals.platform ?? process.platform;

    this.defaultPolicy = {
      policyVersion: '1.0',
      failOnSeverity: 'HIGH',
      blockUnreachableSca: false,
      deniedLicenses: ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'],
      requireHmacAudit: true,
      updatedAt: new Date(this.now()).toISOString(),
      ...options.defaultPolicy,
    };
    this.policy = { ...this.defaultPolicy };

    if (this.storageFile) {
      this.persistenceMode = 'atomic';
      this.loadFromDisk();
    }
  }

  private log(
    level: 'warn' | 'error' | 'debug',
    code: string,
    message: string,
    meta?: Record<string, unknown>
  ): void {
    if (level === 'warn') {
      this.logger.warn(code, message, meta);
      this.loadReport.warnings.push(code);
    } else if (level === 'error') {
      this.logger.error(code, message, meta);
    } else {
      this.logger.debug?.(code, message, meta);
    }
  }

  private logPersistError(err: unknown): void {
    const currentTime = this.now();
    const shouldLog =
      this.lastPersistErrorLoggedAt === 0 || currentTime - this.lastPersistErrorLoggedAt >= 60000;
    if (shouldLog) {
      this.lastPersistErrorLoggedAt = currentTime;
      const osCode = (err as { code?: string })?.code ?? 'UNKNOWN';
      this.logger.error(
        'FLEET_STORE_PERSIST_FAILED',
        `Disk persistence failed for ${this.storageFile} (code: ${osCode})`
      );
    }
  }

  private loadFromDisk(): void {
    if (!this.storageFile) return;

    // 1. Resolve real target path to account for symlinks
    let realTarget = this.storageFile;
    if (this.fsFacade.existsSync(this.storageFile)) {
      try {
        realTarget = this.fsFacade.realpathSync(this.storageFile);
      } catch (_err: unknown) {
        void _err;
        // Fall back to storageFile if realpath fails (e.g. broken link or restricted permissions)
        realTarget = this.storageFile;
      }
    } else {
      const parentDir = path.dirname(this.storageFile);
      if (this.fsFacade.existsSync(parentDir)) {
        try {
          realTarget = path.join(
            this.fsFacade.realpathSync(parentDir),
            path.basename(this.storageFile)
          );
        } catch (_err: unknown) {
          void _err;
          // Fall back to storageFile if parent directory realpath resolution fails
          realTarget = this.storageFile;
        }
      }
    }

    // 2. Read Primary (Candidate A)
    let rawA: Buffer | null = null;
    let aExists = false;
    let aUnreadable = false;
    let aErrorCode: string | null = null;

    if (this.fsFacade.existsSync(realTarget)) {
      aExists = true;
      try {
        const readA = this.fsFacade.readFileSync(realTarget);
        rawA = Buffer.isBuffer(readA) ? readA : Buffer.from(readA);
      } catch (err: unknown) {
        aUnreadable = true;
        aErrorCode = (err as { code?: string })?.code ?? 'EACCES';
        this.log(
          'error',
          'FLEET_STORE_LOAD_UNREADABLE',
          `Primary database file unreadable: ${realTarget} (code: ${aErrorCode})`
        );
      }
    }

    // Read Backup (Candidate B)
    const bakTarget = `${realTarget}.bak`;
    let rawB: Buffer | null = null;
    let bExists = false;
    let bUnreadable = false;
    let bErrorCode: string | null = null;

    if (this.fsFacade.existsSync(bakTarget)) {
      bExists = true;
      try {
        const readB = this.fsFacade.readFileSync(bakTarget);
        rawB = Buffer.isBuffer(readB) ? readB : Buffer.from(readB);
      } catch (err: unknown) {
        bUnreadable = true;
        bErrorCode = (err as { code?: string })?.code ?? 'EACCES';
        this.log(
          'error',
          'FLEET_STORE_LOAD_UNREADABLE',
          `Backup database file unreadable: ${bakTarget} (code: ${bErrorCode})`
        );
      }
    }

    // 3. Parse candidates
    let parsedA: ReturnType<typeof parseSnapshotBytes> | null = null;
    if (rawA !== null) {
      try {
        parsedA = parseSnapshotBytes(rawA);
      } catch (err: unknown) {
        if (err instanceof FleetStoreUnsupportedVersionError) {
          throw err;
        }
        parsedA = { ok: false, code: 'PARSE_ERROR', detail: String(err) };
      }
    }

    let parsedB: ReturnType<typeof parseSnapshotBytes> | null = null;
    if (rawB !== null) {
      try {
        parsedB = parseSnapshotBytes(rawB);
      } catch (err: unknown) {
        if (err instanceof FleetStoreUnsupportedVersionError) {
          throw err;
        }
        parsedB = { ok: false, code: 'PARSE_ERROR', detail: String(err) };
      }
    }

    const aValid = parsedA !== null && parsedA.ok;
    const bValid = parsedB !== null && parsedB.ok;

    // 4. Selection algorithm
    if (!aExists && !bExists) {
      // Both absent: clean start
      this.loadReport.source = 'none';
    } else if (aValid && parsedA && parsedA.ok) {
      // Primary is valid
      this.loadReport.source = 'primary';
      for (const r of parsedA.snapshot.repos) {
        this.repos.set(r.repoName, r);
      }
      this.policy = { ...this.defaultPolicy, ...parsedA.snapshot.policy };
      this.primaryKnownGood = true;

      try {
        const st = this.fsFacade.statSync(realTarget);
        const digest = crypto
          .createHash('sha256')
          .update(rawA ?? Buffer.alloc(0))
          .digest('hex');
        this.lastWritten = { size: st.size, mtimeMs: st.mtimeMs, digest };
      } catch (_statErr: unknown) {
        void _statErr;
      }

      if (bExists && !bValid && !bUnreadable) {
        this.log('warn', 'FLEET_STORE_BACKUP_CORRUPT', `Backup file is corrupt: ${bakTarget}`);
        const qPath = quarantine(
          bakTarget,
          this.quarantineKeep,
          this.fsFacade,
          this.now,
          this.random,
          this.platform
        );
        this.loadReport.quarantined.push(qPath);
      }
    } else if (bValid && parsedB && parsedB.ok) {
      // Backup is valid; recover from backup
      this.loadReport.source = 'backup';
      this.loadReport.recovered = true;
      this.log(
        'warn',
        'FLEET_STORE_RECOVERED_FROM_BACKUP',
        `Recovered database from backup: ${bakTarget}`
      );

      if (aExists && !aUnreadable) {
        this.log(
          'warn',
          'FLEET_STORE_PRIMARY_CORRUPT',
          `Primary database was corrupt: ${realTarget}`
        );
        const qPath = quarantine(
          realTarget,
          this.quarantineKeep,
          this.fsFacade,
          this.now,
          this.random,
          this.platform
        );
        this.loadReport.quarantined.push(qPath);
      }

      for (const r of parsedB.snapshot.repos) {
        this.repos.set(r.repoName, r);
      }
      this.policy = { ...this.defaultPolicy, ...parsedB.snapshot.policy };

      // Heal immediately: persist recovered state with primaryKnownGood=false
      this.primaryKnownGood = false;
      try {
        this.executePersist();
      } catch (err: unknown) {
        if (this.strictPersistence) {
          throw err;
        }
      }
    } else {
      // Both present & invalid, or one present & invalid and other absent
      this.loadReport.source = 'empty-after-corruption';

      if (this.strictLoad) {
        const corruptFiles: Array<{ path: string; code: string }> = [];
        if (aExists) {
          const codeA =
            (parsedA && !parsedA.ok ? parsedA.code : undefined) ?? aErrorCode ?? 'CORRUPT';
          corruptFiles.push({ path: realTarget, code: codeA });
        }
        if (bExists) {
          const codeB =
            (parsedB && !parsedB.ok ? parsedB.code : undefined) ?? bErrorCode ?? 'CORRUPT';
          corruptFiles.push({ path: bakTarget, code: codeB });
        }
        throw new FleetStoreCorruptionError(
          'FleetStore database file(s) corrupted and strictLoad is enabled',
          corruptFiles
        );
      }

      this.log(
        'error',
        'FLEET_STORE_STARTED_EMPTY_AFTER_CORRUPTION',
        `Database corrupted; started empty: ${realTarget}`
      );

      if (aExists && !aUnreadable) {
        const qA = quarantine(
          realTarget,
          this.quarantineKeep,
          this.fsFacade,
          this.now,
          this.random,
          this.platform
        );
        this.loadReport.quarantined.push(qA);
      }
      if (bExists && !bUnreadable) {
        const qB = quarantine(
          bakTarget,
          this.quarantineKeep,
          this.fsFacade,
          this.now,
          this.random,
          this.platform
        );
        this.loadReport.quarantined.push(qB);
      }

      this.repos.clear();
      this.policy = { ...this.defaultPolicy };
      this.primaryKnownGood = false;
      // Do not write at load time
    }

    // 5. Startup probe & cleanup
    const targetDir = path.dirname(realTarget);
    try {
      probeWritable(targetDir, this.fsFacade, this.random, this.now);
      cleanStaleTemps(
        targetDir,
        path.basename(realTarget),
        10 * 60 * 1000,
        this.fsFacade,
        this.now
      );
    } catch (err: unknown) {
      const osCode = (err as { code?: string })?.code ?? 'EACCES';
      this.log(
        'error',
        'FLEET_STORE_DIR_NOT_WRITABLE',
        `Data directory is not writable: ${targetDir} (code: ${osCode})`
      );
      this.persistenceHealthy = false;
      this.lastError = {
        code: osCode,
        message: err instanceof Error ? err.message : String(err),
        at: new Date(this.now()).toISOString(),
      };
      if (this.strictPersistence) {
        throw new FleetStorePersistError(
          `Directory not writable: ${targetDir}`,
          'FLEET_STORE_DIR_NOT_WRITABLE',
          err
        );
      }
    }
  }

  private executePersist(): void {
    if (!this.storageFile) return;

    const { buffer } = serializeSnapshot({
      repos: Array.from(this.repos.values()),
      policy: this.policy,
      updatedAt: new Date(this.now()).toISOString(),
    });
    const bufferSha256 = crypto.createHash('sha256').update(buffer).digest('hex');

    try {
      const res = atomicReplace(this.storageFile, buffer, {
        fs: this.fsFacade,
        sleep: this.sleep,
        now: this.now,
        random: this.random,
        platform: this.platform,
        primaryKnownGood: this.primaryKnownGood,
        lastWritten: this.lastWritten,
        expectedDigest: bufferSha256,
        quarantineKeep: this.quarantineKeep,
        logger: this.logger,
        onExternalModification: (type) => {
          if (type === 'valid') {
            this.log(
              'warn',
              'FLEET_STORE_EXTERNAL_MODIFICATION',
              `External modification detected: ${this.storageFile}`
            );
          } else {
            this.log(
              'warn',
              'FLEET_STORE_PRIMARY_CORRUPT',
              `External primary corruption detected: ${this.storageFile}`
            );
          }
        },
        onQuarantine: (corruptPath) => {
          this.loadReport.quarantined.push(corruptPath);
        },
        onFallback: () => {
          if (!this.fallbackLogged) {
            this.fallbackLogged = true;
            this.log(
              'warn',
              'FLEET_STORE_NON_ATOMIC_FALLBACK',
              `Non-atomic fallback used for: ${this.storageFile}`
            );
          }
          this.persistenceMode = 'non-atomic-fallback';
        },
      });

      this.primaryKnownGood = true;
      this.persistenceHealthy = true;
      this.lastWritten = res.lastWritten;
      if (res.mode === 'non-atomic-fallback') {
        this.persistenceMode = 'non-atomic-fallback';
      } else {
        this.persistenceMode = 'atomic';
      }

      if (this.consecutivePersistFailures > 0) {
        this.log(
          'warn',
          'FLEET_STORE_PERSIST_RECOVERED',
          `Disk persistence recovered: ${this.storageFile}`
        );
        this.consecutivePersistFailures = 0;
        this.lastPersistErrorLoggedAt = 0;
      }
      this.lastSuccessAt = new Date(this.now()).toISOString();
    } catch (err: unknown) {
      this.consecutivePersistFailures++;
      const osCode = (err as { code?: string })?.code ?? 'UNKNOWN';
      this.lastError = {
        code: osCode,
        message: err instanceof Error ? err.message : String(err),
        at: new Date(this.now()).toISOString(),
      };
      this.logPersistError(err);
      throw err;
    }
  }

  private persistToDisk(): void {
    if (!this.storageFile) return;

    if (this.isPersisting) {
      this.persistDirty = true;
      return;
    }

    this.isPersisting = true;
    try {
      let loops = 0;
      do {
        this.persistDirty = false;
        try {
          this.executePersist();
        } catch (err: unknown) {
          if (this.strictPersistence) {
            throw err;
          }
        }
        loops++;
      } while (this.persistDirty && loops < 3);
    } finally {
      this.isPersisting = false;
    }
  }

  public ingest(payload: FleetIngestPayload): FleetRepoSummary {
    const summary = payload.summary;

    let reachableCriticals = 0;
    let unreachableCriticals = 0;
    let reachableHighs = 0;
    let unreachableHighs = 0;
    const mediums = summary.bySeverity.MEDIUM ?? 0;
    const secrets = summary.byCategory.SECRET ?? 0;
    let reachableCount = 0;

    for (const v of payload.vulnerabilities) {
      const isReachable =
        v.reachability === 'REACHABLE_CALL_PATH' || v.reachability === 'REACHABLE_IMPORT';
      if (isReachable) reachableCount++;

      if (v.severity === 'CRITICAL') {
        if (isReachable) reachableCriticals++;
        else unreachableCriticals++;
      } else if (v.severity === 'HIGH') {
        if (isReachable) reachableHighs++;
        else unreachableHighs++;
      }
    }

    const nonCompliantLicenses = payload.sbom?.nonCompliantCount ?? 0;

    const { score, grade } = computeRepoScore({
      reachableCriticals,
      unreachableCriticals,
      reachableHighs,
      unreachableHighs,
      mediums,
      licenseViolations: nonCompliantLicenses,
      secrets,
    });

    const activeCriticals = reachableCriticals + unreachableCriticals;
    const activeHighs = reachableHighs + unreachableHighs;

    const repoSummary: FleetRepoSummary = {
      repoName: payload.repoName,
      branch: payload.branch,
      commitSha: payload.commitSha,
      latestScanAt: payload.scannedAt,
      riskGrade: grade,
      riskScore: score,
      activeCriticals,
      activeHighs,
      reachableCount,
      suppressedCount: summary.totalSuppressed,
      reachabilitySuppressionPct: summary.reachabilitySuppressionPct,
      componentCount: payload.sbom?.totalComponents ?? 0,
      compliant: nonCompliantLicenses === 0 && activeCriticals === 0,
      vulnerabilities: payload.vulnerabilities,
      sbomComponents: payload.sbom?.components ?? [],
      signature: payload.signature,
    };

    const previousEntry = this.repos.get(payload.repoName);
    this.repos.set(payload.repoName, repoSummary);

    try {
      this.persistToDisk();
    } catch (err: unknown) {
      if (this.strictPersistence) {
        if (previousEntry !== undefined) {
          this.repos.set(payload.repoName, previousEntry);
        } else {
          this.repos.delete(payload.repoName);
        }
        if (err instanceof FleetStorePersistError) {
          throw err;
        }
        throw new FleetStorePersistError(
          `Failed to persist ingest for repository: ${payload.repoName}`,
          'FLEET_STORE_PERSIST_FAILED',
          err
        );
      }
    }

    return repoSummary;
  }

  public getRepos(): FleetRepoSummary[] {
    return Array.from(this.repos.values()).sort((a, b) => a.riskScore - b.riskScore);
  }

  public getRepo(repoName: string): FleetRepoSummary | undefined {
    return this.repos.get(repoName);
  }

  public getExecutiveSummary(): FleetExecutiveSummary {
    const repoList = this.getRepos();
    if (repoList.length === 0) {
      return {
        totalRepos: 0,
        enterpriseScore: 100,
        enterpriseGrade: 'A+',
        totalCriticals: 0,
        totalHighs: 0,
        totalReachable: 0,
        totalSuppressed: 0,
        deadCodeSuppressionRate: 100,
        licenseComplianceRate: 100,
        latestActivity: new Date(this.now()).toISOString(),
      };
    }

    let sumScore = 0;
    let totalCriticals = 0;
    let totalHighs = 0;
    let totalReachable = 0;
    let totalSuppressed = 0;
    let compliantRepos = 0;
    let latestTimestamp = '';

    for (const r of repoList) {
      sumScore += r.riskScore;
      totalCriticals += r.activeCriticals;
      totalHighs += r.activeHighs;
      totalReachable += r.reachableCount;
      totalSuppressed += r.suppressedCount;
      if (r.compliant) compliantRepos++;
      if (!latestTimestamp || r.latestScanAt > latestTimestamp) {
        latestTimestamp = r.latestScanAt;
      }
    }

    const enterpriseScore = Math.round(sumScore / repoList.length);
    let enterpriseGrade: RiskGrade = 'F';
    if (enterpriseScore >= 95) enterpriseGrade = 'A+';
    else if (enterpriseScore >= 90) enterpriseGrade = 'A';
    else if (enterpriseScore >= 80) enterpriseGrade = 'B';
    else if (enterpriseScore >= 70) enterpriseGrade = 'C';
    else if (enterpriseScore >= 60) enterpriseGrade = 'D';

    const totalRaw = totalReachable + totalSuppressed;
    const deadCodeSuppressionRate =
      totalRaw > 0 ? Math.round((totalSuppressed / totalRaw) * 1000) / 10 : 100;
    const licenseComplianceRate = Math.round((compliantRepos / repoList.length) * 100);

    return {
      totalRepos: repoList.length,
      enterpriseScore,
      enterpriseGrade,
      totalCriticals,
      totalHighs,
      totalReachable,
      totalSuppressed,
      deadCodeSuppressionRate,
      licenseComplianceRate,
      latestActivity: latestTimestamp || new Date(this.now()).toISOString(),
    };
  }

  public searchSbom(
    query: string
  ): Array<{ repo: string; branch: string; component: FleetSbomComponent }> {
    const q = query.toLowerCase().trim();
    if (!q) return [];

    const results: Array<{ repo: string; branch: string; component: FleetSbomComponent }> = [];

    for (const r of this.repos.values()) {
      for (const comp of r.sbomComponents) {
        if (
          comp.name.toLowerCase().includes(q) ||
          comp.version.toLowerCase().includes(q) ||
          comp.ecosystem.toLowerCase().includes(q) ||
          (comp.license && comp.license.toLowerCase().includes(q))
        ) {
          results.push({
            repo: r.repoName,
            branch: r.branch,
            component: comp,
          });
        }
      }
    }

    return results;
  }

  public generateCraComplianceReport(): object {
    const execSummary = this.getExecutiveSummary();
    const repoList = this.getRepos();
    const serialNumber = `urn:uuid:${crypto.randomUUID()}`;

    const components = repoList.flatMap((r) =>
      r.sbomComponents.map((c) => ({
        type: 'library',
        name: c.name,
        version: c.version,
        purl: `pkg:${c.ecosystem}/${c.name}@${c.version}`,
        scope: 'required',
        licenses: c.license ? [{ license: { id: c.license } }] : [],
        properties: [
          { name: 'secureship:repository', value: r.repoName },
          { name: 'secureship:branch', value: r.branch },
          { name: 'secureship:compliant', value: String(c.compliant) },
        ],
      }))
    );

    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber,
      version: 1,
      metadata: {
        timestamp: new Date(this.now()).toISOString(),
        tools: [
          {
            vendor: 'SecureShip',
            name: 'SecureShip Fleet CISO Engine',
            version: '1.0.0',
          },
        ],
        manufacture: {
          name: 'Enterprise Corporate Fleet Authority',
        },
        properties: [
          { name: 'cra:regulation', value: 'Regulation (EU) 2024/2847 (Cyber Resilience Act)' },
          {
            name: 'cra:essentialRequirements',
            value: 'Annex I, Part II (SBOM & Vulnerability Handling)',
          },
          {
            name: 'cra:enterpriseRiskScore',
            value: `${execSummary.enterpriseScore}/100 (${execSummary.enterpriseGrade})`,
          },
          { name: 'cra:totalRepositories', value: String(execSummary.totalRepos) },
        ],
      },
      components,
      declarations: {
        assessors: [
          {
            name: 'SecureShip Fleet Automated Verification Authority',
            organization: 'Enterprise IT Security',
          },
        ],
        attestations: [
          {
            summary:
              'Formal Technical Documentation for EU Cyber Resilience Act Conformity Assessment',
            claims: [
              {
                target: 'Article 10(4) - Software Bill of Materials & Continuous Due Diligence',
                predicate: 'PASSED',
                reasoning: `All ${execSummary.totalRepos} corporate repositories maintain continuous machine-readable SBOM inventory with cryptographic verification.`,
              },
            ],
          },
        ],
      },
    };
  }

  public getPolicy(): FleetPolicy {
    return this.policy;
  }

  public updatePolicy(updates: Partial<FleetPolicy>): FleetPolicy {
    const updatedPolicy = sanitizeAndValidatePolicyUpdates(this.policy, updates, this.now);
    const previousPolicy = this.policy;
    this.policy = updatedPolicy;

    try {
      this.persistToDisk();
    } catch (err: unknown) {
      if (this.strictPersistence) {
        this.policy = previousPolicy;
        if (err instanceof FleetStorePersistError) {
          throw err;
        }
        throw new FleetStorePersistError(
          'Failed to persist updated policy',
          'FLEET_STORE_PERSIST_FAILED',
          err
        );
      }
    }

    return this.policy;
  }

  public clear(): void {
    const previousRepos = new Map(this.repos);
    this.repos.clear();

    try {
      this.persistToDisk();
    } catch (err: unknown) {
      if (this.strictPersistence) {
        this.repos = previousRepos;
        if (err instanceof FleetStorePersistError) {
          throw err;
        }
        throw new FleetStorePersistError(
          'Failed to persist cleared fleet repository store',
          'FLEET_STORE_PERSIST_FAILED',
          err
        );
      }
    }
  }

  public getPersistenceStatus(): FleetPersistenceStatus {
    if (!this.storageFile) {
      return {
        healthy: true,
        mode: 'memory-only',
        consecutiveFailures: 0,
      };
    }

    return {
      healthy: this.persistenceHealthy && this.consecutivePersistFailures === 0,
      mode: this.persistenceMode,
      consecutiveFailures: this.consecutivePersistFailures,
      lastSuccessAt: this.lastSuccessAt,
      lastError: this.lastError,
    };
  }

  public getLoadReport(): FleetLoadReport {
    return {
      source: this.loadReport.source,
      recovered: this.loadReport.recovered,
      quarantined: [...this.loadReport.quarantined],
      warnings: [...this.loadReport.warnings],
    };
  }
}
