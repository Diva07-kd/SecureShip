import crypto from 'node:crypto';
import type { FleetIngestPayload, FleetRepoSummary } from '@secureship/contracts';
import type { FleetStoreLogger } from '../../src/storage/fleet-store.js';

export function makeCanary(): string {
  return 'CANARY_' + crypto.randomBytes(16).toString('hex');
}

export function makePayload(
  repoName: string,
  nComponents: number = 2,
  canary?: string
): FleetIngestPayload {
  const effectiveRepoName = canary ? `${repoName}_${canary}` : repoName;
  const components = Array.from({ length: nComponents }, (_, i) => ({
    name: canary ? `component-${i}-${canary}` : `component-${i}`,
    version: `1.0.${i}`,
    ecosystem: 'npm',
    compliant: true,
    license: 'MIT',
  }));

  return {
    fleetToken: 'corp-valid-test-token-at-least-24-chars',
    repoName: effectiveRepoName,
    branch: 'main',
    commitSha: 'a1b2c3d4e5f678901234567890abcdef12345678',
    scannedAt: '2026-11-04T00:00:00.000Z',
    durationMs: 150,
    summary: {
      totalRaw: 10,
      totalReported: 2,
      totalSuppressed: 8,
      bySeverity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      byCategory: { SAST: 1, SCA: 1, SECRET: 0, IAC: 0, SUPPLY_CHAIN: 0 },
      reachabilitySuppressionPct: 80,
    },
    vulnerabilities: [
      {
        ruleId: 'VULN-001',
        severity: 'CRITICAL',
        category: 'SAST',
        reachability: 'REACHABLE_CALL_PATH',
      },
      {
        ruleId: 'VULN-002',
        severity: 'HIGH',
        category: 'SCA',
        reachability: 'UNREACHABLE',
      },
    ],
    sbom: {
      totalComponents: nComponents,
      compliantCount: nComponents,
      nonCompliantCount: 0,
      components,
    },
  };
}

export function makeRepoSummary(
  repoName: string,
  riskScore: number = 90,
  riskGrade: 'A' | 'B' | 'C' | 'D' | 'F' = 'A',
  canary?: string
): FleetRepoSummary {
  const effectiveName = canary ? `${repoName}_${canary}` : repoName;
  return {
    repoName: effectiveName,
    branch: 'main',
    commitSha: 'a1b2c3d4e5f678901234567890abcdef12345678',
    latestScanAt: '2026-11-04T00:00:00.000Z',
    riskGrade,
    riskScore,
    activeCriticals: 0,
    activeHighs: 0,
    reachableCount: 0,
    suppressedCount: 0,
    reachabilitySuppressionPct: 0,
    componentCount: 2,
    compliant: true,
    vulnerabilities: [],
    sbomComponents: [],
  };
}

export function computeSnapshotDigest(data: {
  formatVersion: number;
  repos: unknown[];
  policy: unknown;
}): string {
  const compact = JSON.stringify({
    formatVersion: data.formatVersion,
    repos: data.repos,
    policy: data.policy,
  });
  return crypto.createHash('sha256').update(compact, 'utf8').digest('hex');
}

export function legacyFile(state: { repos: unknown[]; policy?: unknown }): string {
  return JSON.stringify(
    {
      repos: state.repos,
      policy: state.policy ?? {
        policyVersion: '1.0',
        failOnSeverity: 'HIGH',
        blockUnreachableSca: false,
        deniedLicenses: ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'],
        requireHmacAudit: true,
        updatedAt: '2026-11-04T00:00:00.000Z',
      },
    },
    null,
    2
  );
}

export function v1File(state: {
  repos: unknown[];
  policy?: unknown;
  formatVersion?: number;
  updatedAt?: string;
  customDigest?: string;
  omitIntegrity?: boolean;
}): string {
  const formatVersion = state.formatVersion ?? 1;
  const policy = state.policy ?? {
    policyVersion: '1.0',
    failOnSeverity: 'HIGH',
    blockUnreachableSca: false,
    deniedLicenses: ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'],
    requireHmacAudit: true,
    updatedAt: '2026-11-04T00:00:00.000Z',
  };

  const digest =
    state.customDigest ??
    computeSnapshotDigest({
      formatVersion,
      repos: state.repos,
      policy,
    });

  const snapshot: Record<string, unknown> = {
    formatVersion,
    repos: state.repos,
    policy,
    updatedAt: state.updatedAt ?? '2026-11-04T00:00:00.000Z',
  };

  if (!state.omitIntegrity) {
    snapshot.integrity = {
      algorithm: 'sha256',
      digest,
    };
  }

  return JSON.stringify(snapshot, null, 2);
}

export function truncate(bytes: Buffer | string, n: number): Buffer {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8');
  return buf.subarray(0, n);
}

export function withBom(bytes: Buffer | string): Buffer {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, 'utf8');
  return Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), buf]);
}

export interface LogEntry {
  level: 'warn' | 'error' | 'debug';
  code: string;
  text: string;
  meta?: Record<string, unknown>;
}

export class LoggerSpy implements FleetStoreLogger {
  public entries: LogEntry[] = [];

  public warn(code: string, message: string, meta?: Record<string, unknown>): void {
    this.entries.push({ level: 'warn', code, text: message, meta });
  }

  public error(code: string, message: string, meta?: Record<string, unknown>): void {
    this.entries.push({ level: 'error', code, text: message, meta });
  }

  public debug(code: string, message: string, meta?: Record<string, unknown>): void {
    this.entries.push({ level: 'debug', code, text: message, meta });
  }

  public hasCode(code: string): boolean {
    return this.entries.some((e) => e.code === code);
  }

  public countCode(code: string): number {
    return this.entries.filter((e) => e.code === code).length;
  }

  public codes(): string[] {
    return this.entries.map((e) => e.code);
  }

  public texts(): string[] {
    return this.entries.map((e) => e.text);
  }

  public clear(): void {
    this.entries = [];
  }
}
