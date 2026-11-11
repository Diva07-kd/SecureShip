import crypto from 'node:crypto';
import type { FleetRepoSummary, FleetPolicy, Severity } from '@secureship/contracts';

export const FLEET_STORE_FORMAT_VERSION = 1;

export const VALID_SEVERITIES: readonly Severity[] = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
] as const;

export const KNOWN_POLICY_FIELDS: readonly (keyof FleetPolicy)[] = [
  'policyVersion',
  'failOnSeverity',
  'blockUnreachableSca',
  'deniedLicenses',
  'requireHmacAudit',
  'updatedAt',
] as const;

/**
 * Base error class for all FleetStore storage and persistence errors.
 */
export class FleetStoreError extends Error {
  public readonly code: string;

  constructor(message: string, code: string = 'FLEET_STORE_ERROR') {
    super(message);
    this.name = 'FleetStoreError';
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when storage corruption is detected and strictLoad is enabled.
 */
export class FleetStoreCorruptionError extends FleetStoreError {
  public readonly files: Array<{ path: string; code: string }>;

  constructor(message: string, files: Array<{ path: string; code: string }>) {
    super(message, 'FLEET_STORE_CORRUPTION_ERROR');
    this.name = 'FleetStoreCorruptionError';
    this.files = files;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when attempting to load a database file with a formatVersion higher than supported.
 */
export class FleetStoreUnsupportedVersionError extends FleetStoreError {
  public readonly version: number;

  constructor(message: string, version: number) {
    super(message, 'FLEET_STORE_UNSUPPORTED_VERSION');
    this.name = 'FleetStoreUnsupportedVersionError';
    this.version = version;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when persisting state to disk fails and strictPersistence is enabled.
 */
export class FleetStorePersistError extends FleetStoreError {
  public override readonly cause?: unknown;

  constructor(message: string, code = 'FLEET_STORE_PERSIST_FAILED', cause?: unknown) {
    super(message, code);
    this.name = 'FleetStorePersistError';
    this.cause = cause;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when an updatePolicy payload contains invalid fields or types.
 */
export class FleetStoreValidationError extends FleetStoreError {
  public readonly details: string[];

  constructor(message: string, details: string[]) {
    super(message, 'VALIDATION_FAILED');
    this.name = 'FleetStoreValidationError';
    this.details = details;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface FleetSnapshotIntegrity {
  algorithm: 'sha256';
  digest: string;
}

export interface FleetSnapshotV1 {
  formatVersion: 1;
  repos: FleetRepoSummary[];
  policy: FleetPolicy;
  updatedAt: string;
  integrity?: FleetSnapshotIntegrity;
}

/**
 * Safely sanitizes an object by removing prototype-polluting properties.
 */
export function sanitizePlainObject<T extends object>(input: T): T {
  const clean = Object.create(null);
  for (const key of Object.getOwnPropertyNames(input)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    clean[key] = (input as Record<string, unknown>)[key];
  }
  return Object.assign({}, clean);
}

/**
 * Computes the SHA-256 integrity digest of the snapshot state.
 * Digest is the SHA-256 hex string of compact JSON.stringify({ formatVersion, repos, policy }).
 */
export function computeDigest(data: {
  formatVersion: number;
  repos: FleetRepoSummary[];
  policy: FleetPolicy;
}): string {
  const compactJson = JSON.stringify({
    formatVersion: data.formatVersion,
    repos: data.repos,
    policy: data.policy,
  });
  return crypto.createHash('sha256').update(compactJson, 'utf8').digest('hex');
}

/**
 * Serializes the current fleet store state into a format v1 Buffer with integrity digest.
 */
export function serializeSnapshot(state: {
  repos: FleetRepoSummary[];
  policy: FleetPolicy;
  updatedAt?: string;
}): { buffer: Buffer; digest: string } {
  const formatVersion = FLEET_STORE_FORMAT_VERSION;
  const updatedAt = state.updatedAt ?? new Date().toISOString();
  const digest = computeDigest({
    formatVersion,
    repos: state.repos,
    policy: state.policy,
  });

  const snapshot: FleetSnapshotV1 = {
    formatVersion,
    repos: state.repos,
    policy: state.policy,
    updatedAt,
    integrity: {
      algorithm: 'sha256',
      digest,
    },
  };

  const text = JSON.stringify(snapshot, null, 2);
  const buffer = Buffer.from(text, 'utf8');
  return { buffer, digest };
}

export type SnapshotValidationResult =
  | { ok: true; snapshot: FleetSnapshotV1; isLegacy: boolean }
  | { ok: false; code: string; detail: string };

/**
 * Structurally validates candidate snapshot data.
 */
export function validateSnapshot(value: unknown): SnapshotValidationResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, code: 'INVALID_ROOT', detail: 'Root must be a plain object' };
  }

  const raw = sanitizePlainObject(value as Record<string, unknown>);
  let isLegacy = false;
  let formatVersion = 1;

  if (raw.formatVersion !== undefined) {
    if (
      typeof raw.formatVersion !== 'number' ||
      !Number.isInteger(raw.formatVersion) ||
      raw.formatVersion < 1
    ) {
      return {
        ok: false,
        code: 'INVALID_FORMAT_VERSION',
        detail: 'formatVersion must be a positive integer',
      };
    }
    if (raw.formatVersion > FLEET_STORE_FORMAT_VERSION) {
      return {
        ok: false,
        code: 'UNSUPPORTED_VERSION',
        detail: `Format version ${raw.formatVersion} exceeds supported version ${FLEET_STORE_FORMAT_VERSION}`,
      };
    }
    formatVersion = 1;
  } else {
    isLegacy = true;
  }

  // repos validation
  if (!Array.isArray(raw.repos)) {
    return { ok: false, code: 'INVALID_REPOS', detail: 'repos must be an array' };
  }

  const seenRepoNames = new Set<string>();
  const validatedRepos: FleetRepoSummary[] = [];

  for (let i = 0; i < raw.repos.length; i++) {
    const item = raw.repos[i];
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      return {
        ok: false,
        code: 'INVALID_REPO_ENTRY',
        detail: `repos[${i}] must be a plain object`,
      };
    }

    const r = sanitizePlainObject(item as Record<string, unknown>);
    if (typeof r.repoName !== 'string' || r.repoName.trim().length === 0) {
      return {
        ok: false,
        code: 'INVALID_REPO_NAME',
        detail: `repos[${i}].repoName must be a non-empty string`,
      };
    }

    if (seenRepoNames.has(r.repoName)) {
      return {
        ok: false,
        code: 'DUPLICATE_REPO_NAME',
        detail: `Duplicate repoName "${r.repoName}" at index ${i}`,
      };
    }
    seenRepoNames.add(r.repoName);

    const numericFields = [
      'riskScore',
      'activeCriticals',
      'activeHighs',
      'reachableCount',
      'suppressedCount',
    ] as const;

    for (const field of numericFields) {
      const val = r[field];
      if (typeof val !== 'number' || !Number.isFinite(val)) {
        return {
          ok: false,
          code: 'INVALID_REPO_METRIC',
          detail: `repos[${i}].${field} must be a finite number`,
        };
      }
    }

    if (typeof r.latestScanAt !== 'string') {
      return {
        ok: false,
        code: 'INVALID_REPO_TIMESTAMP',
        detail: `repos[${i}].latestScanAt must be a string`,
      };
    }

    if (typeof r.compliant !== 'boolean') {
      return {
        ok: false,
        code: 'INVALID_REPO_COMPLIANCE',
        detail: `repos[${i}].compliant must be a boolean`,
      };
    }

    if (!Array.isArray(r.vulnerabilities)) {
      return {
        ok: false,
        code: 'INVALID_REPO_VULNERABILITIES',
        detail: `repos[${i}].vulnerabilities must be an array`,
      };
    }

    if (!Array.isArray(r.sbomComponents)) {
      return {
        ok: false,
        code: 'INVALID_REPO_COMPONENTS',
        detail: `repos[${i}].sbomComponents must be an array`,
      };
    }

    validatedRepos.push(r as unknown as FleetRepoSummary);
  }

  // policy validation (known fields type checked, unknown fields dropped, merged over defaults by consumer)
  let validatedPolicy: FleetPolicy | undefined;
  if (raw.policy !== undefined) {
    if (!raw.policy || typeof raw.policy !== 'object' || Array.isArray(raw.policy)) {
      return { ok: false, code: 'INVALID_POLICY', detail: 'policy must be a plain object' };
    }
    const p = sanitizePlainObject(raw.policy as Record<string, unknown>);

    if (p.policyVersion !== undefined && typeof p.policyVersion !== 'string') {
      return {
        ok: false,
        code: 'INVALID_POLICY_FIELD',
        detail: 'policy.policyVersion must be a string',
      };
    }
    if (
      p.failOnSeverity !== undefined &&
      (typeof p.failOnSeverity !== 'string' ||
        !VALID_SEVERITIES.includes(p.failOnSeverity as Severity))
    ) {
      return {
        ok: false,
        code: 'INVALID_POLICY_FIELD',
        detail: 'policy.failOnSeverity must be a valid Severity',
      };
    }
    if (p.blockUnreachableSca !== undefined && typeof p.blockUnreachableSca !== 'boolean') {
      return {
        ok: false,
        code: 'INVALID_POLICY_FIELD',
        detail: 'policy.blockUnreachableSca must be a boolean',
      };
    }
    if (
      p.deniedLicenses !== undefined &&
      (!Array.isArray(p.deniedLicenses) || !p.deniedLicenses.every((x) => typeof x === 'string'))
    ) {
      return {
        ok: false,
        code: 'INVALID_POLICY_FIELD',
        detail: 'policy.deniedLicenses must be an array of strings',
      };
    }
    if (p.requireHmacAudit !== undefined && typeof p.requireHmacAudit !== 'boolean') {
      return {
        ok: false,
        code: 'INVALID_POLICY_FIELD',
        detail: 'policy.requireHmacAudit must be a boolean',
      };
    }
    if (p.updatedAt !== undefined && typeof p.updatedAt !== 'string') {
      return {
        ok: false,
        code: 'INVALID_POLICY_FIELD',
        detail: 'policy.updatedAt must be a string',
      };
    }

    const knownPolicy: Partial<FleetPolicy> = {};
    if (typeof p.policyVersion === 'string') knownPolicy.policyVersion = p.policyVersion;
    if (
      typeof p.failOnSeverity === 'string' &&
      VALID_SEVERITIES.includes(p.failOnSeverity as Severity)
    ) {
      knownPolicy.failOnSeverity = p.failOnSeverity as Severity;
    }
    if (typeof p.blockUnreachableSca === 'boolean')
      knownPolicy.blockUnreachableSca = p.blockUnreachableSca;
    if (Array.isArray(p.deniedLicenses) && p.deniedLicenses.every((x) => typeof x === 'string')) {
      knownPolicy.deniedLicenses = [...p.deniedLicenses];
    }
    if (typeof p.requireHmacAudit === 'boolean') knownPolicy.requireHmacAudit = p.requireHmacAudit;
    if (typeof p.updatedAt === 'string') knownPolicy.updatedAt = p.updatedAt;

    validatedPolicy = knownPolicy as FleetPolicy;
  } else {
    isLegacy = true;
  }

  // integrity check if present
  let integrity: FleetSnapshotIntegrity | undefined;
  if (raw.integrity !== undefined) {
    if (!raw.integrity || typeof raw.integrity !== 'object' || Array.isArray(raw.integrity)) {
      return { ok: false, code: 'INVALID_INTEGRITY', detail: 'integrity must be a plain object' };
    }
    const integ = sanitizePlainObject(raw.integrity as Record<string, unknown>);
    if (integ.algorithm !== 'sha256' || typeof integ.digest !== 'string') {
      return {
        ok: false,
        code: 'INVALID_INTEGRITY',
        detail: 'integrity must have algorithm "sha256" and string digest',
      };
    }

    if (validatedPolicy) {
      const computed = computeDigest({
        formatVersion,
        repos: validatedRepos,
        policy: validatedPolicy,
      });
      if (computed !== integ.digest) {
        return { ok: false, code: 'INTEGRITY_MISMATCH', detail: 'Cryptographic digest mismatch' };
      }
    }
    integrity = { algorithm: 'sha256', digest: integ.digest };
  } else {
    isLegacy = true;
  }

  const updatedAt = typeof raw.updatedAt === 'string' ? raw.updatedAt : new Date().toISOString();

  return {
    ok: true,
    snapshot: {
      formatVersion: 1,
      repos: validatedRepos,
      policy: validatedPolicy ?? ({} as FleetPolicy),
      updatedAt,
      integrity,
    },
    isLegacy,
  };
}

/**
 * Parses raw bytes into a validated snapshot, stripping leading UTF-8 BOM if present.
 * Throws FleetStoreUnsupportedVersionError if formatVersion > 1.
 */
export function parseSnapshotBytes(buffer: Buffer): SnapshotValidationResult {
  let text: string;
  if (buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) {
    text = buffer.subarray(3).toString('utf8');
  } else {
    text = buffer.toString('utf8');
  }

  if (text.charCodeAt(0) === 0xfeff) {
    text = text.slice(1);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err: unknown) {
    return {
      ok: false,
      code: 'JSON_SYNTAX_ERROR',
      detail: err instanceof Error ? err.message : String(err),
    };
  }

  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    const rawObj = parsed as Record<string, unknown>;
    const v = rawObj.formatVersion;
    if (typeof v === 'number' && Number.isFinite(v) && v > FLEET_STORE_FORMAT_VERSION) {
      throw new FleetStoreUnsupportedVersionError(
        `Database formatVersion ${v} is newer than supported version ${FLEET_STORE_FORMAT_VERSION}`,
        v
      );
    }
  }

  return validateSnapshot(parsed);
}

/**
 * Sanitizes and validates an updatePolicy payload.
 * Keeps only known FleetPolicy fields, drops unknown/proto fields, type-checks all values,
 * and throws FleetStoreValidationError with expected types (never values) on invalid input.
 */
export function sanitizeAndValidatePolicyUpdates(
  currentPolicy: FleetPolicy,
  updates: unknown,
  now?: () => number
): FleetPolicy {
  if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
    throw new FleetStoreValidationError('Invalid policy payload: must be a plain object', [
      'payload: expected plain object',
    ]);
  }

  const raw = sanitizePlainObject(updates as Record<string, unknown>);
  const errors: string[] = [];
  const sanitized: Partial<FleetPolicy> = {};

  if ('policyVersion' in raw) {
    if (typeof raw.policyVersion === 'string') {
      sanitized.policyVersion = raw.policyVersion;
    } else {
      errors.push('policyVersion: expected string');
    }
  }

  if ('failOnSeverity' in raw) {
    if (
      typeof raw.failOnSeverity === 'string' &&
      VALID_SEVERITIES.includes(raw.failOnSeverity as Severity)
    ) {
      sanitized.failOnSeverity = raw.failOnSeverity as Severity;
    } else {
      errors.push('failOnSeverity: expected "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"');
    }
  }

  if ('blockUnreachableSca' in raw) {
    if (typeof raw.blockUnreachableSca === 'boolean') {
      sanitized.blockUnreachableSca = raw.blockUnreachableSca;
    } else {
      errors.push('blockUnreachableSca: expected boolean');
    }
  }

  if ('deniedLicenses' in raw) {
    if (
      Array.isArray(raw.deniedLicenses) &&
      raw.deniedLicenses.every((x) => typeof x === 'string')
    ) {
      sanitized.deniedLicenses = [...raw.deniedLicenses];
    } else {
      errors.push('deniedLicenses: expected array of strings');
    }
  }

  if ('requireHmacAudit' in raw) {
    if (typeof raw.requireHmacAudit === 'boolean') {
      sanitized.requireHmacAudit = raw.requireHmacAudit;
    } else {
      errors.push('requireHmacAudit: expected boolean');
    }
  }

  if ('updatedAt' in raw) {
    if (typeof raw.updatedAt === 'string') {
      sanitized.updatedAt = raw.updatedAt;
    } else {
      errors.push('updatedAt: expected string');
    }
  }

  if (errors.length > 0) {
    throw new FleetStoreValidationError('Invalid policy payload', errors);
  }

  const defaultUpdatedAt = new Date(now ? now() : Date.now()).toISOString();

  return {
    ...currentPolicy,
    ...sanitized,
    updatedAt: sanitized.updatedAt ?? defaultUpdatedAt,
  };
}
