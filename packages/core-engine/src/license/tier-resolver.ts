import path from 'node:path';
import {
  type LicenseTier,
  type TierCapabilities,
  type LicenseStatusReport,
  type LicenseJwtPayload,
  TIER_CAPABILITY_DEFAULTS,
} from '@secureship/contracts';
import { getDefaultLicensePath, readLicenseFile, writeLicenseFile } from './license-storage.js';
import { verifyLicenseJwt, buildTierCapabilitiesFromPayload } from './license-validator.js';
import { SECURESHIP_PUBLIC_KEY_PEM } from './license-keys.js';
import { getDefaultAiUsagePath, getMonthlyAiUsage } from './ai-usage-ledger.js';

export interface ResolvedTierState {
  tier: LicenseTier;
  capabilities: TierCapabilities;
  status: 'ACTIVE' | 'EXPIRED' | 'UNLICENSED_FREE' | 'INVALID_SIGNATURE';
  payload?: LicenseJwtPayload;
  error?: string;
  daysRemaining?: number;
  isNearExpiry?: boolean;
  licensePath: string;
  source: 'jwt' | 'default';
}

/**
 * Resolves the active SecureShip license tier and operational capabilities.
 * 1. Checks if a local JWT exists in ~/.secureship/license.jwt (or SECURESHIP_LICENSE_PATH).
 * 2. Cryptographically verifies its RSA signature and timestamps offline.
 * 3. Falls back cleanly to FREE_BYOK tier if no valid license exists.
 */
export async function resolveTierCapabilities(
  options: {
    licensePath?: string;
    publicKeyPem?: string;
    autoRefresh?: boolean;
    licenseServerUrl?: string;
  } = {}
): Promise<ResolvedTierState> {
  const licensePath = options.licensePath ?? getDefaultLicensePath();
  const publicKeyPem =
    options.publicKeyPem ?? process.env.SECURESHIP_PUBLIC_KEY ?? SECURESHIP_PUBLIC_KEY_PEM;

  const rawToken = readLicenseFile(licensePath);

  // No license token found -> Unlicensed free tier
  if (!rawToken) {
    return {
      tier: 'FREE_BYOK',
      capabilities: TIER_CAPABILITY_DEFAULTS['FREE_BYOK'],
      status: 'UNLICENSED_FREE',
      licensePath,
      source: 'default',
    };
  }

  // Validate the JWT offline
  const result = verifyLicenseJwt(rawToken, publicKeyPem);

  // Expired token
  if (result.isExpired) {
    return {
      tier: 'FREE_BYOK', // Downgraded to free upon expiry
      capabilities: TIER_CAPABILITY_DEFAULTS['FREE_BYOK'],
      status: 'EXPIRED',
      payload: result.payload,
      error: result.error,
      daysRemaining: 0,
      licensePath,
      source: 'default',
    };
  }

  // Cryptographic signature error or schema mismatch
  if (!result.valid || !result.payload) {
    return {
      tier: 'FREE_BYOK',
      capabilities: TIER_CAPABILITY_DEFAULTS['FREE_BYOK'],
      status: 'INVALID_SIGNATURE',
      error: result.error,
      licensePath,
      source: 'default',
    };
  }

  // Near-expiry warning (TASK 5)
  const daysRemaining = Math.ceil((result.payload.exp * 1000 - Date.now()) / (24 * 60 * 60 * 1000));
  if (daysRemaining <= 7 && daysRemaining > 0) {
    // Use process.stderr to not pollute JSON output
    process.stderr.write(
      `[SecureShip] WARNING: Your ${result.payload.tier} license expires in ${daysRemaining} day(s). ` +
        `Run 'secureship license activate <new-key>' to renew.\n`
    );
  }

  // Background refresh if within 7 days of expiry (TASK 1)
  if (options.autoRefresh !== false && isNearExpiry(result.payload.exp)) {
    void refreshLicenseInBackground(licensePath, rawToken, options.licenseServerUrl, {
      publicKeyPem,
    });
  }

  return {
    tier: result.payload.tier,
    capabilities: buildTierCapabilitiesFromPayload(result.payload),
    status: 'ACTIVE',
    payload: result.payload,
    daysRemaining: result.daysRemaining,
    isNearExpiry: result.isNearExpiry,
    licensePath,
    source: 'jwt',
  };
}

/**
 * Builds a full license status report conforming to LicenseStatusReportSchema.
 */
export async function getLicenseStatusReport(
  options: {
    licensePath?: string;
    ledgerPath?: string;
    publicKeyPem?: string;
  } = {}
): Promise<LicenseStatusReport> {
  const tierState = await resolveTierCapabilities({
    licensePath: options.licensePath,
    publicKeyPem: options.publicKeyPem,
    autoRefresh: false,
  });

  const ledgerPath = options.ledgerPath ?? getDefaultAiUsagePath();
  const usage = getMonthlyAiUsage(ledgerPath);

  return {
    status: tierState.status,
    tier: tierState.tier,
    email: tierState.payload?.sub,
    orgId: tierState.payload?.orgId,
    seats: tierState.payload?.seats,
    issuedAt: tierState.payload?.iat
      ? new Date(tierState.payload.iat * 1000).toISOString()
      : undefined,
    expiresAt: tierState.payload?.exp
      ? new Date(tierState.payload.exp * 1000).toISOString()
      : undefined,
    daysRemaining: tierState.daysRemaining,
    monthlyAiUsage: {
      month: usage.month,
      fixesUsed: usage.fixesUsed,
      limit: tierState.capabilities.maxMonthlyAiFixes,
    },
    capabilities: {
      allowCallPathReachability: tierState.capabilities.allowCallPathReachability,
      allowCiCdGatekeeper: tierState.capabilities.allowCiCdGatekeeper,
      allowSignedComplianceExport: tierState.capabilities.allowSignedComplianceExport,
      allowAirGappedOnPrem: tierState.capabilities.allowAirGappedOnPrem,
    },
    licensePath: tierState.licensePath,
  };
}

export const REFRESH_THRESHOLD_DAYS = 7;

export function isNearExpiry(expTimestampSeconds: number, now: Date = new Date()): boolean {
  const msRemaining = expTimestampSeconds * 1000 - now.getTime();
  return msRemaining > 0 && msRemaining < REFRESH_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;
}

const inFlightRefreshes = new Map<string, Promise<void>>();
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;

/**
 * Background non-blocking license refresh call to license server.
 *
 * Protocol contract:
 * - Sends HTTP GET to `${serverUrl}/v1/validate` with header `Authorization: Bearer <currentJwt>`.
 * - Expects HTTP 200 with JSON response: `{ valid: true, refreshedJwt?: string }`.
 *
 * Security and verification invariants:
 * 1. Shape pre-validation: rejects tokens without exactly 3 non-empty base64url segments (protecting against legacy callers passing email/sub).
 * 2. Public key resolution: uses options.publicKeyPem, process.env.SECURESHIP_PUBLIC_KEY, or SECURESHIP_PUBLIC_KEY_PEM.
 * 3. Offline pre-verification: the current token is cryptographically verified offline; invalid or expired tokens are never transmitted.
 * 4. URL protocol enforcement: https is required; http is strictly limited to loopback addresses (localhost, 127.0.0.1, [::1], ::1).
 * 5. In-flight de-duplication: concurrent calls for the same resolved licensePath share a single request.
 * 6. Request hardening: sends GET with Bearer header, sets redirect: 'error', and enforces a timeout via AbortController (default 5000ms).
 * 7. Defensive response parsing: requires HTTP 200, checks JSON object structure, bounds refreshedJwt length (<= 16384), and validates base64url segments. Legacy 'jwt' key is rejected.
 * 8. Cryptographic verification of refreshed token: verifies RS256 signature and timestamps; enforces matching sub, matching orgId, and strictly greater exp (anti-rollback). A tier change is ALLOWED because the license server rebuilds capabilities from the authoritative database.
 * 9. Compare-and-swap (CAS): re-reads the local license file immediately before writing; aborts if the file on disk was modified during the request.
 * 10. Persistence: writes the verified refreshed token to disk.
 *
 * Fire-and-forget guarantee:
 * Never throws, never rejects, never blocks callers, never logs or prints tokens, keys, or response bodies. All errors are silently swallowed.
 */
export async function refreshLicenseInBackground(
  licensePath: string,
  currentJwt: string,
  serverUrl: string = 'https://license.secureship.dev',
  options?: { publicKeyPem?: string; timeoutMs?: number; now?: number }
): Promise<void> {
  try {
    // 1. Validate currentJwt format: must be 3 non-empty base64url segments
    if (typeof currentJwt !== 'string' || typeof licensePath !== 'string' || !licensePath.trim()) {
      return;
    }
    const trimmedJwt = currentJwt.trim();
    const segments = trimmedJwt.split('.');
    if (
      segments.length !== 3 ||
      !segments[0] ||
      !segments[1] ||
      !segments[2] ||
      !BASE64URL_REGEX.test(segments[0]) ||
      !BASE64URL_REGEX.test(segments[1]) ||
      !BASE64URL_REGEX.test(segments[2])
    ) {
      return;
    }

    // 2. Resolve public key
    const pem =
      options?.publicKeyPem ?? process.env.SECURESHIP_PUBLIC_KEY ?? SECURESHIP_PUBLIC_KEY_PEM;

    // 3. Verify current token offline (never send unverified/expired token over network)
    const currentResult = verifyLicenseJwt(trimmedJwt, pem, options?.now);
    if (!currentResult.valid || !currentResult.payload || currentResult.isExpired) {
      return;
    }
    const current = currentResult.payload;

    // 4. Server URL safety
    if (typeof serverUrl !== 'string') {
      return;
    }
    const cleanServerUrl = serverUrl.trim();
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(cleanServerUrl);
    } catch {
      return;
    }
    const host = parsedUrl.hostname;
    const isLoopback =
      host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
    if (parsedUrl.protocol !== 'https:' && !(parsedUrl.protocol === 'http:' && isLoopback)) {
      return;
    }
    const base = cleanServerUrl.replace(/\/+$/, '');
    const endpointUrl = `${base}/v1/validate`;

    // 5. In-flight de-duplication keyed by path.resolve(licensePath)
    const resolvedPath = path.resolve(licensePath);
    const existing = inFlightRefreshes.get(resolvedPath);
    if (existing) {
      await existing;
      return;
    }

    const refreshPromise = (async () => {
      let timeoutId: NodeJS.Timeout | undefined;
      try {
        // 6. Request: GET with Authorization Bearer header, redirect: 'error', timeout
        const controller = new AbortController();
        const timeoutMs = options?.timeoutMs ?? 5000;
        timeoutId = setTimeout(() => controller.abort(), timeoutMs);

        const res = await fetch(endpointUrl, {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${trimmedJwt}`,
            Accept: 'application/json',
          },
          redirect: 'error',
          signal: controller.signal,
        });

        // 7. Defensive response parsing
        if (!res.ok) {
          return;
        }

        let rawBody: unknown;
        try {
          rawBody = await res.json();
        } catch {
          return;
        }

        if (!rawBody || typeof rawBody !== 'object' || Array.isArray(rawBody)) {
          return;
        }

        const bodyObj = rawBody as Record<string, unknown>;
        const rawRefreshed = bodyObj['refreshedJwt'];
        if (typeof rawRefreshed !== 'string') {
          return;
        }

        const refreshed = rawRefreshed.trim();
        if (refreshed.length === 0 || refreshed.length > 16384) {
          return;
        }

        const refreshedSegments = refreshed.split('.');
        if (
          refreshedSegments.length !== 3 ||
          !refreshedSegments[0] ||
          !refreshedSegments[1] ||
          !refreshedSegments[2] ||
          !BASE64URL_REGEX.test(refreshedSegments[0]) ||
          !BASE64URL_REGEX.test(refreshedSegments[1]) ||
          !BASE64URL_REGEX.test(refreshedSegments[2])
        ) {
          return;
        }

        // 8. Cryptographic verification of refreshed token & claims checks
        const refreshedResult = verifyLicenseJwt(refreshed, pem, options?.now);
        if (!refreshedResult.valid || !refreshedResult.payload || refreshedResult.isExpired) {
          return;
        }
        const refreshedPayload = refreshedResult.payload;

        // Enforce identity preservation and anti-rollback (tier change is allowed)
        if (
          refreshedPayload.sub !== current.sub ||
          refreshedPayload.orgId !== current.orgId ||
          refreshedPayload.exp <= current.exp
        ) {
          return;
        }

        // 9. Compare-and-swap against license file on disk
        const currentOnDisk = readLicenseFile(licensePath);
        if (currentOnDisk === null || currentOnDisk.trim() !== trimmedJwt) {
          return;
        }

        // 10. Write refreshed token to disk (swallowing any error)
        try {
          writeLicenseFile(refreshed, licensePath);
        } catch {
          // Best effort persistence
        }
      } catch {
        // Network, abort, or parsing failure is non-fatal
      } finally {
        if (timeoutId !== undefined) {
          clearTimeout(timeoutId);
        }
      }
    })();

    inFlightRefreshes.set(resolvedPath, refreshPromise);
    try {
      await refreshPromise;
    } finally {
      inFlightRefreshes.delete(resolvedPath);
    }
  } catch {
    // Fire-and-forget: never throw, never reject
  }
}

/**
 * Tier hierarchy levels for capability ordering:
 * FREE_BYOK (0) < PRO_TEAM (1) < ENTERPRISE (2)
 */
export const TIER_HIERARCHY: Record<LicenseTier, number> = {
  FREE_BYOK: 0,
  PRO_TEAM: 1,
  ENTERPRISE: 2,
};

/**
 * Checks whether currentTier meets or exceeds the requiredTier in the license hierarchy.
 * E.g., ENTERPRISE satisfies PRO_TEAM (true), but PRO_TEAM does not satisfy ENTERPRISE (false).
 */
export function meetsMinimumTier(currentTier: LicenseTier, requiredTier: LicenseTier): boolean {
  return TIER_HIERARCHY[currentTier] >= TIER_HIERARCHY[requiredTier];
}

/**
 * Validates a license token against a target tier requirement.
 * 1. Cryptographically verifies RS256 signature and expiry offline.
 * 2. Compares token tier against target required tier.
 * 3. Enforces strict tier isolation:
 *    - If an ENTERPRISE environment receives a PRO_TEAM token, it rejects with an explicit error explaining the tier shortfall.
 *    - If a PRO environment receives an ENTERPRISE token, it accepts and unlocks PRO features with ENTERPRISE superset.
 *    - If a PRO or ENTERPRISE environment receives a FREE_BYOK or invalid token, it rejects.
 */
export function validateLicenseForTier(
  token: string,
  requiredTier: LicenseTier,
  publicKeyPem: string = process.env.SECURESHIP_PUBLIC_KEY ?? SECURESHIP_PUBLIC_KEY_PEM,
  nowEpochSeconds: number = Math.floor(Date.now() / 1000)
): {
  valid: boolean;
  resolvedTier: LicenseTier;
  error?: string;
  payload?: LicenseJwtPayload;
  capabilities?: TierCapabilities;
} {
  const result = verifyLicenseJwt(token, publicKeyPem, nowEpochSeconds);
  if (!result.valid || !result.payload) {
    return {
      valid: false,
      resolvedTier: 'FREE_BYOK',
      error: result.error ?? 'Invalid cryptographic license signature',
    };
  }

  const tokenTier = result.payload.tier;
  if (!meetsMinimumTier(tokenTier, requiredTier)) {
    return {
      valid: false,
      resolvedTier: tokenTier,
      error: `License tier mismatch: Environment requires '${requiredTier}', but token provides '${tokenTier}'. Upgrade license to unlock this environment.`,
      payload: result.payload,
      capabilities: buildTierCapabilitiesFromPayload(result.payload),
    };
  }

  return {
    valid: true,
    resolvedTier: tokenTier,
    payload: result.payload,
    capabilities: buildTierCapabilitiesFromPayload(result.payload),
  };
}
