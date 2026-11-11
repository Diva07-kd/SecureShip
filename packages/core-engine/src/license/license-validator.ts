import crypto from 'node:crypto';
import {
  LicenseJwtHeaderSchema,
  LicenseJwtPayloadSchema,
  type LicenseJwtPayload,
  type TierCapabilities,
  TIER_CAPABILITY_DEFAULTS,
} from '@secureship/contracts';
import { base64UrlDecode, SECURESHIP_PUBLIC_KEY_PEM } from './license-keys.js';

export interface LicenseValidationResult {
  valid: boolean;
  payload?: LicenseJwtPayload;
  error?: string;
  isExpired?: boolean;
  daysRemaining?: number;
  isNearExpiry?: boolean; // Expiring in <= 7 days
}

/**
 * Validates a compact JWT string against the SecureShip RSA-2048 public key.
 * Completely offline: no network requests or external dependencies required.
 */
export function verifyLicenseJwt(
  jwtString: string,
  publicKeyPem: string = process.env.SECURESHIP_PUBLIC_KEY ?? SECURESHIP_PUBLIC_KEY_PEM,
  nowEpochSeconds: number = Math.floor(Date.now() / 1000)
): LicenseValidationResult {
  if (!jwtString || typeof jwtString !== 'string') {
    return { valid: false, error: 'Empty or non-string license token' };
  }

  const parts = jwtString.trim().split('.');
  if (parts.length !== 3) {
    return {
      valid: false,
      error: 'Invalid JWT format: token must contain exactly 3 dot-separated segments',
    };
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  // 1. Decode & validate header
  let rawHeader: unknown;
  try {
    const headerJson = base64UrlDecode(encodedHeader!);
    rawHeader = JSON.parse(headerJson);
  } catch (err) {
    return {
      valid: false,
      error: `Malformed JWT header: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const headerParse = LicenseJwtHeaderSchema.safeParse(rawHeader);
  if (!headerParse.success) {
    const errorDetails = headerParse.error.errors
      .map((e: { message: string }) => e.message)
      .join(', ');
    return {
      valid: false,
      error: `Unsupported JWT header: ${errorDetails}`,
    };
  }

  // 2. Decode & validate payload
  let rawPayload: unknown;
  try {
    const payloadJson = base64UrlDecode(encodedPayload!);
    rawPayload = JSON.parse(payloadJson);
  } catch (err) {
    return {
      valid: false,
      error: `Malformed JWT payload: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const payloadParse = LicenseJwtPayloadSchema.safeParse(rawPayload);
  if (!payloadParse.success) {
    const errorDetails = payloadParse.error.errors
      .map(
        (e: { path: (string | number)[]; message: string }) => `${e.path.join('.')}: ${e.message}`
      )
      .join(', ');
    return {
      valid: false,
      error: `Invalid license payload schema: ${errorDetails}`,
    };
  }

  const payload = payloadParse.data;

  // 3. Cryptographically verify signature
  const messageToVerify = `${encodedHeader}.${encodedPayload}`;
  let signatureBuffer: Buffer;
  try {
    let base64 = encodedSignature!.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) base64 += '=';
    signatureBuffer = Buffer.from(base64, 'base64');
  } catch {
    return { valid: false, error: 'Failed to decode JWT signature buffer' };
  }

  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(messageToVerify);
    verifier.end();

    const isSignatureValid = verifier.verify(publicKeyPem, signatureBuffer);
    if (!isSignatureValid) {
      return {
        valid: false,
        error:
          'Cryptographic signature mismatch: license token has been altered or signed by an untrusted key',
      };
    }
  } catch (err) {
    return {
      valid: false,
      error: `Cryptographic verification error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  // 4. Temporal checks (clock skew tolerance: 60s)
  const CLOCK_SKEW_SECONDS = 60;

  if (payload.iat > nowEpochSeconds + CLOCK_SKEW_SECONDS) {
    return {
      valid: false,
      error: `Token issued in the future (iat: ${payload.iat}, current: ${nowEpochSeconds})`,
    };
  }

  if (payload.exp < nowEpochSeconds - CLOCK_SKEW_SECONDS) {
    const expiredSeconds = nowEpochSeconds - payload.exp;
    const expiredDays = Math.ceil(expiredSeconds / 86400);
    return {
      valid: false,
      isExpired: true,
      payload,
      error: `License expired ${expiredDays} day(s) ago (expired on ${new Date(payload.exp * 1000).toISOString()})`,
    };
  }

  // Calculate days remaining
  const secondsRemaining = payload.exp - nowEpochSeconds;
  const daysRemaining = Math.max(0, Math.floor(secondsRemaining / 86400));
  const isNearExpiry = daysRemaining <= 7;

  return {
    valid: true,
    payload,
    isExpired: false,
    daysRemaining,
    isNearExpiry,
  };
}

/**
 * Builds runtime TierCapabilities from a validated JWT payload,
 * falling back to defined tier defaults for unmodeled fields.
 */
export function buildTierCapabilitiesFromPayload(payload: LicenseJwtPayload): TierCapabilities {
  const defaults = TIER_CAPABILITY_DEFAULTS[payload.tier];

  return {
    tier: payload.tier,
    maxMonthlyAiFixes: payload.maxMonthlyAiFixes,
    allowCrossFileAstGraph: defaults.allowCrossFileAstGraph,
    allowShadowWorktreeSandbox: defaults.allowShadowWorktreeSandbox,
    allowCiCdGatekeeper: payload.allowCiCdGatekeeper,
    allowSignedComplianceExport: payload.allowSignedComplianceExport,
    allowAirGappedOnPrem: payload.allowAirGappedOnPrem,
    allowCustomModelRouting: defaults.allowCustomModelRouting,
    allowImportReachability: defaults.allowImportReachability,
    allowCallPathReachability: payload.allowCallPathReachability,
  };
}
