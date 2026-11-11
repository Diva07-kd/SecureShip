import { describe, it, expect } from 'vitest';
import type { LicenseJwtPayload } from '@secureship/contracts';
import {
  verifyLicenseJwt,
  buildTierCapabilitiesFromPayload,
} from '../../src/license/license-validator.js';
import {
  signLicenseJwt,
  generateLicenseKeyPair,
  base64UrlEncode,
} from '../../src/license/license-keys.js';

describe('License Cryptographic Validator (Phase 5 Offline Engine)', () => {
  // Generate an authentic test keypair
  const { publicKeyPem, privateKeyPem } = generateLicenseKeyPair();
  // Generate an untrusted attacker keypair
  const untrustedKeys = generateLicenseKeyPair();

  const nowEpoch = 1735689600; // Fixed timestamp: 2025-01-01T00:00:00Z

  const validPayload: LicenseJwtPayload = {
    sub: 'lead-dev@organization.com',
    tier: 'PRO_TEAM',
    seats: 20,
    orgId: 'org-enterprise',
    iat: nowEpoch - 3600, // 1 hour ago
    exp: nowEpoch + 30 * 86400, // 30 days in future
    maxMonthlyAiFixes: 100,
    allowCallPathReachability: true,
    allowCiCdGatekeeper: true,
    allowSignedComplianceExport: true,
    allowAirGappedOnPrem: false,
    featureFlags: {},
  };

  it('validates a genuine token signed with the matching private key', () => {
    const validJwt = signLicenseJwt(validPayload, privateKeyPem);
    const result = verifyLicenseJwt(validJwt, publicKeyPem, nowEpoch);

    expect(result.valid).toBe(true);
    expect(result.isExpired).toBe(false);
    expect(result.payload?.sub).toBe('lead-dev@organization.com');
    expect(result.payload?.tier).toBe('PRO_TEAM');
    expect(result.daysRemaining).toBe(30);
    expect(result.isNearExpiry).toBe(false);
  });

  it('rejects a token signed by an untrusted foreign RSA key', () => {
    // Attacker signs payload with their own private key
    const forgedJwt = signLicenseJwt(validPayload, untrustedKeys.privateKeyPem);
    // SecureShip verifies using authentic public key
    const result = verifyLicenseJwt(forgedJwt, publicKeyPem, nowEpoch);

    expect(result.valid).toBe(false);
    expect(result.error).toContain('Cryptographic signature mismatch');
  });

  it('detects and rejects tampered payload bytes (Anti-Tampering Gate)', () => {
    const genuineJwt = signLicenseJwt(validPayload, privateKeyPem);
    const [header, _payload, sig] = genuineJwt.split('.');

    // Attacker modifies tier from PRO_TEAM to ENTERPRISE in the payload
    const tamperedPayloadObj = {
      ...validPayload,
      tier: 'ENTERPRISE',
      maxMonthlyAiFixes: null,
    };
    const tamperedPayloadB64 = base64UrlEncode(JSON.stringify(tamperedPayloadObj));
    const tamperedJwt = `${header}.${tamperedPayloadB64}.${sig}`;

    const result = verifyLicenseJwt(tamperedJwt, publicKeyPem, nowEpoch);
    expect(result.valid).toBe(false);
    expect(result.error).toContain('Cryptographic signature mismatch');
  });

  it('detects an expired token and returns isExpired: true', () => {
    const expiredPayload: LicenseJwtPayload = {
      ...validPayload,
      iat: nowEpoch - 40 * 86400,
      exp: nowEpoch - 10 * 86400, // Expired 10 days ago
    };
    const expiredJwt = signLicenseJwt(expiredPayload, privateKeyPem);
    const result = verifyLicenseJwt(expiredJwt, publicKeyPem, nowEpoch);

    expect(result.valid).toBe(false);
    expect(result.isExpired).toBe(true);
    expect(result.error).toContain('License expired');
    expect(result.payload?.tier).toBe('PRO_TEAM');
  });

  it('flags tokens near expiration (<= 7 days) as isNearExpiry: true', () => {
    const nearExpiryPayload: LicenseJwtPayload = {
      ...validPayload,
      iat: nowEpoch - 25 * 86400,
      exp: nowEpoch + 3 * 86400, // 3 days remaining
    };
    const nearExpiryJwt = signLicenseJwt(nearExpiryPayload, privateKeyPem);
    const result = verifyLicenseJwt(nearExpiryJwt, publicKeyPem, nowEpoch);

    expect(result.valid).toBe(true);
    expect(result.isExpired).toBe(false);
    expect(result.daysRemaining).toBe(3);
    expect(result.isNearExpiry).toBe(true);
  });

  it('rejects tokens issued in the future beyond clock skew tolerance', () => {
    const futurePayload: LicenseJwtPayload = {
      ...validPayload,
      iat: nowEpoch + 3600, // 1 hour in future
      exp: nowEpoch + 30 * 86400,
    };
    const futureJwt = signLicenseJwt(futurePayload, privateKeyPem);
    const result = verifyLicenseJwt(futureJwt, publicKeyPem, nowEpoch);

    expect(result.valid).toBe(false);
    expect(result.error).toContain('Token issued in the future');
  });

  it('rejects malformed token formats with insufficient or extra segments', () => {
    expect(verifyLicenseJwt('', publicKeyPem, nowEpoch).valid).toBe(false);
    expect(verifyLicenseJwt('only-one-segment', publicKeyPem, nowEpoch).valid).toBe(false);
    expect(verifyLicenseJwt('part1.part2', publicKeyPem, nowEpoch).valid).toBe(false);
    expect(verifyLicenseJwt('part1.part2.part3.part4', publicKeyPem, nowEpoch).valid).toBe(false);
  });

  it('builds full TierCapabilities preserving configured overrides', () => {
    const caps = buildTierCapabilitiesFromPayload(validPayload);
    expect(caps.tier).toBe('PRO_TEAM');
    expect(caps.maxMonthlyAiFixes).toBe(100);
    expect(caps.allowCiCdGatekeeper).toBe(true);
    expect(caps.allowCallPathReachability).toBe(true);
    expect(caps.allowSignedComplianceExport).toBe(true);
    expect(caps.allowAirGappedOnPrem).toBe(false);
  });
});
