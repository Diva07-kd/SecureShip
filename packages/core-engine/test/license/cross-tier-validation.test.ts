import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type { LicenseJwtPayload } from '@secureship/contracts';
import {
  signLicenseJwt,
  generateLicenseKeyPair,
  base64UrlEncode,
} from '../../src/license/license-keys.js';
import { verifyLicenseJwt } from '../../src/license/license-validator.js';
import {
  writeLicenseFile,
  readLicenseFile,
  deleteLicenseFile,
} from '../../src/license/license-storage.js';
import {
  resolveTierCapabilities,
  meetsMinimumTier,
  validateLicenseForTier,
  getLicenseStatusReport,
} from '../../src/license/tier-resolver.js';
import {
  canPerformAiFix,
  recordAiFixExecution,
  getMonthlyAiUsage,
} from '../../src/license/ai-usage-ledger.js';

describe('Cross-Tier License Validation & Enforcement Suite (Stage 5 Anti-Cheat)', () => {
  let tempDir: string;
  let licenseFilePath: string;
  let usageFilePath: string;

  // Real RSA-2048 key pairs (genuine cryptography, zero mocks)
  const officialAuthority = generateLicenseKeyPair();
  const rogueAuthority = generateLicenseKeyPair();
  const nowEpoch = Math.floor(Date.now() / 1000);

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-crosstier-test-'));
    licenseFilePath = path.join(tempDir, 'license.jwt');
    usageFilePath = path.join(tempDir, 'ai-usage.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup
    }
  });

  it('generates valid RSA-2048 keys and creates cryptographically verifiable license tokens', () => {
    const payload: LicenseJwtPayload = {
      sub: 'operator@datacenter.local',
      tier: 'PRO_TEAM',
      seats: 5,
      orgId: 'datacenter-ops',
      iat: nowEpoch - 60,
      exp: nowEpoch + 30 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };

    const token = signLicenseJwt(payload, officialAuthority.privateKeyPem);
    expect(typeof token).toBe('string');
    expect(token.split('.')).toHaveLength(3);

    // Cryptographic validation against official public key
    const verification = verifyLicenseJwt(token, officialAuthority.publicKeyPem, nowEpoch);
    expect(verification.valid).toBe(true);
    expect(verification.isExpired).toBe(false);
    expect(verification.payload?.tier).toBe('PRO_TEAM');
    expect(verification.payload?.orgId).toBe('datacenter-ops');
    expect(verification.daysRemaining).toBe(30);
  });

  it('validates and enables PRO_TEAM tier with exact commercial capability limits', async () => {
    const proPayload: LicenseJwtPayload = {
      sub: 'dev@saas.com',
      tier: 'PRO_TEAM',
      seats: 10,
      orgId: 'saas-team',
      iat: nowEpoch - 100,
      exp: nowEpoch + 14 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };

    const proToken = signLicenseJwt(proPayload, officialAuthority.privateKeyPem);
    writeLicenseFile(proToken, licenseFilePath);

    // Verify file storage
    expect(readLicenseFile(licenseFilePath)).toBe(proToken);

    // Resolve tier state
    const state = await resolveTierCapabilities({
      licensePath: licenseFilePath,
      publicKeyPem: officialAuthority.publicKeyPem,
      autoRefresh: false,
    });

    expect(state.tier).toBe('PRO_TEAM');
    expect(state.status).toBe('ACTIVE');
    expect(state.capabilities.allowCiCdGatekeeper).toBe(true);
    expect(state.capabilities.allowSignedComplianceExport).toBe(true);
    expect(state.capabilities.allowCallPathReachability).toBe(true);
    expect(state.capabilities.allowAirGappedOnPrem).toBe(false);
    expect(state.capabilities.maxMonthlyAiFixes).toBe(100);

    // Usage check: should allow up to 100 fixes
    expect(canPerformAiFix(100, usageFilePath).allowed).toBe(true);
    for (let i = 0; i < 100; i++) {
      recordAiFixExecution(usageFilePath);
    }
    const currentUsage = getMonthlyAiUsage(usageFilePath);
    expect(currentUsage.fixesUsed).toBe(100);

    // 101st fix must be blocked by the quota guard
    expect(canPerformAiFix(100, usageFilePath).allowed).toBe(false);
  });

  it('validates and enables ENTERPRISE tier with unlimited AI quota and air-gapped SLA', async () => {
    const entPayload: LicenseJwtPayload = {
      sub: 'ciso@bank.corp',
      tier: 'ENTERPRISE',
      seats: 150,
      orgId: 'global-bank',
      iat: nowEpoch - 50,
      exp: nowEpoch + 365 * 86400,
      maxMonthlyAiFixes: null, // Unlimited
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: true,
      featureFlags: { customRules: true, prioritySupport: true },
    };

    const entToken = signLicenseJwt(entPayload, officialAuthority.privateKeyPem);
    writeLicenseFile(entToken, licenseFilePath);

    const state = await resolveTierCapabilities({
      licensePath: licenseFilePath,
      publicKeyPem: officialAuthority.publicKeyPem,
      autoRefresh: false,
    });

    expect(state.tier).toBe('ENTERPRISE');
    expect(state.status).toBe('ACTIVE');
    expect(state.capabilities.allowCiCdGatekeeper).toBe(true);
    expect(state.capabilities.allowSignedComplianceExport).toBe(true);
    expect(state.capabilities.allowCallPathReachability).toBe(true);
    expect(state.capabilities.allowAirGappedOnPrem).toBe(true);
    expect(state.capabilities.maxMonthlyAiFixes).toBeNull();

    // Enterprise tier allows unlimited AI fix runs without blocking
    for (let i = 0; i < 150; i++) {
      recordAiFixExecution(usageFilePath);
    }
    expect(canPerformAiFix(null, usageFilePath).allowed).toBe(true);
  });

  it('strict isolation: rejects PRO_TEAM license in an ENTERPRISE-required environment', () => {
    const proPayload: LicenseJwtPayload = {
      sub: 'developer@agency.io',
      tier: 'PRO_TEAM',
      seats: 5,
      orgId: 'agency-group',
      iat: nowEpoch - 30,
      exp: nowEpoch + 60 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };

    const proToken = signLicenseJwt(proPayload, officialAuthority.privateKeyPem);

    // 1. Pro token tested against PRO_TEAM requirement -> PASS
    const proCheck = validateLicenseForTier(proToken, 'PRO_TEAM', officialAuthority.publicKeyPem);
    expect(proCheck.valid).toBe(true);
    expect(proCheck.resolvedTier).toBe('PRO_TEAM');
    expect(proCheck.error).toBeUndefined();

    // 2. Pro token tested against ENTERPRISE requirement -> REJECTED!
    const enterpriseCheck = validateLicenseForTier(
      proToken,
      'ENTERPRISE',
      officialAuthority.publicKeyPem
    );
    expect(enterpriseCheck.valid).toBe(false);
    expect(enterpriseCheck.resolvedTier).toBe('PRO_TEAM');
    expect(enterpriseCheck.error).toContain(
      "License tier mismatch: Environment requires 'ENTERPRISE', but token provides 'PRO_TEAM'"
    );

    // Hierarchy sanity check
    expect(meetsMinimumTier('PRO_TEAM', 'ENTERPRISE')).toBe(false);
    expect(meetsMinimumTier('PRO_TEAM', 'PRO_TEAM')).toBe(true);
    expect(meetsMinimumTier('PRO_TEAM', 'FREE_BYOK')).toBe(true);
  });

  it('forward compatibility: accepts ENTERPRISE license in a PRO_TEAM environment (superset)', () => {
    const entPayload: LicenseJwtPayload = {
      sub: 'lead@enterprise.com',
      tier: 'ENTERPRISE',
      seats: 50,
      orgId: 'enterprise-holding',
      iat: nowEpoch - 60,
      exp: nowEpoch + 90 * 86400,
      maxMonthlyAiFixes: null,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: true,
      featureFlags: {},
    };

    const entToken = signLicenseJwt(entPayload, officialAuthority.privateKeyPem);

    // Enterprise token satisfies PRO_TEAM requirement because it is a higher tier
    const proCheck = validateLicenseForTier(entToken, 'PRO_TEAM', officialAuthority.publicKeyPem);
    expect(proCheck.valid).toBe(true);
    expect(proCheck.resolvedTier).toBe('ENTERPRISE');
    expect(proCheck.capabilities?.allowCiCdGatekeeper).toBe(true);
    expect(proCheck.capabilities?.allowSignedComplianceExport).toBe(true);
    expect(proCheck.capabilities?.maxMonthlyAiFixes).toBeNull();

    // Enterprise token satisfies ENTERPRISE requirement
    const entCheck = validateLicenseForTier(entToken, 'ENTERPRISE', officialAuthority.publicKeyPem);
    expect(entCheck.valid).toBe(true);
    expect(entCheck.resolvedTier).toBe('ENTERPRISE');
    expect(entCheck.capabilities?.allowAirGappedOnPrem).toBe(true);

    // Hierarchy sanity check
    expect(meetsMinimumTier('ENTERPRISE', 'PRO_TEAM')).toBe(true);
    expect(meetsMinimumTier('ENTERPRISE', 'ENTERPRISE')).toBe(true);
    expect(meetsMinimumTier('ENTERPRISE', 'FREE_BYOK')).toBe(true);
  });

  it('anti-tampering: detects if an attacker edits a PRO token payload to claim ENTERPRISE', () => {
    const legitimateProPayload: LicenseJwtPayload = {
      sub: 'hacker@shady.net',
      tier: 'PRO_TEAM',
      seats: 1,
      orgId: 'single-user',
      iat: nowEpoch - 10,
      exp: nowEpoch + 30 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };

    // Legitimate PRO token signed by official private key
    const genuineProToken = signLicenseJwt(legitimateProPayload, officialAuthority.privateKeyPem);
    const [headerB64, , sigB64] = genuineProToken.split('.');

    // Attacker tampers the middle section (payload) to claim ENTERPRISE and unlimited fixes
    const tamperedPayload = {
      ...legitimateProPayload,
      tier: 'ENTERPRISE',
      maxMonthlyAiFixes: null,
      allowAirGappedOnPrem: true,
    };
    const tamperedB64 = base64UrlEncode(JSON.stringify(tamperedPayload));
    const forgedToken = `${headerB64}.${tamperedB64}.${sigB64}`;

    // 1. Validator detects altered bytes because signature does not match tampered payload
    const verification = verifyLicenseJwt(forgedToken, officialAuthority.publicKeyPem, nowEpoch);
    expect(verification.valid).toBe(false);
    expect(verification.error).toContain('Cryptographic signature mismatch');

    // 2. Tier validation rejects forged token
    const tierCheck = validateLicenseForTier(
      forgedToken,
      'ENTERPRISE',
      officialAuthority.publicKeyPem
    );
    expect(tierCheck.valid).toBe(false);
    expect(tierCheck.resolvedTier).toBe('FREE_BYOK');
    expect(tierCheck.error).toContain('Cryptographic signature mismatch');
  });

  it('anti-forgery: rejects tokens signed by an untrusted or rogue private key', () => {
    const forgedEnterprisePayload: LicenseJwtPayload = {
      sub: 'unauthorized@external.com',
      tier: 'ENTERPRISE',
      seats: 999,
      orgId: 'unauthorized-org',
      iat: nowEpoch - 20,
      exp: nowEpoch + 365 * 86400,
      maxMonthlyAiFixes: null,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: true,
      featureFlags: {},
    };

    // Attacker generates their own private RSA key and signs an ENTERPRISE token
    const rogueToken = signLicenseJwt(forgedEnterprisePayload, rogueAuthority.privateKeyPem);

    // SecureShip validates against official embedded public key
    const verification = verifyLicenseJwt(rogueToken, officialAuthority.publicKeyPem, nowEpoch);
    expect(verification.valid).toBe(false);
    expect(verification.error).toContain('Cryptographic signature mismatch');

    const tierCheck = validateLicenseForTier(
      rogueToken,
      'ENTERPRISE',
      officialAuthority.publicKeyPem
    );
    expect(tierCheck.valid).toBe(false);
    expect(tierCheck.resolvedTier).toBe('FREE_BYOK');
  });

  it('temporal expiration: downgrades expired PRO and ENTERPRISE licenses cleanly to FREE_BYOK', async () => {
    const expiredPayload: LicenseJwtPayload = {
      sub: 'former-client@expired.org',
      tier: 'ENTERPRISE',
      seats: 20,
      orgId: 'former-client',
      iat: nowEpoch - 60 * 86400,
      exp: nowEpoch - 5 * 86400, // Expired 5 days ago
      maxMonthlyAiFixes: null,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: true,
      featureFlags: {},
    };

    const expiredToken = signLicenseJwt(expiredPayload, officialAuthority.privateKeyPem);
    writeLicenseFile(expiredToken, licenseFilePath);

    // Resolve tier state with expired license on disk
    const state = await resolveTierCapabilities({
      licensePath: licenseFilePath,
      publicKeyPem: officialAuthority.publicKeyPem,
      autoRefresh: false,
    });

    // Must gracefully downgrade to FREE_BYOK without throwing
    expect(state.tier).toBe('FREE_BYOK');
    expect(state.status).toBe('EXPIRED');
    expect(state.daysRemaining).toBe(0);
    expect(state.capabilities.allowCiCdGatekeeper).toBe(false);
    expect(state.capabilities.allowSignedComplianceExport).toBe(false);
    expect(state.capabilities.allowAirGappedOnPrem).toBe(false);
    expect(state.capabilities.maxMonthlyAiFixes).toBe(15);

    // Status report must document expired status and downgrade
    const report = await getLicenseStatusReport({
      licensePath: licenseFilePath,
      publicKeyPem: officialAuthority.publicKeyPem,
      ledgerPath: usageFilePath,
    });

    expect(report.status).toBe('EXPIRED');
    expect(report.tier).toBe('FREE_BYOK');
    expect(report.capabilities.allowCiCdGatekeeper).toBe(false);
  });

  it('license removal: cleanly deletes credentials and restores default FREE_BYOK state', async () => {
    const activePayload: LicenseJwtPayload = {
      sub: 'user@cleanup.test',
      tier: 'PRO_TEAM',
      seats: 3,
      orgId: 'temp-corp',
      iat: nowEpoch - 10,
      exp: nowEpoch + 20 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };

    const activeToken = signLicenseJwt(activePayload, officialAuthority.privateKeyPem);
    writeLicenseFile(activeToken, licenseFilePath);
    expect(fs.existsSync(licenseFilePath)).toBe(true);

    // Remove license file
    const deleted = deleteLicenseFile(licenseFilePath);
    expect(deleted).toBe(true);
    expect(fs.existsSync(licenseFilePath)).toBe(false);

    // Status reverts to UNLICENSED_FREE
    const state = await resolveTierCapabilities({
      licensePath: licenseFilePath,
      publicKeyPem: officialAuthority.publicKeyPem,
      autoRefresh: false,
    });
    expect(state.tier).toBe('FREE_BYOK');
    expect(state.status).toBe('UNLICENSED_FREE');
    expect(state.capabilities.allowCiCdGatekeeper).toBe(false);
  });
});
