import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type { LicenseJwtPayload } from '@secureship/contracts';
import {
  resolveTierCapabilities,
  getLicenseStatusReport,
} from '../../src/license/tier-resolver.js';
import { writeLicenseFile } from '../../src/license/license-storage.js';
import { signLicenseJwt, generateLicenseKeyPair } from '../../src/license/license-keys.js';
import { recordAiFixExecution } from '../../src/license/ai-usage-ledger.js';

describe('Tier Capabilities & Operational Enforcement (Stage 5)', () => {
  let tempDir: string;
  let licenseFilePath: string;
  let usageFilePath: string;

  const { publicKeyPem, privateKeyPem } = generateLicenseKeyPair();
  const nowEpoch = Math.floor(Date.now() / 1000);

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-tier-test-'));
    licenseFilePath = path.join(tempDir, 'license.jwt');
    usageFilePath = path.join(tempDir, 'ai-usage.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('resolves FREE_BYOK tier by default when no license file exists', async () => {
    const tierState = await resolveTierCapabilities({
      licensePath: licenseFilePath,
      publicKeyPem,
      autoRefresh: false,
    });

    expect(tierState.tier).toBe('FREE_BYOK');
    expect(tierState.status).toBe('UNLICENSED_FREE');
    expect(tierState.capabilities.allowCiCdGatekeeper).toBe(false);
    expect(tierState.capabilities.allowSignedComplianceExport).toBe(false);
    expect(tierState.capabilities.maxMonthlyAiFixes).toBe(15);
  });

  it('resolves PRO_TEAM tier and unlocks CI/CD gatekeeper mode when valid JWT exists', async () => {
    const proPayload: LicenseJwtPayload = {
      sub: 'lead@startup.com',
      tier: 'PRO_TEAM',
      seats: 10,
      orgId: 'startup-corp',
      iat: nowEpoch - 100,
      exp: nowEpoch + 30 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };

    const token = signLicenseJwt(proPayload, privateKeyPem);
    writeLicenseFile(token, licenseFilePath);

    const tierState = await resolveTierCapabilities({
      licensePath: licenseFilePath,
      publicKeyPem,
      autoRefresh: false,
    });

    expect(tierState.tier).toBe('PRO_TEAM');
    expect(tierState.status).toBe('ACTIVE');
    expect(tierState.capabilities.allowCiCdGatekeeper).toBe(true);
    expect(tierState.capabilities.allowSignedComplianceExport).toBe(true);
    expect(tierState.capabilities.maxMonthlyAiFixes).toBe(100);
    expect(tierState.daysRemaining).toBeGreaterThanOrEqual(29);
  });

  it('resolves ENTERPRISE tier with unlimited AI quota and on-prem capability', async () => {
    const enterprisePayload: LicenseJwtPayload = {
      sub: 'ciso@global-bank.com',
      tier: 'ENTERPRISE',
      seats: 100,
      orgId: 'global-bank',
      iat: nowEpoch - 100,
      exp: nowEpoch + 365 * 86400,
      maxMonthlyAiFixes: null,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: true,
      featureFlags: {},
    };

    const token = signLicenseJwt(enterprisePayload, privateKeyPem);
    writeLicenseFile(token, licenseFilePath);

    const tierState = await resolveTierCapabilities({
      licensePath: licenseFilePath,
      publicKeyPem,
      autoRefresh: false,
    });

    expect(tierState.tier).toBe('ENTERPRISE');
    expect(tierState.status).toBe('ACTIVE');
    expect(tierState.capabilities.allowAirGappedOnPrem).toBe(true);
    expect(tierState.capabilities.maxMonthlyAiFixes).toBeNull();
  });

  it('downgrades to FREE_BYOK when license token is expired', async () => {
    const expiredPayload: LicenseJwtPayload = {
      sub: 'expired@dev.com',
      tier: 'PRO_TEAM',
      seats: 5,
      orgId: 'expired-org',
      iat: nowEpoch - 60 * 86400,
      exp: nowEpoch - 5 * 86400, // Expired 5 days ago
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };

    const token = signLicenseJwt(expiredPayload, privateKeyPem);
    writeLicenseFile(token, licenseFilePath);

    const tierState = await resolveTierCapabilities({
      licensePath: licenseFilePath,
      publicKeyPem,
      autoRefresh: false,
    });

    expect(tierState.tier).toBe('FREE_BYOK');
    expect(tierState.status).toBe('EXPIRED');
    expect(tierState.capabilities.allowCiCdGatekeeper).toBe(false);
    expect(tierState.error).toContain('License expired');
  });

  it('downgrades to FREE_BYOK when signature is invalid or altered', async () => {
    const untrustedKeypair = generateLicenseKeyPair();
    const forgedPayload: LicenseJwtPayload = {
      sub: 'hacker@attacker.com',
      tier: 'ENTERPRISE',
      seats: 999,
      orgId: 'attacker-org',
      iat: nowEpoch,
      exp: nowEpoch + 30 * 86400,
      maxMonthlyAiFixes: null,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: true,
      featureFlags: {},
    };

    // Signed by untrusted key
    const forgedToken = signLicenseJwt(forgedPayload, untrustedKeypair.privateKeyPem);
    writeLicenseFile(forgedToken, licenseFilePath);

    const tierState = await resolveTierCapabilities({
      licensePath: licenseFilePath,
      publicKeyPem, // Verified by genuine public key
      autoRefresh: false,
    });

    expect(tierState.tier).toBe('FREE_BYOK');
    expect(tierState.status).toBe('INVALID_SIGNATURE');
    expect(tierState.capabilities.allowAirGappedOnPrem).toBe(false);
  });

  it('produces compliant LicenseStatusReport with usage metrics', async () => {
    const proPayload: LicenseJwtPayload = {
      sub: 'dev@acme.com',
      tier: 'PRO_TEAM',
      seats: 15,
      orgId: 'acme-corp',
      iat: nowEpoch - 100,
      exp: nowEpoch + 20 * 86400,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
      featureFlags: {},
    };

    const token = signLicenseJwt(proPayload, privateKeyPem);
    writeLicenseFile(token, licenseFilePath);

    // Record 7 fixes in usage ledger
    for (let i = 0; i < 7; i++) {
      recordAiFixExecution(usageFilePath);
    }

    const report = await getLicenseStatusReport({
      licensePath: licenseFilePath,
      ledgerPath: usageFilePath,
      publicKeyPem,
    });

    expect(report.status).toBe('ACTIVE');
    expect(report.tier).toBe('PRO_TEAM');
    expect(report.email).toBe('dev@acme.com');
    expect(report.orgId).toBe('acme-corp');
    expect(report.seats).toBe(15);
    expect(report.monthlyAiUsage.fixesUsed).toBe(7);
    expect(report.monthlyAiUsage.limit).toBe(100);
    expect(report.capabilities.allowSignedComplianceExport).toBe(true);
    expect(report.capabilities.allowAirGappedOnPrem).toBe(false);
  });
});
