import { describe, it, expect } from 'vitest';
import {
  LicenseJwtHeaderSchema,
  LicenseJwtPayloadSchema,
  LicenseActivationRequestSchema,
  LicenseStatusReportSchema,
  AiUsageLedgerSchema,
} from '../src/license.schema.js';

describe('License Schemas Contract Validation', () => {
  it('validates a compliant RS256 JWT header', () => {
    const validHeader = {
      alg: 'RS256' as const,
      kid: 'secureship-2026-01',
      typ: 'JWT' as const,
    };
    const parsed = LicenseJwtHeaderSchema.parse(validHeader);
    expect(parsed.alg).toBe('RS256');
    expect(parsed.kid).toBe('secureship-2026-01');
    expect(parsed.typ).toBe('JWT');
  });

  it('rejects non-RS256 algorithm in JWT header', () => {
    const invalidHeader = {
      alg: 'HS256',
      kid: 'secureship-2026-01',
      typ: 'JWT',
    };
    expect(() => LicenseJwtHeaderSchema.parse(invalidHeader)).toThrow();
  });

  it('validates a full enterprise license JWT payload', () => {
    const validPayload = {
      sub: 'security-lead@enterprise.com',
      tier: 'ENTERPRISE' as const,
      seats: 50,
      orgId: 'acme-corp',
      iat: 1735689600,
      exp: 1767225600,
      maxMonthlyAiFixes: null,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: true,
      featureFlags: { betaAst: true },
    };

    const parsed = LicenseJwtPayloadSchema.parse(validPayload);
    expect(parsed.sub).toBe('security-lead@enterprise.com');
    expect(parsed.tier).toBe('ENTERPRISE');
    expect(parsed.seats).toBe(50);
    expect(parsed.orgId).toBe('acme-corp');
    expect(parsed.maxMonthlyAiFixes).toBeNull();
    expect(parsed.allowCallPathReachability).toBe(true);
    expect(parsed.allowAirGappedOnPrem).toBe(true);
    expect(parsed.featureFlags['betaAst']).toBe(true);
  });

  it('validates PRO_TEAM license payload with numerical limits', () => {
    const proPayload = {
      sub: 'dev@startup.io',
      tier: 'PRO_TEAM' as const,
      seats: 5,
      orgId: 'startup-io',
      iat: 1735689600,
      exp: 1738368000,
      maxMonthlyAiFixes: 100,
      allowCallPathReachability: true,
      allowCiCdGatekeeper: true,
      allowSignedComplianceExport: true,
      allowAirGappedOnPrem: false,
    };

    const parsed = LicenseJwtPayloadSchema.parse(proPayload);
    expect(parsed.tier).toBe('PRO_TEAM');
    expect(parsed.maxMonthlyAiFixes).toBe(100);
    expect(parsed.allowCiCdGatekeeper).toBe(true);
    expect(parsed.allowAirGappedOnPrem).toBe(false);
  });

  it('rejects payload with negative seat count or invalid tier name', () => {
    const invalidPayload = {
      sub: 'dev@startup.io',
      tier: 'SUPER_TIER', // Invalid tier
      seats: -1, // Illegal negative seat
      orgId: 'startup-io',
      iat: 1735689600,
      exp: 1738368000,
      maxMonthlyAiFixes: 100,
    };

    expect(() => LicenseJwtPayloadSchema.parse(invalidPayload)).toThrow();
  });

  it('validates activation request schema', () => {
    const req = {
      activationCode: 'SS-PRO-2026-X9912',
      email: 'admin@company.com',
      machineFingerprint: 'sha256-abc12345',
    };
    const parsed = LicenseActivationRequestSchema.parse(req);
    expect(parsed.activationCode).toBe('SS-PRO-2026-X9912');
    expect(parsed.email).toBe('admin@company.com');
    expect(parsed.machineFingerprint).toBe('sha256-abc12345');
  });

  it('validates status report schema structure', () => {
    const report = {
      status: 'ACTIVE' as const,
      tier: 'PRO_TEAM' as const,
      email: 'eng@acme.com',
      orgId: 'acme-corp',
      seats: 10,
      issuedAt: '2026-01-01T00:00:00.000Z',
      expiresAt: '2026-02-01T00:00:00.000Z',
      daysRemaining: 28,
      monthlyAiUsage: {
        month: '2026-01',
        fixesUsed: 4,
        limit: 100,
      },
      capabilities: {
        allowCallPathReachability: true,
        allowCiCdGatekeeper: true,
        allowSignedComplianceExport: true,
        allowAirGappedOnPrem: false,
      },
      licensePath: '/home/user/.secureship/license.jwt',
    };

    const parsed = LicenseStatusReportSchema.parse(report);
    expect(parsed.status).toBe('ACTIVE');
    expect(parsed.tier).toBe('PRO_TEAM');
    expect(parsed.monthlyAiUsage.fixesUsed).toBe(4);
    expect(parsed.capabilities.allowCiCdGatekeeper).toBe(true);
  });

  it('validates monthly AI usage ledger schema', () => {
    const ledger = {
      month: '2026-10',
      fixesUsed: 12,
      lastUpdated: '2026-10-23T07:00:00.000Z',
    };
    const parsed = AiUsageLedgerSchema.parse(ledger);
    expect(parsed.month).toBe('2026-10');
    expect(parsed.fixesUsed).toBe(12);
  });
});
