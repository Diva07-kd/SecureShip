import { z } from 'zod';
import { LicenseTierSchema } from './tier-policy.schema.js';

/**
 * Standard JWT Header schema for SecureShip RS256 license tokens.
 */
export const LicenseJwtHeaderSchema = z.object({
  alg: z.literal('RS256'),
  kid: z.string().min(1),
  typ: z.literal('JWT').default('JWT'),
});
export type LicenseJwtHeader = z.infer<typeof LicenseJwtHeaderSchema>;

/**
 * Cryptographically signed JWT payload schema (Phase 5).
 * Matches the specification in DEVELOPEMENT STRAGETY FROM CURRENT STAGE OF THIS PROJECT.md.
 */
export const LicenseJwtPayloadSchema = z.object({
  sub: z.string().min(1), // Email or user identifier
  tier: LicenseTierSchema,
  seats: z.number().int().positive().default(1),
  orgId: z.string().min(1).default('individual'),
  iat: z.number().int().positive(), // Issued-at Unix timestamp (seconds)
  exp: z.number().int().positive(), // Expiration Unix timestamp (seconds)
  maxMonthlyAiFixes: z.number().int().nonnegative().nullable(), // null = unlimited
  allowCallPathReachability: z.boolean().default(false),
  allowCiCdGatekeeper: z.boolean().default(false),
  allowSignedComplianceExport: z.boolean().default(false),
  allowAirGappedOnPrem: z.boolean().default(false),
  featureFlags: z.record(z.unknown()).default({}),
});
export type LicenseJwtPayload = z.infer<typeof LicenseJwtPayloadSchema>;

/**
 * Schema for activating a license via activation code.
 */
export const LicenseActivationRequestSchema = z.object({
  activationCode: z.string().min(6),
  email: z.string().email().optional(),
  machineFingerprint: z.string().optional(),
});
export type LicenseActivationRequest = z.infer<typeof LicenseActivationRequestSchema>;

/**
 * Response schema from license server /v1/activate.
 */
export const LicenseActivationResponseSchema = z.object({
  success: z.boolean(),
  jwt: z.string(),
  tier: LicenseTierSchema,
  expiresAt: z.string(), // ISO-8601
  message: z.string().optional(),
});
export type LicenseActivationResponse = z.infer<typeof LicenseActivationResponseSchema>;

/**
 * Response schema from license server /v1/validate.
 */
export const LicenseValidationResponseSchema = z.object({
  valid: z.boolean(),
  refreshedJwt: z.string().optional(),
  tier: LicenseTierSchema,
  expiresAt: z.string(),
  message: z.string().optional(),
});
export type LicenseValidationResponse = z.infer<typeof LicenseValidationResponseSchema>;

/**
 * License status report schema for 'secureship license status --json'.
 */
export const LicenseStatusReportSchema = z.object({
  status: z.enum(['ACTIVE', 'EXPIRED', 'UNLICENSED_FREE', 'INVALID_SIGNATURE']),
  tier: LicenseTierSchema,
  email: z.string().optional(),
  orgId: z.string().optional(),
  seats: z.number().int().optional(),
  issuedAt: z.string().optional(),
  expiresAt: z.string().optional(),
  daysRemaining: z.number().int().optional(),
  monthlyAiUsage: z.object({
    month: z.string(), // YYYY-MM
    fixesUsed: z.number().int().nonnegative(),
    limit: z.number().int().nonnegative().nullable(),
  }),
  capabilities: z.object({
    allowCallPathReachability: z.boolean(),
    allowCiCdGatekeeper: z.boolean(),
    allowSignedComplianceExport: z.boolean(),
    allowAirGappedOnPrem: z.boolean(),
  }),
  licensePath: z.string(),
});
export type LicenseStatusReport = z.infer<typeof LicenseStatusReportSchema>;

/**
 * Monthly AI usage ledger persisted in ~/.secureship/ai-usage.json.
 */
export const AiUsageLedgerSchema = z.object({
  month: z.string(), // YYYY-MM
  fixesUsed: z.number().int().nonnegative(),
  lastUpdated: z.string(), // ISO timestamp
});
export type AiUsageLedger = z.infer<typeof AiUsageLedgerSchema>;
