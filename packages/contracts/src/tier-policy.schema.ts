import { z } from 'zod';

export const LicenseTierSchema = z.enum(['FREE_BYOK', 'PRO_TEAM', 'ENTERPRISE']);
export type LicenseTier = z.infer<typeof LicenseTierSchema>;

export const TierCapabilitiesSchema = z.object({
  tier: LicenseTierSchema,
  maxMonthlyAiFixes: z.number().int().nonnegative().nullable(), // null = unlimited
  allowCrossFileAstGraph: z.boolean(),
  allowShadowWorktreeSandbox: z.boolean(),
  allowCiCdGatekeeper: z.boolean(),
  allowSignedComplianceExport: z.boolean(),
  /**
   * Enterprise tier designates managed private deployment and commercial SLA support.
   * Local OpenAI-compatible loopback endpoints (Ollama, LM Studio, vLLM) are included
   * and supported across all tiers (no license enforcement code).
   */
  allowAirGappedOnPrem: z.boolean(),
  allowCustomModelRouting: z.boolean(),
  allowImportReachability: z.boolean().default(true),
  allowCallPathReachability: z.boolean().default(false),
});
export type TierCapabilities = z.infer<typeof TierCapabilitiesSchema>;

export const TIER_CAPABILITY_DEFAULTS: Record<LicenseTier, TierCapabilities> = {
  FREE_BYOK: {
    tier: 'FREE_BYOK',
    maxMonthlyAiFixes: 15,
    allowCrossFileAstGraph: false,
    allowShadowWorktreeSandbox: false,
    allowCiCdGatekeeper: false,
    allowSignedComplianceExport: false,
    allowAirGappedOnPrem: false,
    allowCustomModelRouting: true, // BYOK allows user to provide API key
    allowImportReachability: true,
    allowCallPathReachability: false,
  },
  PRO_TEAM: {
    tier: 'PRO_TEAM',
    maxMonthlyAiFixes: 100,
    allowCrossFileAstGraph: true,
    allowShadowWorktreeSandbox: true,
    allowCiCdGatekeeper: true,
    allowSignedComplianceExport: true,
    allowAirGappedOnPrem: false,
    allowCustomModelRouting: true,
    allowImportReachability: true,
    allowCallPathReachability: true,
  },
  ENTERPRISE: {
    tier: 'ENTERPRISE',
    maxMonthlyAiFixes: null, // Unlimited
    allowCrossFileAstGraph: true,
    allowShadowWorktreeSandbox: true,
    allowCiCdGatekeeper: true,
    allowSignedComplianceExport: true,
    allowAirGappedOnPrem: true,
    allowCustomModelRouting: true,
    allowImportReachability: true,
    allowCallPathReachability: true,
  },
};
