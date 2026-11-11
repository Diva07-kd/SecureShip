import { z } from 'zod';
import { NormalizedFindingSchema, SeveritySchema } from './finding.schema.js';

export const SupplyChainThreatTypeSchema = z.enum([
  'INSTALL_SCRIPT',
  'CAPABILITY_VIOLATION',
  'TYPOSQUAT',
  'BIDI_TROJAN',
  'HIGH_ENTROPY',
  'CHRONO_ANOMALY',
  'AI_HALLUCINATION',
  'SEMVER_ANOMALY',
  'MANIFEST_CONFUSION',
  'GOVERNANCE_RISK',
  'EMPTY_OR_MISSING_TARBALL',
  'BIN_CONFUSION',
  'SHELL_OVERRIDE',
  'OBFUSCATION',
  'PROTESTWARE',
]);
export type SupplyChainThreatType = z.infer<typeof SupplyChainThreatTypeSchema>;

export const SupplyChainRuleIdSchema = z.enum([
  'SC-INSTALL-001',
  'SC-INSTALL-002',
  'SC-INSTALL-003',
  'SC-BIN-001',
  'SC-BIN-002',
  'SC-CAP-001',
  'SC-CAP-002',
  'SC-CAP-003',
  'SC-CAP-004',
  'SC-CAP-005',
  'SC-CAP-006',
  'SC-CAP-007',
  'SC-CAP-100',
  'SC-CAP-101',
  'SC-CAP-102',
  'SC-CAP-103',
  'SC-CAP-104',
  'SC-CAP-105',
  'SC-CAP-106',
  'SC-TYPO-001',
  'SC-TYPO-002',
  'SC-TYPO-003',
  'SC-HALL-001',
  'SC-PKG-001',
  'SC-PKG-002',
  'SC-UNI-001',
  'SC-UNI-002',
  'SC-UNI-003',
  'SC-OBF-001',
  'SC-OBF-002',
  'SC-META-001',
  'SC-META-002',
  'SC-META-003',
  'SC-GOV-001',
  'SC-GOV-002',
  'SC-GOV-003',
]);
export type SupplyChainRuleId = z.infer<typeof SupplyChainRuleIdSchema>;

export const SupplyChainEvidenceItemSchema = z.object({
  file: z.string(),
  startLine: z.number().int().nonnegative(),
  startCol: z.number().int().nonnegative(),
  endLine: z.number().int().nonnegative(),
  endCol: z.number().int().nonnegative(),
  snippetSha256: z.string().length(64),
  redactedSnippet: z.string().max(200),
  note: z.string().optional(),
});
export type SupplyChainEvidenceItem = z.infer<typeof SupplyChainEvidenceItemSchema>;

export const SupplyChainCapabilitiesSchema = z.object({
  hasShell: z.boolean().default(false),
  hasNetwork: z.boolean().default(false),
  hasEnvAccess: z.boolean().default(false),
  hasFsSensitive: z.boolean().default(false),
  hasEval: z.boolean().default(false),
  hasDynamicRequire: z.boolean().default(false),
  hasInstallScript: z.boolean().default(false),
  hasDebugInternals: z.boolean().default(false),
});
export type SupplyChainCapabilities = z.infer<typeof SupplyChainCapabilitiesSchema>;

export const ScReachabilitySchema = z.enum([
  'REACHABLE',
  'DEP_REACHABLE_ONLY',
  'NOT_REACHABLE',
  'NOT_APPLICABLE',
  'UNKNOWN',
]);
export type ScReachability = z.infer<typeof ScReachabilitySchema>;

export const SupplyChainAllowlistEntrySchema = z.object({
  packageName: z.string(),
  versionRange: z.string(),
  ruleId: z.string().optional(),
  scriptHash: z.string().optional(),
  reason: z.string().min(10, 'Allowlist reason must be at least 10 characters long'),
  expires: z.string(),
});
export type SupplyChainAllowlistEntry = z.infer<typeof SupplyChainAllowlistEntrySchema>;

export const SupplyChainRuleOverrideSchema = z.object({
  enabled: z.boolean().optional(),
  severity: SeveritySchema.optional(),
  blocking: z.boolean().optional(),
});
export type SupplyChainRuleOverride = z.infer<typeof SupplyChainRuleOverrideSchema>;

export const SupplyChainPolicySchema = z.object({
  enabled: z.boolean().default(false),
  provider: z.enum(['null', 'snapshot', 'registry']).default('null'),
  snapshotDir: z.string().optional(),
  registryUrl: z.string().url().optional(),
  concurrency: z.number().int().positive().default(8),
  packageTimeoutMs: z.number().int().positive().default(30_000),
  maxFileSizeBytes: z.number().int().positive().default(2_097_152), // 2 MiB
  maxTotalBytes: z.number().int().positive().default(104_857_600), // 100 MiB
  maxFileCount: z.number().int().positive().default(20_000),

  typosquat: z
    .object({
      minScore: z.number().min(0).max(1).default(0.82),
      candidateMaxDownloads: z.number().int().positive().default(1_000),
      popularMinDownloads: z.number().int().positive().default(1_000_000),
    })
    .default({}),

  entropy: z
    .object({
      minLength: z.number().int().positive().default(64),
      threshold: z.number().min(0).default(4.5),
    })
    .default({}),

  obfuscation: z
    .object({
      longLine: z.number().int().positive().default(1_000),
    })
    .default({}),

  hallucination: z
    .object({
      minAgeDays: z.number().int().positive().default(30),
    })
    .default({}),

  semver: z
    .object({
      majorJump: z.number().int().positive().default(20),
    })
    .default({}),

  chrono: z
    .object({
      allowBackportSameMajor: z.boolean().default(true),
    })
    .default({}),

  governance: z
    .object({
      dormancyDays: z.number().int().positive().default(365),
    })
    .default({}),

  preInstall: z
    .object({
      forbidInstallScripts: z.boolean().default(true),
    })
    .default({}),

  ruleOverrides: z.record(z.string(), SupplyChainRuleOverrideSchema).default({}),
  allowlist: z.array(SupplyChainAllowlistEntrySchema).default([]),
  privateScopes: z.array(z.string()).default([]),
  failOnSeverity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE']).default('HIGH'),
});
export type SupplyChainPolicy = z.infer<typeof SupplyChainPolicySchema>;

export const SupplyChainDiagnosticSchema = z.object({
  level: z.enum(['INFO', 'WARN', 'ERROR']),
  packageName: z.string().optional(),
  file: z.string().optional(),
  message: z.string(),
});
export type SupplyChainDiagnostic = z.infer<typeof SupplyChainDiagnosticSchema>;

export const SupplyChainStatsSchema = z.object({
  packagesAnalyzed: z.number().int().nonnegative(),
  packagesSkipped: z.number().int().nonnegative(),
  filesScanned: z.number().int().nonnegative(),
  bytesScanned: z.number().int().nonnegative(),
  durationMs: z.number().int().nonnegative(),
  detectorDurations: z.record(z.string(), z.number().int().nonnegative()),
});
export type SupplyChainStats = z.infer<typeof SupplyChainStatsSchema>;

export const SupplyChainScanResultSchema = z.object({
  findings: z.array(NormalizedFindingSchema),
  diagnostics: z.array(SupplyChainDiagnosticSchema),
  stats: SupplyChainStatsSchema,
  policyHash: z.string().length(64),
  engineVersion: z.string(),
});
export type SupplyChainScanResult = z.infer<typeof SupplyChainScanResultSchema>;
