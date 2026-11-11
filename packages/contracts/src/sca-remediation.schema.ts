import { z } from 'zod';
import {
  BaseFileRecordSchema,
  FindingRefSchema,
  SandboxMetadataSchema,
  StageResultSchema,
} from './remediation.schema.js';
import {
  SupplyChainCapabilitiesSchema,
  SupplyChainThreatTypeSchema,
} from './supply-chain.schema.js';
import { SeveritySchema, VerificationStatusSchema } from './finding.schema.js';

export const ScaPackageManagerSchema = z.enum(['npm', 'pnpm', 'yarn', 'pip', 'poetry']);
export type ScaPackageManager = z.infer<typeof ScaPackageManagerSchema>;

export const ScaStrategySchema = z.enum([
  'DIRECT_UPGRADE',
  'TRANSITIVE_PIN',
  'OVERRIDES_INJECTION',
]);
export type ScaStrategy = z.infer<typeof ScaStrategySchema>;

// Pre-Install Security Gate Result (WP7 Gate 4)
export const PreInstallViolationSchema = z.object({
  ruleId: z.string(),
  threatType: SupplyChainThreatTypeSchema.optional(),
  message: z.string(),
  severity: SeveritySchema,
  blocking: z.boolean().default(false),
});
export type PreInstallViolation = z.infer<typeof PreInstallViolationSchema>;

export const TargetVersionFactsSchema = z.object({
  hasInstallScripts: z.boolean().default(false),
  chronoAnomaly: z.boolean().default(false),
  semverAnomaly: z.boolean().default(false),
  manifestConfusion: z.boolean().default(false),
  hasBidiOrInvisibleUnicode: z.boolean().default(false),
  hasTyposquatOrHallucination: z.boolean().default(false),
  capabilities: SupplyChainCapabilitiesSchema.optional(),
  blockingFindingsCount: z.number().int().nonnegative().default(0),
});
export type TargetVersionFacts = z.infer<typeof TargetVersionFactsSchema>;

export const PreInstallGateResultSchema = z.object({
  passed: z.boolean(),
  violations: z.array(PreInstallViolationSchema).default([]),
  targetVersionFacts: TargetVersionFactsSchema,
  safeCandidateVersion: z.string().optional(),
});
export type PreInstallGateResult = z.infer<typeof PreInstallGateResultSchema>;

// The SCA patch proposal - deterministic lockfile & manifest patch
export const ScaPatchProposalSchema = z.object({
  findingFingerprint: z.string().min(1),
  packageManager: ScaPackageManagerSchema,
  targetPackage: z.string().min(1),
  currentVersion: z.string().min(1),
  targetVersion: z.string().min(1),
  isTransitive: z.boolean(),
  strategy: ScaStrategySchema,
  manifestPath: z.string().min(1), // relative path to package.json / requirements.txt / pyproject.toml
  lockfilePath: z.string().optional(), // relative path to lockfile, if known
  transitiveChain: z.array(z.string()).optional(), // [root -> ... -> vulnerablePkg] path
  diff: z.string().optional(), // Unified diff for manifest changes (FixStore.applyFix compatibility)
  attempt: z.number().int().positive().default(1),
  generatedAt: z.string(),
});
export type ScaPatchProposal = z.infer<typeof ScaPatchProposalSchema>;

// Result emitted after the SCA verification ladder run
export const ScaFixReportSchema = z.object({
  schemaVersion: z.literal('1.1'),
  tool: z.string().default('secureship'),
  findingRef: FindingRefSchema,
  proposal: ScaPatchProposalSchema,
  baseFiles: z.array(BaseFileRecordSchema).optional(),
  status: VerificationStatusSchema,
  stages: z.array(StageResultSchema),
  sandbox: SandboxMetadataSchema,
  preInstallGate: PreInstallGateResultSchema.optional(),
  attempts: z.number().int().positive(),
  limitations: z.array(z.string()),
  disclaimer: z.string(),
  createdAt: z.string(),
  signature: z.string(),
});
export type ScaFixReport = z.infer<typeof ScaFixReportSchema>;
