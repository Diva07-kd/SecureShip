import { z } from 'zod';
import { ConfidenceSchema, ScannerNameSchema, SeveritySchema } from './finding.schema.js';
import { SupplyChainPolicySchema } from './supply-chain.schema.js';

export const FailOnSeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE']);
export type FailOnSeverity = z.infer<typeof FailOnSeveritySchema>;

export const IgnoreRuleSchema = z.object({
  ruleId: z.string().optional(),
  pathGlob: z.string().optional(),
  fingerprint: z.string().optional(),
  reason: z.string().min(10, 'Reason must be at least 10 characters long'),
  expires: z.string().refine((val) => {
    const d = new Date(val);
    if (isNaN(d.getTime())) return false;
    // Check max 12 months ahead: ~366 days
    const now = new Date();
    const maxDate = new Date(now.getTime() + 366 * 24 * 60 * 60 * 1000);
    return d.getTime() <= maxDate.getTime();
  }, 'Expiration date must be a valid ISO date at most 12 months in the future'),
});
export type IgnoreRule = z.infer<typeof IgnoreRuleSchema>;

export const Gate1ConfigSchema = z.object({
  enabled: z.boolean().default(true),
  keepProviderSecrets: z.boolean().default(true),
  customTestDirs: z.array(z.string()).default([]),
});
export type Gate1Config = z.infer<typeof Gate1ConfigSchema>;

export const Gate2ModeSchema = z.enum(['off', 'annotate', 'suppress']);
export type Gate2Mode = z.infer<typeof Gate2ModeSchema>;

export const Gate2ConfigSchema = z.object({
  mode: Gate2ModeSchema.default('annotate'),
  neverSuppressSeverities: z.array(SeveritySchema).default(['CRITICAL']),
  entrypoints: z.array(z.string()).optional(),
  extraTestGlobs: z.array(z.string()).optional(),
  maxFileBytes: z.number().int().positive().default(1_048_576), // 1 MB default
  parseTimeoutMs: z.number().int().positive().default(5000), // 5,000 ms default
});
export type Gate2Config = z.infer<typeof Gate2ConfigSchema>;

export const Gate3ModeSchema = z.enum(['off', 'annotate', 'suppress']);
export type Gate3Mode = z.infer<typeof Gate3ModeSchema>;

export const Gate3ConfigSchema = z.object({
  mode: Gate3ModeSchema.default('annotate'),
  neverSuppressSeverities: z.array(SeveritySchema).default(['CRITICAL', 'HIGH']),
  minConfidence: ConfidenceSchema.default('HIGH'),
  consistencyChecks: z.number().int().positive().default(2),
  maxFindings: z.number().int().positive().default(25),
  budgetTokens: z.number().int().positive().default(200_000),
  sliceTokens: z.number().int().positive().default(6_000),
  concurrency: z.number().int().positive().default(2),
});
export type Gate3Config = z.infer<typeof Gate3ConfigSchema>;

export const FixConfigSchema = z.object({
  maxFiles: z.number().int().min(1).max(3).default(1),
  maxChangedLines: z.number().int().positive().default(60),
  maxDiffBytes: z.number().int().positive().default(20000),
  maxAttempts: z.number().int().min(1).max(3).default(2),
  minNewFindingSeverity: SeveritySchema.default('MEDIUM'),
  allowRemovalOnly: z.boolean().default(false),
});
export type FixConfig = z.infer<typeof FixConfigSchema>;

export const StageTimeoutSecSchema = z.object({
  install: z.number().int().positive().default(600),
  typecheck: z.number().int().positive().default(300),
  build: z.number().int().positive().default(600),
  test: z.number().int().positive().default(900),
});
export type StageTimeoutSec = z.infer<typeof StageTimeoutSecSchema>;

export const SandboxLimitsSchema = z.object({
  memory: z.string().default('2g'),
  cpus: z.number().positive().default(2),
  pids: z.number().int().positive().default(512),
  tmpfsMb: z.number().int().positive().default(512),
  stageTimeoutSec: StageTimeoutSecSchema.default({}),
  totalTimeoutSec: z.number().int().positive().default(1800),
  outputCapBytes: z.number().int().positive().default(5242880),
});
export type SandboxLimits = z.infer<typeof SandboxLimitsSchema>;

export const SandboxInstallConfigSchema = z.object({
  enabled: z.boolean().default(false),
  ignoreScripts: z.boolean().default(true),
});
export type SandboxInstallConfig = z.infer<typeof SandboxInstallConfigSchema>;

export const SandboxConfigSchema = z.object({
  backend: z.enum(['container', 'native-isolated', 'host', 'none', 'auto']).default('container'),
  runtime: z.enum(['auto', 'docker', 'podman']).default('auto'),
  images: z
    .object({
      node: z.string().optional(),
      python: z.string().optional(),
    })
    .default({}),
  limits: SandboxLimitsSchema.default({}),
  install: SandboxInstallConfigSchema.default({}),
  commands: z.record(z.string(), z.array(z.string())).optional(),
  trustedHostRepos: z.array(z.string()).default([]),
});
export type SandboxConfig = z.infer<typeof SandboxConfigSchema>;

export const FleetClientConfigSchema = z.object({
  reportTo: z.string().optional(),
  fleetToken: z.string().optional(),
  repoName: z.string().optional(),
  policySync: z.boolean().default(false),
});
export type FleetClientConfig = z.infer<typeof FleetClientConfigSchema>;

export const UserReachabilityConfigSchema = z.object({
  functionLevel: z.enum(['auto', 'off']).default('auto'),
  symbolDataset: z.string().optional(),
});
export type UserReachabilityConfig = z.infer<typeof UserReachabilityConfigSchema>;

export const OfflinePolicyConfigSchema = z.object({
  maxDbAgeDays: z.number().int().positive().default(7),
  strictMaxDbAgeDays: z.number().int().positive().default(30),
  retainGenerations: z.number().int().positive().default(2),
  trustedKeys: z.array(z.string()).default([]),
});
export type OfflinePolicyConfig = z.infer<typeof OfflinePolicyConfigSchema>;

export const UserConfigSchema = z.object({
  enabled: z.boolean().default(false),
  ai: z.boolean().optional(),
  provider: z.enum(['anthropic', 'openai', 'fake']).optional(),
  model: z.string().optional(),
  baseUrl: z.string().optional(),
  gate3: Gate3ConfigSchema.default({}),
  checkovDefaultSeverity: SeveritySchema.optional(),
  fix: FixConfigSchema.default({}),
  sandbox: SandboxConfigSchema.default({}),
  fleet: FleetClientConfigSchema.optional(),
  reachability: UserReachabilityConfigSchema.default({}),
  offline: OfflinePolicyConfigSchema.optional(),
});
export type UserConfig = z.infer<typeof UserConfigSchema>;

export const ConfigSchema = z.object({
  scanners: z.record(ScannerNameSchema, z.boolean()).optional(),
  timeouts: z.record(z.string(), z.number().int().positive()).optional(),
  failOn: FailOnSeveritySchema.default('HIGH'),
  ignore: z.array(IgnoreRuleSchema).default([]),
  gate1: Gate1ConfigSchema.default({}),
  gate2: Gate2ConfigSchema.default({}),
  extraRulePacks: z.array(z.string()).default([]),
  baselinePath: z.string().default('.secureship/baseline.json'),
  binaryOverrides: z.record(ScannerNameSchema, z.string()).optional(),
  checkovDefaultSeverity: SeveritySchema.default('MEDIUM'),
  supplyChain: SupplyChainPolicySchema.optional(),
  fleet: FleetClientConfigSchema.optional(),
  offline: OfflinePolicyConfigSchema.optional(),
});
export type SecureShipConfig = z.infer<typeof ConfigSchema>;
