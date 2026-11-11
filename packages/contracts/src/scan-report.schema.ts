import { z } from 'zod';
import {
  AiVerdictSchema,
  FindingCategorySchema,
  NormalizedFindingSchema,
  ReachabilitySchema,
  ScannerNameSchema,
  SeveritySchema,
} from './finding.schema.js';
import { ScanExecutionStatusSchema } from './adapter.interface.js';
import { SuppressedFindingSchema, SuppressionReasonCodeSchema } from './suppression.schema.js';
import { LicenseTierSchema } from './tier-policy.schema.js';

export const ScannerExecutionSummarySchema = z.object({
  name: ScannerNameSchema,
  version: z.string().optional(),
  status: ScanExecutionStatusSchema,
  durationMs: z.number().nonnegative(),
  rawFindingCount: z.number().int().nonnegative(),
  errorMessage: z.string().optional(),
});
export type ScannerExecutionSummary = z.infer<typeof ScannerExecutionSummarySchema>;

export const AiFindingSkipReasonSchema = z.object({
  reason: z.string(),
  count: z.number().int().nonnegative(),
});
export type AiFindingSkipReason = z.infer<typeof AiFindingSkipReasonSchema>;

export const AiPayloadDetailSchema = z.object({
  findingId: z.string(),
  ruleId: z.string(),
  filePath: z.string(),
  files: z.array(z.string()),
  bytes: z.number().int().nonnegative(),
  estimatedTokens: z.number().int().nonnegative(),
  payload: z.string(),
});
export type AiPayloadDetail = z.infer<typeof AiPayloadDetailSchema>;

export const AiExecutionSummarySchema = z.object({
  provider: z.string(),
  model: z.string(),
  host: z.string(),
  deterministic: z.boolean(),
  findingsConsidered: z.number().int().nonnegative(),
  findingsEligible: z.number().int().nonnegative().optional(),
  findingsSent: z.number().int().nonnegative(),
  findingsSkipped: z.array(AiFindingSkipReasonSchema),
  tokensIn: z.number().int().nonnegative(),
  tokensOut: z.number().int().nonnegative(),
  filesSent: z.array(z.string()),
  truncatedSlices: z.number().int().nonnegative(),
  cacheHits: z.number().int().nonnegative(),
  warnings: z.array(z.string()),
  dryRun: z.boolean().optional(),
  estimate: z.boolean().optional(),
  dryRunPayloads: z.array(AiPayloadDetailSchema).optional(),
});
export type AiExecutionSummary = z.infer<typeof AiExecutionSummarySchema>;

export const FunctionLevelSummarySchema = z.object({
  evaluated: z.number().int().nonnegative(),
  noSymbolData: z.number().int().nonnegative(),
  symbolReferenced: z.number().int().nonnegative(),
  callPathProven: z.number().int().nonnegative(),
  uninvoked: z.number().int().nonnegative(),
  escapedOrUnknown: z.number().int().nonnegative(),
  skippedTier: z.number().int().nonnegative(),
  blockedByReason: z.record(z.string(), z.number().int().nonnegative()),
});
export type FunctionLevelSummary = z.infer<typeof FunctionLevelSummarySchema>;

export const ScanSummarySchema = z.object({
  totalRaw: z.number().int().nonnegative(),
  totalReported: z.number().int().nonnegative(),
  totalSuppressed: z.number().int().nonnegative(),
  totalOutOfScope: z.number().int().nonnegative(),
  bySeverity: z.record(SeveritySchema, z.number().int().nonnegative()),
  byCategory: z.record(FindingCategorySchema, z.number().int().nonnegative()),
  byReachability: z.record(ReachabilitySchema, z.number().int().nonnegative()).optional(),
  unknownByEvidence: z.record(z.string(), z.number().int().nonnegative()).optional(),
  byAiVerdict: z.record(AiVerdictSchema, z.number().int().nonnegative()).optional(),
  suppressedByReason: z.record(SuppressionReasonCodeSchema, z.number().int().nonnegative()),
  functionLevel: FunctionLevelSummarySchema.optional(),
});
export type ScanSummary = z.infer<typeof ScanSummarySchema>;

export const OfflineDatabaseProvenanceSchema = z.object({
  id: z.string(),
  version: z.string(),
  upstreamUpdatedAt: z.string().optional(),
  importedAt: z.string(),
  ageDays: z.number().nonnegative(),
  trust: z.enum(['VERIFIED', 'UNSIGNED', 'PIN_MATCH']),
  generationId: z.string(),
  bundleId: z.string().optional(),
});
export type OfflineDatabaseProvenance = z.infer<typeof OfflineDatabaseProvenanceSchema>;

export const OfflineProvenanceSchema = z.object({
  enabled: z.boolean(),
  completeness: z.enum(['COMPLETE', 'DEGRADED']),
  databases: z.array(OfflineDatabaseProvenanceSchema),
});
export type OfflineProvenance = z.infer<typeof OfflineProvenanceSchema>;

export const ScanReportSchema = z.object({
  schemaVersion: z.enum(['1.0', '1.1', '1.2', '1.3']).default('1.2'),
  tool: z.object({
    name: z.string(),
    version: z.string(),
  }),
  target: z.string(),
  mode: z.enum(['FULL', 'DIFF']),
  diffBase: z.string().optional(),
  startedAt: z.string().datetime(),
  durationMs: z.number().nonnegative(),
  scanners: z.array(ScannerExecutionSummarySchema),
  findings: z.array(NormalizedFindingSchema),
  suppressed: z.array(SuppressedFindingSchema),
  summary: ScanSummarySchema,
  ai: AiExecutionSummarySchema.optional(),
  tier: LicenseTierSchema.optional(),
  offline: OfflineProvenanceSchema.optional(),
  warnings: z.array(z.string()).default([]),
});
export type ScanReport = z.infer<typeof ScanReportSchema>;
