import { z } from 'zod';
import {
  FindingCategorySchema,
  SeveritySchema,
  VerificationStatusSchema,
} from './finding.schema.js';

export const PatchProposalSchema = z.object({
  findingFingerprint: z.string().min(1),
  summary: z.string().max(400),
  diff: z.string().max(20000),
  rationale: z.string().max(600),
  assumptions: z.array(z.string().max(200)).max(5),
  risks: z.array(z.string().max(200)).max(5),
  model: z.string().min(1),
  promptVersion: z.string().min(1),
  attempt: z.number().int().positive(),
});
export type PatchProposal = z.infer<typeof PatchProposalSchema>;

export const PatchPolicyViolationCodeSchema = z.enum([
  'MALFORMED_DIFF',
  'CONTEXT_MISMATCH',
  'OUTSIDE_ROOT',
  'PROTECTED_PATH',
  'TEST_FILE',
  'SENSITIVE_FILE',
  'BINARY_PATCH',
  'SYMLINK',
  'MODE_CHANGE',
  'NEW_FILE',
  'DELETE_FILE',
  'RENAME',
  'TOO_MANY_FILES',
  'TOO_MANY_LINES',
  'OUTSIDE_SCOPE',
  'SUPPRESSION_MARKER',
  'NEW_DEPENDENCY',
  'NEW_DANGEROUS_API',
  'SECRET_IN_PATCH',
  'HIDDEN_UNICODE',
  'REMOVAL_ONLY',
  'EXCESSIVE_DELETION',
  'EOL_INCONSISTENT',
]);
export type PatchPolicyViolationCode = z.infer<typeof PatchPolicyViolationCodeSchema>;

export const PatchPolicyViolationSchema = z.object({
  code: PatchPolicyViolationCodeSchema,
  detail: z.string(),
  file: z.string().optional(),
  line: z.number().int().optional(),
});
export type PatchPolicyViolation = z.infer<typeof PatchPolicyViolationSchema>;

export const PatchPolicyResultSchema = z.object({
  allowed: z.boolean(),
  violations: z.array(PatchPolicyViolationSchema),
});
export type PatchPolicyResult = z.infer<typeof PatchPolicyResultSchema>;

export const StageIdSchema = z.enum([
  'APPLY',
  'POLICY',
  'SYNTAX',
  'RESCAN',
  'NEW_FINDINGS',
  'IMPORTS',
  'INSTALL',
  'TYPECHECK',
  'BUILD',
  'TEST',
]);
export type StageId = z.infer<typeof StageIdSchema>;

export const StageOutcomeSchema = z.enum(['PASS', 'FAIL', 'SKIPPED', 'INCONCLUSIVE']);
export type StageOutcome = z.infer<typeof StageOutcomeSchema>;

export const StageResultSchema = z.object({
  id: StageIdSchema,
  outcome: StageOutcomeSchema,
  detail: z.string(),
  durationMs: z.number().int().nonnegative(),
  argv: z.array(z.string()).optional(),
  exitCode: z.number().int().nullable().optional(),
  baselineExitCode: z.number().int().nullable().optional(),
  flakyRerun: z.boolean().optional(),
  outputSha256: z.string().optional(),
  outputTail: z.string().max(2048).optional(),
});
export type StageResult = z.infer<typeof StageResultSchema>;

export const BaseFileRecordSchema = z.object({
  path: z.string().min(1),
  sha256: z.string().length(64),
});
export type BaseFileRecord = z.infer<typeof BaseFileRecordSchema>;

export const FindingRefSchema = z.object({
  fingerprint: z.string().min(1),
  ruleId: z.string().min(1),
  category: FindingCategorySchema,
  severity: SeveritySchema,
  file: z.string().min(1),
  line: z.number().int().positive(),
});
export type FindingRef = z.infer<typeof FindingRefSchema>;

export const SandboxMetadataSchema = z.object({
  backend: z.enum(['container', 'host', 'none', 'native-isolated', 'auto']),
  runtime: z.string().optional(),
  runtimeVersion: z.string().optional(),
  imageDigest: z.string().optional(),
  networkMode: z.string(),
  limits: z.record(z.string(), z.unknown()),
});
export type SandboxMetadata = z.infer<typeof SandboxMetadataSchema>;

export const ScannerMetadataSchema = z.object({
  name: z.string(),
  version: z.string(),
});
export type ScannerMetadata = z.infer<typeof ScannerMetadataSchema>;

export const FixReportSchema = z.object({
  schemaVersion: z.literal('1.0'),
  tool: z.string().default('secureship'),
  findingRef: FindingRefSchema,
  patchSha256: z.string().length(64),
  proposalSummary: z.string(),
  baseFiles: z.array(BaseFileRecordSchema),
  status: VerificationStatusSchema,
  requirement: VerificationStatusSchema,
  requirementMet: z.boolean(),
  stages: z.array(StageResultSchema),
  sandbox: SandboxMetadataSchema,
  scanners: z.array(ScannerMetadataSchema),
  attempts: z.number().int().positive(),
  limitations: z.array(z.string()),
  disclaimer: z.string(),
  createdAt: z.string(),
  signature: z.string(),
});
export type FixReport = z.infer<typeof FixReportSchema>;
