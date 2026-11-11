import { z } from 'zod';

export const ScannerNameSchema = z.enum([
  'opengrep',
  'semgrep',
  'gitleaks',
  'osv-scanner',
  'trivy',
  'checkov',
  'generic',
]);
export type ScannerName = z.infer<typeof ScannerNameSchema>;

export const FindingCategorySchema = z.enum(['SAST', 'SCA', 'SECRET', 'IAC', 'SUPPLY_CHAIN']);
export type FindingCategory = z.infer<typeof FindingCategorySchema>;

export const SeveritySchema = z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
export type Severity = z.infer<typeof SeveritySchema>;

export const ConfidenceSchema = z.enum(['HIGH', 'MEDIUM', 'LOW']);
export type Confidence = z.infer<typeof ConfidenceSchema>;

import {
  ReachabilitySchema,
  type Reachability,
  ReachabilityDetailSchema,
  type ReachabilityDetail,
} from './reachability.schema.js';
export { ReachabilitySchema, type Reachability, ReachabilityDetailSchema, type ReachabilityDetail };

export const VerificationStatusSchema = z.enum([
  'UNVERIFIED',
  'VERIFIED_STATIC',
  'VERIFIED_RUNTIME',
  'FAILED',
  'INCONCLUSIVE',
]);
export type VerificationStatus = z.infer<typeof VerificationStatusSchema>;

export const UpstreamValidationStatusSchema = z.enum([
  'VALIDATED_UPSTREAM',
  'UNVALIDATED',
  'UNKNOWN',
]);
export type UpstreamValidationStatus = z.infer<typeof UpstreamValidationStatusSchema>;

export const ScopeTagSchema = z.enum(['PRODUCTION', 'TEST_OR_MOCK', 'DOCUMENTATION', 'EXAMPLE']);
export type ScopeTag = z.infer<typeof ScopeTagSchema>;

export const FindingLocationSchema = z.object({
  filePath: z.string().min(1),
  startLine: z.number().int().nonnegative(),
  endLine: z.number().int().nonnegative(),
  startColumn: z.number().int().nonnegative().optional(),
  endColumn: z.number().int().nonnegative().optional(),
  redactedSnippet: z.string().optional(),
});
export type FindingLocation = z.infer<typeof FindingLocationSchema>;

export const ScannerEvidenceSchema = z.object({
  scannerName: ScannerNameSchema,
  scannerRuleId: z.string(),
  message: z.string(),
  timestamp: z.string().datetime().optional(),
  metadata: z.record(z.unknown()).optional(),
});
export type ScannerEvidence = z.infer<typeof ScannerEvidenceSchema>;

export const FixRecommendationSchema = z.object({
  explanation: z.string(),
  proposedDiff: z.string().optional(),
  replacementContent: z.string().optional(),
  suggestedPackageUpgrade: z
    .object({
      packageName: z.string(),
      currentVersion: z.string(),
      targetVersion: z.string(),
    })
    .optional(),
});
export type FixRecommendation = z.infer<typeof FixRecommendationSchema>;

export const AiVerdictSchema = z.enum([
  'LIKELY_TRUE_POSITIVE',
  'LIKELY_FALSE_POSITIVE',
  'NEEDS_HUMAN_REVIEW',
]);
export type AiVerdict = z.infer<typeof AiVerdictSchema>;

export const AiCitationSchema = z.object({
  file: z.string(),
  line: z.number().int().positive(),
  quote: z.string().max(200),
});
export type AiCitation = z.infer<typeof AiCitationSchema>;

export const AiTriageSchema = z.object({
  verdict: AiVerdictSchema,
  confidence: ConfidenceSchema,
  rationale: z.string().max(600),
  citations: z.array(AiCitationSchema).max(5),
  exploitabilityNotes: z.string().max(300).optional(),
  model: z.string(),
  promptVersion: z.string(),
  cached: z.boolean(),
  consistency: z
    .object({
      samples: z.number().int().positive(),
      agreed: z.boolean(),
    })
    .optional(),
  tokens: z
    .object({
      in: z.number().int().nonnegative(),
      out: z.number().int().nonnegative(),
    })
    .optional(),
  injectionFlag: z.boolean().optional(),
});
export type AiTriage = z.infer<typeof AiTriageSchema>;

export const NormalizedFindingSchema = z.object({
  id: z.string().min(1),
  fingerprint: z.string().length(64), // SHA-256
  ruleId: z.string().min(1),
  scannerName: ScannerNameSchema,
  category: FindingCategorySchema,
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  reachability: ReachabilitySchema.default('UNKNOWN'),
  reachabilityDetail: ReachabilityDetailSchema.optional(),
  location: FindingLocationSchema,
  upstreamValidationStatus: UpstreamValidationStatusSchema.default('UNKNOWN'),
  verificationStatus: VerificationStatusSchema.default('UNVERIFIED'),
  scopeTag: ScopeTagSchema.default('PRODUCTION'),
  title: z.string(),
  description: z.string(),
  cweIds: z.array(z.string()).default([]),
  aliases: z.array(z.string()).optional(),
  package: z
    .object({
      ecosystem: z.string(),
      name: z.string(),
      version: z.string(),
      fixedVersion: z.string().optional(),
    })
    .optional(),
  lockfilePath: z.string().optional(),
  evidence: z.array(ScannerEvidenceSchema).min(1),
  fixRecommendation: FixRecommendationSchema.optional(),
  aiTriage: AiTriageSchema.optional(),
  createdAt: z.string().datetime(),
});

export type NormalizedFinding = z.infer<typeof NormalizedFindingSchema>;
