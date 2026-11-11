import { z } from 'zod';

export const ReachabilitySchema = z.enum([
  'REACHABLE_CALL_PATH',
  'REACHABLE_IMPORT',
  'UNREACHABLE',
  'UNKNOWN',
]);
export type Reachability = z.infer<typeof ReachabilitySchema>;

export const ReachabilityConfidenceSchema = z.enum(['HIGH', 'MEDIUM', 'LOW']);
export type ReachabilityConfidence = z.infer<typeof ReachabilityConfidenceSchema>;

export const ReachabilityEvidenceKindSchema = z.enum([
  'IMPORT_CHAIN',
  'PACKAGE_IMPORTED',
  'TRANSITIVE_VIA',
  'DEV_ONLY',
  'NOT_IMPORTED',
  'DEAD_FILE',
  'CONFIG_REFERENCE',
  'TEST_ONLY_IMPORT',
  'DYNAMIC_UNKNOWN',
  'NO_ENTRYPOINT',
  'UNSUPPORTED_LANGUAGE',
  'UNMAPPED_PACKAGE',
  'NO_LOCKFILE_TREE',
  'NOT_APPLICABLE',
  'PARSE_FAILURE',
  'TAINT_FLOW',
  // Phase B Function-Level Evidence Kinds
  'SYMBOL_REFERENCED',
  'SYMBOL_CALL_PATH',
  'UNINVOKED_SYMBOL',
  'NAMESPACE_ESCAPES',
  'SYMBOL_DATA_UNAVAILABLE',
]);
export type ReachabilityEvidenceKind = z.infer<typeof ReachabilityEvidenceKindSchema>;

export const SymbolSourceSchema = z.enum(['STRUCTURED_ADVISORY', 'CURATED_DB', 'HEURISTIC_TEXT']);
export type SymbolSource = z.infer<typeof SymbolSourceSchema>;

export const SymbolUsageSiteSchema = z.object({
  file: z.string(),
  line: z.number().int().nonnegative(),
  form: z.string(),
});
export type SymbolUsageSite = z.infer<typeof SymbolUsageSiteSchema>;

export const SymbolDatasetMetadataSchema = z.object({
  id: z.string(),
  sourceUrls: z.array(z.string()),
});
export type SymbolDatasetMetadata = z.infer<typeof SymbolDatasetMetadataSchema>;

export const TaintStepSchema = z.object({
  variable: z.string(),
  line: z.number(),
  column: z.number().optional(),
  codeSnippet: z.string().optional(),
  description: z.string().optional(),
});
export type TaintStep = z.infer<typeof TaintStepSchema>;

export const TaintFlowDetailSchema = z.object({
  sourceType: z.string(), // e.g. "HTTP_QUERY", "HTTP_BODY", "HTTP_PARAM", "CLI_ARG"
  sourceExpression: z.string(), // e.g. "req.query.id"
  sourceLine: z.number(),
  sinkType: z.string(), // e.g. "SQL_QUERY", "COMMAND_INJECTION", "EVAL_CODE", "FILE_READ"
  sinkExpression: z.string(), // e.g. "db.query(sql)"
  sinkLine: z.number(),
  taintSteps: z.array(TaintStepSchema).default([]),
  isExploitable: z.boolean().default(true),
});
export type TaintFlowDetail = z.infer<typeof TaintFlowDetailSchema>;

export const ReachabilityEvidenceSchema = z.object({
  kind: ReachabilityEvidenceKindSchema,
  chain: z.array(z.string()).max(10).optional(),
  via: z.array(z.string()).optional(),
  notes: z.string().optional(),
  taintFlow: TaintFlowDetailSchema.optional(),
  // Phase B Function-Level Evidence Fields
  symbols: z.array(z.string()).optional(),
  symbolSource: SymbolSourceSchema.optional(),
  usageSites: z.array(SymbolUsageSiteSchema).max(5).optional(),
  dataset: SymbolDatasetMetadataSchema.optional(),
  blockedBy: z.string().optional(),
});
export type ReachabilityEvidence = z.infer<typeof ReachabilityEvidenceSchema>;

export const ReachabilityDetailSchema = z.object({
  verdict: ReachabilitySchema,
  analysisConfidence: ReachabilityConfidenceSchema,
  evidence: ReachabilityEvidenceSchema,
  limitations: z.array(z.string()).default([]),
});
export type ReachabilityDetail = z.infer<typeof ReachabilityDetailSchema>;
