import { z } from 'zod';

export const SymbolEntryPointKindSchema = z.enum(['FUNCTION', 'CLASS', 'METHOD', 'PROPERTY']);
export type SymbolEntryPointKind = z.infer<typeof SymbolEntryPointKindSchema>;

export const SymbolTriggerConditionSchema = z.enum(['CALL', 'IMPORT_TIME', 'UNKNOWN']);
export type SymbolTriggerCondition = z.infer<typeof SymbolTriggerConditionSchema>;

export const SymbolEntryPointSchema = z
  .object({
    module: z.string().min(1, 'module must be non-empty (use . for root module)'),
    export: z.string().min(1, 'export must be non-empty (e.g. template or default)'),
    kind: SymbolEntryPointKindSchema,
    via: z.array(z.string().min(1)).optional(),
  })
  .strict()
  .refine(
    (ep: { module: string; export: string; kind: SymbolEntryPointKind; via?: string[] }) => {
      if (ep.kind === 'METHOD') {
        return Array.isArray(ep.via) && ep.via.length > 0;
      }
      return true;
    },
    {
      message:
        'entryPoints of kind METHOD must specify a non-empty via array of exports producing instances',
      path: ['via'],
    }
  );
export type SymbolEntryPoint = z.infer<typeof SymbolEntryPointSchema>;

export const VulnerableSymbolEntrySchema = z
  .object({
    id: z.string().min(1),
    aliases: z.array(z.string()).default([]),
    ecosystem: z.enum(['npm', 'pypi']),
    package: z.string().min(1),
    entryPoints: z.array(SymbolEntryPointSchema).min(1, 'At least one entry point must be defined'),
    triggeredOn: SymbolTriggerConditionSchema,
    entryPointsComplete: z.boolean(),
    sourceUrls: z.array(z.string().url()).min(1, 'At least one source advisory URL is required'),
    fixCommitUrls: z.array(z.string().url()).min(1, 'At least one fix commit URL is required'),
    verifiedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'verifiedAt must be YYYY-MM-DD'),
    verifiedBy: z.string().min(1),
    notes: z.string(),
  })
  .strict();
export type VulnerableSymbolEntry = z.infer<typeof VulnerableSymbolEntrySchema>;

export const VulnerableSymbolDatasetSchema = z
  .object({
    version: z.string().min(1),
    datasetId: z.string().min(1),
    description: z.string().optional(),
    entries: z.array(VulnerableSymbolEntrySchema),
  })
  .strict();
export type VulnerableSymbolDataset = z.infer<typeof VulnerableSymbolDatasetSchema>;

export const SymbolDatasetManifestSchema = z
  .object({
    filename: z.string().min(1),
    sha256: z
      .string()
      .regex(/^[a-f0-9]{64}$/, 'sha256 must be a 64-character lowercase hex digest'),
    bytes: z.number().int().positive(),
    entryCount: z.number().int().nonnegative(),
    updatedAt: z.string(),
  })
  .strict();
export type SymbolDatasetManifest = z.infer<typeof SymbolDatasetManifestSchema>;

/**
 * Checks if a dataset entry meets all criteria to permit HIGH confidence pruning.
 * Anti-Cheat and Soundness Rule:
 * Entries with triggeredOn != CALL, kind METHOD without via, or entryPointsComplete == false
 * are never used for HIGH pruning.
 */
export function isEligibleForHighPruning(entry: VulnerableSymbolEntry): boolean {
  if (entry.triggeredOn !== 'CALL') {
    return false;
  }
  if (!entry.entryPointsComplete) {
    return false;
  }
  for (const ep of entry.entryPoints) {
    if (ep.kind === 'METHOD' && (!ep.via || ep.via.length === 0)) {
      return false;
    }
  }
  return true;
}
