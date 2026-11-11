import { z } from 'zod';

export const OfflineComponentFileSchema = z.object({
  path: z.string(),
  size: z.number().int().nonnegative(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/i),
  mode: z.number().int().optional(),
});
export type OfflineComponentFile = z.infer<typeof OfflineComponentFileSchema>;

export const OfflineComponentSchema = z.object({
  id: z.string(),
  kind: z.enum(['db', 'tool', 'license']),
  version: z.string(),
  upstreamUpdatedAt: z.string().optional(),
  upstreamMetadata: z.record(z.unknown()).optional(),
  totalSizeBytes: z.number().int().nonnegative().default(0),
  files: z.array(OfflineComponentFileSchema).default([]),
});
export type OfflineComponent = z.infer<typeof OfflineComponentSchema>;

export const OfflineGenerationManifestSchema = z.object({
  schemaVersion: z.literal(1),
  generationId: z.string(),
  createdAt: z.string(),
  importedAt: z.string(),
  trust: z.enum(['VERIFIED', 'UNSIGNED', 'PIN_MATCH']),
  keyId: z.string().optional(),
  bundleId: z.string().optional(),
  cliVersion: z.string().optional(),
  components: z.array(OfflineComponentSchema).default([]),
});
export type OfflineGenerationManifest = z.infer<typeof OfflineGenerationManifestSchema>;

export interface OfflineDatabaseProvenance {
  id: string;
  version: string;
  upstreamUpdatedAt?: string;
  importedAt: string;
  ageDays: number;
  trust: 'VERIFIED' | 'UNSIGNED' | 'PIN_MATCH';
  generationId: string;
  bundleId?: string;
}

export interface OfflineContext {
  enabled: boolean;
  completeness: 'COMPLETE' | 'DEGRADED';
  generationId?: string;
  generationDir?: string;
  trivyCacheDir?: string;
  osvDbDir?: string;
  databases: OfflineDatabaseProvenance[];
  warnings: string[];
  error?: string;
}

export interface FreshnessResult {
  ageDays: number;
  isStale: boolean;
  isExpired: boolean;
  status: 'FRESH' | 'STALE' | 'EXPIRED';
  evaluatedTimestamp: string;
}

export const OfflineBundleManifestSchema = z.object({
  schemaVersion: z.literal(1),
  createdAt: z.string(),
  cliVersion: z.string(),
  bundleId: z.string(),
  platforms: z.array(z.string()).default([]),
  toolPins: z.record(z.string(), z.unknown()).optional(),
  totalSize: z.number().int().nonnegative(),
  keyId: z.string().optional(),
  signature: z.string().optional(),
  components: z.array(OfflineComponentSchema).default([]),
});
export type OfflineBundleManifest = z.infer<typeof OfflineBundleManifestSchema>;
