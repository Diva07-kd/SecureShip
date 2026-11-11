import { z } from 'zod';

export interface SarifRegion {
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  snippet?: { text?: string; [key: string]: unknown };
  [key: string]: unknown;
}

export const SarifRegionSchema: z.ZodType<SarifRegion> = z
  .object({
    startLine: z.number().int().optional(),
    endLine: z.number().int().optional(),
    startColumn: z.number().int().optional(),
    endColumn: z.number().int().optional(),
    snippet: z
      .object({
        text: z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

export interface SarifArtifactLocation {
  uri?: string;
  uriBaseId?: string;
  index?: number;
  [key: string]: unknown;
}

export const SarifArtifactLocationSchema: z.ZodType<SarifArtifactLocation> = z
  .object({
    uri: z.string().optional(),
    uriBaseId: z.string().optional(),
    index: z.number().int().optional(),
  })
  .passthrough();

export interface SarifPhysicalLocation {
  artifactLocation?: SarifArtifactLocation;
  region?: SarifRegion;
  [key: string]: unknown;
}

export const SarifPhysicalLocationSchema: z.ZodType<SarifPhysicalLocation> = z
  .object({
    artifactLocation: SarifArtifactLocationSchema.optional(),
    region: SarifRegionSchema.optional(),
  })
  .passthrough();

export interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
  message?: { text?: string; [key: string]: unknown };
  [key: string]: unknown;
}

export const SarifLocationSchema: z.ZodType<SarifLocation> = z
  .object({
    physicalLocation: SarifPhysicalLocationSchema.optional(),
    message: z
      .object({
        text: z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text?: string; [key: string]: unknown };
  fullDescription?: { text?: string; markdown?: string; [key: string]: unknown };
  help?: { text?: string; markdown?: string; [key: string]: unknown };
  helpUri?: string;
  properties?: Record<string, unknown>;
  defaultConfiguration?: { level?: string; [key: string]: unknown };
  [key: string]: unknown;
}

export const SarifRuleSchema: z.ZodType<SarifRule> = z
  .object({
    id: z.string(),
    name: z.string().optional(),
    shortDescription: z
      .object({
        text: z.string().optional(),
      })
      .passthrough()
      .optional(),
    fullDescription: z
      .object({
        text: z.string().optional(),
        markdown: z.string().optional(),
      })
      .passthrough()
      .optional(),
    help: z
      .object({
        text: z.string().optional(),
        markdown: z.string().optional(),
      })
      .passthrough()
      .optional(),
    helpUri: z.string().optional(),
    properties: z.record(z.string(), z.unknown()).optional(),
    defaultConfiguration: z
      .object({
        level: z.string().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

export interface SarifSuppression {
  kind?: string;
  justification?: string;
  status?: string;
  [key: string]: unknown;
}

export interface SarifResult {
  ruleId?: string;
  ruleIndex?: number;
  message?: { text?: string; markdown?: string; [key: string]: unknown };
  level?: string;
  locations?: SarifLocation[];
  partialFingerprints?: Record<string, string>;
  properties?: Record<string, unknown>;
  suppressions?: SarifSuppression[];
  [key: string]: unknown;
}

export const SarifResultSchema: z.ZodType<SarifResult> = z
  .object({
    ruleId: z.string().optional(),
    ruleIndex: z.number().int().optional(),
    message: z
      .object({
        text: z.string().optional(),
        markdown: z.string().optional(),
      })
      .passthrough()
      .optional(),
    level: z.string().optional(),
    locations: z.array(SarifLocationSchema).optional(),
    partialFingerprints: z.record(z.string(), z.string()).optional(),
    properties: z.record(z.string(), z.unknown()).optional(),
    suppressions: z
      .array(
        z
          .object({
            kind: z.string().optional(),
            justification: z.string().optional(),
            status: z.string().optional(),
          })
          .passthrough()
      )
      .optional(),
  })
  .passthrough();

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version?: string;
      rules?: SarifRule[];
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  results?: SarifResult[];
  originalUriBaseIds?: Record<string, { uri?: string; uriBaseId?: string; [key: string]: unknown }>;
  [key: string]: unknown;
}

export const SarifRunSchema: z.ZodType<SarifRun> = z
  .object({
    tool: z
      .object({
        driver: z
          .object({
            name: z.string(),
            version: z.string().optional(),
            rules: z.array(SarifRuleSchema).optional(),
          })
          .passthrough(),
      })
      .passthrough(),
    results: z.array(SarifResultSchema).optional(),
    originalUriBaseIds: z
      .record(
        z.string(),
        z
          .object({
            uri: z.string().optional(),
            uriBaseId: z.string().optional(),
          })
          .passthrough()
      )
      .optional(),
  })
  .passthrough();

export interface SarifLog {
  version?: string;
  $schema?: string;
  runs?: SarifRun[];
  [key: string]: unknown;
}

export const SarifLogSchema: z.ZodType<SarifLog> = z
  .object({
    version: z.string().optional(),
    $schema: z.string().optional(),
    runs: z.array(SarifRunSchema).default([]),
  })
  .passthrough();
