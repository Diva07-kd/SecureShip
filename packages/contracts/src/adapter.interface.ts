import { z } from 'zod';
import type { FindingCategory, NormalizedFinding, ScannerName } from './finding.schema.js';
import type { ProjectProfile } from './project-profile.schema.js';

export const ScanExecutionStatusSchema = z.enum([
  'SUCCESS',
  'PARTIAL_FAILURE',
  'TIMEOUT',
  'TOOL_MISSING',
  'ERROR',
]);
export type ScanExecutionStatus = z.infer<typeof ScanExecutionStatusSchema>;

export const ScanExecutionResultSchema = z.object({
  scannerName: z.string(),
  status: ScanExecutionStatusSchema,
  findings: z.array(z.any()), // Validated findings list
  durationMs: z.number().nonnegative(),
  exitCode: z.number().nullable(),
  rawOutputRedacted: z.string().optional(),
  errorMessage: z.string().optional(),
  timedOut: z.boolean().default(false),
});
export type ScanExecutionResult = {
  scannerName: ScannerName;
  status: ScanExecutionStatus;
  findings: NormalizedFinding[];
  durationMs: number;
  exitCode: number | null;
  rawOutputRedacted?: string;
  errorMessage?: string;
  timedOut: boolean;
};

export interface ScanOptions {
  timeoutMs?: number;
  maxBufferBytes?: number;
  rulePaths?: string[];
  includeTests?: boolean;
  incrementalDiffOnly?: boolean;
  changedFiles?: string[];
}

export interface IScannerAdapter {
  readonly name: ScannerName;
  readonly category: FindingCategory;
  version(): Promise<string>;
  isAvailable(): Promise<boolean>;
  supportsProject(profile: ProjectProfile): boolean;
  scan(targetDir: string, options?: ScanOptions): Promise<ScanExecutionResult>;
}
