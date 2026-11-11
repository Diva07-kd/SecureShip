import { z } from 'zod';
import { ScannerNameSchema } from './finding.schema.js';

export const DetectedLanguageSchema = z.enum([
  'TypeScript',
  'JavaScript',
  'Python',
  'Go',
  'Java',
  'Rust',
  'PHP',
  'Ruby',
]);
export type DetectedLanguage = z.infer<typeof DetectedLanguageSchema>;

export const DetectedPackageManagerSchema = z.enum([
  'pnpm',
  'npm',
  'yarn',
  'pip',
  'poetry',
  'go',
  'maven',
  'cargo',
  'composer',
  'bundler',
]);
export type DetectedPackageManager = z.infer<typeof DetectedPackageManagerSchema>;

export const ProjectProfileSchema = z.object({
  workspaceRoot: z.string().min(1),
  languages: z.array(DetectedLanguageSchema).default([]),
  frameworks: z.array(z.string()).default([]),
  packageManagers: z.array(DetectedPackageManagerSchema).default([]),
  lockfiles: z.array(z.string()).default([]),
  iacManifests: z.array(z.string()).default([]),
  testDirectories: z.array(z.string()).default([]),
  recommendedScanners: z.array(ScannerNameSchema).default([]),
  totalFilesScanned: z.number().int().nonnegative().default(0),
  hasGit: z.boolean().default(false),
});

export type ProjectProfile = z.infer<typeof ProjectProfileSchema>;
