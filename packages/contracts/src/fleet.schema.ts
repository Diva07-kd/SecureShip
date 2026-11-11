import { z } from 'zod';
import { SeveritySchema } from './finding.schema.js';
import { FindingCategorySchema } from './finding.schema.js';
import { ReachabilitySchema } from './reachability.schema.js';

export const FleetVulnerabilityItemSchema = z.object({
  ruleId: z.string(),
  severity: SeveritySchema,
  category: FindingCategorySchema,
  packageName: z.string().optional(),
  packageVersion: z.string().optional(),
  cveId: z.string().optional(),
  reachability: ReachabilitySchema.optional(),
  title: z.string().optional(),
});
export type FleetVulnerabilityItem = z.infer<typeof FleetVulnerabilityItemSchema>;

export const FleetSbomComponentSchema = z.object({
  name: z.string(),
  version: z.string(),
  ecosystem: z.string(),
  license: z.string().optional(),
  compliant: z.boolean().default(true),
});
export type FleetSbomComponent = z.infer<typeof FleetSbomComponentSchema>;

export const FleetIngestPayloadSchema = z.object({
  fleetToken: z.string(),
  repoName: z.string(),
  branch: z.string().default('main'),
  commitSha: z.string().default('head'),
  scannedAt: z.string(),
  durationMs: z.number().nonnegative(),
  summary: z.object({
    totalRaw: z.number().int().nonnegative(),
    totalReported: z.number().int().nonnegative(),
    totalSuppressed: z.number().int().nonnegative(),
    bySeverity: z.record(SeveritySchema, z.number().int().nonnegative()),
    byCategory: z.record(FindingCategorySchema, z.number().int().nonnegative()),
    byReachability: z.record(ReachabilitySchema, z.number().int().nonnegative()).optional(),
    reachabilitySuppressionPct: z.number().min(0).max(100).default(0),
  }),
  vulnerabilities: z.array(FleetVulnerabilityItemSchema).default([]),
  sbom: z
    .object({
      totalComponents: z.number().int().nonnegative(),
      compliantCount: z.number().int().nonnegative(),
      nonCompliantCount: z.number().int().nonnegative(),
      components: z.array(FleetSbomComponentSchema).default([]),
    })
    .optional(),
  signature: z.string().optional(),
});
export type FleetIngestPayload = z.infer<typeof FleetIngestPayloadSchema>;

export const RiskGradeSchema = z.enum(['A+', 'A', 'B', 'C', 'D', 'F']);
export type RiskGrade = z.infer<typeof RiskGradeSchema>;

export const FleetRepoSummarySchema = z.object({
  repoName: z.string(),
  branch: z.string(),
  commitSha: z.string(),
  latestScanAt: z.string(),
  riskGrade: RiskGradeSchema,
  riskScore: z.number().min(0).max(100),
  activeCriticals: z.number().int().nonnegative(),
  activeHighs: z.number().int().nonnegative(),
  reachableCount: z.number().int().nonnegative(),
  suppressedCount: z.number().int().nonnegative(),
  reachabilitySuppressionPct: z.number(),
  componentCount: z.number().int().nonnegative(),
  compliant: z.boolean(),
  vulnerabilities: z.array(FleetVulnerabilityItemSchema).default([]),
  sbomComponents: z.array(FleetSbomComponentSchema).default([]),
  signature: z.string().optional(),
});
export type FleetRepoSummary = z.infer<typeof FleetRepoSummarySchema>;

export const FleetExecutiveSummarySchema = z.object({
  totalRepos: z.number().int().nonnegative(),
  enterpriseScore: z.number().min(0).max(100),
  enterpriseGrade: RiskGradeSchema,
  totalCriticals: z.number().int().nonnegative(),
  totalHighs: z.number().int().nonnegative(),
  totalReachable: z.number().int().nonnegative(),
  totalSuppressed: z.number().int().nonnegative(),
  deadCodeSuppressionRate: z.number(),
  licenseComplianceRate: z.number(),
  latestActivity: z.string(),
});
export type FleetExecutiveSummary = z.infer<typeof FleetExecutiveSummarySchema>;

export const FleetPolicySchema = z.object({
  policyVersion: z.string().default('1.0'),
  failOnSeverity: SeveritySchema.default('HIGH'),
  blockUnreachableSca: z.boolean().default(false),
  deniedLicenses: z.array(z.string()).default(['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0']),
  requireHmacAudit: z.boolean().default(true),
  updatedAt: z.string(),
});
export type FleetPolicy = z.infer<typeof FleetPolicySchema>;

/**
 * Computes an executive risk score (0-100) and letter grade (A+ to F).
 * Reachable vulnerabilities carry higher weight than unreachable/test vulnerabilities.
 */
export function computeRepoScore(params: {
  reachableCriticals: number;
  unreachableCriticals: number;
  reachableHighs: number;
  unreachableHighs: number;
  mediums: number;
  licenseViolations: number;
  secrets: number;
}): { score: number; grade: RiskGrade } {
  let score = 100;

  // Reachable Critical: -25 pts, Unreachable Critical: -5 pts
  score -= params.reachableCriticals * 25;
  score -= params.unreachableCriticals * 5;

  // Reachable High: -12 pts, Unreachable High: -2 pts
  score -= params.reachableHighs * 12;
  score -= params.unreachableHighs * 2;

  // Medium: -1 pt
  score -= params.mediums * 1;

  // License violation: -10 pts
  score -= params.licenseViolations * 10;

  // Hardcoded Secret in code: -20 pts
  score -= params.secrets * 20;

  // Clamp 0 to 100
  score = Math.max(0, Math.min(100, Math.round(score)));

  let grade: RiskGrade = 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';
  else grade = 'F';

  return { score, grade };
}
