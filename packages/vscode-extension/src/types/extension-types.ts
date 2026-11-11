/**
 * Local extension types mirroring @secureship/contracts schemas.
 *
 * NOTE: The extension does not import @secureship/contracts directly
 * to ensure zero unnecessary dependencies and avoid bundling WASM
 * or native binaries into the .vsix package.
 */

export type ExtSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ExtCategory = 'SAST' | 'SCA' | 'SECRET' | 'IAC' | 'SUPPLY_CHAIN';

export type ExtReachability = 'REACHABLE' | 'UNREACHABLE' | 'UNKNOWN' | 'NOT_APPLICABLE';

export type ExtLicenseTier = 'FREE_BYOK' | 'PRO_TEAM' | 'ENTERPRISE';

export type ExtScannerName =
  | 'opengrep'
  | 'semgrep'
  | 'gitleaks'
  | 'osv-scanner'
  | 'trivy'
  | 'checkov'
  | 'generic'
  | string;

export interface ExtFindingLocation {
  filePath: string;
  startLine: number; // 1-indexed (per CLI / NormalizedFinding contract)
  endLine: number; // 1-indexed
  startColumn?: number;
  endColumn?: number;
  redactedSnippet?: string;
}

export interface ExtPackageInfo {
  ecosystem?: string;
  name: string;
  version?: string;
  fixedVersion?: string;
}

export interface ExtFixRecommendation {
  explanation: string;
  proposedDiff?: string;
  replacementContent?: string;
  suggestedPackageUpgrade?: {
    packageName: string;
    currentVersion: string;
    targetVersion: string;
  };
}

export interface ExtAiCitation {
  file: string;
  line: number;
  quote: string;
}

export interface ExtAiTriage {
  verdict: 'LIKELY_TRUE_POSITIVE' | 'LIKELY_FALSE_POSITIVE' | 'NEEDS_HUMAN_REVIEW';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  rationale: string;
  citations?: ExtAiCitation[];
  exploitabilityNotes?: string;
  model?: string;
  promptVersion?: string;
  cached?: boolean;
}

export interface ExtScannerEvidence {
  scannerName: string;
  scannerRuleId: string;
  message: string;
  timestamp?: string;
  metadata?: Record<string, unknown>;
}

export interface ExtNormalizedFinding {
  id: string; // UUID
  fingerprint: string; // 64-char SHA-256
  ruleId: string;
  scannerName: ExtScannerName;
  category: ExtCategory;
  severity: ExtSeverity;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  reachability?: ExtReachability;
  location: ExtFindingLocation;
  title: string;
  description: string;
  aiTriage?: ExtAiTriage;
  fixRecommendation?: ExtFixRecommendation;
  package?: ExtPackageInfo;
  cweIds?: string[];
  aliases?: string[];
  evidence?: ExtScannerEvidence[];
  lockfilePath?: string;
}

export interface ExtScannerExecutionSummary {
  name: string;
  version?: string;
  status: 'SUCCESS' | 'FAILED' | 'SKIPPED' | 'TIMEOUT' | string;
  durationMs: number;
  rawFindingCount: number;
  errorMessage?: string;
}

export interface ExtScanSummary {
  totalRaw: number;
  totalReported: number;
  totalSuppressed: number;
  totalOutOfScope?: number;
  bySeverity: Record<ExtSeverity, number>;
  byCategory: Record<string, number>;
  byReachability?: Record<string, number>;
}

export interface ExtScanReport {
  schemaVersion?: '1.0' | '1.1' | '1.2' | string;
  tool?: {
    name: string;
    version: string;
  };
  target?: string;
  mode?: 'FULL' | 'DIFF' | string;
  startedAt?: string;
  durationMs?: number;
  findings: ExtNormalizedFinding[];
  suppressed?: unknown[];
  summary: ExtScanSummary;
  scanners?: ExtScannerExecutionSummary[];
  tier?: ExtLicenseTier;
  warnings?: string[];
}

export interface ExtCliStatus {
  tier: ExtLicenseTier;
  status: string;
  email?: string;
  seats?: number;
  daysRemaining?: number;
  capabilities?: Record<string, boolean>;
  monthlyAiUsage?: {
    used: number;
    limit: number;
  };
}

export interface ScanState {
  status: 'idle' | 'scanning' | 'complete' | 'error';
  lastReport?: ExtScanReport | null;
  lastScanAt?: Date;
  errorMessage?: string;
}
