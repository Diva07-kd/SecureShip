export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingCategory = 'SAST' | 'SCA' | 'SECRET' | 'IAC' | 'SUPPLY_CHAIN';

export type ReachabilityVerdict = 'REACHABLE' | 'UNREACHABLE' | 'UNKNOWN';

export interface SnippetLine {
  lineNumber: number;
  content: string;
  isTarget: boolean;
}

export interface CodeSnippet {
  filePath: string;
  startLine: number;
  endLine: number;
  targetStart: number;
  targetEnd: number;
  lines: SnippetLine[];
  rawContent: string;
}

export interface FindingLocation {
  filePath: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
  snippet?: string;
}

export interface NormalizedFinding {
  id: string;
  ruleId: string;
  scannerName: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  location: FindingLocation;
  cweIds: string[];
  owaspCategory: string;
  reachability: ReachabilityVerdict;
  confidence?: string;
  snippetContext?: CodeSnippet;
  snippet?: CodeSnippet;
  metadata?: Record<string, unknown>;
}

export interface ScannerSummary {
  name: string;
  status: string;
  durationMs?: number;
  rawFindingCount?: number;
  errorMessage?: string;
}

export interface ScanSummary {
  totalFindings: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  byOwasp: Record<string, number>;
  byScanner: Record<string, number>;
  byReachability: Record<string, number>;
  severityCounts?: Record<string, number>;
  owaspCounts?: Record<string, number>;
}

export interface ScanReport {
  id: string;
  jobId?: string;
  targetName?: string;
  status: string;
  durationMs: number;
  createdAt: string;
  scanners: ScannerSummary[];
  findings: NormalizedFinding[];
  summary: ScanSummary;
  warnings?: string[];
}

export type JobStatusType = 'queued' | 'running' | 'done' | 'failed';

export interface JobRecord {
  jobId: string;
  status: JobStatusType;
  stage: string;
  progress: number;
  pollUrl: string;
  reportUrl?: string;
  error?: string | null;
  targetName?: string;
  createdAt?: string;
  startedAt?: string;
  completedAt?: string;
}

export interface SystemHealth {
  status: string;
  version: string;
  queue: {
    queuedJobs: number;
    isProcessing: boolean;
    activeJobId: string | null;
  };
  scanners: Record<string, string>;
}
