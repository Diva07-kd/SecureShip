import {
  type AiExecutionSummary,
  type LicenseTier,
  type NormalizedFinding,
  OfflineProvenance,
  type ScannerExecutionSummary,
  type ScanReport,
  ScanReportSchema,
  type SuppressedFinding,
} from '@secureship/contracts';
import { SuppressionLedger } from '../suppression/ledger.js';

export interface ReportBuilderOptions {
  targetDir: string;
  mode: 'FULL' | 'DIFF';
  diffBase?: string;
  startedAt: string;
  durationMs: number;
  scanners: ScannerExecutionSummary[];
  ledger: SuppressionLedger;
  ai?: AiExecutionSummary;
  tier?: LicenseTier;
  warnings?: string[];
  includeReachability?: boolean;
  functionLevelOptions?: { skippedTier?: number };
  offline?: OfflineProvenance;
}

export class ReportBuilder {
  /**
   * Constructs and strictly schema-validates a ScanReport.
   */
  public static build(options: ReportBuilderOptions): ScanReport {
    const summary = options.ledger.computeSummary(
      options.includeReachability ?? true,
      options.functionLevelOptions
    );
    const findings: NormalizedFinding[] = options.ledger.getReportedFindings();
    const suppressed: SuppressedFinding[] = options.ledger.getSuppressedFindings();

    const rawReport = {
      schemaVersion: '1.3' as const,
      tool: {
        name: 'secureship',
        version: '1.0.0-beta.1',
      },
      target: options.targetDir,
      mode: options.mode,
      diffBase: options.diffBase,
      startedAt: options.startedAt,
      durationMs: options.durationMs,
      scanners: options.scanners,
      findings,
      suppressed,
      summary,
      ai: options.ai,
      tier: options.tier,
      offline: options.offline,
      warnings: options.warnings ?? [],
    };

    return ScanReportSchema.parse(rawReport);
  }
}
