import {
  type NormalizedFinding,
  type ScanReport,
  type Severity,
  type SuppressedFinding,
  whiteLabelRuleId,
} from '@secureship/contracts';

export interface SarifExporterOptions {
  includeSuppressed?: boolean;
}

export class SarifExporter {
  /**
   * Maps SecureShip Severity to standard SARIF result level.
   */
  public static toSarifLevel(severity: Severity): 'error' | 'warning' | 'note' | 'none' {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'note';
      case 'INFO':
        return 'none';
      default:
        return 'warning';
    }
  }

  /**
   * Maps SecureShip Severity to standard CVSS numerical score.
   */
  public static toCvssScore(severity: Severity): string {
    switch (severity) {
      case 'CRITICAL':
        return '9.5';
      case 'HIGH':
        return '8.0';
      case 'MEDIUM':
        return '5.5';
      case 'LOW':
        return '2.0';
      case 'INFO':
        return '0.0';
      default:
        return '5.0';
    }
  }

  /**
   * Generates a fully compliant SARIF 2.1.0 document from a ScanReport.
   */
  public static export(report: ScanReport, options: SarifExporterOptions = {}): string {
    const rulesMap = new Map<
      string,
      {
        id: string;
        name?: string;
        shortDescription?: { text: string };
        fullDescription?: { text: string };
        help?: { text: string };
        properties?: Record<string, unknown>;
      }
    >();

    const results: Array<Record<string, unknown>> = [];

    const processFinding = (finding: NormalizedFinding, suppression?: SuppressedFinding) => {
      const brandedRuleId = whiteLabelRuleId(finding.ruleId, finding.category);

      // 1. Add rule definition if not yet present
      if (!rulesMap.has(brandedRuleId)) {
        rulesMap.set(brandedRuleId, {
          id: brandedRuleId,
          name: finding.title,
          shortDescription: { text: finding.title },
          fullDescription: { text: finding.description },
          help: {
            text: finding.fixRecommendation?.explanation ?? finding.description,
          },
          properties: {
            tags: finding.cweIds.map((cwe) => `external/cwe/${cwe.toLowerCase()}`),
            'security-severity': SarifExporter.toCvssScore(finding.severity),
            precision: finding.confidence.toLowerCase(),
          },
        });
      }

      // 2. Format result
      const physicalLocation: Record<string, unknown> = {
        artifactLocation: {
          uri: finding.location.filePath,
        },
      };

      if (finding.location.startLine > 0) {
        const region: Record<string, unknown> = {
          startLine: finding.location.startLine,
          endLine: finding.location.endLine,
        };
        if (finding.location.startColumn !== undefined) {
          region['startColumn'] = finding.location.startColumn;
        }
        if (finding.location.endColumn !== undefined) {
          region['endColumn'] = finding.location.endColumn;
        }
        if (finding.location.redactedSnippet) {
          region['snippet'] = {
            text: finding.location.redactedSnippet,
          };
        }
        physicalLocation['region'] = region;
      }

      const resultObj: Record<string, unknown> = {
        ruleId: brandedRuleId,
        level: SarifExporter.toSarifLevel(finding.severity),
        message: {
          text: finding.description || finding.title,
        },
        locations: [
          {
            physicalLocation,
          },
        ],
        partialFingerprints: {
          'secureship/v1': finding.fingerprint,
        },
        properties: {
          severity: finding.severity,
          confidence: finding.confidence,
          category: finding.category,
          scopeTag: finding.scopeTag,
          aliases: Array.from(new Set([finding.ruleId, ...(finding.aliases ?? [])])),
          package: finding.package,
          secureship: {
            aiTriage: finding.aiTriage,
            reachability: finding.reachabilityDetail
              ? {
                  verdict: finding.reachabilityDetail.verdict,
                  confidence: finding.reachabilityDetail.analysisConfidence,
                  evidence: finding.reachabilityDetail.evidence,
                  limitations: finding.reachabilityDetail.limitations,
                }
              : undefined,
          },
        },
      };

      if (suppression) {
        resultObj['suppressions'] = [
          {
            kind: 'external',
            justification: suppression.reasonCode,
          },
        ];
      }

      results.push(resultObj);
    };

    // Add reported findings
    for (const f of report.findings) {
      processFinding(f);
    }

    // Add suppressed findings if requested
    if (options.includeSuppressed) {
      for (const s of report.suppressed) {
        processFinding(s.finding, s);
      }
    }

    const driverName =
      report.tool.name === 'secureship' ? 'SecureShip Security Suite' : report.tool.name;

    const sarifDoc = {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: driverName,
              fullName: 'SecureShip Security Suite - Complete AppSec & Supply Chain Engine',
              version: report.tool.version,
              informationUri: 'https://secureship.dev',
              rules: Array.from(rulesMap.values()),
            },
          },
          ...(report.offline
            ? {
                properties: {
                  offline: report.offline,
                },
              }
            : {}),
          results,
        },
      ],
    };

    return JSON.stringify(sarifDoc, null, 2);
  }
}
