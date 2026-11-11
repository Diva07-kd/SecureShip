import { execFileSync } from 'node:child_process';
import path from 'node:path';
import crypto from 'node:crypto';
import pc from 'picocolors';
import {
  type FleetIngestPayload,
  type FleetPolicy,
  type FleetRepoSummary,
  type FleetVulnerabilityItem,
  type FleetSbomComponent,
  type ScanReport,
  type Reachability,
  FleetIngestPayloadSchema,
  FleetPolicySchema,
} from '@secureship/contracts';
import { discoverPackages, evaluateLicenseCompliance } from '@secureship/core-engine';
import { assertSafeFleetEndpoint } from '@secureship/fleet';

export interface GitInfo {
  repoName: string;
  branch: string;
  commitSha: string;
}

export class FleetClient {
  /**
   * Resolves Git metadata safely without failing if outside a Git repository.
   */
  public static resolveGitInfo(targetDir: string, defaultName?: string): GitInfo {
    let repoName = defaultName || path.basename(path.resolve(targetDir));
    let branch = 'main';
    let commitSha = '0000000000000000000000000000000000000000';

    try {
      const originUrl = execFileSync('git', ['config', '--get', 'remote.origin.url'], {
        cwd: targetDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        encoding: 'utf-8',
        timeout: 2000,
      }).trim();

      if (originUrl) {
        const match = originUrl.match(/[:/]([^/:]+?)(?:\.git)?$/);
        if (match && match[1]) {
          repoName = match[1];
        }
      }
    } catch {
      // Non-git directory or git not present
    }

    try {
      const branchOut = execFileSync('git', ['rev-parse', '--abbrev-ref', 'HEAD'], {
        cwd: targetDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        encoding: 'utf-8',
        timeout: 2000,
      }).trim();

      if (branchOut && branchOut !== 'HEAD') {
        branch = branchOut;
      }
    } catch {
      // Detached head or non-git
    }

    try {
      const commitOut = execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd: targetDir,
        stdio: ['ignore', 'pipe', 'ignore'],
        encoding: 'utf-8',
        timeout: 2000,
      }).trim();

      if (commitOut) {
        commitSha = commitOut;
      }
    } catch {
      // Non-git
    }

    return { repoName, branch, commitSha };
  }

  /**
   * Fetches central security policy from Fleet Server.
   */
  public static async fetchPolicy(
    fleetUrl: string,
    fleetToken?: string
  ): Promise<FleetPolicy | null> {
    try {
      const safeUrl = assertSafeFleetEndpoint(fleetUrl, { env: process.env });
      const normalizedUrl = safeUrl.origin;
      const headers: Record<string, string> = {
        Accept: 'application/json',
      };
      if (fleetToken) {
        headers['Authorization'] = `Bearer ${fleetToken}`;
      }

      const res = await fetch(`${normalizedUrl}/api/policy`, {
        method: 'GET',
        headers,
        redirect: 'error',
        signal: AbortSignal.timeout(15000),
      });

      if (!res.ok) {
        return null;
      }

      const json = await res.json();
      const parsed = FleetPolicySchema.safeParse(json);
      return parsed.success ? parsed.data : null;
    } catch {
      return null;
    }
  }

  /**
   * Extracts privacy-preserving, zero-code-leak metadata and pushes to SecureShip Fleet.
   */
  public static async pushTelemetry(options: {
    targetDir: string;
    report: ScanReport;
    fleetUrl: string;
    fleetToken?: string;
    repoName?: string;
    isJson?: boolean;
    c?: ReturnType<typeof pc.createColors>;
  }): Promise<{ success: boolean; repoSummary?: FleetRepoSummary; error?: string }> {
    const {
      targetDir,
      report,
      fleetUrl,
      fleetToken = 'secureship-default-fleet-token',
      isJson,
      c = pc,
    } = options;
    const safeUrl = assertSafeFleetEndpoint(fleetUrl, { env: process.env });
    const normalizedUrl = safeUrl.origin;

    try {
      const gitInfo = FleetClient.resolveGitInfo(targetDir, options.repoName);

      // Compute Reachability breakdown
      const byReachability: Record<Reachability, number> = {
        REACHABLE_CALL_PATH: 0,
        REACHABLE_IMPORT: 0,
        UNREACHABLE: 0,
        UNKNOWN: 0,
      };

      let reachableTotal = 0;
      let unreachableTotal = 0;

      for (const finding of report.findings) {
        if (finding.reachability) {
          byReachability[finding.reachability] = (byReachability[finding.reachability] || 0) + 1;
          if (
            finding.reachability === 'REACHABLE_CALL_PATH' ||
            finding.reachability === 'REACHABLE_IMPORT'
          ) {
            reachableTotal++;
          } else if (finding.reachability === 'UNREACHABLE') {
            unreachableTotal++;
          }
        }
      }

      const totalEvaluatedReachability = reachableTotal + unreachableTotal;
      const reachabilitySuppressionPct =
        totalEvaluatedReachability > 0
          ? Math.round((unreachableTotal / totalEvaluatedReachability) * 100)
          : 0;

      // Extract Zero-Code Vulnerabilities (Metadata ONLY - NO code snippets, NO raw diffs)
      const topVulnerabilities: FleetVulnerabilityItem[] = report.findings.slice(0, 50).map((f) => {
        let pkgName: string | undefined;
        let pkgVer: string | undefined;
        let cve: string | undefined;

        if (f.package) {
          pkgName = f.package.name;
          pkgVer = f.package.version;
        }

        if (f.aliases && f.aliases.length > 0) {
          cve = f.aliases.find((a) => a.startsWith('CVE-')) ?? f.aliases[0];
        }

        return {
          ruleId: f.ruleId,
          severity: f.severity,
          category: f.category,
          packageName: pkgName,
          packageVersion: pkgVer,
          cveId: cve,
          reachability: f.reachability,
          title: f.title || f.ruleId,
        };
      });

      // Discover SBOM packages and license compliance
      const pkgs = discoverPackages(path.resolve(targetDir));
      const compliance = evaluateLicenseCompliance(pkgs);

      const sbomComponents: FleetSbomComponent[] = pkgs.map((p) => {
        const isViolating = compliance.violations.some(
          (v) => v.packageName === p.name && v.version === p.version
        );
        const pkgLicense =
          typeof p.packageJson?.['license'] === 'string'
            ? (p.packageJson['license'] as string)
            : undefined;
        return {
          name: p.name,
          version: p.version,
          ecosystem: p.ecosystem,
          license: pkgLicense,
          compliant: !isViolating,
        };
      });

      const hmac = crypto.createHmac('sha256', fleetToken);
      hmac.update(
        `${gitInfo.repoName}:${gitInfo.commitSha}:${report.durationMs}:${report.summary.totalReported}`
      );
      const signature = hmac.digest('hex');

      const payload: FleetIngestPayload = {
        fleetToken,
        repoName: gitInfo.repoName,
        branch: gitInfo.branch,
        commitSha: gitInfo.commitSha,
        scannedAt: new Date().toISOString(),
        durationMs: report.durationMs,
        signature,
        summary: {
          totalRaw:
            report.summary.totalRaw ??
            report.summary.totalReported + (report.suppressed?.length ?? 0),
          totalReported: report.summary.totalReported,
          totalSuppressed: report.summary.totalSuppressed ?? report.suppressed?.length ?? 0,
          bySeverity: {
            CRITICAL: report.summary.bySeverity?.CRITICAL ?? 0,
            HIGH: report.summary.bySeverity?.HIGH ?? 0,
            MEDIUM: report.summary.bySeverity?.MEDIUM ?? 0,
            LOW: report.summary.bySeverity?.LOW ?? 0,
            INFO: report.summary.bySeverity?.INFO ?? 0,
          },
          byCategory: {
            SAST: report.summary.byCategory?.SAST ?? 0,
            SCA: report.summary.byCategory?.SCA ?? 0,
            SECRET: report.summary.byCategory?.SECRET ?? 0,
            IAC: report.summary.byCategory?.IAC ?? 0,
            SUPPLY_CHAIN: report.summary.byCategory?.SUPPLY_CHAIN ?? 0,
          },
          byReachability,
          reachabilitySuppressionPct,
        },
        vulnerabilities: topVulnerabilities,
        sbom: {
          totalComponents: pkgs.length,
          compliantCount: compliance.compliantCount,
          nonCompliantCount: compliance.violationCount,
          components: sbomComponents,
        },
      };

      // Validate schema compliance before transmission
      FleetIngestPayloadSchema.parse(payload);

      const res = await fetch(`${normalizedUrl}/api/ingest`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${fleetToken}`,
        },
        body: JSON.stringify(payload),
        redirect: 'error',
        signal: AbortSignal.timeout(15000),
      });

      if (!res.ok) {
        const errText = await res.text();
        return {
          success: false,
          error: `Fleet Server responded with status ${res.status}: ${errText}`,
        };
      }

      const resJson = (await res.json()) as { status: string; repo?: FleetRepoSummary };

      if (!isJson) {
        console.log(c.bold(c.cyan('\n🌐 SecureShip Fleet Telemetry Sync:')));
        console.log(`  Fleet Endpoint : ${c.underline(normalizedUrl)}`);
        console.log(
          `  Repository     : ${c.bold(gitInfo.repoName)} (${c.dim(`branch: ${gitInfo.branch}, commit: ${gitInfo.commitSha.substring(0, 7)}`)})`
        );
        console.log(
          `  Privacy Audit  : ${c.green('✔ ZERO source lines transferred')} | ${c.green('✔ ZERO secrets transferred')}`
        );
        if (resJson.repo) {
          const gradeColor =
            resJson.repo.riskGrade === 'A+' || resJson.repo.riskGrade === 'A'
              ? c.green
              : resJson.repo.riskGrade === 'B' || resJson.repo.riskGrade === 'C'
                ? c.yellow
                : c.red;
          console.log(
            `  Security Grade : ${gradeColor(c.bold(`[ ${resJson.repo.riskGrade} ]`))} (Risk Score: ${resJson.repo.riskScore}/100)`
          );
        }
      }

      return { success: true, repoSummary: resJson.repo };
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      if (!isJson) {
        console.warn(
          c.yellow(`\n⚠ Fleet Telemetry Notice: Failed to push to ${normalizedUrl} (${errMsg})`)
        );
      }
      return { success: false, error: errMsg };
    }
  }
}
