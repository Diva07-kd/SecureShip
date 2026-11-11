import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import {
  FleetServer,
  FleetStore,
  buildFleetRuntimeConfig,
  formatAuthLabel,
  formatDisplayUrl,
  formatReadHint,
  resolveClientFleetToken,
  assertSafeFleetEndpoint,
  installSignalHandlers,
} from '@secureship/fleet';
import type { FleetExecutiveSummary, FleetRepoSummary } from '@secureship/contracts';

export interface FleetStartOptions {
  port?: number | string;
  host?: string;
  data?: string;
  token?: string;
  tokenFile?: string;
  allowedHost?: string[];
  allowedOrigin?: string[];
}

export interface FleetStatusOptions {
  endpoint?: string;
  token?: string;
  tokenFile?: string;
  json?: boolean;
}

export interface FleetExportCraOptions {
  endpoint?: string;
  token?: string;
  tokenFile?: string;
  output?: string;
}

export class FleetCommand {
  /**
   * Starts the self-hosted Fleet Cockpit server & Web UI.
   */
  public static async start(options: FleetStartOptions = {}): Promise<number> {
    let config;
    try {
      config = await buildFleetRuntimeConfig({
        env: process.env,
        args: {
          port: options.port,
          host: options.host,
          data: options.data,
          token: options.token,
          tokenFile: options.tokenFile,
          allowedHost: options.allowedHost,
          allowedOrigin: options.allowedOrigin,
        },
      });
    } catch (err: unknown) {
      console.error(
        pc.red(
          `\n✖ Failed to configure SecureShip Fleet server: ${err instanceof Error ? err.message : String(err)}`
        )
      );
      return 1;
    }

    for (const w of config.warnings) {
      console.error(pc.yellow(w));
    }

    const store = new FleetStore({
      storageFile: config.dataPath,
      dbPath: config.dataPath,
    });
    const server = new FleetServer({
      ...config.serverOptions,
      store,
    });

    try {
      const activePort = await server.start();
      const url = formatDisplayUrl(config.host, activePort);

      console.log(
        pc.bold(pc.cyan('\n🛡️  SecureShip Fleet: Enterprise CISO Cockpit & Telemetry Hub\n'))
      );
      console.log(`  🌐 Web Dashboard : ${pc.bold(pc.green(url))}`);
      console.log(`  📥 Central Ingest : ${pc.underline(`${url}/api/ingest`)}`);
      console.log(`  📋 Corporate Policy: ${pc.underline(`${url}/api/policy`)}`);
      console.log(`  💾 State Storage  : ${pc.dim(config.dataPath)}`);
      console.log(
        `  🔒 Auth           : ${pc.bold(pc.yellow(`required (source: ${formatAuthLabel(config.tokenSource, config.tokenFilePath)})`))}`
      );
      if (config.tokenSource === 'generated' && config.tokenFilePath) {
        console.log(`  🔑 Token Read Hint: ${pc.cyan(formatReadHint(config.tokenFilePath))}`);
      }
      console.log(
        pc.dim(
          '\n  Zero-Code-Leak Principle: Developer CLI sends ONLY metadata (0 bytes of code leaves VPC).'
        )
      );
      console.log(pc.dim('  Press Ctrl+C to shutdown server.\n'));

      // Keep running until interrupt using installSignalHandlers
      await new Promise<void>((resolve) => {
        installSignalHandlers({
          server,
          onExit: (code) => {
            console.log(pc.yellow('\nShutting down SecureShip Fleet server...'));
            resolve();
            process.exit(code);
          },
        });
      });

      return 0;
    } catch (err: unknown) {
      console.error(
        pc.red(
          `\n✖ Failed to start SecureShip Fleet server: ${err instanceof Error ? err.message : String(err)}`
        )
      );
      return 1;
    }
  }

  /**
   * Queries Fleet API and prints an executive multi-repo risk summary.
   */
  public static async status(options: FleetStatusOptions = {}): Promise<number> {
    const rawEndpoint = options.endpoint ?? 'http://127.0.0.1:4000';
    let safeUrl: URL;
    try {
      safeUrl = assertSafeFleetEndpoint(rawEndpoint, { env: process.env });
    } catch (err: unknown) {
      console.error(
        pc.red(`\n✖ Invalid endpoint: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 1;
    }
    const endpoint = safeUrl.origin;

    let token: string | undefined;
    try {
      token = await resolveClientFleetToken({
        endpoint: rawEndpoint,
        flagToken: options.token,
        flagTokenFile: options.tokenFile,
        env: process.env,
      });
    } catch (err: unknown) {
      console.error(
        pc.red(`\n✖ Token resolution failed: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 1;
    }

    const headers: Record<string, string> = { Accept: 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const [sumRes, reposRes] = await Promise.all([
        fetch(`${endpoint}/api/fleet/summary`, {
          headers,
          redirect: 'error',
          signal: AbortSignal.timeout(15000),
        }),
        fetch(`${endpoint}/api/fleet/repos`, {
          headers,
          redirect: 'error',
          signal: AbortSignal.timeout(15000),
        }),
      ]);

      if (!sumRes.ok) {
        throw new Error(`Summary API returned status ${sumRes.status}`);
      }
      if (!reposRes.ok) {
        throw new Error(`Repos API returned status ${reposRes.status}`);
      }

      const summary = (await sumRes.json()) as FleetExecutiveSummary;
      const repos = (await reposRes.json()) as FleetRepoSummary[];

      if (options.json) {
        process.stdout.write(JSON.stringify({ summary, repos }, null, 2) + '\n');
        return 0;
      }

      console.log(pc.bold(pc.cyan('\n🏛️  SecureShip Fleet: Executive Risk Summary\n')));
      const gradeColor =
        summary.enterpriseGrade === 'A+' || summary.enterpriseGrade === 'A'
          ? pc.green
          : summary.enterpriseGrade === 'B' || summary.enterpriseGrade === 'C'
            ? pc.yellow
            : pc.red;

      console.log(
        `  Company Risk Grade : ${gradeColor(pc.bold(`[ ${summary.enterpriseGrade} ]`))} (Enterprise Score: ${summary.enterpriseScore}/100)`
      );
      console.log(`  Tracked Repos      : ${pc.bold(summary.totalRepos)}`);
      console.log(
        `  Active Vulnerabilities: ${summary.totalCriticals > 0 ? pc.red(`${summary.totalCriticals} Critical`) : pc.green('0 Critical')}, ${summary.totalHighs > 0 ? pc.yellow(`${summary.totalHighs} High`) : pc.green('0 High')}`
      );
      console.log(
        `  Reachability Gate  : ${pc.green(`${summary.deadCodeSuppressionRate}%`)} unreachable dead-code alerts suppressed (${summary.totalSuppressed} total)`
      );
      console.log(
        `  License Compliance : ${pc.green(`${summary.licenseComplianceRate}%`)} compliant components`
      );
      console.log(`  Latest Scan Activity: ${pc.dim(summary.latestActivity)}\n`);

      if (repos.length > 0) {
        console.log(pc.bold('  Repository Breakdown:'));
        for (const r of repos) {
          const rGradeColor =
            r.riskGrade === 'A+' || r.riskGrade === 'A'
              ? pc.green
              : r.riskGrade === 'B' || r.riskGrade === 'C'
                ? pc.yellow
                : pc.red;
          const statusIcon = r.activeCriticals === 0 ? pc.green('✔') : pc.red('✖');
          console.log(
            `    ${statusIcon} ${pc.bold(r.repoName.padEnd(24))} Grade: ${rGradeColor(r.riskGrade.padEnd(3))} Score: ${String(r.riskScore).padStart(3)}/100 | Criticals: ${r.activeCriticals} | High: ${r.activeHighs} | Branch: ${pc.dim(r.branch)}`
          );
        }
        console.log();
      }

      return 0;
    } catch (err: unknown) {
      console.error(
        pc.red(
          `\n✖ Error connecting to Fleet server at ${endpoint}: ${err instanceof Error ? err.message : String(err)}`
        )
      );
      console.error(
        pc.yellow('  Ensure `secureship fleet start` is running or verify your --endpoint.\n')
      );
      return 1;
    }
  }

  /**
   * Downloads EU Cyber Resilience Act (CRA) compliant CycloneDX 1.5 JSON report.
   */
  public static async exportCra(options: FleetExportCraOptions = {}): Promise<number> {
    const rawEndpoint = options.endpoint ?? 'http://127.0.0.1:4000';
    let safeUrl: URL;
    try {
      safeUrl = assertSafeFleetEndpoint(rawEndpoint, { env: process.env });
    } catch (err: unknown) {
      console.error(
        pc.red(`\n✖ Invalid endpoint: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 1;
    }
    const endpoint = safeUrl.origin;

    const outPath = path.resolve(options.output ?? 'eu-cra-cyclonedx-1.5.json');

    let token: string | undefined;
    try {
      token = await resolveClientFleetToken({
        endpoint: rawEndpoint,
        flagToken: options.token,
        flagTokenFile: options.tokenFile,
        env: process.env,
      });
    } catch (err: unknown) {
      console.error(
        pc.red(`\n✖ Token resolution failed: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 1;
    }

    const headers: Record<string, string> = { Accept: 'application/json' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    try {
      const res = await fetch(`${endpoint}/api/fleet/compliance/cra`, {
        headers,
        redirect: 'error',
        signal: AbortSignal.timeout(15000),
      });
      if (!res.ok) {
        throw new Error(`Fleet CRA API returned status ${res.status}`);
      }

      const reportJson = await res.json();
      fs.writeFileSync(outPath, JSON.stringify(reportJson, null, 2), 'utf-8');

      console.log(
        pc.bold(pc.green('\n✔ EU Cyber Resilience Act (CRA) Compliance Report Generated!'))
      );
      console.log(`  File saved to : ${pc.bold(outPath)}`);
      console.log(`  Standard      : CycloneDX 1.5 JSON (Annex I, Part II Attestation)`);
      console.log(`  Jurisdiction  : EU Regulation 2024/2847 Ready\n`);
      return 0;
    } catch (err: unknown) {
      console.error(
        pc.red(
          `\n✖ Failed to export CRA compliance report from ${endpoint}: ${err instanceof Error ? err.message : String(err)}`
        )
      );
      return 1;
    }
  }
}
