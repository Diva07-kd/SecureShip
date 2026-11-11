import { existsSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import {
  type FailOnSeverity,
  type IScannerAdapter,
  type Severity,
  type ScanReport,
  type NormalizedFinding,
  getEngineBrand,
  whiteLabelRuleId,
} from '@secureship/contracts';
import {
  ScanOrchestrator,
  SarifExporter,
  ConfigLoader,
  discoverPackages,
  evaluateLicenseCompliance,
  checkDirWritable,
  assertOfflineAllowed,
} from '@secureship/core-engine';
import {
  CheckovAdapter,
  GitleaksAdapter,
  OpengrepAdapter,
  OsvScannerAdapter,
  TrivyAdapter,
} from '@secureship/scanner-adapters';
import { ConsentManager, HttpClient, UserConfigLoader } from '@secureship/ai';
import { ScaReachabilityAnalyzer } from '@secureship/reachability';
import { sanitizeTerminalOutput } from '../utils/sanitize-output.js';
import { EngineBootstrapper } from '../engine/bootstrapper.js';
import { FleetClient } from '../utils/fleet-client.js';

export interface ScanCommandOptions {
  scanners?: string;
  diff?: string;
  staged?: boolean;
  diffLines?: boolean;
  failOn?: string;
  json?: boolean;
  output?: string;
  sarif?: string;
  includeSuppressed?: boolean;
  includeNonProduction?: boolean;
  baseline?: string;
  updateBaseline?: boolean;
  config?: string;
  timeout?: string;
  concurrency?: string;
  offline?: boolean;
  dbDir?: string;
  strict?: boolean;
  noColor?: boolean;
  color?: boolean;
  verbose?: boolean;
  gate2?: 'off' | 'annotate' | 'suppress';
  noCache?: boolean;
  functionLevel?: boolean;
  // Phase 4 Gate 3 AI Triage options
  ai?: boolean;
  gate3?: 'off' | 'annotate' | 'suppress';
  aiProvider?: 'anthropic' | 'openai' | 'fake';
  aiModel?: string;
  aiBaseUrl?: string;
  aiMaxFindings?: string;
  aiBudgetTokens?: string;
  aiConcurrency?: string;
  noAiCache?: boolean;
  aiDryRun?: boolean;
  aiEstimate?: boolean;
  aiTrace?: boolean | string;
  reachabilityFilter?: 'reachable' | 'no-info' | 'not-applicable' | 'all';
  supplyChain?: boolean;
  supplyChainOnly?: boolean;
  // Phase 2 Developer Experience Options:
  watch?: boolean;
  newOnly?: boolean;
  // Phase 4 SBOM & License Compliance Options:
  checkLicenses?: boolean;
  allow?: string[];
  deny?: string[];
  // Phase 6 Fleet Multi-Repo Telemetry & Policy Options:
  reportTo?: string;
  fleetToken?: string;
  repoName?: string;
  fleetPolicy?: boolean;
}

const SEVERITY_RANK: Record<Severity | 'NONE', number> = {
  CRITICAL: 50,
  HIGH: 40,
  MEDIUM: 30,
  LOW: 20,
  INFO: 10,
  NONE: 0,
};

type PicoColors = ReturnType<typeof pc.createColors>;

export class ScanCommand {
  /**
   * Main entry point for the 'secureship scan' command.
   */
  public static async run(targetPath = '.', options: ScanCommandOptions = {}): Promise<number> {
    if (options.watch) {
      return ScanCommand.runWatch(targetPath, options);
    }

    const isJson = Boolean(options.json);
    const noColor = Boolean(options.noColor) || options.color === false;
    const c: PicoColors = noColor ? pc.createColors(false) : pc;
    if (noColor) {
      process.env.NO_COLOR = '1';
      process.env.FORCE_COLOR = '0';
    }

    // Load configuration to pass scanner binary overrides if specified
    const config = ConfigLoader.loadConfig(targetPath, options.config);
    const overrides = config.binaryOverrides ?? {};

    // Phase 6 Fleet Corporate Policy Synchronization
    const fleetUrl = options.reportTo || config.fleet?.reportTo;
    if ((options.fleetPolicy || config.fleet?.policySync) && fleetUrl) {
      if (options.offline) {
        assertOfflineAllowed('fleet', true);
      }
      const fleetToken = options.fleetToken || config.fleet?.fleetToken;
      const policy = await FleetClient.fetchPolicy(fleetUrl, fleetToken);
      if (policy) {
        if (!isJson) {
          console.log(
            c.cyan(
              `ℹ [Fleet Policy] Synchronized central security policy from ${fleetUrl} (fail-on: ${policy.failOnSeverity})`
            )
          );
        }
        if (!options.failOn && policy.failOnSeverity) {
          options.failOn = policy.failOnSeverity;
        }
        if (policy.deniedLicenses && policy.deniedLicenses.length > 0) {
          options.deny = [...(options.deny ?? []), ...policy.deniedLicenses];
          options.checkLicenses = true;
        }
      }
    }

    // Instantiate built-in scanner adapters
    const adapters: IScannerAdapter[] = [
      new OpengrepAdapter({ binaryOverride: overrides['opengrep'] }),
      new GitleaksAdapter({ binaryOverride: overrides['gitleaks'] }),
      new TrivyAdapter({ offline: options.offline, binaryOverride: overrides['trivy'] }),
      new OsvScannerAdapter({ offline: options.offline, binaryOverride: overrides['osv-scanner'] }),
      new CheckovAdapter({
        offline: options.offline,
        binaryOverride: overrides['checkov'],
        defaultSeverity: config.checkovDefaultSeverity,
      }),
    ];

    // Auto-bootstrap missing security sub-engines seamlessly
    if (!options.offline) {
      await EngineBootstrapper.autoProvision({
        silent: true,
        targetDir: path.resolve(targetPath),
      });
    }

    const abortController = new AbortController();
    const sigintHandler = () => {
      abortController.abort();
      if (!isJson) {
        console.error(c.red('\nScan cancelled by user interrupt (SIGINT).'));
      }
      process.exit(130);
    };
    process.once('SIGINT', sigintHandler);

    try {
      if (options.gate2 && !['off', 'annotate', 'suppress'].includes(options.gate2)) {
        const errorMsg = `Invalid --gate2 mode "${options.gate2}". Allowed modes: off, annotate, suppress`;
        if (isJson) {
          process.stderr.write(JSON.stringify({ error: errorMsg }) + '\n');
        } else {
          console.error(c.red(`\n✖ Error: ${errorMsg}`));
        }
        return 2;
      }

      if (options.gate3 && !['off', 'annotate', 'suppress'].includes(options.gate3)) {
        const errorMsg = `Invalid --gate3 mode "${options.gate3}". Allowed modes: off, annotate, suppress`;
        if (isJson) {
          process.stderr.write(JSON.stringify({ error: errorMsg }) + '\n');
        } else {
          console.error(c.red(`\n✖ Error: ${errorMsg}`));
        }
        return 2;
      }

      // Validate AI parameters if AI triage is enabled (A3, A9)
      if (options.ai) {
        const userConfig = UserConfigLoader.loadUserConfig();
        const providerName = options.aiProvider || userConfig.provider || 'openai';
        const modelName = options.aiModel !== undefined ? options.aiModel : userConfig.model;
        const defaultBase =
          providerName === 'anthropic'
            ? 'https://api.anthropic.com/v1'
            : providerName === 'fake'
              ? 'http://localhost:8080/v1'
              : 'https://api.openai.com/v1';
        const baseUrl = options.aiBaseUrl || userConfig.baseUrl || defaultBase;

        if (!modelName) {
          const errorMsg =
            'Model name is required when --ai is enabled (no default). Specify via --ai-model <name> or run `secureship ai enable`.';
          if (isJson) {
            process.stderr.write(JSON.stringify({ error: errorMsg }) + '\n');
          } else {
            console.error(c.red(`\n✖ Error: ${errorMsg}`));
          }
          return 2;
        }

        try {
          HttpClient.validateEndpoint(baseUrl);
        } catch (err: unknown) {
          const errorMsg = `Invalid AI endpoint: ${err instanceof Error ? err.message : String(err)}`;
          if (isJson) {
            process.stderr.write(JSON.stringify({ error: errorMsg }) + '\n');
          } else {
            console.error(c.red(`\n✖ Error: ${errorMsg}`));
          }
          return 2;
        }

        // Consent and Key checks (skip for dry-run and estimate per A15)
        if (!options.aiDryRun && !options.aiEstimate) {
          const consent = ConsentManager.checkConsent(baseUrl);
          if (!consent.consented) {
            const errorMsg = `Missing consent for AI endpoint '${baseUrl}': ${consent.reason}. Run \`secureship ai enable\` to configure consent.`;
            if (isJson) {
              process.stderr.write(JSON.stringify({ error: errorMsg }) + '\n');
            } else {
              console.error(c.red(`\n✖ Error: ${errorMsg}`));
            }
            return 2;
          }

          if (providerName !== 'fake') {
            const apiKey = UserConfigLoader.resolveApiKey(providerName);
            if (!apiKey) {
              const envVar = providerName === 'anthropic' ? 'ANTHROPIC_API_KEY' : 'OPENAI_API_KEY';
              const errorMsg = `Missing API key for provider '${providerName}'. Provide via ${envVar} or SECURESHIP_AI_API_KEY.`;
              if (isJson) {
                process.stderr.write(JSON.stringify({ error: errorMsg }) + '\n');
              } else {
                console.error(c.red(`\n✖ Error: ${errorMsg}`));
              }
              return 2;
            }
          }
        }
      }

      const SCANNER_ALIASES: Record<string, string> = {
        sast: 'opengrep',
        'secureship-ast': 'opengrep',
        secrets: 'gitleaks',
        secret: 'gitleaks',
        'secureship-secret': 'gitleaks',
        sca: 'trivy',
        'secureship-sca': 'trivy',
        intel: 'osv-scanner',
        vuln: 'osv-scanner',
        'secureship-intel': 'osv-scanner',
        iac: 'checkov',
        'secureship-iac': 'checkov',
      };

      const parsedScanners = options.scanners
        ? options.scanners
            .split(/[,\s]+/)
            .map((s) => s.trim().toLowerCase())
            .filter(Boolean)
            .map((s) => SCANNER_ALIASES[s] ?? s)
        : undefined;

      if (parsedScanners) {
        const knownNames = new Set(adapters.map((a) => a.name.toLowerCase()));
        const unknown = parsedScanners.filter((s) => !knownNames.has(s.toLowerCase()));
        if (unknown.length > 0) {
          const supportedEngines =
            'sast, secrets, sca, intel, iac (or secureship-ast, secureship-secret, secureship-sca, secureship-intel, secureship-iac)';
          throw new Error(
            `Unknown scanner(s) specified: ${unknown.join(', ')}. Supported engines: ${supportedEngines}`
          );
        }
      }

      let resolvedBaseline = options.baseline;
      if (options.newOnly && !resolvedBaseline) {
        resolvedBaseline =
          config.baselinePath ?? path.join(targetPath, '.secureship', 'baseline.json');
      }

      const report: ScanReport = await ScanOrchestrator.scan({
        targetDir: targetPath,
        scanners: parsedScanners,
        diffRef: options.diff,
        staged: options.staged,
        diffLines: options.diffLines,
        includeSuppressed: options.includeSuppressed,
        includeNonProduction: options.includeNonProduction,
        baselinePath: resolvedBaseline,
        updateBaseline: options.updateBaseline,
        configPath: options.config,
        timeoutMs: options.timeout ? parseInt(options.timeout, 10) : undefined,
        concurrency: options.concurrency ? parseInt(options.concurrency, 10) : undefined,
        offline: options.offline,
        dbDir: options.dbDir,
        strict: options.strict,
        signal: abortController.signal,
        adapters,
        gate2Mode: options.gate2,
        noCache: options.noCache,
        functionLevel: options.functionLevel,
        // Gate 3
        ai: options.ai,
        gate3Mode: options.gate3,
        aiProvider: options.aiProvider,
        aiModel: options.aiModel,
        aiBaseUrl: options.aiBaseUrl,
        aiMaxFindings: options.aiMaxFindings ? parseInt(options.aiMaxFindings, 10) : undefined,
        aiBudgetTokens: options.aiBudgetTokens ? parseInt(options.aiBudgetTokens, 10) : undefined,
        aiConcurrency: options.aiConcurrency ? parseInt(options.aiConcurrency, 10) : undefined,
        noAiCache: options.noAiCache,
        aiDryRun: options.aiDryRun,
        aiEstimate: options.aiEstimate,
        aiTrace: options.aiTrace,
        supplyChain: options.supplyChainOnly ? true : options.supplyChain,
        supplyChainOnly: options.supplyChainOnly,
      });

      if (options.reachabilityFilter && options.reachabilityFilter !== 'all') {
        report.findings = ScaReachabilityAnalyzer.filterByReachability(
          report.findings,
          options.reachabilityFilter
        );
      }

      // Write --output JSON if specified
      if (options.output) {
        const outPath = path.resolve(options.output);
        const outDir = path.dirname(outPath);
        const writability = checkDirWritable(outDir);
        if (!writability.writable) {
          throw new Error(`Cannot write scan output to '${outPath}': ${writability.error}`);
        }
        writeFileSync(outPath, JSON.stringify(report, null, 2), 'utf-8');
      }

      // Write --sarif file if specified
      if (options.sarif) {
        const sarifPath = path.resolve(options.sarif);
        const sarifDir = path.dirname(sarifPath);
        const writability = checkDirWritable(sarifDir);
        if (!writability.writable) {
          throw new Error(`Cannot write SARIF output to '${sarifPath}': ${writability.error}`);
        }
        const sarifText = SarifExporter.export(report, {
          includeSuppressed: options.includeSuppressed,
        });
        writeFileSync(sarifPath, sarifText, 'utf-8');
      }

      // Output report
      if (isJson) {
        // Pure JSON directly to stdout
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
      } else {
        ScanCommand.printHumanReport(report, options, c);
      }

      // After scan completes, calculate baseline suppression notice:
      if (options.newOnly) {
        const suppressedBaselineCount =
          report.suppressed?.filter((s) => s.reasonCode === 'BASELINE_KNOWN').length ?? 0;
        if (!isJson) {
          if (!existsSync(path.resolve(resolvedBaseline!))) {
            console.log(
              c.yellow(
                `ℹ [Notice] No baseline found at '${resolvedBaseline}'. All findings treated as new. Run 'secureship scan --update-baseline' to establish a baseline.`
              )
            );
          } else {
            console.log(
              c.cyan(
                `ℹ [New-Only Active] ${suppressedBaselineCount} known baseline finding(s) suppressed. Showing only newly introduced findings.`
              )
            );
          }
        }
      }

      // Phase 6 SecureShip Fleet Zero-Code Telemetry Ingestion
      const fleetTargetUrl = options.reportTo || config.fleet?.reportTo;
      if (fleetTargetUrl && !options.aiDryRun && !options.aiEstimate) {
        if (options.offline) {
          assertOfflineAllowed('fleet', true);
        }
        await FleetClient.pushTelemetry({
          targetDir: targetPath,
          report,
          fleetUrl: fleetTargetUrl,
          fleetToken: options.fleetToken || config.fleet?.fleetToken,
          repoName: options.repoName || config.fleet?.repoName,
          isJson,
          c,
        });
      }

      // Check for infrastructure failure or uncompleted scans (Exit code 3) (R2, A9)
      const successfulScanners = report.scanners.filter((s) => s.status === 'SUCCESS');
      const noScannerCompleted = report.scanners.length > 0 && successfulScanners.length === 0;

      const strictFailed =
        Boolean(options.strict) && report.scanners.some((s) => s.status !== 'SUCCESS');

      if (noScannerCompleted || strictFailed) {
        if (!isJson) {
          if (noScannerCompleted) {
            console.error(c.yellow('\n⚠ NOT SCANNED: no scanner completed'));
            for (const sc of report.scanners) {
              console.error(
                c.yellow(`  - ${sc.name} (${sc.status}): ${sc.errorMessage ?? 'No details'}`)
              );
            }
          } else {
            console.error(
              c.red(
                '\n✖ Infrastructure Failure: Strict mode failed due to missing or errored scanner.'
              )
            );
          }
        }
        return 3;
      }

      // Diagnostic modes (--ai-dry-run, --ai-estimate) exit 0 (Item J1)
      if (options.aiDryRun || options.aiEstimate) {
        return 0;
      }

      // Evaluate license compliance if --check-licenses was passed
      let complianceFailed = false;
      if (options.checkLicenses) {
        const pkgs = discoverPackages(path.resolve(targetPath));
        const compliance = evaluateLicenseCompliance(pkgs, {
          allow: options.allow,
          deny: options.deny,
        });

        if (!isJson) {
          console.log(c.bold(c.cyan('\n⚖ License Compliance Analysis:')));
          console.log(`  Total Packages Evaluated : ${compliance.totalPackages}`);
          console.log(`  Compliant Packages       : ${c.green(compliance.compliantCount)}`);
          console.log(
            `  Violations Detected      : ${compliance.violationCount > 0 ? c.red(compliance.violationCount) : c.green(0)}`
          );

          if (compliance.violations.length > 0) {
            console.log(c.bold(c.red('\nLicense Violations:')));
            for (const v of compliance.violations) {
              const badge =
                v.severity === 'CRITICAL'
                  ? c.bgRed(c.white(` ${v.severity} `))
                  : c.yellow(`[${v.severity}]`);
              console.log(
                `  ${badge} ${c.bold(v.packageName)}@${v.version} — License: ${c.underline(v.license)}`
              );
              console.log(`     ↳ ${c.dim(v.reason)}`);
            }
          } else {
            console.log(c.green('\n✔ All package licenses comply with configured policy.'));
          }
        }

        if (compliance.violations.length > 0) {
          complianceFailed = true;
        }
      }

      if (complianceFailed) {
        return 1;
      }

      // Evaluate failOn threshold (Exit code 1 vs 0) (A9)
      const failOn = (options.failOn?.toUpperCase() as FailOnSeverity) || 'HIGH';
      const failOnRank = SEVERITY_RANK[failOn] ?? SEVERITY_RANK['HIGH'];

      if (failOnRank > 0) {
        const hasFailingFindings = report.findings.some(
          (f) => SEVERITY_RANK[f.severity] >= failOnRank
        );
        if (hasFailingFindings) {
          return 1;
        }
      }

      // Check for blocking supply-chain findings (Section 10: blocking finding => non-zero)
      const hasBlockingFinding = report.findings.some((f) => {
        if (f.category === 'SUPPLY_CHAIN') {
          const meta = f.evidence?.[0]?.metadata as Record<string, unknown> | undefined;
          return Boolean(meta?.['blocking']);
        }
        return false;
      });
      if (hasBlockingFinding) {
        return 1;
      }

      return 0;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (isJson) {
        process.stderr.write(JSON.stringify({ error: msg }) + '\n');
      } else {
        console.error(c.red(`\n✖ Error: ${msg}`));
      }
      if (msg.includes('[Offline Security Violation]')) {
        return 3;
      }
      return 2; // Usage / Config error
    } finally {
      process.removeListener('SIGINT', sigintHandler);
    }
  }

  /**
   * Prints the human-friendly report table and findings.
   */
  private static printHumanReport(
    report: ScanReport,
    options: ScanCommandOptions,
    c: PicoColors = pc
  ): void {
    console.log(c.bold(c.cyan('\n🛡️  SecureShip Security Scan Report\n')));
    console.log(`Target      : ${c.bold(report.target)}`);
    console.log(
      `Scan Mode   : ${c.bold(report.mode)}${report.diffBase ? ` (${report.diffBase})` : ''}`
    );
    console.log(`Duration    : ${c.bold(`${report.durationMs}ms`)}\n`);

    // Banner for Gate 3 suppress mode (A9)
    if (options.gate3 === 'suppress') {
      console.log(
        c.yellow(
          c.bold(
            '⚠ EXPERIMENTAL: Gate 3 AI suppression is active. Never suppresses CRITICAL or HIGH findings.\n'
          )
        )
      );
    }

    // 1. Scanner Execution Table (R3: Pad first, then colorize)
    console.log(c.bold('Scanner Execution Status:'));
    console.log(
      `  ${'Scanner / Engine'.padEnd(28)} ${'Version'.padEnd(16)} ${'Status'.padEnd(16)} ${'Time'.padEnd(10)} Findings`
    );
    console.log(`  ${'─'.repeat(82)}`);

    for (const sc of report.scanners) {
      const brand = getEngineBrand(sc.name);
      const statusPadded = sc.status.padEnd(16);
      let statusColored = c.green(statusPadded);
      if (sc.status === 'TOOL_MISSING') statusColored = c.yellow(statusPadded);
      if (sc.status === 'PARTIAL_FAILURE') statusColored = c.yellow(statusPadded);
      if (sc.status === 'TIMEOUT' || sc.status === 'ERROR') statusColored = c.red(statusPadded);

      const ver = (sc.version ?? 'Embedded').slice(0, 15);
      const displayName = brand.shortLabel;
      console.log(
        `  ${c.bold(displayName.padEnd(28))} ${ver.padEnd(16)} ${statusColored} ${`${sc.durationMs}ms`.padEnd(10)} ${sc.rawFindingCount}`
      );
      if (sc.errorMessage) {
        console.log(`    ↳ ${c.gray(sc.errorMessage)}`);
      }
    }

    const successful = report.scanners.filter((s) => s.status === 'SUCCESS');
    const notSuccessful = report.scanners.filter((s) => s.status !== 'SUCCESS');

    // 2. Reported Findings
    if (report.findings.length > 0) {
      console.log(c.bold(`\nReported Security Findings (${report.findings.length}):`));
      if (report.summary.byReachability !== undefined && options.gate2 !== 'off') {
        console.log(c.gray('  Import-level analysis only; not proof of exploitability or safety.'));
        console.log(
          c.gray(
            '  Function-level analysis is static and best-effort; vulnerable-symbol data may be incomplete.'
          )
        );
      }
      if (report.ai) {
        console.log(c.gray('  AI triage is advisory, not proof.'));
      }

      const isGate2Active = report.summary.byReachability !== undefined && options.gate2 !== 'off';

      for (const finding of report.findings) {
        let badge = c.red(finding.severity);
        if (finding.severity === 'MEDIUM') badge = c.yellow(finding.severity);
        if (finding.severity === 'LOW') badge = c.blue(finding.severity);
        if (finding.severity === 'INFO') badge = c.gray(finding.severity);

        let reachTag = '';
        if (isGate2Active) {
          const lbl = resolveReachabilityLabel(finding, c);
          reachTag = ` ${lbl.coloredTag}`;
        }

        let aiTag = '';
        if (finding.aiTriage) {
          const v = finding.aiTriage.verdict;
          if (v === 'LIKELY_FALSE_POSITIVE') aiTag = ` ${c.green('[AI: LIKELY FP]')}`;
          else if (v === 'LIKELY_TRUE_POSITIVE') aiTag = ` ${c.red('[AI: LIKELY TP]')}`;
          else aiTag = ` ${c.yellow('[AI: NEEDS REVIEW]')}`;
        }

        const brand = getEngineBrand(finding.scannerName);
        const brandedRuleId = whiteLabelRuleId(finding.ruleId, finding.category);
        const locationStr = `${finding.location.filePath}:${finding.location.startLine}`;
        console.log(
          `\n  [${badge}]${reachTag}${aiTag} ${c.bold(sanitizeTerminalOutput(finding.title))}`
        );
        console.log(
          `    Rule     : ${c.cyan(brandedRuleId)} (${finding.category}) [${c.gray(brand.shortLabel)}]`
        );
        if (finding.package) {
          console.log(
            `    Package  : ${finding.package.name}@${finding.package.version} (${finding.package.ecosystem})`
          );
        }
        console.log(`    Location : ${c.underline(locationStr)}`);
        if (finding.location.redactedSnippet) {
          console.log(
            `    Snippet  : ${c.gray(sanitizeTerminalOutput(finding.location.redactedSnippet.trim()))}`
          );
        }
        if (finding.category === 'SUPPLY_CHAIN') {
          const meta = finding.evidence?.[0]?.metadata as Record<string, unknown> | undefined;
          if (meta?.['capabilities']) {
            const caps = meta['capabilities'] as Record<string, boolean>;
            const activeCaps = Object.entries(caps)
              .filter(([, v]) => Boolean(v))
              .map(([k]) => k);
            if (activeCaps.length > 0) {
              console.log(`    Capabilities: ${c.yellow(activeCaps.join(', '))}`);
            }
          }
          if (finding.fixRecommendation?.explanation) {
            console.log(`    Remediation : ${c.green(finding.fixRecommendation.explanation)}`);
          }
        }
        if (finding.aiTriage) {
          console.log(
            `    AI Triage: ${finding.aiTriage.verdict} (confidence: ${finding.aiTriage.confidence}, model: ${finding.aiTriage.model})`
          );
          console.log(`    Rationale: ${c.gray(finding.aiTriage.rationale)}`);
        }
        if (options.verbose && finding.reachabilityDetail) {
          const detail = finding.reachabilityDetail;
          console.log(
            `    Reachability: ${detail.verdict} (confidence: ${detail.analysisConfidence})`
          );
          if (detail.evidence.symbols && detail.evidence.symbols.length > 0) {
            console.log(`    Symbol      : ${c.cyan(detail.evidence.symbols.join(', '))}`);
          }
          if (detail.evidence.symbolSource) {
            console.log(`    Source Tier : ${c.cyan(detail.evidence.symbolSource)}`);
          }
          if (detail.evidence.usageSites && detail.evidence.usageSites.length > 0) {
            const sites = detail.evidence.usageSites
              .map((s) => `${s.file}:${s.line} (${s.form})`)
              .join(', ');
            console.log(`    Usage Sites : ${c.gray(sites)}`);
          }
          if (detail.evidence.chain && detail.evidence.chain.length > 0) {
            console.log(`    Chain       : ${c.gray(detail.evidence.chain.join(' -> '))}`);
          }
          if (detail.evidence.blockedBy) {
            console.log(`    Blocked By  : ${c.yellow(detail.evidence.blockedBy)}`);
          }
          if (detail.evidence.notes) {
            console.log(`    Evidence    : ${c.gray(detail.evidence.notes)}`);
          }
          if (detail.evidence.via && detail.evidence.via.length > 0) {
            console.log(`    Via         : ${c.gray(detail.evidence.via.join(' -> '))}`);
          }
        }
      }
    } else {
      // R2: Never print bare "Clean" when scanners were missing or no scanner completed
      if (successful.length === 0) {
        if (options.supplyChainOnly) {
          console.log(
            c.green('\n✔ Clean: No supply-chain security findings reported at or above threshold.')
          );
        } else {
          console.log(c.yellow('\n⚠ NOT SCANNED: no sub-engine completed'));
          for (const sc of report.scanners) {
            const brand = getEngineBrand(sc.name);
            console.log(
              c.yellow(`  - ${brand.shortLabel} (${sc.status}): ${sc.errorMessage ?? 'No details'}`)
            );
          }
        }
      } else if (notSuccessful.length > 0) {
        const ranNames = successful.map((s) => getEngineBrand(s.name).shortLabel).join(', ');
        const notRanNames = notSuccessful.map((s) => getEngineBrand(s.name).shortLabel).join(', ');
        console.log(
          c.yellow(`\nClean for scanners that ran: ${ranNames}. NOT scanned: ${notRanNames}.`)
        );
      } else {
        console.log(c.green('\n✔ Clean: No security findings reported at or above threshold.'));
      }
    }

    // Gate 2 suppression banner
    const sum = report.summary;
    const gate2Suppressed = sum.suppressedByReason.GATE2_UNREACHABLE ?? 0;
    if (gate2Suppressed > 0) {
      console.log(
        c.cyan(
          `\nℹ Gate 2: ${gate2Suppressed} unreachable SCA finding(s) suppressed. Use --include-suppressed to list them.`
        )
      );
    }

    // Gate 3 suppression banner (A9)
    const gate3Suppressed = sum.suppressedByReason.GATE3_LIKELY_FALSE_POSITIVE ?? 0;
    if (gate3Suppressed > 0) {
      console.log(
        c.cyan(
          `\nℹ Gate 3: ${gate3Suppressed} likely false positive finding(s) suppressed by AI. Use --include-suppressed to list them.`
        )
      );
    }

    // 3. One-line Summary & Suppression ledger details
    console.log(c.bold('\nSummary:'));
    console.log(
      `  Total: ${sum.totalRaw} raw | ${c.bold(String(sum.totalReported))} reported | ` +
        `${c.yellow(String(sum.totalSuppressed))} suppressed (${sum.suppressedByReason.GATE1_TEST_OR_MOCK} test/mock, ` +
        `${sum.suppressedByReason.USER_IGNORE_RULE} ignored, ${sum.suppressedByReason.BASELINE_KNOWN} baseline, ` +
        `${sum.suppressedByReason.GATE2_UNREACHABLE ?? 0} gate2-unreachable, ` +
        `${sum.suppressedByReason.GATE3_LIKELY_FALSE_POSITIVE ?? 0} gate3-likely-fp) | ` +
        `${sum.totalOutOfScope} out of diff scope.`
    );

    if (sum.byReachability && options.gate2 !== 'off') {
      const counts: Record<string, number> = {
        imported: 0,
        'not imported': 0,
        'not reached from entrypoint': 0,
        'dev/test only': 0,
        'type-only import': 0,
        'test-only import': 0,
        unknown: 0,
      };

      for (const f of report.findings) {
        const lbl = resolveReachabilityLabel(f, c);
        counts[lbl.countKey] = (counts[lbl.countKey] ?? 0) + 1;
      }

      const notImported = counts['not imported'] ?? 0;
      const notReached = counts['not reached from entrypoint'] ?? 0;
      const devOnly = counts['dev/test only'] ?? 0;
      const typeOnly = counts['type-only import'] ?? 0;
      const testOnly = counts['test-only import'] ?? 0;
      const imported = counts.imported ?? 0;
      const unknownCount = counts.unknown ?? 0;

      const parts: string[] = [];
      parts.push(`${c.green(String(imported))} imported`);
      if (
        notImported > 0 ||
        (notReached === 0 && devOnly === 0 && typeOnly === 0 && testOnly === 0)
      ) {
        parts.push(`${c.cyan(String(notImported))} not imported`);
      }
      if (notReached > 0) {
        parts.push(`${c.cyan(String(notReached))} not reached from entrypoint`);
      }
      if (devOnly > 0) {
        parts.push(`${c.yellow(String(devOnly))} dev/test only`);
      }
      if (typeOnly > 0) {
        parts.push(`${c.blue(String(typeOnly))} type-only import`);
      }
      if (testOnly > 0) {
        parts.push(`${c.yellow(String(testOnly))} test-only import`);
      }
      parts.push(`${c.gray(String(unknownCount))} unknown`);

      console.log(`  Reachability: ${parts.join(' | ')}.`);
      if (sum.unknownByEvidence && Object.keys(sum.unknownByEvidence).length > 0) {
        const evParts = Object.entries(sum.unknownByEvidence)
          .sort((a, b) => b[1] - a[1])
          .map(([k, v]) => `${v} ${k.toLowerCase()}`);
        console.log(`    ↳ Unknown reasons: ${evParts.join(', ')}`);
      }

      if (sum.functionLevel) {
        const fl = sum.functionLevel;
        let blockedReasonStr = '';
        const blockedEntries = Object.entries(fl.blockedByReason || {}).sort((a, b) => b[1] - a[1]);
        if (blockedEntries.length > 0) {
          const topReasons = blockedEntries
            .slice(0, 3)
            .map(([r, count]) => `${count} ${r.toLowerCase()}`)
            .join(', ');
          blockedReasonStr = ` (top reasons: ${topReasons})`;
        }
        const totalBlocked = Object.values(fl.blockedByReason || {}).reduce((a, b) => a + b, 0);
        console.log(
          `  Function-level: ${fl.evaluated} evaluated, ${fl.uninvoked} not referenced, ` +
            `${fl.symbolReferenced + fl.callPathProven} referenced, ${fl.noSymbolData} no symbol data, ` +
            `${totalBlocked} blocked${blockedReasonStr}.`
        );
        if (fl.skippedTier > 0) {
          console.log(
            c.yellow(
              '  Notice        : Function-level reachability requires a higher tier; import-level analysis used.'
            )
          );
        }
        console.log(
          c.gray(
            '  Disclaimer    : Function-level analysis is static and best-effort; vulnerable-symbol data may be incomplete.'
          )
        );
      }
    }

    if (report.ai) {
      console.log(
        `  AI Triage   : ${report.ai.findingsConsidered} considered | ${report.ai.findingsSent} sent | ` +
          `${report.ai.findingsSkipped.length} skipped (${report.ai.tokensIn} in / ${report.ai.tokensOut} out tokens, ` +
          `cache hits: ${report.ai.cacheHits}).`
      );
      console.log(c.gray('  Notice      : AI triage is advisory, not proof.'));
    }

    if (options.aiEstimate && report.ai) {
      console.log(c.bold(c.cyan('\n📊 AI Triage Estimate (Zero Network):')));
      console.log(`  Findings Considered : ${report.ai.findingsConsidered}`);
      console.log(
        `  Findings Eligible   : ${report.ai.findingsEligible ?? report.ai.findingsSent}`
      );
      if (report.ai.findingsSkipped.length > 0) {
        console.log('  Skipped by Reason   :');
        for (const skip of report.ai.findingsSkipped) {
          console.log(`    ↳ ${skip.reason.padEnd(20)}: ${skip.count}`);
        }
      } else {
        console.log('  Skipped by Reason   : (none)');
      }
      console.log(`  Token Estimate      : ~${report.ai.tokensIn} tokens`);
    }

    if (options.aiDryRun && report.ai?.dryRunPayloads) {
      console.log(c.bold(c.cyan('\n🔍 AI Dry-Run Redacted Payloads (Zero Network):')));
      let totalBytes = 0;
      let totalTokens = 0;
      const allFiles = new Set<string>();

      for (let i = 0; i < report.ai.dryRunPayloads.length; i++) {
        const p = report.ai.dryRunPayloads[i];
        if (!p) continue;
        totalBytes += p.bytes;
        totalTokens += p.estimatedTokens;
        p.files.forEach((f) => allFiles.add(f));

        console.log(
          c.bold(
            `\n  Finding [${i + 1}/${report.ai.dryRunPayloads.length}]: ${p.findingId} (${p.ruleId})`
          )
        );
        console.log(`    Target File : ${p.filePath}`);
        console.log(`    Sliced Files: ${p.files.join(', ')}`);
        console.log(`    Payload Size: ${p.bytes} bytes | ~${p.estimatedTokens} tokens`);
        console.log(c.gray('    --- Redacted Payload Begin ---'));
        for (const line of p.payload.split('\n')) {
          console.log(`    ${line}`);
        }
        console.log(c.gray('    --- Redacted Payload End ---'));
      }

      console.log(c.bold('\n  AI Dry-Run Totals:'));
      console.log(`    Findings Inspected : ${report.ai.dryRunPayloads.length}`);
      console.log(`    Unique Files Sliced: ${allFiles.size} (${Array.from(allFiles).join(', ')})`);
      console.log(`    Total Payload Size : ${totalBytes} bytes`);
      console.log(`    Total Token Estimate: ~${totalTokens} tokens`);
    }

    if (report.warnings && report.warnings.length > 0) {
      console.log(c.bold(c.yellow('\nEngine Warnings:')));
      for (const w of report.warnings) {
        console.log(`  ${c.yellow('⚠')} ${c.yellow(w)}`);
      }
    }

    if (sum.totalSuppressed > 0) {
      console.log(
        c.gray('  (Run with --include-suppressed to inspect suppressed findings in report)\n')
      );
    }
  }

  public static async runWatch(targetPath: string, options: ScanCommandOptions): Promise<number> {
    const chokidar = await import('chokidar');
    const noColor = Boolean(options.noColor) || options.color === false;
    const c = noColor ? pc.createColors(false) : pc;
    const resolvedPath = path.resolve(targetPath);

    console.log(c.bold(c.cyan('\n👁  SecureShip Watch Mode Active')));
    console.log(c.gray(`Monitoring: ${resolvedPath}. Press Ctrl+C to stop.\n`));

    // Initial full scan on start
    await ScanCommand.run(targetPath, { ...options, watch: false });

    let debounceTimer: NodeJS.Timeout | null = null;

    const watcher = chokidar.watch(resolvedPath, {
      ignored: [
        '**/node_modules/**',
        '**/.git/**',
        '**/dist/**',
        '**/.secureship/**',
        '**/coverage/**',
        '**/*.tmp',
      ],
      persistent: true,
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 200, pollInterval: 50 },
    });

    const abortController = new AbortController();
    let resolvePromise!: (code: number) => void;
    const watchPromise = new Promise<number>((res) => {
      resolvePromise = res;
    });

    const sigintHandler = () => {
      console.log(pc.yellow('\nWatch mode terminated by user.'));
      abortController.abort();
      void watcher.close().then(() => resolvePromise(0));
    };
    process.once('SIGINT', sigintHandler);

    const onFileChanged = (changedPath: string) => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(async () => {
        const rel = path.relative(resolvedPath, changedPath).replace(/\\/g, '/');
        console.log(c.bold(c.cyan(`\n[SecureShip Watch] Changed: ${rel} — re-scanning...\n`)));

        // Incremental strategy: package.json → supply chain only; source files → full scan
        const isPackageJson = rel.endsWith('package.json');
        const scanOptions: ScanCommandOptions = {
          ...options,
          watch: false,
          supplyChainOnly: isPackageJson ? true : options.supplyChainOnly,
        };
        await ScanCommand.run(targetPath, scanOptions);
      }, 300);
    };

    watcher.on('change', onFileChanged);
    watcher.on('add', onFileChanged);
    watcher.on('unlink', onFileChanged);
    watcher.on('error', (err: unknown) => {
      console.error(c.red(`[SecureShip Watch] Watcher error: ${String(err)}`));
    });

    return watchPromise;
  }
}

export interface ReachabilityLabelResult {
  tag: string;
  countKey:
    | 'imported'
    | 'not imported'
    | 'dev/test only'
    | 'type-only import'
    | 'not reached from entrypoint'
    | 'test-only import'
    | 'unknown';
  coloredTag: string;
}

export function resolveReachabilityLabel(
  finding: NormalizedFinding,
  c: PicoColors = pc
): ReachabilityLabelResult {
  const detail = finding.reachabilityDetail;
  const kind = detail?.evidence?.kind;
  const notes = detail?.evidence?.notes?.toLowerCase() ?? '';
  const verdict = detail?.verdict ?? finding.reachability;

  if (kind === 'SYMBOL_CALL_PATH') {
    return {
      tag: '[CALL PATH PROVEN]',
      countKey: 'imported',
      coloredTag: c.green('[CALL PATH PROVEN]'),
    };
  }
  if (kind === 'SYMBOL_REFERENCED') {
    return {
      tag: '[SYMBOL REFERENCED]',
      countKey: 'imported',
      coloredTag: c.green('[SYMBOL REFERENCED]'),
    };
  }
  if (kind === 'UNINVOKED_SYMBOL') {
    return {
      tag: '[SYMBOL NOT REFERENCED]',
      countKey: 'not imported',
      coloredTag: c.cyan('[SYMBOL NOT REFERENCED]'),
    };
  }
  if (kind === 'NAMESPACE_ESCAPES') {
    return {
      tag: '[IMPORTED]',
      countKey: 'imported',
      coloredTag: c.yellow('[IMPORTED]'),
    };
  }
  if (kind === 'DEAD_FILE') {
    return {
      tag: '[NOT REACHED FROM ENTRYPOINT]',
      countKey: 'not reached from entrypoint',
      coloredTag: c.cyan('[NOT REACHED FROM ENTRYPOINT]'),
    };
  }
  if (kind === 'NOT_IMPORTED') {
    return {
      tag: '[NOT IMPORTED]',
      countKey: 'not imported',
      coloredTag: c.cyan('[NOT IMPORTED]'),
    };
  }
  if (kind === 'TEST_ONLY_IMPORT') {
    return {
      tag: '[TEST-ONLY IMPORT]',
      countKey: 'test-only import',
      coloredTag: c.yellow('[TEST-ONLY IMPORT]'),
    };
  }
  if (notes.includes('type-only')) {
    return {
      tag: '[TYPE-ONLY IMPORT]',
      countKey: 'type-only import',
      coloredTag: c.blue('[TYPE-ONLY IMPORT]'),
    };
  }
  if (kind === 'DEV_ONLY') {
    return {
      tag: '[DEV/TEST ONLY]',
      countKey: 'dev/test only',
      coloredTag: c.yellow('[DEV/TEST ONLY]'),
    };
  }
  if (verdict === 'REACHABLE_CALL_PATH' || verdict === 'REACHABLE_IMPORT') {
    return {
      tag: '[IMPORTED]',
      countKey: 'imported',
      coloredTag: c.green('[IMPORTED]'),
    };
  }
  if (verdict === 'UNREACHABLE') {
    return {
      tag: '[NOT IMPORTED]',
      countKey: 'not imported',
      coloredTag: c.cyan('[NOT IMPORTED]'),
    };
  }
  return {
    tag: '[UNKNOWN]',
    countKey: 'unknown',
    coloredTag: c.gray('[UNKNOWN]'),
  };
}
