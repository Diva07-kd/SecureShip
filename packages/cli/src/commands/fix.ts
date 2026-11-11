import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import {
  type FixReport,
  type NormalizedFinding,
  type PatchProposal,
  type ScanReport,
  type UserConfig,
  type VerificationStatus,
  type ScaPatchProposal,
  type ScaFixReport,
  type IScannerAdapter,
} from '@secureship/contracts';
import {
  FixGenerator,
  ConsentManager,
  UserConfigLoader,
  AnthropicProvider,
  OpenAiProvider,
  type ILlmProvider,
  type FixPromptPayload,
} from '@secureship/ai';
import { FakeLlmProvider } from '@secureship/ai/testing';
import {
  VerificationLadder,
  ScaVerificationLadder,
  FixStore,
  type ApplyFixOptions,
} from '@secureship/core-engine';
import { LockfileTreeParser, type LockfileGraph } from '@secureship/reachability';
import { DepGraphBuilder, MinVersionResolver, TransitivePinner } from '@secureship/patch-engine';
import {
  OpengrepAdapter,
  GitleaksAdapter,
  TrivyAdapter,
  OsvScannerAdapter,
  CheckovAdapter,
} from '@secureship/scanner-adapters';

export interface FixCommandOptions {
  report?: string;
  finding?: string;
  root?: string;
  require?: VerificationStatus;
  verify?: 'all' | 'static' | 'none';
  attempts?: number;
  json?: boolean;
  noCache?: boolean;
}

export class FixCommand {
  /**
   * Main remediation entry point: secureship fix <fingerprint|id|index>
   */
  public static async run(
    targetArg: string | undefined,
    options: FixCommandOptions
  ): Promise<number> {
    const rootDir = path.resolve(options.root ?? '.');
    const targetFindingRef = targetArg ?? options.finding;

    if (!targetFindingRef) {
      console.error(
        pc.red('Error: A target finding fingerprint, ID, or 1-based index is required.')
      );
      console.error(pc.gray('Example: secureship fix 1  or  secureship fix <fingerprint>'));
      return 2;
    }

    // 1. Locate ScanReport
    const reportPath = FixCommand.findReportPath(rootDir, options.report);
    if (!reportPath || !fs.existsSync(reportPath)) {
      console.error(
        pc.red(`Error: ScanReport not found at '${reportPath ?? 'default locations'}'.`)
      );
      console.error(
        pc.gray('Run `secureship scan` first or specify the report path with --report <file>.')
      );
      return 2;
    }

    let scanReport: ScanReport;
    try {
      scanReport = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    } catch (err) {
      console.error(
        pc.red(
          `Error: Failed to parse ScanReport: ${err instanceof Error ? err.message : String(err)}`
        )
      );
      return 2;
    }

    // 2. Resolve Finding
    const finding = FixCommand.resolveFinding(scanReport, targetFindingRef);
    if (!finding) {
      console.error(
        pc.red(
          `Error: Finding '${targetFindingRef}' not found in ScanReport (${scanReport.findings.length} total findings).`
        )
      );
      return 2;
    }

    const adapters = FixCommand.buildAdapters();
    const userConfig = UserConfigLoader.loadUserConfig();

    // SCA branch — use ScaVerificationLadder instead of VerificationLadder
    if (finding.category === 'SCA' && finding.package) {
      return FixCommand.runScaFix(finding, options, rootDir, userConfig, adapters);
    }

    // 3. Category & Credential Eligibility Check
    const eligibility = FixGenerator.checkEligibility(finding);
    if (!eligibility.eligible) {
      console.error(pc.red(`\nRemediation Refused: ${eligibility.reason}\n`));
      return 2;
    }

    // 4. User Config & AI Consent
    if (!userConfig.ai && userConfig.provider !== 'fake') {
      console.error(pc.red('\nAI Triage / Remediation is not enabled in user configuration.'));
      console.error(
        pc.gray(
          'Run `secureship ai enable --provider <provider> --model <model>` to configure BYOK.\n'
        )
      );
      return 2;
    }

    // Check consent
    if (userConfig.provider !== 'fake') {
      const consentCheck = ConsentManager.checkConsent(
        userConfig.baseUrl ?? 'https://api.openai.com/v1',
        userConfig.provider ?? 'openai'
      );
      if (!consentCheck.consented) {
        console.error(pc.red('\nMissing user consent for outbound AI code analysis.'));
        console.error(pc.gray('Run `secureship ai enable` to provide informed consent.\n'));
        return 2;
      }
    }

    // Resolve Provider
    let provider: ILlmProvider;
    try {
      provider = FixCommand.resolveProvider(userConfig);
    } catch (err) {
      console.error(
        pc.red(`\nInfrastructure Error: ${err instanceof Error ? err.message : String(err)}\n`)
      );
      return 3;
    }

    console.log(pc.bold(pc.cyan(`\n🛠️  SecureShip Gate 4 Remediation Engine: ${finding.ruleId}`)));
    console.log(
      pc.gray(`Target File : ${finding.location.filePath}:${finding.location.startLine}`)
    );
    console.log(pc.gray(`Severity    : ${finding.severity} | Category: ${finding.category}`));
    console.log(
      pc.gray(
        `Provider    : ${userConfig.provider ?? 'default'} | Model: ${userConfig.model ?? 'default'}\n`
      )
    );

    // 5. Generate Fix Proposal
    const maxAttempts = options.attempts ?? userConfig.fix?.maxAttempts ?? 2;
    let proposal: PatchProposal | undefined;
    let initialPayload: FixPromptPayload | undefined;

    try {
      const genResult = await FixGenerator.generate({
        rootDir,
        finding,
        provider,
        userConfig,
        noCache: options.noCache,
      });

      if (!genResult.eligible || !genResult.proposal) {
        console.error(
          pc.red(
            `Remediation generation refused: ${genResult.ineligibleReason ?? 'No proposal generated'}`
          )
        );
        return 2;
      }

      proposal = genResult.proposal;
      initialPayload = genResult.promptPayload;
      if (genResult.cacheHit) {
        console.log(pc.cyan('⚡ Retrieved verified patch proposal from local HMAC cache.'));
      }
    } catch (err) {
      console.error(
        pc.red(`AI Provider Failure: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 3;
    }

    // 6. Verification Ladder
    const requirement = options.require ?? 'VERIFIED_STATIC';
    const skipDynamic = options.verify === 'none' || options.verify === 'static';

    let ladderResult = await VerificationLadder.execute({
      rootDir,
      finding,
      proposal,
      userConfig,
      adapters,
      requirement,
      skipDynamic,
    });

    // 7. Retry Loop if Failed and Attempts Remaining
    let currentAttempt = 1;
    while (!ladderResult.allowed && currentAttempt < maxAttempts && initialPayload) {
      currentAttempt++;
      console.log(
        pc.yellow(
          `\nVerification attempt ${currentAttempt - 1} failed (${ladderResult.failureReason ?? 'Check failed'}). Initiating repair retry ${currentAttempt}/${maxAttempts}...`
        )
      );

      try {
        const retryProposal = await FixGenerator.generateRetry(
          { rootDir, finding, provider, userConfig },
          initialPayload,
          currentAttempt,
          proposal.diff,
          ladderResult.failureReason ?? 'Verification checks failed'
        );

        proposal = retryProposal;
        ladderResult = await VerificationLadder.execute({
          rootDir,
          finding,
          proposal,
          userConfig,
          adapters,
          requirement,
          skipDynamic,
        });
      } catch (err) {
        console.warn(
          pc.yellow(
            `Retry attempt ${currentAttempt} failed: ${err instanceof Error ? err.message : String(err)}`
          )
        );
        break;
      }
    }

    // 8. Save Fix Bundle to FixStore
    const store = new FixStore();
    const fixId = await store.saveFix(rootDir, ladderResult.report, proposal.diff);

    // 9. Format Output
    if (options.json) {
      console.log(JSON.stringify(ladderResult.report, null, 2));
    } else {
      FixCommand.printHumanReport(ladderResult.report, proposal, fixId);
    }

    // 10. Exit Codes
    if (ladderResult.allowed) {
      return 0;
    }

    return 1;
  }

  /**
   * secureship fix apply <id>
   */
  public static async apply(
    fixId: string | undefined,
    options: ApplyFixOptions & { root?: string }
  ): Promise<number> {
    if (!fixId) {
      console.error(pc.red('Error: Fix ID is required for `secureship fix apply <id>`.'));
      console.error(pc.gray('Run `secureship fix list` to view available fixes.'));
      return 2;
    }

    const rootDir = path.resolve(options.root ?? '.');
    const store = new FixStore();

    console.log(pc.bold(pc.cyan(`\n📦 Applying Verified Fix '${fixId}' to Working Tree...\n`)));

    const result = await store.applyFix(rootDir, fixId, options);
    if (!result.success) {
      console.error(pc.red(`Apply Refused (Exit ${result.exitCode}): ${result.error}`));
      return result.exitCode;
    }

    console.log(pc.green(`✔ Fix successfully and atomically applied to working tree!`));
    for (const f of result.appliedFiles ?? []) {
      console.log(`  • ${pc.bold(f)}`);
    }
    console.log(pc.gray('\nNote: Working tree modified on disk. Commit changes when ready.\n'));
    return 0;
  }

  /**
   * secureship fix list
   */
  public static async list(options: { root?: string; json?: boolean }): Promise<number> {
    const rootDir = path.resolve(options.root ?? '.');
    const store = new FixStore();
    const fixes = await store.listFixes(rootDir);

    if (options.json) {
      console.log(JSON.stringify(fixes, null, 2));
      return 0;
    }

    console.log(
      pc.bold(pc.cyan(`\n📋 Stored Fix Proposals for Repository (${fixes.length} total):\n`))
    );
    if (fixes.length === 0) {
      console.log(pc.gray('No stored fixes found. Generate one with `secureship fix <finding>`.'));
      return 0;
    }

    for (const f of fixes) {
      const statusColor =
        f.status === 'VERIFIED_RUNTIME' || f.status === 'VERIFIED_STATIC'
          ? pc.green
          : f.status === 'FAILED'
            ? pc.red
            : pc.yellow;

      const summary =
        'proposalSummary' in f
          ? f.proposalSummary
          : `${f.proposal.strategy}: ${f.proposal.targetPackage} -> ${f.proposal.targetVersion}`;

      console.log(
        `• ${pc.bold(f.findingRef.file)}:${f.findingRef.line} [${pc.cyan(f.findingRef.ruleId)}]`
      );
      console.log(`  Status    : ${statusColor(f.status)}`);
      console.log(`  Summary   : ${summary}`);
      console.log(`  Created At: ${f.createdAt}\n`);
    }

    return 0;
  }

  /**
   * secureship fix show <id>
   */
  public static async show(fixId: string | undefined, options: { root?: string }): Promise<number> {
    if (!fixId) {
      console.error(pc.red('Error: Fix ID is required for `secureship fix show <id>`.'));
      return 2;
    }

    const rootDir = path.resolve(options.root ?? '.');
    const store = new FixStore();
    const item = await store.getFix(rootDir, fixId);

    if (!item) {
      console.error(pc.red(`Error: Fix '${fixId}' not found.`));
      return 2;
    }

    const summary =
      'proposalSummary' in item.report
        ? item.report.proposalSummary
        : `${item.report.proposal.strategy}: ${item.report.proposal.targetPackage} -> ${item.report.proposal.targetVersion}`;

    console.log(pc.bold(pc.cyan(`\nFix Proposal Details: ${fixId}\n`)));
    console.log(`File: ${item.report.findingRef.file}:${item.report.findingRef.line}`);
    console.log(`Status: ${item.report.status}`);
    console.log(`Summary: ${summary}`);
    console.log(
      `Signature Valid: ${item.validSig ? pc.green('✔ Verified') : pc.red('✖ Invalid')}`
    );

    console.log(pc.bold('\nUnified Diff:\n'));
    console.log(item.diff);
    return 0;
  }

  /**
   * secureship fix discard <id>
   */
  public static async discard(
    fixId: string | undefined,
    options: { root?: string }
  ): Promise<number> {
    if (!fixId) {
      console.error(pc.red('Error: Fix ID is required for `secureship fix discard <id>`.'));
      return 2;
    }

    const rootDir = path.resolve(options.root ?? '.');
    const store = new FixStore();
    const ok = await store.discardFix(rootDir, fixId);

    if (ok) {
      console.log(pc.green(`✔ Fix '${fixId}' discarded.`));
      return 0;
    }

    console.error(pc.red(`Error: Fix '${fixId}' not found.`));
    return 2;
  }

  private static findReportPath(rootDir: string, explicitPath?: string): string | null {
    if (explicitPath) return path.resolve(rootDir, explicitPath);

    const candidates = [
      path.join(rootDir, '.secureship', 'report.json'),
      path.join(rootDir, 'secureship.report.json'),
    ];

    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }

    return null;
  }

  private static resolveFinding(report: ScanReport, ref: string): NormalizedFinding | null {
    // 1. Exact fingerprint match
    const byFp = report.findings.find((f) => f.fingerprint === ref);
    if (byFp) return byFp;

    // 2. Exact ID match
    const byId = report.findings.find((f) => f.id === ref);
    if (byId) return byId;

    // 3. 1-based index match
    const idx = parseInt(ref, 10);
    if (!isNaN(idx) && idx >= 1 && idx <= report.findings.length) {
      return report.findings[idx - 1] ?? null;
    }

    return null;
  }

  private static resolveProvider(userConfig: UserConfig): ILlmProvider {
    const providerName = userConfig.provider ?? 'anthropic';

    if (providerName === 'fake') {
      return new FakeLlmProvider();
    }

    if (providerName === 'anthropic') {
      return new AnthropicProvider();
    }

    if (providerName === 'openai') {
      return new OpenAiProvider();
    }

    throw new Error(`Unsupported AI provider: ${providerName}`);
  }

  private static printHumanReport(report: FixReport, proposal: PatchProposal, fixId: string): void {
    const statusColor =
      report.status === 'VERIFIED_RUNTIME' || report.status === 'VERIFIED_STATIC'
        ? pc.green
        : report.status === 'FAILED'
          ? pc.red
          : pc.yellow;

    console.log(pc.bold('\nVerification Result:'));
    console.log(`  Status      : ${statusColor(pc.bold(report.status))}`);
    console.log(
      `  Requirement : ${pc.bold(report.requirement)} (Met: ${report.requirementMet ? pc.green('YES') : pc.red('NO')})`
    );
    console.log(`  Fix ID      : ${pc.cyan(pc.bold(fixId))}`);
    console.log(`  Summary     : ${report.proposalSummary}`);

    console.log(pc.bold('\nVerification Ladder Stages:'));
    for (const stage of report.stages) {
      const icon =
        stage.outcome === 'PASS'
          ? pc.green('✔')
          : stage.outcome === 'FAIL'
            ? pc.red('✖')
            : pc.yellow('○');

      const outcomeText =
        stage.outcome === 'PASS'
          ? pc.green('PASS')
          : stage.outcome === 'FAIL'
            ? pc.red('FAIL')
            : pc.yellow(stage.outcome);

      console.log(
        `  ${icon} ${stage.id.padEnd(14)} ${outcomeText.padEnd(14)} (${stage.durationMs}ms) - ${stage.detail}`
      );
    }

    console.log(pc.bold('\nCandidate Unified Diff:'));
    console.log(pc.gray('----------------------------------------------------'));
    for (const line of proposal.diff.split('\n')) {
      if (line.startsWith('+') && !line.startsWith('+++')) {
        console.log(pc.green(line));
      } else if (line.startsWith('-') && !line.startsWith('---')) {
        console.log(pc.red(line));
      } else if (line.startsWith('@@')) {
        console.log(pc.cyan(line));
      } else {
        console.log(line);
      }
    }
    console.log(pc.gray('----------------------------------------------------'));

    console.log(pc.bold('\nWorking Tree Status:'));
    console.log(
      pc.green('  ✔ UNTOUCHED. User working tree was not modified during verification.')
    );

    console.log(pc.bold('\nNext Steps:'));
    console.log(`  To apply this patch atomically to your working tree, run:`);
    console.log(`    ${pc.cyan(`secureship fix apply ${fixId}`)}\n`);
  }

  public static buildAdapters(): IScannerAdapter[] {
    return [
      new OpengrepAdapter(),
      new GitleaksAdapter(),
      new TrivyAdapter(),
      new OsvScannerAdapter(),
      new CheckovAdapter(),
    ];
  }

  public static async runScaFix(
    finding: NormalizedFinding,
    options: FixCommandOptions,
    rootDir: string,
    userConfig: UserConfig,
    adapters: IScannerAdapter[]
  ): Promise<number> {
    const pkg = finding.package!;

    // 1. Builds LockfileGraph via LockfileTreeParser.parse(rootDir)
    const lockfileRes = LockfileTreeParser.parse(rootDir);
    const graph: LockfileGraph = lockfileRes.success
      ? lockfileRes.graph
      : {
          format: 'NPM_V2_V3',
          nodes: new Map(),
          dependentsMap: new Map(),
          directProdDependencies: new Set([pkg.name]),
          directDevDependencies: new Set(),
        };

    // 2. Builds DepGraphBuilder(graph) and calls isDirect(), getTransitiveChains()
    const graphBuilder = new DepGraphBuilder(graph);
    const isDirect = graphBuilder.isDirect(pkg.name);
    const chains = graphBuilder.getTransitiveChains(pkg.name);
    const shortestChain = chains.length > 0 ? chains[0] : undefined;

    // 3. Calls MinVersionResolver.resolve(finding.package.version, finding.package.fixedVersion)
    const targetVersion = MinVersionResolver.resolve(pkg.version, pkg.fixedVersion);

    // Detect package manager & manifest path
    let pm: 'npm' | 'pnpm' | 'yarn' | 'pip' | 'poetry' = 'npm';
    let manifestPath = 'package.json';

    const pnpmLock = path.join(rootDir, 'pnpm-lock.yaml');
    const yarnLock = path.join(rootDir, 'yarn.lock');
    const reqTxt = path.join(rootDir, 'requirements.txt');
    const pyproject = path.join(rootDir, 'pyproject.toml');

    const eco = (pkg.ecosystem ?? '').toLowerCase();
    if (
      ['pip', 'pypi', 'python'].includes(eco) ||
      fs.existsSync(reqTxt) ||
      fs.existsSync(pyproject)
    ) {
      if (fs.existsSync(pyproject) && !fs.existsSync(reqTxt)) {
        pm = 'poetry';
        manifestPath = 'pyproject.toml';
      } else {
        pm = 'pip';
        manifestPath = 'requirements.txt';
      }
    } else {
      if (fs.existsSync(pnpmLock)) {
        pm = 'pnpm';
      } else if (fs.existsSync(yarnLock)) {
        pm = 'yarn';
      } else {
        pm = 'npm';
      }
      manifestPath = 'package.json';
    }

    if (finding.location?.filePath) {
      const locPath = finding.location.filePath.replace(/\\/g, '/');
      const basename = path.basename(locPath).toLowerCase();
      if (
        basename === 'package.json' ||
        basename.startsWith('requirements') ||
        basename === 'pyproject.toml'
      ) {
        manifestPath = path.isAbsolute(locPath)
          ? path.relative(rootDir, locPath).replace(/\\/g, '/')
          : locPath;
      }
    }

    let strategy: 'DIRECT_UPGRADE' | 'TRANSITIVE_PIN' | 'OVERRIDES_INJECTION' = 'DIRECT_UPGRADE';
    if (!isDirect) {
      strategy =
        shortestChain && shortestChain.length > 2 ? 'OVERRIDES_INJECTION' : 'TRANSITIVE_PIN';
    }

    // 4. Constructs a ScaPatchProposal (no LLM involved - deterministic)
    const proposal: ScaPatchProposal = {
      findingFingerprint: finding.fingerprint,
      packageManager: pm,
      targetPackage: pkg.name,
      currentVersion: pkg.version,
      targetVersion,
      isTransitive: !isDirect,
      strategy,
      manifestPath,
      lockfilePath: finding.lockfilePath,
      transitiveChain: shortestChain,
      attempt: 1,
      generatedAt: new Date().toISOString(),
    };

    const pinner = new TransitivePinner(graph, rootDir);
    const pinResult = pinner.computeFix(proposal);
    if ('unifiedDiff' in pinResult && pinResult.unifiedDiff) {
      proposal.diff = pinResult.unifiedDiff;
    }

    console.log(pc.bold(pc.cyan(`\n🛠️  SecureShip SCA Remediation Engine: ${finding.ruleId}`)));
    console.log(pc.gray(`Target Package : ${pkg.name} (${pkg.version} -> ${targetVersion})`));
    console.log(pc.gray(`Strategy       : ${strategy} | Direct: ${isDirect ? 'YES' : 'NO'}`));
    console.log(pc.gray(`Manifest       : ${manifestPath}\n`));

    // 5. Calls ScaVerificationLadder.execute(...)
    const requirement = options.require ?? 'VERIFIED_STATIC';
    const skipDynamic = options.verify === 'none' || options.verify === 'static';

    const ladderResult = await ScaVerificationLadder.execute({
      rootDir,
      finding,
      proposal,
      userConfig,
      adapters,
      requirement,
      skipDynamic,
    });

    const store = new FixStore();
    const fixId = await store.saveFix(rootDir, ladderResult.report, proposal.diff ?? '');

    // 6. Prints result (same table format as existing fix output)
    if (options.json) {
      console.log(JSON.stringify(ladderResult.report, null, 2));
    } else {
      FixCommand.printHumanScaReport(ladderResult.report, proposal, fixId);
    }

    return ladderResult.allowed ? 0 : 1;
  }

  private static printHumanScaReport(
    report: ScaFixReport,
    proposal: ScaPatchProposal,
    fixId: string
  ): void {
    const statusColor =
      report.status === 'VERIFIED_RUNTIME' || report.status === 'VERIFIED_STATIC'
        ? pc.green
        : report.status === 'FAILED'
          ? pc.red
          : pc.yellow;

    console.log(pc.bold('\nVerification Result:'));
    console.log(`  Status      : ${statusColor(pc.bold(report.status))}`);
    console.log(
      `  Strategy    : ${pc.bold(proposal.strategy)} (Package: ${proposal.targetPackage} -> ${proposal.targetVersion})`
    );
    console.log(`  Fix ID      : ${pc.cyan(pc.bold(fixId))}`);
    console.log(`  Manifest    : ${proposal.manifestPath}`);

    console.log(pc.bold('\nVerification Ladder Stages:'));
    for (const stage of report.stages) {
      const icon =
        stage.outcome === 'PASS'
          ? pc.green('✔')
          : stage.outcome === 'FAIL'
            ? pc.red('✖')
            : pc.yellow('○');

      const outcomeText =
        stage.outcome === 'PASS'
          ? pc.green('PASS')
          : stage.outcome === 'FAIL'
            ? pc.red('FAIL')
            : pc.yellow(stage.outcome);

      console.log(
        `  ${icon} ${stage.id.padEnd(14)} ${outcomeText.padEnd(14)} (${stage.durationMs}ms) - ${stage.detail}`
      );
    }

    if (proposal.diff) {
      console.log(pc.bold('\nCandidate Unified Diff:'));
      console.log(pc.gray('----------------------------------------------------'));
      for (const line of proposal.diff.split('\n')) {
        if (line.startsWith('+') && !line.startsWith('+++')) {
          console.log(pc.green(line));
        } else if (line.startsWith('-') && !line.startsWith('---')) {
          console.log(pc.red(line));
        } else if (line.startsWith('@@')) {
          console.log(pc.cyan(line));
        } else {
          console.log(line);
        }
      }
      console.log(pc.gray('----------------------------------------------------'));
    }

    console.log(pc.bold('\nWorking Tree Status:'));
    console.log(
      pc.green('  ✔ UNTOUCHED. User working tree was not modified during verification.')
    );

    console.log(pc.bold('\nNext Steps:'));
    console.log(`  To apply this patch atomically to your working tree, run:`);
    console.log(`    ${pc.cyan(`secureship fix apply ${fixId}`)}\n`);
  }
}
