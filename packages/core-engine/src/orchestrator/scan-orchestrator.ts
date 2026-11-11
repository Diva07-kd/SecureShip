import fs from 'node:fs';
import path from 'node:path';
import type {
  AiExecutionSummary,
  AiPayloadDetail,
  IScannerAdapter,
  NormalizedFinding,
  ProjectProfile,
  Reachability,
  ReachabilityDetail,
  ScanExecutionResult,
  ScannerExecutionSummary,
  ScanReport,
  SecureShipConfig,
  Severity,
} from '@secureship/contracts';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import { ReachabilityEngine, type VulnerableSymbolDataset } from '@secureship/reachability';
import { ContextSlicer } from '@secureship/context-slicer';
import {
  AiCache,
  AiError,
  AnthropicProvider,
  BudgetTracker,
  ConsentManager,
  HttpClient,
  type ILlmProvider,
  OpenAiProvider,
  PromptBuilder,
  SkepticEngine,
  UserConfigLoader,
} from '@secureship/ai';
import { FakeLlmProvider } from '@secureship/ai/testing';
import { ProjectDetector } from '../detector/project-detector.js';
import { FindingCorrelator } from '../normalizer/finding-correlator.js';
import { DiffScope, type DiffScopeOptions, type DiffScopeResult } from '../git/diff-scope.js';
import { Gate1Scope, type Gate1Options } from '../gates/gate1-scope.js';
import { SuppressionLedger } from '../suppression/ledger.js';
import { IgnoreRulesEvaluator } from '../suppression/ignore-rules.js';
import { BaselineEvaluator } from '../suppression/baseline.js';
import { ConfigLoader } from '../config/load-config.js';
import { ReportBuilder } from '../report/report-builder.js';
import { analyzeSupplyChain } from '../supply-chain/index.js';
import {
  resolveTierCapabilities,
  canPerformAiFix,
  recordAiFixExecution,
  getMonthlyAiUsage,
} from '../license/index.js';
import { logger } from '../logger/secureship-logger.js';
import { createOfflineContext, assertOfflineAllowed } from '../offline/index.js';

export interface OrchestratorRunOptions {
  targetDir?: string;
  scanners?: string[]; // user-requested scanner filter
  diffRef?: string;
  staged?: boolean;
  diffLines?: boolean;
  includeSuppressed?: boolean;
  includeNonProduction?: boolean;
  baselinePath?: string;
  updateBaseline?: boolean;
  configPath?: string;
  timeoutMs?: number;
  concurrency?: number;
  offline?: boolean;
  strict?: boolean;
  dbDir?: string;
  fleetUrl?: string;
  signal?: AbortSignal;
  adapters: IScannerAdapter[];
  gate2Mode?: 'off' | 'annotate' | 'suppress';
  noCache?: boolean;
  // Phase 4 Gate 3 AI Triage options
  ai?: boolean;
  gate3Mode?: 'off' | 'annotate' | 'suppress';
  aiProvider?: 'anthropic' | 'openai' | 'fake';
  aiModel?: string;
  aiBaseUrl?: string;
  aiMaxFindings?: number;
  aiBudgetTokens?: number;
  aiConcurrency?: number;
  noAiCache?: boolean;
  aiDryRun?: boolean;
  aiEstimate?: boolean;
  aiTrace?: boolean | string;
  aiConsentPath?: string;
  aiConfigPath?: string;
  customLlmProvider?: ILlmProvider;
  supplyChain?: boolean;
  supplyChainOnly?: boolean;
  // Phase 5 License options
  licensePath?: string;
  licenseServerUrl?: string;
  // Phase B Function-Level Reachability options
  functionLevel?: boolean;
  symbolDataset?: VulnerableSymbolDataset | null;
}

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
};

const REACHABILITY_ORDER: Record<Reachability, number> = {
  REACHABLE_CALL_PATH: 0,
  REACHABLE_IMPORT: 1,
  UNKNOWN: 2,
  UNREACHABLE: 3,
};

const AI_VERDICT_ORDER: Record<string, number> = {
  LIKELY_TRUE_POSITIVE: 0,
  NEEDS_HUMAN_REVIEW: 1,
  LIKELY_FALSE_POSITIVE: 2,
};

function compareFindings(a: NormalizedFinding, b: NormalizedFinding): number {
  const sevA = SEVERITY_ORDER[a.severity] ?? 99;
  const sevB = SEVERITY_ORDER[b.severity] ?? 99;
  if (sevA !== sevB) return sevA - sevB;

  const reachA =
    REACHABILITY_ORDER[a.reachabilityDetail?.verdict ?? a.reachability ?? 'UNKNOWN'] ?? 99;
  const reachB =
    REACHABILITY_ORDER[b.reachabilityDetail?.verdict ?? b.reachability ?? 'UNKNOWN'] ?? 99;
  if (reachA !== reachB) return reachA - reachB;

  const aiA = a.aiTriage?.verdict ? (AI_VERDICT_ORDER[a.aiTriage.verdict] ?? 99) : 99;
  const aiB = b.aiTriage?.verdict ? (AI_VERDICT_ORDER[b.aiTriage.verdict] ?? 99) : 99;
  if (aiA !== aiB) return aiA - aiB;

  const fileDiff = a.location.filePath.localeCompare(b.location.filePath);
  if (fileDiff !== 0) return fileDiff;

  const lineDiff = (a.location.startLine ?? 0) - (b.location.startLine ?? 0);
  if (lineDiff !== 0) return lineDiff;

  const ruleDiff = a.ruleId.localeCompare(b.ruleId);
  if (ruleDiff !== 0) return ruleDiff;

  return a.fingerprint.localeCompare(b.fingerprint);
}

function compareCandidatesForAi(a: NormalizedFinding, b: NormalizedFinding): number {
  const sevA = SEVERITY_ORDER[a.severity] ?? 99;
  const sevB = SEVERITY_ORDER[b.severity] ?? 99;
  if (sevA !== sevB) return sevA - sevB;

  const reachA =
    REACHABILITY_ORDER[a.reachabilityDetail?.verdict ?? a.reachability ?? 'UNKNOWN'] ?? 99;
  const reachB =
    REACHABILITY_ORDER[b.reachabilityDetail?.verdict ?? b.reachability ?? 'UNKNOWN'] ?? 99;
  if (reachA !== reachB) return reachA - reachB;

  return a.fingerprint.localeCompare(b.fingerprint);
}

export class ScanOrchestrator {
  /**
   * Concurrency-bounded execution helper.
   */
  private static async runWithConcurrency<T>(
    items: T[],
    fn: (item: T) => Promise<void>,
    limit: number
  ): Promise<void> {
    const pool = new Set<Promise<void>>();
    for (const item of items) {
      const promise = fn(item);
      pool.add(promise);
      const cleanup = () => pool.delete(promise);
      promise.then(cleanup, cleanup);
      if (pool.size >= limit) {
        await Promise.race(pool);
      }
    }
    await Promise.all(pool);
  }

  /**
   * Executes the full SecureShip scan pipeline.
   */
  public static async scan(options: OrchestratorRunOptions): Promise<ScanReport> {
    const startedAt = new Date().toISOString();
    const startTime = Date.now();

    const targetDir = path.resolve(options.targetDir ?? process.cwd());

    // 0. Resolve License Tier & Capabilities (Stage 5)
    const tierState = await resolveTierCapabilities({
      licensePath: options.licensePath,
      licenseServerUrl: options.licenseServerUrl,
    });
    const tierCaps = tierState.capabilities;

    // Phase 5: AI Usage Quota Enforcement (FREE_BYOK: 15 fixes/month)
    if (options.ai && !options.aiDryRun && tierCaps.maxMonthlyAiFixes !== null) {
      const usage = getMonthlyAiUsage(); // from ai-usage-ledger
      if (usage.fixesUsed >= tierCaps.maxMonthlyAiFixes) {
        logger.warn(
          `Monthly AI fix quota reached (${usage.fixesUsed}/${tierCaps.maxMonthlyAiFixes} for ${tierCaps.tier}). ` +
            `Gate 3 AI disabled. Upgrade to PRO_TEAM for 100 fixes/month. ` +
            `Run 'secureship license upgrade' to unlock more.`
        );
        options.ai = false;
      }
    }

    // 1. Validate baseline flags: --update-baseline with --diff or --staged is illegal
    if (options.updateBaseline && (options.diffRef || options.staged)) {
      throw new Error(
        'Cannot update baseline in incremental diff or staged mode (--update-baseline combined with --diff or --staged). Baselines must represent the complete repository state.'
      );
    }

    // 2. Load configuration
    const config: SecureShipConfig = ConfigLoader.loadConfig(targetDir, options.configPath);

    // 2.1 Egress Guards & Offline Context Initialization (Phase C)
    const isOffline = options.offline ?? false;
    if (isOffline) {
      if (options.fleetUrl) {
        assertOfflineAllowed('fleet', true);
      }
      if (options.ai && options.aiBaseUrl) {
        const isLoopback = (u?: string) => {
          if (!u) return false;
          try {
            const parsed = new URL(u);
            return (
              parsed.hostname === 'localhost' ||
              parsed.hostname === '127.0.0.1' ||
              parsed.hostname === '::1'
            );
          } catch {
            return false;
          }
        };
        assertOfflineAllowed('cloud-ai', true, { isLoopback: isLoopback(options.aiBaseUrl) });
      }
    }

    const offlineCtx = createOfflineContext({
      offline: isOffline,
      strict: options.strict,
      dbDir: options.dbDir,
      maxStaleDays: config.offline?.maxDbAgeDays,
      maxExpiredDays: config.offline?.strictMaxDbAgeDays,
    });

    // 3. Detect project intelligence profile
    const profile: ProjectProfile = ProjectDetector.detect(targetDir);

    // 4. Select scanners to run (bypassed if supplyChainOnly is requested)
    const selectedAdapters = options.supplyChainOnly
      ? []
      : ScanOrchestrator.selectAdapters(options.adapters, profile, config, options.scanners);

    // 5. Compute incremental diff scope if active
    const diffScopeOptions: DiffScopeOptions = {
      diffRef: options.diffRef,
      staged: options.staged,
      diffLines: options.diffLines,
    };

    const diffScope: DiffScopeResult = await DiffScope.computeDiffScope(
      targetDir,
      diffScopeOptions
    );

    // 6. Execute selected scanners in parallel
    const concurrency = options.concurrency ?? 4;
    const scannerSummaries: ScannerExecutionSummary[] = [];
    const rawFindings: NormalizedFinding[] = [];
    const warnings: string[] = [];

    if (offlineCtx.enabled && offlineCtx.warnings.length > 0) {
      warnings.push(...offlineCtx.warnings);
    }

    // Configure scanner adapter cache environments if offline database is present
    if (offlineCtx.enabled) {
      if (offlineCtx.trivyCacheDir) {
        process.env.TRIVY_CACHE_DIR = offlineCtx.trivyCacheDir;
      }
      if (offlineCtx.osvDbDir) {
        process.env.OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY = offlineCtx.osvDbDir;
      }
    }

    const changedFilesList = diffScope.targetRelativeFiles ?? Array.from(diffScope.changedFiles);

    await ScanOrchestrator.runWithConcurrency(
      selectedAdapters,
      async (adapter) => {
        // Honor AbortSignal
        if (options.signal?.aborted) {
          scannerSummaries.push({
            name: adapter.name,
            status: 'ERROR',
            durationMs: 0,
            rawFindingCount: 0,
            errorMessage: 'Scan aborted by user signal.',
          });
          return;
        }

        const timeout =
          options.timeoutMs ??
          config.timeouts?.[adapter.name] ??
          config.timeouts?.['default'] ??
          60_000;

        let versionStr: string | undefined;
        try {
          versionStr = await adapter.version();
        } catch {
          // Version error non-blocking
        }

        const result: ScanExecutionResult = await adapter.scan(targetDir, {
          timeoutMs: timeout,
          changedFiles: diffScope.isDiffMode ? changedFilesList : undefined,
          includeTests: options.includeNonProduction,
        });

        scannerSummaries.push({
          name: adapter.name,
          version: versionStr,
          status: result.status,
          durationMs: result.durationMs,
          rawFindingCount: result.findings.length,
          errorMessage: result.errorMessage,
        });

        if (result.findings.length > 0) {
          rawFindings.push(...result.findings);
        }
      },
      concurrency
    );

    // If --strict is set and any scanner failed or was missing, or if all scanners failed
    if (options.strict) {
      const anyFailed = scannerSummaries.some((s) => s.status !== 'SUCCESS');
      if (anyFailed) {
        warnings.push('Strict mode enabled: one or more scanners did not succeed cleanly.');
      }
    }

    // 7. Finding Normalization & SCA Correlation
    const correlatedFindings = FindingCorrelator.correlate(rawFindings, profile);

    // 7.1 Supply-Chain Threat Analysis (if enabled)
    const isSupplyChainEnabled =
      options.supplyChainOnly ?? options.supplyChain ?? config.supplyChain?.enabled ?? false;
    const supplyChainFindings: NormalizedFinding[] = [];
    if (isSupplyChainEnabled) {
      try {
        const rawPolicy = config.supplyChain ?? { enabled: true };
        const parsedPolicy = SupplyChainPolicySchema.parse(rawPolicy);
        if (options.offline) {
          parsedPolicy.provider = 'null';
        }
        const scResult = await analyzeSupplyChain({
          rootDir: targetDir,
          policy: parsedPolicy,
          signal: options.signal,
          concurrency: options.concurrency,
        });
        supplyChainFindings.push(...scResult.findings);
        for (const diag of scResult.diagnostics) {
          if (diag.level === 'WARN' || diag.level === 'ERROR') {
            warnings.push(`[SupplyChain] ${diag.message}`);
          }
        }
      } catch (err: unknown) {
        warnings.push(
          `Supply chain analysis failed: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    }

    const allCorrelatedFindings = [...correlatedFindings, ...supplyChainFindings];

    // 8. Suppression Ledger & Pipeline Evaluation (Precedence Rule)
    const ledger = new SuppressionLedger();
    ledger.recordRaw(allCorrelatedFindings.length);

    const gate1Options: Gate1Options = {
      enabled: config.gate1?.enabled ?? true,
      keepProviderSecrets: config.gate1?.keepProviderSecrets ?? true,
      includeNonProduction: options.includeNonProduction ?? false,
      customTestDirs: config.gate1?.customTestDirs,
    };

    const ignoreEvaluator = new IgnoreRulesEvaluator(config.ignore ?? []);

    const rawBaselinePath =
      options.baselinePath ??
      config.baselinePath ??
      path.join(targetDir, '.secureship', 'baseline.json');
    const baselineFilePath = path.isAbsolute(rawBaselinePath)
      ? rawBaselinePath
      : path.resolve(targetDir, rawBaselinePath);

    const baselineEvaluator = new BaselineEvaluator(baselineFilePath);

    // 8.1 Initialize Gate 2 Reachability Engine if enabled
    let gate2Mode = options.gate2Mode ?? config.gate2?.mode ?? 'annotate';
    if (!['off', 'annotate', 'suppress'].includes(gate2Mode)) {
      throw new Error(`Invalid gate2 mode "${gate2Mode}". Allowed modes: off, annotate, suppress`);
    }

    // Gate 2 suppress mode requires PRO_TEAM (allowCiCdGatekeeper) in production/CLI
    if (
      gate2Mode === 'suppress' &&
      !tierCaps.allowCiCdGatekeeper &&
      !process.env.VITEST &&
      process.env.NODE_ENV !== 'test'
    ) {
      warnings.push(
        `[License] Gate 2 'suppress' mode requires PRO_TEAM tier. Running in 'annotate' mode. Upgrade at https://secureship.dev/pricing.`
      );
      gate2Mode = 'annotate';
    }

    // Resolve Function-Level Reachability (Phase B Deliverable 6)
    // Spec: functionLevel = (config != off) AND tier capability allowCallPathReachability
    let userReachabilityConfig = 'auto';
    try {
      const userCfg = UserConfigLoader.loadUserConfig();
      if (userCfg.reachability?.functionLevel) {
        userReachabilityConfig = userCfg.reachability.functionLevel;
      }
    } catch {
      // Fall back to default
    }

    const functionLevelConfigEnabled =
      options.functionLevel !== false && userReachabilityConfig !== 'off';

    let functionLevel = false;
    let skippedTier = 0;
    if (functionLevelConfigEnabled) {
      if (tierCaps.allowCallPathReachability) {
        functionLevel = true;
      } else {
        skippedTier = 1;
        warnings.push(
          'Function-level reachability requires a higher tier; import-level analysis used.'
        );
        logger.debug(
          'Function-level reachability requires a higher tier; import-level analysis used.'
        );
      }
    }

    let reachEngine: ReachabilityEngine | null = null;
    if (gate2Mode !== 'off') {
      reachEngine = new ReachabilityEngine(targetDir, {
        userConfigEntrypoints: config.gate2?.entrypoints,
        noCache: options.noCache,
        parseTimeoutMs: config.gate2?.parseTimeoutMs,
        maxFileBytes: config.gate2?.maxFileBytes,
        functionLevel,
        symbolDataset: options.symbolDataset,
      });
      try {
        await reachEngine.init();
      } catch (err: unknown) {
        warnings.push(
          `Gate 2 reachability engine initialization failed: ${err instanceof Error ? err.message : String(err)}`
        );
        reachEngine = null;
      }
    }

    const candidateFindingsForGate3: NormalizedFinding[] = [];

    for (const finding of allCorrelatedFindings) {
      // Step 1 (Diff Scoping): Apply diff scope FIRST.
      // Findings outside the diff are counted in totalOutOfScope and never enter the ledger.
      if (
        diffScope.isDiffMode &&
        !DiffScope.isFindingInScope(finding, diffScope, options.diffLines)
      ) {
        ledger.recordOutOfScope(1);
        continue;
      }

      // Step 2 (Gate 1 Scope): Test/mock/doc/example filtering
      const gate1Res = Gate1Scope.evaluate(finding, gate1Options, profile);
      finding.scopeTag = gate1Res.scopeTag;

      if (gate1Res.shouldSuppress) {
        ledger.suppress(
          finding,
          gate1Res.suppressionReason!,
          gate1Res.suppressionDetail!,
          'Gate 1 Scope Classifier'
        );
        continue;
      }

      // Step 2.5 (Supply Chain Policy Allowlist)
      if (finding.category === 'SUPPLY_CHAIN' && config.supplyChain?.allowlist) {
        const metadataItems =
          (finding.evidence?.[0]?.metadata?.['items'] as Array<{ snippetSha256?: string }>) ?? [];
        const matchingAllow = config.supplyChain.allowlist.find((entry) => {
          if (entry.packageName !== finding.package?.name) return false;
          if (entry.ruleId && entry.ruleId !== finding.ruleId) return false;
          if (entry.scriptHash) {
            const hasMatchingHash = metadataItems.some(
              (item) => item?.snippetSha256 === entry.scriptHash
            );
            if (!hasMatchingHash) return false;
          }
          return true;
        });

        if (matchingAllow) {
          ledger.suppress(
            finding,
            'SUPPLY_CHAIN_ALLOWLISTED',
            matchingAllow.reason,
            'Supply Chain Policy Allowlist'
          );
          continue;
        }
      }

      // Step 3 (Ignore Rules): secureship.config.json ignore patterns
      const ignoreRes = ignoreEvaluator.evaluate(finding);
      if (ignoreRes.isIgnored) {
        ledger.suppress(finding, 'USER_IGNORE_RULE', ignoreRes.detail!, 'User Ignore Rule');
        continue;
      }

      // Step 4 (Baseline): .secureship/baseline.json
      if (baselineEvaluator.isKnownInBaseline(finding)) {
        const entry = baselineEvaluator.getBaselineEntry(finding);
        ledger.suppress(
          finding,
          'BASELINE_KNOWN',
          `Finding was previously recorded in baseline (first seen: ${entry?.firstSeen ?? 'unknown'})`,
          'Baseline Ledger'
        );
        continue;
      }

      // Step 5 (Gate 2 Reachability Evaluation)
      if (reachEngine) {
        let detail: ReachabilityDetail;
        try {
          detail = reachEngine.evaluate(finding);
        } catch (err: unknown) {
          detail = {
            verdict: 'UNKNOWN',
            analysisConfidence: 'LOW',
            evidence: {
              kind: 'PARSE_FAILURE',
              notes: `Evaluation error: ${err instanceof Error ? err.message : String(err)}`,
            },
            limitations: ['Import-level analysis only; not proof of exploitability or safety.'],
          };
        }
        finding.reachabilityDetail = detail;
        finding.reachability = detail.verdict;

        if (finding.category === 'SUPPLY_CHAIN') {
          // Escalate reachable dangerous capability combinations to P1 CRITICAL
          const isDangerousCombo =
            finding.ruleId === 'SC-CAP-100' ||
            finding.ruleId === 'SC-CAP-101' ||
            finding.ruleId === 'SC-CAP-102' ||
            finding.ruleId === 'SC-CAP-103' ||
            finding.ruleId === 'SC-CAP-104' ||
            finding.severity === 'CRITICAL';

          if (
            (detail.verdict === 'REACHABLE_IMPORT' || detail.verdict === 'REACHABLE_CALL_PATH') &&
            isDangerousCombo
          ) {
            finding.severity = 'CRITICAL';
          }
        } else if (gate2Mode === 'suppress') {
          const neverSuppress = new Set(config.gate2?.neverSuppressSeverities ?? ['CRITICAL']);
          const isQualifyingSca =
            finding.category === 'SCA' &&
            detail.verdict === 'UNREACHABLE' &&
            (detail.analysisConfidence === 'HIGH' ||
              (detail.analysisConfidence === 'MEDIUM' && detail.evidence.kind === 'DEV_ONLY')) &&
            !neverSuppress.has(finding.severity);

          if (isQualifyingSca) {
            let suppressionDetail =
              detail.evidence.notes ??
              `Package ${finding.package?.name ?? ''} is not imported from production code`;
            if (detail.evidence.kind === 'UNINVOKED_SYMBOL') {
              const symStr = detail.evidence.symbols?.join(', ') || 'N/A';
              const srcStr = detail.evidence.symbolSource || 'UNKNOWN';
              const urlStr = detail.evidence.dataset?.sourceUrls?.join(', ') || 'N/A';
              suppressionDetail = `Symbol '${symStr}' from source ${srcStr} is not invoked (Dataset URLs: ${urlStr})`;
            }
            ledger.suppress(
              finding,
              'GATE2_UNREACHABLE',
              suppressionDetail,
              'Gate 2 Reachability Engine'
            );
            continue;
          }
        }
      }

      // Step 6: Candidate finding passed diff, Gate 1, ignore, baseline, and Gate 2
      candidateFindingsForGate3.push(finding);
    }

    // Gate 3 AI Triage Execution (A1-A16)
    let aiSummary: AiExecutionSummary | undefined;

    if (
      options.ai &&
      !options.aiDryRun &&
      !options.aiEstimate &&
      !process.env.VITEST &&
      process.env.NODE_ENV !== 'test'
    ) {
      // Check monthly AI quota limit under active tier (Stage 5.2)
      const quotaCheck = canPerformAiFix(tierCaps.maxMonthlyAiFixes);
      if (!quotaCheck.allowed) {
        warnings.push(
          `[License] Monthly AI triage quota (${tierCaps.maxMonthlyAiFixes}/${tierCaps.maxMonthlyAiFixes}) reached for ${tierCaps.tier} tier. Upgrade to PRO_TEAM via 'secureship license upgrade' for additional quota.`
        );
        options.ai = false;
      }
    }

    if (options.ai) {
      const successfulScanners = scannerSummaries.filter((s) => s.status === 'SUCCESS');
      if (scannerSummaries.length > 0 && successfulScanners.length === 0) {
        // Missing scanners keeps exit 3 and makes zero AI calls (A9)
        for (const finding of candidateFindingsForGate3) {
          ledger.addReported(finding);
        }
      } else {
        const userConfig = UserConfigLoader.loadUserConfig(
          {
            ai: true,
            gate3Mode: options.gate3Mode,
            provider: options.aiProvider,
            model: options.aiModel,
            baseUrl: options.aiBaseUrl,
            maxFindings: options.aiMaxFindings,
            budgetTokens: options.aiBudgetTokens,
            concurrency: options.aiConcurrency,
          },
          options.aiConfigPath
        );

        const providerName = options.aiProvider || userConfig.provider || 'openai';
        const modelName = options.aiModel || userConfig.model || '';
        const defaultBase =
          providerName === 'anthropic'
            ? 'https://api.anthropic.com/v1'
            : providerName === 'fake'
              ? 'http://localhost:8080/v1'
              : 'https://api.openai.com/v1';
        const baseUrl = options.aiBaseUrl || userConfig.baseUrl || defaultBase;
        const gate3Mode = options.gate3Mode || userConfig.gate3?.mode || 'annotate';
        const budgetTokens = options.aiBudgetTokens || userConfig.gate3?.budgetTokens || 200_000;
        const maxFindings = options.aiMaxFindings || userConfig.gate3?.maxFindings || 25;
        const concurrency = options.aiConcurrency || userConfig.gate3?.concurrency || 2;

        HttpClient.setMaxConcurrency(concurrency);

        // Model name is required (no default model) (A3, A9)
        if (!modelName && !options.aiDryRun && !options.aiEstimate) {
          throw new AiError(
            'Model name is required for AI triage (--model or SECURESHIP_AI_MODEL or user config).',
            'CONFIG_ERROR'
          );
        }

        const budgetTracker = new BudgetTracker(maxFindings, budgetTokens);

        // Dry-run and estimate need no key and no consent (A15)
        if (!options.aiDryRun && !options.aiEstimate && providerName !== 'fake') {
          // Consent check (A3)
          const consentManager = new ConsentManager(options.aiConsentPath);
          const consentCheck = consentManager.hasConsent(providerName, baseUrl);
          if (!consentCheck.consented) {
            throw new AiError(
              consentCheck.reason ||
                'AI consent has not been granted. Run "secureship ai enable" to record consent.',
              'CONFIG_ERROR'
            );
          }

          // API Key check (A2)
          const isLoopback = HttpClient.isLoopbackHost(new URL(baseUrl).hostname);
          const apiKey = UserConfigLoader.resolveApiKey(providerName);
          if (!apiKey && !isLoopback) {
            throw new AiError(
              `Missing API key for provider '${providerName}'. Configure via ANTHROPIC_API_KEY, OPENAI_API_KEY, SECURESHIP_AI_API_KEY, or ~/.secureship/ai-key.`,
              'CONFIG_ERROR'
            );
          }
        }

        let provider: ILlmProvider;
        if (options.customLlmProvider) {
          provider = options.customLlmProvider;
        } else if (providerName === 'anthropic') {
          provider = new AnthropicProvider();
        } else if (providerName === 'fake') {
          provider = new FakeLlmProvider();
        } else {
          provider = new OpenAiProvider();
        }

        const cache = new AiCache(!options.noAiCache);
        const skeptic = new SkepticEngine(provider, cache);
        const apiKey = UserConfigLoader.resolveApiKey(providerName);

        budgetTracker.recordConsidered(candidateFindingsForGate3.length);

        // Separate and prioritize eligible candidates
        const eligibleCandidates: NormalizedFinding[] = [];
        for (const finding of candidateFindingsForGate3) {
          if (finding.category === 'SECRET') {
            budgetTracker.recordSkip('SECRET');
            ledger.addReported(finding);
          } else if (finding.category === 'SCA') {
            budgetTracker.recordSkip('SCA');
            ledger.addReported(finding);
          } else if (finding.category === 'SUPPLY_CHAIN') {
            budgetTracker.recordSkip('SUPPLY_CHAIN');
            ledger.addReported(finding);
          } else if (ContextSlicer.isCredentialClassFinding(finding)) {
            budgetTracker.recordSkip('CREDENTIAL_CLASS');
            ledger.addReported(finding);
          } else {
            eligibleCandidates.push(finding);
          }
        }

        eligibleCandidates.sort(compareCandidatesForAi);
        budgetTracker.recordEligible(eligibleCandidates.length);

        let deterministicOverall = true;
        const dryRunPayloads: AiPayloadDetail[] = [];
        const traceEntries: Array<Record<string, unknown>> = [];

        for (const finding of eligibleCandidates) {
          if (!budgetTracker.canSendFinding()) {
            budgetTracker.recordSkip('BUDGET_EXCEEDED');
            ledger.addReported(finding);
            continue;
          }

          const sliceResult = await ContextSlicer.sliceFinding(targetDir, finding, {
            sliceTokens: userConfig.gate3?.sliceTokens ?? 6000,
          });

          if (sliceResult.skipped) {
            budgetTracker.recordSkip(sliceResult.skipReason);
            ledger.addReported(finding);
            continue;
          }

          budgetTracker.recordFindingSent();
          budgetTracker.recordFiles(sliceResult.filesSent);
          if (sliceResult.truncated) {
            budgetTracker.recordTruncatedSlice();
          }

          // In dry-run or estimate mode, assemble the exact redacted payload and token estimate
          if (options.aiDryRun || options.aiEstimate) {
            const systemPrompt = PromptBuilder.buildSystemPrompt();
            const { userPrompt } = PromptBuilder.buildUserPrompt(sliceResult, 0);
            const fullPayload = `${systemPrompt}\n\n--- USER PROMPT ---\n${userPrompt}`;
            const byteCount = Buffer.byteLength(fullPayload, 'utf-8');

            budgetTracker.recordTokens(sliceResult.estimatedTokens, 0);

            if (options.aiDryRun) {
              dryRunPayloads.push({
                findingId: finding.id,
                ruleId: finding.ruleId,
                filePath: finding.location.filePath,
                files: sliceResult.filesSent,
                bytes: byteCount,
                estimatedTokens: sliceResult.estimatedTokens,
                payload: fullPayload,
              });
            }

            if (options.aiTrace) {
              traceEntries.push({
                findingId: finding.id,
                ruleId: finding.ruleId,
                filePath: finding.location.filePath,
                startLine: finding.location.startLine,
                request: {
                  systemPrompt,
                  userPrompt,
                },
                response: null,
                tokens: { in: sliceResult.estimatedTokens, out: 0 },
                dryRun: true,
              });
            }

            finding.aiTriage = {
              verdict: 'NEEDS_HUMAN_REVIEW',
              confidence: 'MEDIUM',
              rationale:
                'Dry-run inspection: payload assembled and validated without network transmission.',
              citations: [],
              model: modelName || 'dry-run-model',
              promptVersion: PromptBuilder.PROMPT_VERSION,
              cached: false,
            };
            ledger.addReported(finding);
            continue;
          }

          let triageRes;
          try {
            triageRes = await skeptic.triage(sliceResult, {
              gate3Mode,
              model: modelName,
              baseUrl,
              apiKey,
              bypassCache: options.noAiCache,
              signal: options.signal,
            });
          } catch (err: unknown) {
            // Failure isolation (T6): provider failure leaves finding untouched with warning
            const msg = err instanceof Error ? err.message : String(err);
            warnings.push(`AI triage failure for finding '${finding.id}': ${msg}`);
            budgetTracker.addWarning(msg);
            ledger.addReported(finding);
            continue;
          }

          budgetTracker.recordTokens(triageRes.tokensIn, triageRes.tokensOut);
          if (triageRes.cacheHit) budgetTracker.recordCacheHit();
          if (triageRes.warning) budgetTracker.addWarning(triageRes.warning);
          deterministicOverall = deterministicOverall && triageRes.deterministic;

          finding.aiTriage = triageRes.triage;

          if (options.aiTrace) {
            traceEntries.push({
              findingId: finding.id,
              ruleId: finding.ruleId,
              filePath: finding.location.filePath,
              startLine: finding.location.startLine,
              request: triageRes.rawRequest ?? null,
              response: triageRes.rawResponse ?? null,
              triage: triageRes.triage,
              tokens: { in: triageRes.tokensIn, out: triageRes.tokensOut },
              cacheHit: triageRes.cacheHit,
              deterministic: triageRes.deterministic,
            });
          }

          if (gate3Mode === 'suppress') {
            const neverSuppress = new Set(
              userConfig.gate3?.neverSuppressSeverities ?? ['CRITICAL', 'HIGH']
            );
            const isQualifying =
              finding.category === 'SAST' &&
              !neverSuppress.has(finding.severity) &&
              triageRes.triage.verdict === 'LIKELY_FALSE_POSITIVE' &&
              triageRes.triage.confidence === 'HIGH' &&
              triageRes.triage.citations.length > 0 &&
              triageRes.triage.consistency?.agreed === true &&
              !sliceResult.truncated &&
              !triageRes.triage.injectionFlag;

            if (isQualifying) {
              ledger.suppress(
                finding,
                'GATE3_LIKELY_FALSE_POSITIVE',
                triageRes.triage.rationale,
                'Gate 3 AI Triage'
              );
            } else {
              ledger.addReported(finding);
            }
          } else {
            ledger.addReported(finding);
          }
        }

        if (options.aiTrace) {
          const resolvedTarget = path.resolve(targetDir);
          let tracePath: string;
          if (typeof options.aiTrace === 'string') {
            tracePath = path.resolve(options.aiTrace);
            const rel = path.relative(resolvedTarget, tracePath);
            if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
              throw new Error(
                `--ai-trace destination path "${options.aiTrace}" cannot be inside the scan target directory "${targetDir}" to prevent committing prompt telemetry.`
              );
            }
          } else {
            const defaultDir = path.join(UserConfigLoader.getUserConfigDir(), 'traces');
            tracePath = path.join(defaultDir, `ai-trace-${Date.now()}.json`);
          }

          const traceDir = path.dirname(tracePath);
          if (!fs.existsSync(traceDir)) {
            fs.mkdirSync(traceDir, { recursive: true });
          }

          const traceData = {
            timestamp: new Date().toISOString(),
            targetDir: resolvedTarget,
            findingsTraced: traceEntries.length,
            traces: traceEntries,
          };

          fs.writeFileSync(tracePath, JSON.stringify(traceData, null, 2), {
            encoding: 'utf-8',
            mode: 0o600,
          });
          if (process.platform !== 'win32') {
            try {
              fs.chmodSync(tracePath, 0o600);
            } catch {
              // Ignore chmod failure if filesystem does not support POSIX modes
            }
          }
        }

        const hostUrl = new URL(baseUrl);
        const hostStr = hostUrl.host;
        aiSummary = budgetTracker.toExecutionSummary(
          providerName,
          modelName || 'unspecified',
          hostStr,
          deterministicOverall,
          options.aiDryRun,
          options.aiEstimate,
          options.aiDryRun ? dryRunPayloads : undefined
        );

        if (
          !options.aiDryRun &&
          !options.aiEstimate &&
          !process.env.VITEST &&
          process.env.NODE_ENV !== 'test'
        ) {
          recordAiFixExecution();
        }
      }
    } else {
      for (const finding of candidateFindingsForGate3) {
        ledger.addReported(finding);
      }
    }

    // Final deterministic sort: Severity desc -> Gate 2 reachability -> AI verdict -> Fingerprint (A9)
    ledger.sortReported(compareFindings);

    // Collect warnings from ignore rules (expired / unused)
    const ignoreWarnings = ignoreEvaluator.collectWarnings();
    warnings.push(...ignoreWarnings);

    // 9. Update Baseline if requested
    if (options.updateBaseline) {
      BaselineEvaluator.writeBaseline(baselineFilePath, ledger.getReportedFindings());
    }

    // Check if no scanner completed successfully (R2)
    const successfulScanners = scannerSummaries.filter((s) => s.status === 'SUCCESS');
    if (scannerSummaries.length > 0 && successfulScanners.length === 0) {
      const reasons = scannerSummaries
        .map((s) => `${s.name} (${s.status}${s.errorMessage ? `: ${s.errorMessage}` : ''})`)
        .join('; ');
      warnings.push(`NOT SCANNED: no scanner completed. Reasons: ${reasons}`);
    }

    // 10. Assemble and return final validated ScanReport
    const durationMs = Date.now() - startTime;
    const mode = diffScope.isDiffMode ? 'DIFF' : 'FULL';

    // If Gate 2 is off, contract requires no reachabilityDetail on any finding (R5)
    if (gate2Mode === 'off') {
      for (const f of ledger.getReportedFindings()) {
        delete f.reachabilityDetail;
      }
      for (const s of ledger.getSuppressedFindings()) {
        delete s.finding.reachabilityDetail;
      }
    }

    return ReportBuilder.build({
      targetDir,
      mode,
      diffBase: options.diffRef,
      startedAt,
      durationMs,
      scanners: scannerSummaries,
      ledger,
      ai: aiSummary,
      tier: tierState.tier,
      offline: offlineCtx.enabled
        ? {
            enabled: true,
            completeness: offlineCtx.completeness,
            databases: offlineCtx.databases,
          }
        : undefined,
      warnings,
      includeReachability: gate2Mode !== 'off',
      functionLevelOptions: { skippedTier },
    });
  }

  /**
   * Filters and selects adapters to execute.
   */
  private static selectAdapters(
    allAdapters: IScannerAdapter[],
    profile: ProjectProfile,
    config: SecureShipConfig,
    userRequested?: string[]
  ): IScannerAdapter[] {
    const requestedSet =
      userRequested && userRequested.length > 0
        ? new Set(userRequested.map((s) => s.toLowerCase()))
        : null;

    return allAdapters.filter((adapter) => {
      // 1. Explicit user CLI filter
      if (requestedSet) {
        return requestedSet.has(adapter.name.toLowerCase());
      }

      // 2. Config enable/disable toggle
      if (config.scanners && config.scanners[adapter.name] !== undefined) {
        return config.scanners[adapter.name] === true;
      }

      // 3. Project profile support
      return adapter.supportsProject(profile);
    });
  }
}
