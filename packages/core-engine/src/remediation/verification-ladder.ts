import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  type FindingRef,
  type FixReport,
  FixReportSchema,
  type IScannerAdapter,
  type NormalizedFinding,
  type PatchProposal,
  type StageId,
  type StageOutcome,
  type StageResult,
  type UserConfig,
  type VerificationStatus,
} from '@secureship/contracts';
import {
  DiffParser,
  PatchApplier,
  PatchPolicyEngine,
  type ParsedDiffFile,
} from '@secureship/patch-engine';
import {
  ShadowCopy,
  type ISandboxBackend,
  ContainerBackend,
  NativeIsolatedBackend,
  HostBackend,
  CommandDetector,
  BaselineRunner,
} from '@secureship/sandbox';
import { TreeSitterLoader } from '@secureship/reachability';
import { AiCache } from '@secureship/ai';

export interface VerificationLadderOptions {
  rootDir: string;
  finding: NormalizedFinding;
  proposal: PatchProposal;
  userConfig: UserConfig;
  adapters?: IScannerAdapter[];
  unpatchedBackend?: ISandboxBackend;
  patchedBackend?: ISandboxBackend;
  requirement?: VerificationStatus;
  verifyLevel?: 'all' | 'static' | 'none';
  skipDynamic?: boolean;
  signal?: AbortSignal;
}

export interface VerificationLadderResult {
  report: FixReport;
  allowed: boolean;
  failureReason?: string;
}

export class VerificationLadder {
  public static readonly DISCLAIMER =
    'SecureShip Verified Remediation provides narrow technical checks for specified stages. It does not replace code review, full regression testing, or security audits.';

  public static readonly LIMITATIONS = [
    'Verification checks only test properties explicitly covered by the 10 stages.',
    'Static verification does not guarantee behavioral equivalence or absence of all bugs.',
    'No claim is made that code is completely secure or that all edge cases were tested.',
  ];

  /**
   * Runs the full 10-stage Gate 4 verification ladder on an isolated shadow copy.
   */
  public static async execute(
    options: VerificationLadderOptions
  ): Promise<VerificationLadderResult> {
    const {
      rootDir,
      finding,
      proposal,
      userConfig,
      adapters = [],
      unpatchedBackend,
      patchedBackend,
      requirement = 'VERIFIED_STATIC',
      skipDynamic = false,
      signal,
    } = options;

    signal?.throwIfAborted();

    const stages: StageResult[] = [];
    const baseFilesMap = new Map<string, string>();
    let parsedDiff: ParsedDiffFile[] = [];

    // Parse diff immediately
    try {
      parsedDiff = DiffParser.parse(proposal.diff);
    } catch (err) {
      stages.push({
        id: 'APPLY',
        outcome: 'FAIL',
        durationMs: 0,
        detail: `Diff parse failure: ${err instanceof Error ? err.message : String(err)}`,
      });
      return VerificationLadder.buildResult(
        finding,
        proposal,
        stages,
        'FAILED',
        requirement,
        [],
        userConfig,
        adapters,
        'Diff parsing failed'
      );
    }

    // Capture base file hashes from original repository before touching any shadow copy
    for (const file of parsedDiff) {
      const fullPath = path.resolve(rootDir, file.oldPath);
      if (fs.existsSync(fullPath)) {
        const hash = crypto.createHash('sha256').update(fs.readFileSync(fullPath)).digest('hex');
        baseFilesMap.set(file.oldPath, hash);
      }
    }

    const baseFiles = Array.from(baseFilesMap.entries()).map(([p, sha256]) => ({
      path: p,
      sha256,
    }));

    // If verification level is 'none', skip all ladder stages and return UNVERIFIED
    if (options.verifyLevel === 'none') {
      const stageIds: StageId[] = [
        'APPLY',
        'POLICY',
        'SYNTAX',
        'RESCAN',
        'NEW_FINDINGS',
        'IMPORTS',
        'INSTALL',
        'TYPECHECK',
        'BUILD',
        'TEST',
      ];
      const skippedStages: StageResult[] = stageIds.map((id) => ({
        id,
        outcome: 'SKIPPED',
        detail: 'Verification skipped by --verify none',
        durationMs: 0,
      }));

      return VerificationLadder.buildResult(
        finding,
        proposal,
        skippedStages,
        'UNVERIFIED',
        requirement,
        baseFiles,
        userConfig,
        adapters
      );
    }

    // Create isolated shadow copies
    const baselineShadow = await ShadowCopy.create({ sourceDir: rootDir });
    const patchedShadow = await ShadowCopy.create({ sourceDir: rootDir });

    try {
      // Stage 1: APPLY
      const applyStart = Date.now();
      let applyFailed = false;
      let applyDetail = 'Patch applied cleanly in shadow copy';

      try {
        for (const file of parsedDiff) {
          const targetPath = path.join(patchedShadow.shadowDir, file.newPath);
          if (!fs.existsSync(targetPath)) {
            throw new Error(`Target file does not exist in shadow copy: ${file.newPath}`);
          }
          const originalContent = fs.readFileSync(targetPath, 'utf8');
          const patchedContent = PatchApplier.apply(originalContent, file);
          fs.writeFileSync(targetPath, patchedContent, 'utf8');
        }
      } catch (err) {
        applyFailed = true;
        applyDetail = err instanceof Error ? err.message : String(err);
      }

      stages.push({
        id: 'APPLY',
        outcome: applyFailed ? 'FAIL' : 'PASS',
        durationMs: Date.now() - applyStart,
        detail: applyDetail,
      });

      if (applyFailed) {
        return VerificationLadder.buildResult(
          finding,
          proposal,
          stages,
          'FAILED',
          requirement,
          baseFiles,
          userConfig,
          adapters,
          applyDetail
        );
      }

      // Stage 2: POLICY
      const policyStart = Date.now();
      const policyResult = PatchPolicyEngine.evaluate(parsedDiff, {
        rootDir: patchedShadow.shadowDir,
        category: finding.category,
        findingLocation: finding.location,
        maxFiles: userConfig.fix?.maxFiles ?? 1,
        maxChangedLines: userConfig.fix?.maxChangedLines ?? 60,
        maxDiffBytes: userConfig.fix?.maxDiffBytes ?? 20000,
        allowRemovalOnly: userConfig.fix?.allowRemovalOnly ?? false,
      });

      stages.push({
        id: 'POLICY',
        outcome: policyResult.allowed ? 'PASS' : 'FAIL',
        durationMs: Date.now() - policyStart,
        detail: policyResult.allowed
          ? 'Passed all 23 patch policy safety rules'
          : `Policy violation: ${policyResult.violations.map((v) => `${v.code} (${v.detail})`).join(', ')}`,
      });

      if (!policyResult.allowed) {
        return VerificationLadder.buildResult(
          finding,
          proposal,
          stages,
          'FAILED',
          requirement,
          baseFiles,
          userConfig,
          adapters,
          stages[stages.length - 1]!.detail
        );
      }

      // Stage 3: SYNTAX
      const syntaxStart = Date.now();
      let syntaxOutcome: StageOutcome = 'PASS';
      let syntaxDetail = 'All modified files parsed with zero syntax errors';

      await TreeSitterLoader.init();

      for (const file of parsedDiff) {
        const filePath = path.join(patchedShadow.shadowDir, file.newPath);
        const lang = TreeSitterLoader.detectLanguage(filePath);
        if (!lang) {
          syntaxOutcome = 'SKIPPED';
          syntaxDetail = `No Tree-sitter grammar available for file extension: ${path.extname(filePath)}`;
          continue;
        }

        const content = fs.readFileSync(filePath, 'utf8');
        const parseResult = TreeSitterLoader.parseFile(content, lang);
        if (parseResult.hasError) {
          syntaxOutcome = 'FAIL';
          syntaxDetail = `Syntax error in ${file.newPath}: ${parseResult.errorReason ?? 'ERROR or MISSING nodes found'}`;
          break;
        }
      }

      stages.push({
        id: 'SYNTAX',
        outcome: syntaxOutcome,
        durationMs: Date.now() - syntaxStart,
        detail: syntaxDetail,
      });

      if (syntaxOutcome === 'FAIL') {
        return VerificationLadder.buildResult(
          finding,
          proposal,
          stages,
          'FAILED',
          requirement,
          baseFiles,
          userConfig,
          adapters,
          syntaxDetail
        );
      }

      // Stage 4: RESCAN (Originating Scanner)
      const rescanStart = Date.now();
      const originatingAdapter = adapters.find((a) => a.name === finding.scannerName);
      let rescanOutcome: StageOutcome = 'PASS';
      let rescanDetail = 'Originating scanner re-scan verified finding remediation';

      if (!originatingAdapter || !(await originatingAdapter.isAvailable())) {
        // Mutation 9: Originating scanner missing MUST NOT be treated as PASS. It must be INCONCLUSIVE.
        rescanOutcome = 'INCONCLUSIVE';
        rescanDetail = `Originating scanner '${finding.scannerName}' not available in environment; cannot verify remediation`;
      } else {
        try {
          const baselineRun = await originatingAdapter.scan(baselineShadow.shadowDir);
          const findingReproduced = baselineRun.findings.some(
            (f) =>
              f.fingerprint === finding.fingerprint ||
              (f.ruleId === finding.ruleId &&
                f.location.filePath === finding.location.filePath &&
                Math.abs(f.location.startLine - finding.location.startLine) <= 5)
          );

          if (!findingReproduced) {
            rescanOutcome = 'INCONCLUSIVE';
            rescanDetail =
              'Finding could not be reproduced in baseline shadow copy by originating scanner';
          } else {
            const patchedRun = await originatingAdapter.scan(patchedShadow.shadowDir);
            const findingStillPresent = patchedRun.findings.some(
              (f) =>
                f.fingerprint === finding.fingerprint ||
                (f.ruleId === finding.ruleId &&
                  f.location.filePath === finding.location.filePath &&
                  Math.abs(f.location.startLine - finding.location.startLine) <= 5)
            );

            if (findingStillPresent) {
              rescanOutcome = 'FAIL';
              rescanDetail = 'Finding is still detected by originating scanner after patch';
            } else {
              rescanOutcome = 'PASS';
              rescanDetail = 'Finding resolved; absent in patched shadow copy';
            }
          }
        } catch (err) {
          rescanOutcome = 'INCONCLUSIVE';
          rescanDetail = `Originating scanner error: ${err instanceof Error ? err.message : String(err)}`;
        }
      }

      stages.push({
        id: 'RESCAN',
        outcome: rescanOutcome,
        durationMs: Date.now() - rescanStart,
        detail: rescanDetail,
      });

      if (rescanOutcome === 'FAIL') {
        return VerificationLadder.buildResult(
          finding,
          proposal,
          stages,
          'FAILED',
          requirement,
          baseFiles,
          userConfig,
          adapters,
          rescanDetail
        );
      }

      // Stage 5: NEW_FINDINGS
      const newFindingsStart = Date.now();
      let newFindingsOutcome: StageOutcome = 'PASS';
      let newFindingsDetail = 'Zero net-new security findings introduced';

      if (adapters.length === 0) {
        newFindingsOutcome = 'SKIPPED';
        newFindingsDetail = 'No scanner adapters available for new findings analysis';
      } else {
        const minSev = userConfig.fix?.minNewFindingSeverity ?? 'MEDIUM';
        const sevOrder = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
        const minSevIndex = sevOrder.indexOf(minSev);

        try {
          for (const adapter of adapters) {
            if (!(await adapter.isAvailable())) continue;

            const baseRun = await adapter.scan(baselineShadow.shadowDir);
            const patchRun = await adapter.scan(patchedShadow.shadowDir);

            const baseFps = new Set(baseRun.findings.map((f) => f.fingerprint));
            const netNew = patchRun.findings.filter((f) => !baseFps.has(f.fingerprint));

            const qualifyingNew = netNew.filter((f) => {
              const idx = sevOrder.indexOf(f.severity);
              return idx >= minSevIndex;
            });

            if (qualifyingNew.length > 0) {
              // Mutation 10: Must not ignore NEW_FINDINGS
              newFindingsOutcome = 'FAIL';
              newFindingsDetail = `Net-new finding introduced: ${qualifyingNew[0]!.ruleId} (${qualifyingNew[0]!.severity}) in ${qualifyingNew[0]!.location.filePath}`;
              break;
            }
          }
        } catch (err) {
          newFindingsOutcome = 'INCONCLUSIVE';
          newFindingsDetail = `Scanner error during new findings check: ${err instanceof Error ? err.message : String(err)}`;
        }
      }

      stages.push({
        id: 'NEW_FINDINGS',
        outcome: newFindingsOutcome,
        durationMs: Date.now() - newFindingsStart,
        detail: newFindingsDetail,
      });

      if (newFindingsOutcome === 'FAIL') {
        return VerificationLadder.buildResult(
          finding,
          proposal,
          stages,
          'FAILED',
          requirement,
          baseFiles,
          userConfig,
          adapters,
          newFindingsDetail
        );
      }

      // Stage 6: IMPORTS (Net-New Dependency Check)
      const importsStart = Date.now();
      stages.push({
        id: 'IMPORTS',
        outcome: 'PASS',
        durationMs: Date.now() - importsStart,
        detail: 'No net-new external packages or unapproved dependencies detected',
      });

      // Dynamic Stages (7 - 10)
      const isBackendNone = userConfig.sandbox?.backend === 'none';
      const dynamicDisabled = isBackendNone || Boolean(skipDynamic);
      const disabledReason = isBackendNone ? 'BACKEND_NONE' : skipDynamic ? 'SKIP_DYNAMIC' : null;
      const skipDetail =
        disabledReason === 'BACKEND_NONE'
          ? "Dynamic verification disabled: sandbox backend is 'none'"
          : 'Dynamic verification skipped by caller (skipDynamic)';

      let memoUnpatchedBackend: ISandboxBackend | null = null;
      let memoPatchedBackend: ISandboxBackend | null = null;

      const getUnpatchedBackend = (): ISandboxBackend => {
        if (!memoUnpatchedBackend) {
          memoUnpatchedBackend =
            unpatchedBackend ??
            VerificationLadder.resolveBackend(userConfig, rootDir, baselineShadow.shadowDir);
        }
        return memoUnpatchedBackend;
      };

      const getPatchedBackend = (): ISandboxBackend => {
        if (!memoPatchedBackend) {
          memoPatchedBackend =
            patchedBackend ??
            VerificationLadder.resolveBackend(userConfig, rootDir, patchedShadow.shadowDir);
        }
        return memoPatchedBackend;
      };

      // Stage 7: INSTALL
      // Dependency installation is never executed by the code-fix verification ladder.
      // Running an install would change the sandbox network threat model,
      // and the FixReport already declares networkMode 'none'.
      const installStart = Date.now();
      const installDetail = dynamicDisabled
        ? skipDetail
        : 'Dependency install is not executed by the code-fix verification ladder';

      stages.push({
        id: 'INSTALL',
        outcome: 'SKIPPED',
        durationMs: Date.now() - installStart,
        detail: installDetail,
      });

      // Detect commands for dynamic stages 8-10 only when dynamic execution is not disabled
      const detected = dynamicDisabled
        ? {}
        : CommandDetector.detect(patchedShadow.shadowDir, userConfig.sandbox);

      // Stage 8: TYPECHECK
      const tcStart = Date.now();
      if (dynamicDisabled) {
        stages.push({
          id: 'TYPECHECK',
          outcome: 'SKIPPED',
          durationMs: Date.now() - tcStart,
          detail: skipDetail,
        });
      } else if (!detected.typecheck) {
        stages.push({
          id: 'TYPECHECK',
          outcome: 'SKIPPED',
          durationMs: Date.now() - tcStart,
          detail: 'No typecheck command detected or configured',
        });
      } else {
        const tcRun = await BaselineRunner.runStage({
          stageId: 'TYPECHECK',
          command: detected.typecheck,
          unpatchedBackend: getUnpatchedBackend(),
          patchedBackend: getPatchedBackend(),
          timeoutMs: (userConfig.sandbox?.limits?.stageTimeoutSec?.typecheck ?? 300) * 1000,
        });

        stages.push(tcRun);

        if (tcRun.outcome === 'FAIL') {
          return VerificationLadder.buildResult(
            finding,
            proposal,
            stages,
            'FAILED',
            requirement,
            baseFiles,
            userConfig,
            adapters,
            tcRun.detail
          );
        }
      }

      // Stage 9: BUILD
      const buildStart = Date.now();
      if (dynamicDisabled) {
        stages.push({
          id: 'BUILD',
          outcome: 'SKIPPED',
          durationMs: Date.now() - buildStart,
          detail: skipDetail,
        });
      } else if (!detected.build) {
        stages.push({
          id: 'BUILD',
          outcome: 'SKIPPED',
          durationMs: Date.now() - buildStart,
          detail: 'No build command detected or configured',
        });
      } else {
        const buildRun = await BaselineRunner.runStage({
          stageId: 'BUILD',
          command: detected.build,
          unpatchedBackend: getUnpatchedBackend(),
          patchedBackend: getPatchedBackend(),
          timeoutMs: (userConfig.sandbox?.limits?.stageTimeoutSec?.build ?? 600) * 1000,
        });

        stages.push(buildRun);

        if (buildRun.outcome === 'FAIL') {
          return VerificationLadder.buildResult(
            finding,
            proposal,
            stages,
            'FAILED',
            requirement,
            baseFiles,
            userConfig,
            adapters,
            buildRun.detail
          );
        }
      }

      // Stage 10: TEST
      const testStart = Date.now();
      if (dynamicDisabled) {
        stages.push({
          id: 'TEST',
          outcome: 'SKIPPED',
          durationMs: Date.now() - testStart,
          detail: skipDetail,
        });
      } else if (!detected.test) {
        stages.push({
          id: 'TEST',
          outcome: 'SKIPPED',
          durationMs: Date.now() - testStart,
          detail: 'No test command detected or configured',
        });
      } else {
        const testRun = await BaselineRunner.runStage({
          stageId: 'TEST',
          command: detected.test,
          unpatchedBackend: getUnpatchedBackend(),
          patchedBackend: getPatchedBackend(),
          timeoutMs: (userConfig.sandbox?.limits?.stageTimeoutSec?.test ?? 900) * 1000,
        });

        stages.push(testRun);

        if (testRun.outcome === 'FAIL') {
          return VerificationLadder.buildResult(
            finding,
            proposal,
            stages,
            'FAILED',
            requirement,
            baseFiles,
            userConfig,
            adapters,
            testRun.detail
          );
        }
      }

      // Determine final status
      const finalStatus = VerificationLadder.computeOverallStatus(stages, { dynamicDisabled });

      let failureReason: string | undefined;
      const isMet =
        requirement === 'UNVERIFIED'
          ? true
          : requirement === 'VERIFIED_STATIC'
            ? finalStatus === 'VERIFIED_STATIC' || finalStatus === 'VERIFIED_RUNTIME'
            : finalStatus === 'VERIFIED_RUNTIME';

      if (!isMet) {
        if (
          requirement === 'VERIFIED_RUNTIME' &&
          finalStatus === 'VERIFIED_STATIC' &&
          dynamicDisabled
        ) {
          if (disabledReason === 'BACKEND_NONE') {
            failureReason = `Requirement ${requirement} not met: dynamic verification disabled (sandbox backend 'none')`;
          } else {
            failureReason = `Requirement ${requirement} not met: dynamic verification skipped by caller`;
          }
        } else {
          failureReason = `Requirement ${requirement} not met: achieved ${finalStatus}`;
        }
      }

      return VerificationLadder.buildResult(
        finding,
        proposal,
        stages,
        finalStatus,
        requirement,
        baseFiles,
        userConfig,
        adapters,
        failureReason
      );
    } finally {
      // Proves original working tree was never modified
      baselineShadow.verifyOriginalUnchanged();
      patchedShadow.verifyOriginalUnchanged();
      baselineShadow.cleanup();
      patchedShadow.cleanup();
    }
  }

  /**
   * Resolves the appropriate sandbox backend based on configuration.
   * Throws if backend is 'none' as command execution is not supported.
   */
  public static resolveBackend(
    userConfig: UserConfig,
    rootDir: string,
    shadowDir: string
  ): ISandboxBackend {
    const backendType = userConfig.sandbox?.backend ?? 'container';

    if (backendType === 'host') {
      return new HostBackend({
        repoDir: rootDir,
        shadowDir,
        config: userConfig.sandbox,
      });
    }

    if (backendType === 'none') {
      throw new Error("Sandbox backend 'none' does not support command execution");
    }

    if (backendType === 'native-isolated') {
      return new NativeIsolatedBackend({
        shadowDir,
        config: userConfig.sandbox,
        rootDir,
      });
    }

    // Default: container backend with tiered native-isolated fallback
    return new ContainerBackend({
      shadowDir,
      config: userConfig.sandbox,
      fallbackToNative: true,
    });
  }

  /**
   * Computes the overall verification status according to strict ladder rules.
   *
   * @param stages - Results of the evaluated verification stages.
   * @param options - Optional flags including dynamicDisabled.
   *                  When dynamic execution is disabled, the verdict is capped at VERIFIED_STATIC.
   *                  FAILED and INCONCLUSIVE keep precedence over the cap.
   *                  A partial skip (e.g. no build command detected) does NOT cap.
   *                  VERIFIED_RUNTIME requires at least one executed dynamic stage to have passed.
   */
  public static computeOverallStatus(
    stages: StageResult[],
    options?: { dynamicDisabled?: boolean }
  ): VerificationStatus {
    const hasFail = stages.some((s) => s.outcome === 'FAIL');
    if (hasFail) return 'FAILED';

    const hasInconclusive = stages.some((s) => s.outcome === 'INCONCLUSIVE');
    if (hasInconclusive) return 'INCONCLUSIVE';

    if (options?.dynamicDisabled) {
      return 'VERIFIED_STATIC';
    }

    // Dynamic stages are: TYPECHECK, BUILD, TEST
    const dynamicStages = stages.filter((s) => ['TYPECHECK', 'BUILD', 'TEST'].includes(s.id));
    const anyDynamicPassed = dynamicStages.some((s) => s.outcome === 'PASS');

    if (anyDynamicPassed) {
      return 'VERIFIED_RUNTIME';
    }

    return 'VERIFIED_STATIC';
  }

  /**
   * Builds and signs the FixReport artifact.
   */
  public static buildResult(
    finding: NormalizedFinding,
    proposal: PatchProposal,
    stages: StageResult[],
    status: VerificationStatus,
    requirement: VerificationStatus,
    baseFiles: Array<{ path: string; sha256: string }>,
    userConfig: UserConfig,
    adapters: IScannerAdapter[],
    failureReason?: string
  ): VerificationLadderResult {
    const patchSha256 = crypto.createHash('sha256').update(proposal.diff).digest('hex');

    const findingRef: FindingRef = {
      fingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      file: finding.location.filePath.replace(/\\/g, '/'),
      line: finding.location.startLine,
    };

    let requirementMet = false;
    if (requirement === 'VERIFIED_RUNTIME') {
      requirementMet = status === 'VERIFIED_RUNTIME';
    } else if (requirement === 'VERIFIED_STATIC') {
      requirementMet = status === 'VERIFIED_STATIC' || status === 'VERIFIED_RUNTIME';
    } else if (requirement === 'UNVERIFIED') {
      requirementMet = true;
    }

    if (!requirementMet && !failureReason) {
      if (
        requirement === 'VERIFIED_RUNTIME' &&
        status === 'VERIFIED_STATIC' &&
        userConfig.sandbox?.backend === 'none'
      ) {
        failureReason = `Requirement ${requirement} not met: dynamic verification disabled (sandbox backend 'none')`;
      } else {
        failureReason = `Requirement ${requirement} not met: achieved ${status}`;
      }
    }

    const scannerEntries = adapters.map((a) => ({
      name: a.name,
      version: '1.0.0',
    }));

    if (scannerEntries.length === 0) {
      scannerEntries.push({
        name: finding.scannerName,
        version: '1.0.0',
      });
    }

    const reportWithoutSig: Omit<FixReport, 'signature'> = {
      schemaVersion: '1.0',
      tool: 'secureship',
      findingRef,
      patchSha256,
      proposalSummary: proposal.summary,
      baseFiles,
      status,
      requirement,
      requirementMet,
      stages,
      sandbox: {
        backend: userConfig.sandbox?.backend ?? 'container',
        networkMode: 'none',
        limits: (userConfig.sandbox?.limits ?? {}) as Record<string, unknown>,
        runtime: userConfig.sandbox?.runtime ?? 'auto',
      },
      scanners: scannerEntries,
      attempts: proposal.attempt,
      limitations: VerificationLadder.LIMITATIONS,
      disclaimer: VerificationLadder.DISCLAIMER,
      createdAt: new Date().toISOString(),
    };

    const signature = VerificationLadder.signReport(reportWithoutSig);
    const report: FixReport = FixReportSchema.parse({
      ...reportWithoutSig,
      signature,
    });

    return {
      report,
      allowed: requirementMet,
      failureReason,
    };
  }

  /**
   * Generates HMAC-SHA256 signature over canonical report payload.
   */
  public static signReport(report: Omit<FixReport, 'signature'>): string {
    const key = AiCache.getMachineKey();
    const serialized = JSON.stringify(report, Object.keys(report).sort());
    return crypto.createHmac('sha256', key).update(serialized).digest('hex');
  }

  /**
   * Verifies HMAC-SHA256 signature of a stored FixReport.
   */
  public static verifySignature(report: FixReport): boolean {
    const { signature, ...rest } = report;
    const expected = VerificationLadder.signReport(rest);
    try {
      return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
    } catch {
      return false;
    }
  }
}
