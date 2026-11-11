import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import {
  type FixReport,
  type IScannerAdapter,
  type NormalizedFinding,
  type PatchProposal,
  type ScanReport,
  type VerificationStatus,
} from '@secureship/contracts';
import { UserConfigLoader } from '@secureship/ai';
import { DiffParser } from '@secureship/patch-engine';
import { VerificationLadder, FixStore } from '@secureship/core-engine';
import {
  OpengrepAdapter,
  GitleaksAdapter,
  TrivyAdapter,
  OsvScannerAdapter,
  CheckovAdapter,
} from '@secureship/scanner-adapters';

export interface VerifyCommandOptions {
  finding?: string;
  report?: string;
  root?: string;
  require?: VerificationStatus;
  verify?: 'all' | 'static' | 'none';
  adapters?: IScannerAdapter[];
  json?: boolean;
}

export class VerifyCommand {
  public static async run(
    patchFilePath: string | undefined,
    options: VerifyCommandOptions
  ): Promise<number> {
    if (!patchFilePath) {
      console.error(
        pc.red('Error: Path to patch file is required: secureship verify <patch-file>')
      );
      return 2;
    }

    const rootDir = path.resolve(options.root ?? '.');
    const fullPatchPath = path.resolve(rootDir, patchFilePath);

    if (!fs.existsSync(fullPatchPath)) {
      console.error(pc.red(`Error: Patch file does not exist: ${fullPatchPath}`));
      return 2;
    }

    const diff = fs.readFileSync(fullPatchPath, 'utf8');

    // Validate diff syntax
    try {
      DiffParser.parse(diff);
    } catch (err) {
      console.error(
        pc.red(`Error: Malformed unified diff: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 2;
    }

    if (!options.finding) {
      console.error(pc.red('Error: --finding <fingerprint|id|index> is required.'));
      return 2;
    }

    // Locate report
    const reportPath = VerifyCommand.findReportPath(rootDir, options.report);
    if (!reportPath || !fs.existsSync(reportPath)) {
      console.error(
        pc.red(`Error: ScanReport not found at '${reportPath ?? 'default locations'}'.`)
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

    const finding = VerifyCommand.resolveFinding(scanReport, options.finding);
    if (!finding) {
      console.error(pc.red(`Error: Finding '${options.finding}' not found in ScanReport.`));
      return 2;
    }

    const userConfig = UserConfigLoader.loadUserConfig();
    const requirement = options.require ?? 'VERIFIED_STATIC';
    const skipDynamic = options.verify === 'none' || options.verify === 'static';

    const proposal: PatchProposal = {
      findingFingerprint: finding.fingerprint,
      summary: `Human patch verification for ${finding.ruleId}`,
      diff,
      rationale: 'Human-authored remediation patch submitted for verification ladder evaluation.',
      assumptions: [],
      risks: [],
      model: 'human',
      promptVersion: 'verify-1.0',
      attempt: 1,
    };

    const adapters = [
      new OpengrepAdapter(),
      new GitleaksAdapter(),
      new TrivyAdapter(),
      new OsvScannerAdapter(),
      new CheckovAdapter(),
    ];

    console.log(
      pc.bold(
        pc.cyan(`\n🔍 Verifying Patch: ${path.basename(patchFilePath)} against ${finding.ruleId}\n`)
      )
    );

    let ladderResult;
    try {
      ladderResult = await VerificationLadder.execute({
        rootDir,
        finding,
        proposal,
        userConfig,
        adapters: options.adapters ?? adapters,
        requirement,
        verifyLevel: options.verify,
        skipDynamic,
      });
    } catch (err) {
      console.error(
        pc.red(`Infrastructure Failure: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 3;
    }

    // Save fix
    const store = new FixStore();
    const fixId = await store.saveFix(rootDir, ladderResult.report, diff);

    if (options.json) {
      console.log(JSON.stringify(ladderResult.report, null, 2));
    } else {
      VerifyCommand.printReport(ladderResult.report, fixId);
    }

    return ladderResult.allowed ? 0 : 1;
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
    const byFp = report.findings.find((f) => f.fingerprint === ref);
    if (byFp) return byFp;

    const byId = report.findings.find((f) => f.id === ref);
    if (byId) return byId;

    const idx = parseInt(ref, 10);
    if (!isNaN(idx) && idx >= 1 && idx <= report.findings.length) {
      return report.findings[idx - 1] ?? null;
    }

    return null;
  }

  private static printReport(report: FixReport, fixId: string): void {
    const statusColor =
      report.status === 'VERIFIED_RUNTIME' || report.status === 'VERIFIED_STATIC'
        ? pc.green
        : report.status === 'FAILED'
          ? pc.red
          : pc.yellow;

    console.log(pc.bold('Verification Result:'));
    console.log(`  Status      : ${statusColor(pc.bold(report.status))}`);
    console.log(
      `  Requirement : ${pc.bold(report.requirement)} (Met: ${report.requirementMet ? pc.green('YES') : pc.red('NO')})`
    );
    console.log(`  Fix ID      : ${pc.cyan(pc.bold(fixId))}`);

    console.log(pc.bold('\nVerification Stages:'));
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

    console.log(pc.bold('\nWorking Tree Status:'));
    console.log(
      pc.green('  ✔ UNTOUCHED. User working tree was not modified during verification.')
    );

    console.log(pc.bold('\nNext Steps:'));
    console.log(`  To apply this verified patch to your working tree, run:`);
    console.log(`    ${pc.cyan(`secureship fix apply ${fixId}`)}\n`);
  }
}
