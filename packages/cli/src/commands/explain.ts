import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import { ScanReportSchema, type ScanReport } from '@secureship/contracts';
import { ContextSlicer, SlicerDenylist } from '@secureship/context-slicer';
import {
  AnthropicProvider,
  ConsentManager,
  HttpClient,
  OpenAiProvider,
  SkepticEngine,
  UserConfigLoader,
} from '@secureship/ai';

export interface ExplainOptions {
  report?: string;
  finding?: string;
  root?: string;
  json?: boolean;
}

export class ExplainCommand {
  public static async run(targetArg: string | undefined, options: ExplainOptions): Promise<number> {
    const rootDir = path.resolve(options.root ?? process.cwd());

    // Resolve report file path and finding selector supporting both syntaxes:
    // 1. New spec: explain <fingerprint|index> --report <file> --root <dir>
    // 2. Legacy: explain <report.json> --finding <id> --root <dir>
    let reportFilePath: string | undefined = options.report;
    let selector: string | undefined = targetArg ?? options.finding;

    if (!reportFilePath && targetArg && (fs.existsSync(targetArg) || targetArg.endsWith('.json'))) {
      reportFilePath = targetArg;
      selector = options.finding;
    }

    if (!reportFilePath) {
      console.error(pc.red('Error: --report <file> is required to specify the ScanReport JSON.'));
      return 2;
    }

    if (!selector) {
      console.error(
        pc.red(
          'Error: Finding fingerprint or index is required: secureship explain <fingerprint|index> --report <file>'
        )
      );
      return 2;
    }

    // 1. Verify report file exists and parse untrusted report
    if (!fs.existsSync(reportFilePath)) {
      console.error(pc.red(`Error: Report file not found at '${reportFilePath}'`));
      return 2;
    }

    let report: ScanReport;
    try {
      const rawContent = fs.readFileSync(reportFilePath, 'utf-8');
      const parsedJson = JSON.parse(rawContent);
      report = ScanReportSchema.parse(parsedJson);
    } catch (err: unknown) {
      console.error(
        pc.red(
          `Error: Invalid or malformed report file: ${err instanceof Error ? err.message : String(err)}`
        )
      );
      return 2;
    }

    // 2. Select finding to explain by fingerprint, ID, ruleId, or 1-based / 0-based index
    let finding = report.findings.find(
      (f) => f.fingerprint === selector || f.id === selector || f.ruleId === selector
    );

    if (!finding && /^\d+$/.test(selector)) {
      const idx = parseInt(selector, 10);
      if (idx >= 1 && idx <= report.findings.length) {
        finding = report.findings[idx - 1];
      } else if (idx === 0 && report.findings.length > 0) {
        finding = report.findings[0];
      }
    }

    if (!finding) {
      console.error(
        pc.red(
          `Error: Finding with fingerprint, ID, or index '${selector}' was not found in report.`
        )
      );
      return 2;
    }

    // 3. Jail path inside rootDir (A11)
    const findingRelPath = SlicerDenylist.jailPath(rootDir, finding.location.filePath);
    if (!findingRelPath) {
      console.error(
        pc.red(
          `Security Error: Finding path traverses outside jail root '${rootDir}'. Refusing explanation.`
        )
      );
      return 2;
    }

    const targetFile = path.join(rootDir, findingRelPath);
    if (!fs.existsSync(targetFile)) {
      console.error(
        pc.red(
          `Error: Source file '${findingRelPath}' does not exist inside root directory '${rootDir}'.`
        )
      );
      return 2;
    }

    // 4. Load AI config and consent
    const userConfig = UserConfigLoader.loadUserConfig();
    const providerName = userConfig.provider || 'openai';
    const modelName = userConfig.model;
    const defaultBase =
      providerName === 'anthropic' ? 'https://api.anthropic.com/v1' : 'https://api.openai.com/v1';
    const baseUrl = userConfig.baseUrl || defaultBase;

    if (!userConfig.ai || !modelName) {
      console.error(pc.red('Error: AI model is not configured. Run `secureship ai enable` first.'));
      return 2;
    }

    try {
      HttpClient.validateEndpoint(baseUrl);
    } catch (err: unknown) {
      console.error(
        pc.red(`Endpoint validation error: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 2;
    }

    const consent = ConsentManager.checkConsent(baseUrl);
    if (!consent.consented) {
      console.error(
        pc.red(
          `Consent missing for endpoint '${baseUrl}': ${consent.reason}. Run \`secureship ai enable\` first.`
        )
      );
      return 2;
    }

    const apiKey = UserConfigLoader.resolveApiKey(providerName);
    if (!apiKey) {
      console.error(
        pc.red(
          `Missing API key for provider '${providerName}'. Sourced from environment variables.`
        )
      );
      return 2;
    }

    // 5. Slice context with redaction and denylist
    const sliceResult = await ContextSlicer.sliceFinding(rootDir, finding, {
      sliceTokens: 6000,
    });

    if (sliceResult.skipped) {
      console.error(
        pc.yellow(
          `Cannot explain finding: context slicer skipped finding (${sliceResult.skipReason}).`
        )
      );
      return 0;
    }

    // 6. Request explanation through SkepticEngine
    const provider = providerName === 'anthropic' ? new AnthropicProvider() : new OpenAiProvider();
    const skeptic = new SkepticEngine(provider);

    console.log(
      pc.cyan(`\nAnalyzing finding ${pc.bold(finding.id)} with ${providerName} (${modelName})...\n`)
    );

    try {
      const triageRes = await skeptic.triage(sliceResult, {
        gate3Mode: 'annotate',
        model: modelName,
        baseUrl,
        apiKey,
      });

      console.log(
        pc.bold(pc.yellow('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'))
      );
      console.log(
        pc.bold(pc.yellow('  ADVISORY AI EXPLANATION (Non-Binding Security Intelligence)  '))
      );
      console.log(
        pc.bold(pc.yellow('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'))
      );
      console.log(`Finding ID   : ${pc.bold(finding.id)}`);
      console.log(`Rule ID      : ${finding.ruleId}`);
      console.log(`File Path    : ${findingRelPath}:${finding.location.startLine}`);
      console.log(
        `AI Verdict   : ${pc.bold(triageRes.triage.verdict)} (Confidence: ${triageRes.triage.confidence})`
      );
      console.log(`Rationale    :\n${triageRes.triage.rationale}\n`);

      if (triageRes.triage.citations.length > 0) {
        console.log(pc.bold('Verified Citations:'));
        for (const c of triageRes.triage.citations) {
          console.log(`  • Line ${c.line}: "${pc.gray(c.quote)}"`);
        }
        console.log();
      }

      console.log(
        pc.gray(
          `Tokens: In ${triageRes.tokensIn}, Out ${triageRes.tokensOut} | Cached: ${triageRes.cacheHit}`
        )
      );
      return 0;
    } catch (err: unknown) {
      console.error(
        pc.red(`AI explanation failed: ${err instanceof Error ? err.message : String(err)}`)
      );
      return 1;
    }
  }
}
