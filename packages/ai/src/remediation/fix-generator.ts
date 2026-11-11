import {
  PatchProposalSchema,
  type FindingRef,
  type NormalizedFinding,
  type PatchProposal,
  type UserConfig,
} from '@secureship/contracts';
import { ContextSlicer, type SlicedFindingContext } from '@secureship/context-slicer';
import { DiffParser } from '@secureship/patch-engine';
import { OutputSanitizer } from '../sanitize/output-sanitizer.js';
import { FixCache } from '../cache/fix-cache.js';
import { type ILlmProvider } from '../providers/provider.interface.js';
import { UserConfigLoader } from '../user-config/user-config-loader.js';
import {
  FIX_PROMPT_VERSION,
  FixPromptBuilder,
  type FixPromptPayload,
} from './fix-prompt-builder.js';

export interface FixGeneratorOptions {
  rootDir: string;
  finding: NormalizedFinding;
  provider: ILlmProvider;
  userConfig: UserConfig;
  apiKey?: string;
  signal?: AbortSignal;
  noCache?: boolean;
  explicitCacheDir?: string;
}

export interface FixGenerationResult {
  eligible: boolean;
  ineligibleReason?: string;
  proposal?: PatchProposal;
  slice?: SlicedFindingContext;
  sliceHash?: string;
  cacheHit?: boolean;
  promptPayload?: FixPromptPayload;
}

export class FixGenerator {
  public static readonly CREDENTIAL_CWES = new Set([
    'CWE-798',
    'CWE-259',
    'CWE-321',
    'secureship-js-hardcoded-jwt-secret',
  ]);

  /**
   * Validates if a finding is eligible for AI remediation.
   * SECRET, credential-class, and SCA findings are strictly ineligible.
   */
  public static checkEligibility(finding: NormalizedFinding): {
    eligible: boolean;
    reason?: string;
  } {
    if (finding.category === 'SECRET') {
      return {
        eligible: false,
        reason: 'Findings in the SECRET category cannot be remediated by AI (BYOK privacy policy).',
      };
    }

    if (finding.category === 'SCA') {
      return {
        eligible: false,
        reason:
          'Findings in the SCA category (dependency vulnerabilities) are out of scope for single-file source patching.',
      };
    }

    // Check credential-class findings
    const ruleLower = finding.ruleId.toLowerCase();
    const isCred =
      FixGenerator.CREDENTIAL_CWES.has(finding.ruleId) ||
      finding.cweIds?.some((c) => FixGenerator.CREDENTIAL_CWES.has(c)) ||
      ruleLower.includes('hardcoded') ||
      ruleLower.includes('credential');

    if (isCred) {
      return {
        eligible: false,
        reason:
          'Findings involving hardcoded credentials or secret keys (CWE-798/259/321) cannot be sent to an AI model.',
      };
    }

    return { eligible: true };
  }

  /**
   * Generates a candidate fix proposal using the configured LLM provider.
   */
  public static async generate(options: FixGeneratorOptions): Promise<FixGenerationResult> {
    const { rootDir, finding, provider, userConfig, signal, noCache } = options;

    // 1. Eligibility Check
    const eligibility = FixGenerator.checkEligibility(finding);
    if (!eligibility.eligible) {
      return {
        eligible: false,
        ineligibleReason: eligibility.reason,
      };
    }

    // 2. Slice Context
    const sliceResult = await ContextSlicer.sliceFinding(rootDir, finding, {
      sliceTokens: userConfig.gate3?.sliceTokens ?? 6000,
    });

    if (sliceResult.skipped) {
      return {
        eligible: false,
        ineligibleReason: `Context slicer skipped finding: ${sliceResult.skipReason}`,
      };
    }

    const sliceHash = sliceResult.contentHash;
    const model = userConfig.model ?? 'claude-3-5-sonnet-20241022';

    const findingRef: FindingRef = {
      fingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      file: finding.location.filePath.replace(/\\/g, '/'),
      line: finding.location.startLine,
    };

    const cacheKey = FixCache.computeKey(
      finding.fingerprint,
      sliceHash,
      model,
      FIX_PROMPT_VERSION,
      1
    );

    // 3. Check Cache
    const fixCache = new FixCache(!noCache, options.explicitCacheDir);
    if (!noCache) {
      const cached = fixCache.get(cacheKey);
      if (cached) {
        return {
          eligible: true,
          proposal: cached,
          slice: sliceResult,
          sliceHash,
          cacheHit: true,
        };
      }
    }

    // 4. Build Prompt & Query Provider
    const promptPayload = FixPromptBuilder.buildInitialPrompt(findingRef, sliceResult.primarySlice);
    const resolvedApiKey =
      options.apiKey ??
      (userConfig.provider ? UserConfigLoader.resolveApiKey(userConfig.provider) : undefined);

    const response = await provider.sendTriageRequest(
      {
        model,
        apiKey: resolvedApiKey,
        baseUrl: userConfig.baseUrl,
        systemPrompt: promptPayload.systemPrompt,
        userPrompt: promptPayload.userPrompt,
        maxTokens: 4096,
        temperature: 0,
      },
      signal
    );

    const parsedProposal = FixGenerator.parseAndSanitizeOutput(
      response.rawText,
      findingRef.fingerprint,
      model,
      1
    );

    // 5. Cache Valid Proposal
    if (!noCache && parsedProposal) {
      fixCache.set(cacheKey, parsedProposal);
    }

    return {
      eligible: true,
      proposal: parsedProposal,
      slice: sliceResult,
      sliceHash,
      cacheHit: false,
      promptPayload,
    };
  }

  /**
   * Generates a retry fix proposal given verification failure feedback.
   */
  public static async generateRetry(
    options: FixGeneratorOptions,
    basePayload: FixPromptPayload,
    attempt: number,
    previousDiff: string,
    failureFeedback: string
  ): Promise<PatchProposal> {
    const { finding, provider, userConfig, signal } = options;
    const model = userConfig.model ?? 'claude-3-5-sonnet-20241022';

    const retryPrompt = FixPromptBuilder.buildRetryPrompt(basePayload, {
      attempt,
      previousDiff,
      failureReason: failureFeedback,
    });

    const resolvedApiKey =
      options.apiKey ??
      (userConfig.provider ? UserConfigLoader.resolveApiKey(userConfig.provider) : undefined);

    const response = await provider.sendTriageRequest(
      {
        model,
        apiKey: resolvedApiKey,
        baseUrl: userConfig.baseUrl,
        systemPrompt: basePayload.systemPrompt,
        userPrompt: retryPrompt,
        maxTokens: 4096,
        temperature: 0,
      },
      signal
    );

    return FixGenerator.parseAndSanitizeOutput(
      response.rawText,
      finding.fingerprint,
      model,
      attempt
    );
  }

  /**
   * Strictly parses model response text into a validated PatchProposal.
   * Strips markdown fences, repairs JSON wrappers, and sanitizes text fields.
   */
  public static parseAndSanitizeOutput(
    rawText: string,
    findingFingerprint: string,
    model: string,
    attempt: number
  ): PatchProposal {
    let clean = rawText.trim();

    // Strip markdown code fences if model wrapped response in ```json ... ```
    if (clean.startsWith('```')) {
      clean = clean
        .replace(/^```(?:json)?\s*/i, '')
        .replace(/```\s*$/, '')
        .trim();
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(clean);
    } catch {
      // Attempt extracting first JSON block matching { ... }
      const firstBrace = clean.indexOf('{');
      const lastBrace = clean.lastIndexOf('}');
      if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
        const candidate = clean.substring(firstBrace, lastBrace + 1);
        try {
          parsedJson = JSON.parse(candidate);
        } catch (err: unknown) {
          throw new Error(
            `Malformed Model Output: Failed to parse JSON response from LLM: ${err instanceof Error ? err.message : String(err)}`
          );
        }
      } else {
        throw new Error('Malformed Model Output: No JSON object found in LLM response');
      }
    }

    const rawProposal = parsedJson as Record<string, unknown>;

    // Sanitize string fields
    const summary = OutputSanitizer.sanitizeText(String(rawProposal.summary ?? ''), 400);
    const diff = String(rawProposal.diff ?? '');
    const rationale = OutputSanitizer.sanitizeRationale(String(rawProposal.rationale ?? ''));
    const assumptions = Array.isArray(rawProposal.assumptions)
      ? rawProposal.assumptions.map((a) => OutputSanitizer.sanitizeText(String(a), 200))
      : [];
    const risks = Array.isArray(rawProposal.risks)
      ? rawProposal.risks.map((r) => OutputSanitizer.sanitizeText(String(r), 200))
      : [];

    const validated = PatchProposalSchema.parse({
      findingFingerprint,
      summary,
      diff,
      rationale,
      assumptions,
      risks,
      model,
      promptVersion: FIX_PROMPT_VERSION,
      attempt,
    });

    // Validate unified diff syntax immediately
    DiffParser.parse(validated.diff);

    return validated;
  }
}
