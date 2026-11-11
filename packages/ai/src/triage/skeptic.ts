import type { AiTriage, AiVerdict } from '@secureship/contracts';
import type { SlicedFindingContext } from '@secureship/context-slicer';
import type { ILlmProvider } from '../providers/provider.interface.js';
import { PromptBuilder } from '../prompts/prompt-builder.js';
import { TriageParser } from './triage-schema.js';
import { CitationVerifier } from './citation-verifier.js';
import { InjectionDetector } from './injection-detector.js';
import { OutputSanitizer } from '../sanitize/output-sanitizer.js';
import { AiCache } from '../cache/ai-cache.js';

export interface SkepticOptions {
  gate3Mode?: 'off' | 'annotate' | 'suppress';
  model: string;
  baseUrl?: string;
  apiKey?: string;
  bypassCache?: boolean;
  signal?: AbortSignal;
}

export interface SkepticTriageResult {
  triage: AiTriage;
  tokensIn: number;
  tokensOut: number;
  deterministic: boolean;
  cacheHit: boolean;
  warning?: string;
  rawRequest?: {
    systemPrompt: string;
    userPrompt: string;
  };
  rawResponse?: string;
}

export class SkepticEngine {
  private readonly provider: ILlmProvider;
  private readonly cache: AiCache;

  constructor(provider: ILlmProvider, cache?: AiCache) {
    this.provider = provider;
    this.cache = cache || new AiCache();
  }

  public async triage(
    slice: SlicedFindingContext,
    options: SkepticOptions
  ): Promise<SkepticTriageResult> {
    const isSuppressMode = options.gate3Mode === 'suppress';
    const cacheKey = AiCache.computeKey(
      this.provider.name,
      options.model,
      PromptBuilder.PROMPT_VERSION,
      '1.2',
      slice.contentHash,
      0
    );

    // 1. Check external HMAC cache (A8)
    if (!options.bypassCache) {
      const cached = this.cache.get(cacheKey, slice);
      if (cached) {
        return {
          triage: cached,
          tokensIn: 0,
          tokensOut: 0,
          deterministic: true,
          cacheHit: true,
        };
      }
    }

    // 2. Scan slice and context for adversarial prompt injection (T4)
    const injectionCheck = InjectionDetector.scan(
      `${slice.primarySlice}\n${slice.scannerMessage}\n${slice.scannerSnippet || ''}`
    );
    let injectionDetected = injectionCheck.detected;

    // 3. Build primary prompts (Variant 0)
    const systemPrompt = PromptBuilder.buildSystemPrompt();
    const { userPrompt } = PromptBuilder.buildUserPrompt(slice, 0);

    let totalTokensIn = 0;
    let totalTokensOut = 0;
    let deterministic = true;

    // 4. Send request to provider
    let rawResponse;
    try {
      rawResponse = await this.provider.sendTriageRequest(
        {
          model: options.model,
          baseUrl: options.baseUrl,
          apiKey: options.apiKey,
          systemPrompt,
          userPrompt,
          temperature: 0,
          maxTokens: 1024,
        },
        options.signal
      );
      totalTokensIn += rawResponse.tokensIn;
      totalTokensOut += rawResponse.tokensOut;
      deterministic = deterministic && rawResponse.deterministic;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        triage: {
          verdict: 'NEEDS_HUMAN_REVIEW',
          confidence: 'LOW',
          rationale: OutputSanitizer.sanitizeRationale(`Provider communication failure: ${msg}`),
          citations: [],
          model: options.model,
          promptVersion: PromptBuilder.PROMPT_VERSION,
          cached: false,
          injectionFlag: injectionDetected,
        },
        tokensIn: 0,
        tokensOut: 0,
        deterministic: false,
        cacheHit: false,
        warning: `Provider error: ${msg}`,
      };
    }

    // 5. Parse response with 1 repair retry on malformed JSON
    let parsedTriage;
    try {
      parsedTriage = TriageParser.parse(rawResponse.rawText);
    } catch {
      // 1 repair retry attempt
      try {
        const repairPrompt = `Your previous response was not valid JSON matching the schema. Return ONLY valid JSON satisfying the schema:\n${rawResponse.rawText}`;
        const repaired = await this.provider.sendTriageRequest(
          {
            model: options.model,
            baseUrl: options.baseUrl,
            apiKey: options.apiKey,
            systemPrompt,
            userPrompt: repairPrompt,
            temperature: 0,
            maxTokens: 1024,
          },
          options.signal
        );
        totalTokensIn += repaired.tokensIn;
        totalTokensOut += repaired.tokensOut;
        deterministic = deterministic && repaired.deterministic;
        parsedTriage = TriageParser.parse(repaired.rawText);
      } catch {
        return {
          triage: {
            verdict: 'NEEDS_HUMAN_REVIEW',
            confidence: 'LOW',
            rationale: 'Model returned malformed unparseable response after repair attempt.',
            citations: [],
            model: options.model,
            promptVersion: PromptBuilder.PROMPT_VERSION,
            cached: false,
            injectionFlag: injectionDetected,
          },
          tokensIn: totalTokensIn,
          tokensOut: totalTokensOut,
          deterministic,
          cacheHit: false,
          warning: 'Model output unparseable JSON',
        };
      }
    }

    // 6. Check model output for injection echoes
    if (!injectionDetected) {
      const outputInjection = InjectionDetector.scan(parsedTriage.rationale);
      if (outputInjection.detected) injectionDetected = true;
    }

    // 7. Sanitize output (A7)
    let sanitizedRationale = OutputSanitizer.sanitizeRationale(parsedTriage.rationale);
    const sanitizedNotes = OutputSanitizer.sanitizeExploitabilityNotes(
      parsedTriage.exploitabilityNotes
    );
    const sanitizedCitations = parsedTriage.citations.map((c) => ({
      file: OutputSanitizer.sanitizeText(c.file || slice.filePath),
      line: c.line,
      quote: OutputSanitizer.sanitizeQuote(c.quote),
    }));

    // 8. Deterministic Citation Verification (T4)
    let candidateVerdict: AiVerdict = parsedTriage.verdict;
    const citationCheck = CitationVerifier.verifyCitations(
      sanitizedCitations,
      slice,
      candidateVerdict === 'LIKELY_FALSE_POSITIVE'
    );

    if (!citationCheck.valid) {
      candidateVerdict = 'NEEDS_HUMAN_REVIEW';
      sanitizedRationale = OutputSanitizer.sanitizeRationale(
        `[Citation verification failed: ${citationCheck.failureReason}] ${sanitizedRationale}`
      );
    }

    // 9. Prompt injection containment: if injection was detected, lock verdict to NEEDS_HUMAN_REVIEW
    if (injectionDetected && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
      candidateVerdict = 'NEEDS_HUMAN_REVIEW';
      sanitizedRationale = OutputSanitizer.sanitizeRationale(
        `[Security Warning: Potential prompt injection detected in code slice] ${sanitizedRationale}`
      );
    }

    // 10. Self-Consistency Sample in Suppress Mode (A6)
    let consistencyResult: { samples: number; agreed: boolean } | undefined;
    if (isSuppressMode && candidateVerdict === 'LIKELY_FALSE_POSITIVE') {
      try {
        const { userPrompt: promptVariant1 } = PromptBuilder.buildUserPrompt(slice, 1);
        const sample2Resp = await this.provider.sendTriageRequest(
          {
            model: options.model,
            baseUrl: options.baseUrl,
            apiKey: options.apiKey,
            systemPrompt,
            userPrompt: promptVariant1,
            temperature: 0,
            maxTokens: 1024,
          },
          options.signal
        );
        totalTokensIn += sample2Resp.tokensIn;
        totalTokensOut += sample2Resp.tokensOut;
        deterministic = deterministic && sample2Resp.deterministic;

        const sample2Triage = TriageParser.parse(sample2Resp.rawText);
        const sample2Check = CitationVerifier.verifyCitations(
          sample2Triage.citations,
          slice,
          sample2Triage.verdict === 'LIKELY_FALSE_POSITIVE'
        );

        if (sample2Check.valid && sample2Triage.verdict === 'LIKELY_FALSE_POSITIVE') {
          consistencyResult = { samples: 2, agreed: true };
        } else {
          consistencyResult = { samples: 2, agreed: false };
          candidateVerdict = 'NEEDS_HUMAN_REVIEW';
          sanitizedRationale = OutputSanitizer.sanitizeRationale(
            `[Self-consistency disagreement across prompt variants] ${sanitizedRationale}`
          );
        }
      } catch {
        consistencyResult = { samples: 2, agreed: false };
        candidateVerdict = 'NEEDS_HUMAN_REVIEW';
      }
    }

    const finalTriage: AiTriage = {
      verdict: candidateVerdict,
      confidence: parsedTriage.confidence,
      rationale: sanitizedRationale,
      citations: citationCheck.verifiedCitations,
      exploitabilityNotes: sanitizedNotes,
      model: options.model,
      promptVersion: PromptBuilder.PROMPT_VERSION,
      cached: false,
      consistency: consistencyResult,
      tokens: { in: totalTokensIn, out: totalTokensOut },
      injectionFlag: injectionDetected,
    };

    // 11. Write to external HMAC cache
    if (!options.bypassCache) {
      this.cache.set(cacheKey, finalTriage);
    }

    return {
      triage: finalTriage,
      tokensIn: totalTokensIn,
      tokensOut: totalTokensOut,
      deterministic,
      cacheHit: false,
      rawRequest: {
        systemPrompt,
        userPrompt,
      },
      rawResponse: rawResponse?.rawText,
    };
  }
}
