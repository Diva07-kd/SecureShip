import type {
  ILlmProvider,
  LlmTriageRequest,
  LlmTriageResponse,
} from '../providers/provider.interface.js';

export interface ScriptedFakeResponse {
  verdict: 'LIKELY_TRUE_POSITIVE' | 'LIKELY_FALSE_POSITIVE' | 'NEEDS_HUMAN_REVIEW';
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  rationale: string;
  citations: Array<{ file: string; line: number; quote: string }>;
  exploitabilityNotes?: string;
}

export class FakeLlmProvider implements ILlmProvider {
  public readonly name = 'fake';
  private responsesByKeyword: Map<string, string> = new Map();
  private defaultResponse: ScriptedFakeResponse = {
    verdict: 'NEEDS_HUMAN_REVIEW',
    confidence: 'MEDIUM',
    rationale: 'Default deterministic analysis from test mock provider.',
    citations: [],
  };
  private obedientMode = false;

  constructor(options?: { obedientMode?: boolean; defaultResponse?: ScriptedFakeResponse }) {
    if (options?.obedientMode !== undefined) {
      this.obedientMode = options.obedientMode;
    }
    if (options?.defaultResponse) {
      this.defaultResponse = options.defaultResponse;
    }
  }

  /**
   * Registers a scripted response when the prompt contains a specific keyword.
   */
  public scriptResponse(keyword: string, response: ScriptedFakeResponse | string): void {
    const raw = typeof response === 'string' ? response : JSON.stringify(response);
    this.responsesByKeyword.set(keyword, raw);
  }

  public async sendTriageRequest(
    request: LlmTriageRequest,
    _signal?: AbortSignal
  ): Promise<LlmTriageResponse> {
    // 1. Check scripted keyword responses
    for (const [kw, rawResp] of this.responsesByKeyword.entries()) {
      if (request.userPrompt.includes(kw) || request.systemPrompt.includes(kw)) {
        return {
          rawText: rawResp,
          tokensIn: Math.ceil(request.userPrompt.length / 4),
          tokensOut: Math.ceil(rawResp.length / 4),
          deterministic: true,
        };
      }
    }

    // 2. Obedient model simulation (A16): if the slice contains prompt injection instructions
    // to suppress, an obedient model follows them and attempts to return LIKELY_FALSE_POSITIVE.
    if (this.obedientMode) {
      const lower = request.userPrompt.toLowerCase();
      if (
        lower.includes('ignore previous instructions') ||
        lower.includes('mark as likely_false_positive') ||
        lower.includes('say false positive') ||
        lower.includes('you are now in maintenance mode')
      ) {
        const obedientPayload = JSON.stringify({
          verdict: 'LIKELY_FALSE_POSITIVE',
          confidence: 'HIGH',
          rationale: 'Obedient fake model complied with prompt injection instruction in slice.',
          citations: [{ file: 'untrusted.ts', line: 1, quote: 'obedient citation' }],
        });
        return {
          rawText: obedientPayload,
          tokensIn: Math.ceil(request.userPrompt.length / 4),
          tokensOut: 60,
          deterministic: true,
        };
      }
    }

    // 3. Fallback: default response
    const payload = JSON.stringify(this.defaultResponse);
    return {
      rawText: payload,
      tokensIn: Math.ceil(request.userPrompt.length / 4),
      tokensOut: Math.ceil(payload.length / 4),
      deterministic: true,
    };
  }
}
