export type AiErrorCode =
  | 'AUTH'
  | 'RATE_LIMIT'
  | 'TIMEOUT'
  | 'NETWORK'
  | 'SERVER'
  | 'MALFORMED'
  | 'TOO_LARGE'
  | 'ABORTED'
  | 'CONFIG_ERROR';

export class AiError extends Error {
  public readonly code: AiErrorCode;
  public readonly status?: number;
  public readonly retryAfterMs?: number;

  constructor(message: string, code: AiErrorCode, status?: number, retryAfterMs?: number) {
    super(message);
    this.name = 'AiError';
    this.code = code;
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

export interface LlmTriageRequest {
  model: string;
  baseUrl?: string;
  apiKey?: string;
  systemPrompt: string;
  userPrompt: string;
  temperature?: number;
  maxTokens?: number;
}

export interface LlmTriageResponse {
  rawText: string;
  tokensIn: number;
  tokensOut: number;
  deterministic: boolean;
}

export interface ILlmProvider {
  readonly name: string;
  sendTriageRequest(request: LlmTriageRequest, signal?: AbortSignal): Promise<LlmTriageResponse>;
}
