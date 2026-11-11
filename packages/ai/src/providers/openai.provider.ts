import {
  type ILlmProvider,
  type LlmTriageRequest,
  type LlmTriageResponse,
  AiError,
} from './provider.interface.js';
import { HttpClient } from './http-client.js';

export class OpenAiProvider implements ILlmProvider {
  public readonly name = 'openai';

  public async sendTriageRequest(
    request: LlmTriageRequest,
    signal?: AbortSignal
  ): Promise<LlmTriageResponse> {
    if (!request.model) {
      throw new AiError('Model name is required for OpenAI-compatible provider.', 'CONFIG_ERROR');
    }

    const base = request.baseUrl || 'https://api.openai.com/v1';
    const endpoint = base.endsWith('/chat/completions')
      ? base
      : `${base.replace(/\/+$/, '')}/chat/completions`;

    const headers: Record<string, string> = {
      'content-type': 'application/json',
    };
    if (request.apiKey) {
      headers['authorization'] = `Bearer ${request.apiKey}`;
    }

    let deterministic = true;
    const payload: Record<string, unknown> = {
      model: request.model,
      max_tokens: request.maxTokens || 1024,
      temperature: 0,
      messages: [
        { role: 'system', content: request.systemPrompt },
        { role: 'user', content: request.userPrompt },
      ],
    };

    let response;
    try {
      response = await HttpClient.request(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal,
      });
    } catch (err: unknown) {
      // Check if temperature 0 was rejected (e.g. reasoning models o1/o3 or custom servers)
      if (
        err instanceof AiError &&
        err.status === 400 &&
        err.message.toLowerCase().includes('temperature')
      ) {
        deterministic = false;
        delete payload.temperature;
        response = await HttpClient.request(endpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
          signal,
        });
      } else {
        throw err;
      }
    }

    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(response.text);
    } catch {
      throw new AiError('OpenAI API returned invalid non-JSON body', 'MALFORMED', response.status);
    }

    const choices = parsed.choices as
      | Array<{
          message?: { content?: string | null };
        }>
      | undefined;
    const rawText = choices?.[0]?.message?.content ?? '';

    if (!rawText) {
      throw new AiError(
        'OpenAI API response contained no choice content',
        'MALFORMED',
        response.status
      );
    }

    const usage = parsed.usage as
      | { prompt_tokens?: number; completion_tokens?: number }
      | undefined;
    const tokensIn = usage?.prompt_tokens ?? 0;
    const tokensOut = usage?.completion_tokens ?? 0;

    return {
      rawText,
      tokensIn,
      tokensOut,
      deterministic,
    };
  }
}
