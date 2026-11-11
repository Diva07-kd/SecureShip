import {
  type ILlmProvider,
  type LlmTriageRequest,
  type LlmTriageResponse,
  AiError,
} from './provider.interface.js';
import { HttpClient } from './http-client.js';

export class AnthropicProvider implements ILlmProvider {
  public readonly name = 'anthropic';

  public async sendTriageRequest(
    request: LlmTriageRequest,
    signal?: AbortSignal
  ): Promise<LlmTriageResponse> {
    if (!request.model) {
      throw new AiError('Model name is required for Anthropic provider.', 'CONFIG_ERROR');
    }

    const base = request.baseUrl || 'https://api.anthropic.com/v1';
    const endpoint = `${base.replace(/\/+$/, '')}/messages`;

    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'anthropic-version': '2023-06-01',
    };
    if (request.apiKey) {
      headers['x-api-key'] = request.apiKey;
    }

    let deterministic = true;
    const payload: Record<string, unknown> = {
      model: request.model,
      max_tokens: request.maxTokens || 1024,
      temperature: 0,
      system: request.systemPrompt,
      messages: [{ role: 'user', content: request.userPrompt }],
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
      // Check if temperature 0 was rejected (A6)
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
      throw new AiError(
        'Anthropic API returned invalid non-JSON body',
        'MALFORMED',
        response.status
      );
    }

    const contentBlocks = parsed.content as Array<{ type?: string; text?: string }> | undefined;
    const textBlock = contentBlocks?.find((c) => c.type === 'text' || typeof c.text === 'string');
    const rawText = textBlock?.text ?? '';

    if (!rawText) {
      throw new AiError(
        'Anthropic API response contained no text content block',
        'MALFORMED',
        response.status
      );
    }

    const usage = parsed.usage as { input_tokens?: number; output_tokens?: number } | undefined;
    const tokensIn = usage?.input_tokens ?? 0;
    const tokensOut = usage?.output_tokens ?? 0;

    return {
      rawText,
      tokensIn,
      tokensOut,
      deterministic,
    };
  }
}
