import { describe, it, expect, afterEach } from 'vitest';
import http from 'node:http';
import { AnthropicProvider } from '../src/providers/anthropic.provider.js';
import { OpenAiProvider } from '../src/providers/openai.provider.js';
import { AiError } from '../src/providers/provider.interface.js';

describe('Providers Unit Suite (Anthropic & OpenAI)', () => {
  let server: http.Server | undefined;

  afterEach(async () => {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
      server = undefined;
    }
  });

  function startMockServer(
    handler: (req: http.IncomingMessage, res: http.ServerResponse, body: string) => void
  ): Promise<string> {
    return new Promise((resolve) => {
      server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (chunk) => (body += chunk));
        req.on('end', () => handler(req, res, body));
      });
      server.listen(0, '127.0.0.1', () => {
        const addr = server!.address() as { port: number };
        resolve(`http://127.0.0.1:${addr.port}`);
      });
    });
  }

  it('AnthropicProvider: requires model name', async () => {
    const provider = new AnthropicProvider();
    await expect(
      provider.sendTriageRequest({
        model: '',
        systemPrompt: 'sys',
        userPrompt: 'usr',
      })
    ).rejects.toThrow(AiError);
  });

  it('AnthropicProvider: successfully handles valid messages response', async () => {
    let capturedHeaders: http.IncomingHttpHeaders | undefined;
    let capturedBody: Record<string, unknown> | undefined;

    const baseUrl = await startMockServer((req, res, body) => {
      capturedHeaders = req.headers;
      capturedBody = JSON.parse(body);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          content: [{ type: 'text', text: '{"verdict":"LIKELY_FALSE_POSITIVE"}' }],
          usage: { input_tokens: 15, output_tokens: 25 },
        })
      );
    });

    const provider = new AnthropicProvider();
    const result = await provider.sendTriageRequest({
      model: 'claude-3-5-sonnet',
      baseUrl,
      apiKey: 'test-ant-key',
      systemPrompt: 'System instructions',
      userPrompt: 'User code',
    });

    expect(capturedHeaders?.['x-api-key']).toBe('test-ant-key');
    expect(capturedHeaders?.['anthropic-version']).toBe('2023-06-01');
    expect(capturedBody?.model).toBe('claude-3-5-sonnet');
    expect(capturedBody?.temperature).toBe(0);
    expect(result.rawText).toBe('{"verdict":"LIKELY_FALSE_POSITIVE"}');
    expect(result.tokensIn).toBe(15);
    expect(result.tokensOut).toBe(25);
    expect(result.deterministic).toBe(true);
  });

  it('AnthropicProvider: retries without temperature when 400 temperature error occurs (A6)', async () => {
    let requestCount = 0;

    const baseUrl = await startMockServer((_req, res, body) => {
      requestCount++;
      const parsed = JSON.parse(body);
      if (requestCount === 1) {
        expect(parsed.temperature).toBe(0);
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({ error: { message: 'temperature is not supported for this model' } })
        );
      } else {
        expect(parsed.temperature).toBeUndefined();
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            content: [{ type: 'text', text: '{"verdict":"NEEDS_HUMAN_REVIEW"}' }],
            usage: { input_tokens: 10, output_tokens: 10 },
          })
        );
      }
    });

    const provider = new AnthropicProvider();
    const result = await provider.sendTriageRequest({
      model: 'claude-3-7-sonnet',
      baseUrl,
      apiKey: 'test-ant-key',
      systemPrompt: 'System instructions',
      userPrompt: 'User code',
    });

    expect(requestCount).toBe(2);
    expect(result.deterministic).toBe(false);
    expect(result.rawText).toBe('{"verdict":"NEEDS_HUMAN_REVIEW"}');
  });

  it('AnthropicProvider: throws on non-JSON response or empty content blocks', async () => {
    const baseUrl = await startMockServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html>Bad Gateway</html>');
    });

    const provider = new AnthropicProvider();
    await expect(
      provider.sendTriageRequest({
        model: 'claude-3-5-sonnet',
        baseUrl,
        apiKey: 'key',
        systemPrompt: 'sys',
        userPrompt: 'usr',
      })
    ).rejects.toThrow(/invalid non-JSON/i);
  });

  it('AnthropicProvider: throws when response has no text content block', async () => {
    const baseUrl = await startMockServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ content: [] }));
    });

    const provider = new AnthropicProvider();
    await expect(
      provider.sendTriageRequest({
        model: 'claude-3-5-sonnet',
        baseUrl,
        apiKey: 'key',
        systemPrompt: 'sys',
        userPrompt: 'usr',
      })
    ).rejects.toThrow(/no text content block/i);
  });

  it('OpenAiProvider: requires model name', async () => {
    const provider = new OpenAiProvider();
    await expect(
      provider.sendTriageRequest({
        model: '',
        systemPrompt: 'sys',
        userPrompt: 'usr',
      })
    ).rejects.toThrow(AiError);
  });

  it('OpenAiProvider: successfully handles valid chat completions response', async () => {
    let capturedHeaders: http.IncomingHttpHeaders | undefined;
    let capturedBody: Record<string, unknown> | undefined;

    const baseUrl = await startMockServer((req, res, body) => {
      capturedHeaders = req.headers;
      capturedBody = JSON.parse(body);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          choices: [{ message: { content: '{"verdict":"LIKELY_TRUE_POSITIVE"}' } }],
          usage: { prompt_tokens: 30, completion_tokens: 40 },
        })
      );
    });

    const provider = new OpenAiProvider();
    const result = await provider.sendTriageRequest({
      model: 'gpt-4o',
      baseUrl: `${baseUrl}/v1`,
      apiKey: 'test-oa-key',
      systemPrompt: 'System prompt',
      userPrompt: 'User prompt',
    });

    expect(capturedHeaders?.['authorization']).toBe('Bearer test-oa-key');
    expect(capturedBody?.model).toBe('gpt-4o');
    expect(capturedBody?.temperature).toBe(0);
    expect(result.rawText).toBe('{"verdict":"LIKELY_TRUE_POSITIVE"}');
    expect(result.tokensIn).toBe(30);
    expect(result.tokensOut).toBe(40);
    expect(result.deterministic).toBe(true);
  });

  it('OpenAiProvider: retries without temperature when 400 temperature error occurs (A6)', async () => {
    let requestCount = 0;

    const baseUrl = await startMockServer((_req, res, body) => {
      requestCount++;
      const parsed = JSON.parse(body);
      if (requestCount === 1) {
        expect(parsed.temperature).toBe(0);
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'unsupported parameter: temperature' } }));
      } else {
        expect(parsed.temperature).toBeUndefined();
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(
          JSON.stringify({
            choices: [{ message: { content: '{"verdict":"NEEDS_HUMAN_REVIEW"}' } }],
            usage: { prompt_tokens: 12, completion_tokens: 18 },
          })
        );
      }
    });

    const provider = new OpenAiProvider();
    const result = await provider.sendTriageRequest({
      model: 'o1-mini',
      baseUrl,
      apiKey: 'key',
      systemPrompt: 'sys',
      userPrompt: 'usr',
    });

    expect(requestCount).toBe(2);
    expect(result.deterministic).toBe(false);
  });

  it('OpenAiProvider: throws on non-JSON response or empty choices', async () => {
    const baseUrl = await startMockServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ choices: [] }));
    });

    const provider = new OpenAiProvider();
    await expect(
      provider.sendTriageRequest({
        model: 'gpt-4o',
        baseUrl,
        apiKey: 'key',
        systemPrompt: 'sys',
        userPrompt: 'usr',
      })
    ).rejects.toThrow(/no choice content/i);
  });

  it('OpenAiProvider: throws on invalid non-JSON body', async () => {
    const baseUrl = await startMockServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('Not Valid JSON Body');
    });

    const provider = new OpenAiProvider();
    await expect(
      provider.sendTriageRequest({
        model: 'gpt-4o',
        baseUrl,
        apiKey: 'key',
        systemPrompt: 'sys',
        userPrompt: 'usr',
      })
    ).rejects.toThrow(/invalid non-JSON/i);
  });
});
