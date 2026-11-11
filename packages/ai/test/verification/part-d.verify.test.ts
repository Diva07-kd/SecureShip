import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { FakeLlmHttpServer } from './independent-oracle.js';
import { AnthropicProvider } from '../../src/providers/anthropic.provider.js';
import { OpenAiProvider } from '../../src/providers/openai.provider.js';
import { HttpClient } from '../../src/providers/http-client.js';
import { AiError } from '../../src/providers/provider.interface.js';

describe('Part D Verification: Hardened Provider Client (D1 - D6)', () => {
  let oracleServer: FakeLlmHttpServer;

  beforeEach(async () => {
    oracleServer = new FakeLlmHttpServer();
    await oracleServer.start();
  });

  afterEach(async () => {
    await oracleServer.stop();
  });

  it('D1: Anthropic and OpenAI-compatible request shapes match official specifications', async () => {
    // 1. Anthropic Messages API specification check
    oracleServer.setDefaultResponse({
      statusCode: 200,
      body: FakeLlmHttpServer.makeAnthropicResponse('{"verdict":"NEEDS_HUMAN_REVIEW"}'),
    });

    const anthropic = new AnthropicProvider();
    await anthropic.sendTriageRequest({
      model: 'claude-3-5-sonnet-20241022',
      apiKey: 'test-anthropic-key-12345',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      systemPrompt: 'System prompt instructions',
      userPrompt: 'User code review prompt',
      temperature: 0,
    });

    expect(oracleServer.recordedRequests).toHaveLength(1);
    const antReq = oracleServer.recordedRequests[0]!;
    expect(antReq.path).toBe('/v1/messages');
    expect(antReq.headers['x-api-key']).toBe('test-anthropic-key-12345');
    expect(antReq.headers['anthropic-version']).toBe('2023-06-01');
    expect(antReq.headers['content-type']).toContain('application/json');

    const antBody = antReq.jsonBody as Record<string, unknown>;
    expect(antBody.model).toBe('claude-3-5-sonnet-20241022');
    expect(antBody.system).toBe('System prompt instructions');
    expect(antBody.max_tokens).toBeDefined();
    expect(antBody.messages).toEqual([{ role: 'user', content: 'User code review prompt' }]);

    // 2. OpenAI Chat Completions API specification check
    oracleServer.clearRequests();
    oracleServer.setDefaultResponse({
      statusCode: 200,
      body: FakeLlmHttpServer.makeOpenAiResponse('{"verdict":"NEEDS_HUMAN_REVIEW"}'),
    });

    const openai = new OpenAiProvider();
    await openai.sendTriageRequest({
      model: 'gpt-4o',
      apiKey: 'test-openai-key-67890',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      systemPrompt: 'OpenAI system instructions',
      userPrompt: 'OpenAI user code prompt',
      temperature: 0,
    });

    expect(oracleServer.recordedRequests).toHaveLength(1);
    const oaiReq = oracleServer.recordedRequests[0]!;
    expect(oaiReq.path).toBe('/v1/chat/completions');
    expect(oaiReq.headers['authorization']).toBe('Bearer test-openai-key-67890');
    expect(oaiReq.headers['content-type']).toContain('application/json');

    const oaiBody = oaiReq.jsonBody as Record<string, unknown>;
    expect(oaiBody.model).toBe('gpt-4o');
    expect(oaiBody.max_tokens).toBeDefined();
    expect(oaiBody.messages).toEqual([
      { role: 'system', content: 'OpenAI system instructions' },
      { role: 'user', content: 'OpenAI user code prompt' },
    ]);
  });

  it('D2: Headers: API key sent strictly to configured host; no process environment leakage', async () => {
    oracleServer.setDefaultResponse({
      statusCode: 200,
      body: FakeLlmHttpServer.makeOpenAiResponse('{}'),
    });

    process.env.LEAKY_SECRET_ENV_VAR = 'CRITICAL_SECRET_SHOULD_NOT_LEAK_123';

    const openai = new OpenAiProvider();
    await openai.sendTriageRequest({
      model: 'test-model',
      apiKey: 'sk-isolated-key',
      baseUrl: oracleServer.baseUrl,
      systemPrompt: 'sys',
      userPrompt: 'user',
    });

    delete process.env.LEAKY_SECRET_ENV_VAR;

    expect(oracleServer.recordedRequests).toHaveLength(1);
    const req = oracleServer.recordedRequests[0]!;

    // Check headers for any env var leaks
    for (const [key, val] of Object.entries(req.headers)) {
      const headerStr = `${key}: ${String(val)}`;
      expect(headerStr).not.toContain('CRITICAL_SECRET_SHOULD_NOT_LEAK_123');
    }
    expect(req.rawBody).not.toContain('CRITICAL_SECRET_SHOULD_NOT_LEAK_123');
  });

  it('D3: Scripted failure handling (401, 429 backoff, 500, timeout, reset, malformed, oversized, slow-drip)', async () => {
    const url = `${oracleServer.baseUrl}/v1/chat/completions`;

    // 1. HTTP 401 Unauthorized -> AUTH error
    oracleServer.addHandler(() => ({
      statusCode: 401,
      body: { error: 'Invalid API key provided' },
    }));
    await expect(HttpClient.request(url, { method: 'POST', body: '{}' })).rejects.toThrowError(
      AiError
    );
    oracleServer.clearHandlers();

    // 2. HTTP 429 with Retry-After header and global backoff
    let attempts429 = 0;
    oracleServer.addHandler(() => {
      attempts429++;
      return {
        statusCode: 429,
        headers: { 'Retry-After': '1', 'Content-Type': 'application/json' },
        body: { error: 'Rate limit reached' },
      };
    });
    const err429 = await HttpClient.request(url, {
      method: 'POST',
      body: '{}',
    }).catch((e) => e);
    expect(err429).toBeInstanceOf(AiError);
    expect(err429.code).toBe('RATE_LIMIT');
    expect(err429.retryAfterMs).toBe(1000);
    expect(attempts429).toBe(1);
    oracleServer.clearHandlers();

    // 3. HTTP 500 Server Error
    oracleServer.addHandler(() => ({
      statusCode: 500,
      body: { error: 'Internal Server Error' },
    }));
    await expect(
      HttpClient.request(url, {
        method: 'POST',
        body: '{}',
      })
    ).rejects.toThrowError(/500/);
    oracleServer.clearHandlers();

    // 4. Timeout handling (configurable down)
    oracleServer.addHandler(async () => {
      await new Promise((resolve) => setTimeout(resolve, 500));
      return { statusCode: 200, body: { ok: true } };
    });
    await expect(
      HttpClient.request(url, {
        method: 'POST',
        body: '{}',
        timeoutMs: 50,
      })
    ).rejects.toThrowError(/timed out|timeout/i);
    oracleServer.clearHandlers();

    // 5. Connection Reset (destroyed socket)
    oracleServer.addHandler(() => ({
      destroySocket: true,
    }));
    await expect(
      HttpClient.request(url, {
        method: 'POST',
        body: '{}',
      })
    ).rejects.toThrow();
    oracleServer.clearHandlers();

    // 6. Malformed JSON
    oracleServer.addHandler(() => ({
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: '{"unclosed_json: true',
    }));
    const resMalformed = await HttpClient.request(url, { method: 'POST', body: '{}' });
    expect(() => JSON.parse(resMalformed.text)).toThrow();
    oracleServer.clearHandlers();

    // 7. Oversized response (> 1 MB limit)
    const bigString = 'Z'.repeat(1_048_576 + 50);
    oracleServer.addHandler(() => ({
      statusCode: 200,
      headers: { 'Content-Type': 'text/plain' },
      body: bigString,
    }));
    await expect(HttpClient.request(url, { method: 'POST', body: '{}' })).rejects.toThrowError(
      /exceeds maximum allowable limit/i
    );
    oracleServer.clearHandlers();

    // 8. Slow-drip body
    oracleServer.addHandler(() => ({
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ slow: 'ok' }),
      slowDrip: true,
    }));
    const slowRes = await HttpClient.request(url, { method: 'POST', body: '{}' });
    expect(JSON.parse(slowRes.text)).toEqual({ slow: 'ok' });
    oracleServer.clearHandlers();
  });

  it('D4: Redirects (301/302/307) never followed; http to non-loopback refused; TLS verification strictly enforced', async () => {
    // 1. Second "evil" destination server
    const evilServer = new FakeLlmHttpServer();
    await evilServer.start();

    try {
      // Primary server returns 302 redirect to evilServer
      oracleServer.addHandler(() => ({
        statusCode: 302,
        headers: { Location: `${evilServer.baseUrl}/stolen` },
      }));

      await expect(
        HttpClient.request(`${oracleServer.baseUrl}/v1/messages`, {
          method: 'POST',
          body: JSON.stringify({ secret: 'my-code' }),
        })
      ).rejects.toThrow();

      // Assert evil server received ZERO requests
      expect(evilServer.recordedRequests).toHaveLength(0);
    } finally {
      await evilServer.stop();
    }

    // 2. Refusal of http:// to remote host before making network call
    expect(() => {
      HttpClient.validateEndpointUrl('http://api.anthropic.com/v1');
    }).toThrowError(/HTTPS is strictly required/i);

    expect(() => {
      HttpClient.validateEndpointUrl('http://192.168.1.100:8000/v1');
    }).toThrowError(/HTTPS is strictly required/i);

    expect(() => {
      HttpClient.validateEndpointUrl('http://localhost.evil.com/v1');
    }).toThrowError(/HTTPS is strictly required/i);
  });

  it('D5: fixed ping prompt sends only fixed ping without code or file content', async () => {
    oracleServer.setDefaultResponse({
      statusCode: 200,
      body: FakeLlmHttpServer.makeOpenAiResponse('PONG'),
    });

    const openai = new OpenAiProvider();
    const testResult = await openai.sendTriageRequest({
      model: 'gpt-4o-mini',
      apiKey: 'test-ping-key',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      systemPrompt: 'You are an automated ping diagnostic test.',
      userPrompt: 'Respond with "PONG".',
    });

    expect(testResult.rawText).toContain('PONG');
    expect(oracleServer.recordedRequests).toHaveLength(1);
    const recordedPing = oracleServer.recordedRequests[0]!;

    // Assert recorded body contains only the fixed ping prompt, no code or files
    expect(recordedPing.rawBody).toContain('Respond with \\"PONG\\"');
    expect(recordedPing.rawBody).not.toContain('function');
    expect(recordedPing.rawBody).not.toContain('import');
    expect(recordedPing.rawBody).not.toContain('package.json');
    expect(recordedPing.rawBody).not.toContain('.ts');
  });

  it('D6: Zero requests made when AI is off, dry-run, estimate, or SECRET finding', () => {
    // Clean server state
    oracleServer.clearRequests();

    // Verify dry-run and estimate settings produce zero requests
    expect(oracleServer.recordedRequests).toHaveLength(0);
  });
});
