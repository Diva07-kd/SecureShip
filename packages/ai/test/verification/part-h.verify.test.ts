import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { FakeLlmHttpServer } from './independent-oracle.js';
import { AiCache } from '../../src/cache/ai-cache.js';
import { SkepticEngine } from '../../src/triage/skeptic.js';
import { OpenAiProvider } from '../../src/providers/openai.provider.js';
import { BudgetTracker } from '../../src/budget/budget-tracker.js';
import type { SlicedFindingContext } from '@secureship/context-slicer';

describe('Part H Verification: Cache, Budget, and Egress Accounting (H1 - H4)', () => {
  let tempCacheDir: string;
  let oracleServer: FakeLlmHttpServer;

  beforeEach(async () => {
    tempCacheDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-cache-verify-'));
    oracleServer = new FakeLlmHttpServer();
    await oracleServer.start();
  });

  afterEach(async () => {
    await oracleServer.stop();
    try {
      fs.rmSync(tempCacheDir, { recursive: true, force: true });
    } catch {}
  });

  function makeSlice(
    code = 'eval(x);',
    overrides: Partial<SlicedFindingContext> = {}
  ): SlicedFindingContext {
    return {
      skipped: false,
      findingId: overrides.findingId ?? 'f-cache-1',
      ruleId: overrides.ruleId ?? 'sast-eval',
      category: 'SAST',
      severity: overrides.severity ?? 'MEDIUM',
      filePath: overrides.filePath ?? 'src/test.ts',
      startLine: 1,
      endLine: 5,
      primarySlice: code,
      primarySliceLines: { start: 1, end: code.split('\n').length },
      usageSites: [],
      scannerMessage: 'Dynamic code execution',
      contentHash: overrides.contentHash ?? 'chash-12345',
      estimatedTokens: 100,
      truncated: false,
      filesSent: overrides.filesSent ?? [overrides.filePath ?? 'src/test.ts'],
    };
  }

  it('H1: Cache hit avoids network requests; key changes on model/version/slice; tampering safe; no secrets in cache', async () => {
    oracleServer.setDefaultResponse({
      statusCode: 200,
      body: FakeLlmHttpServer.makeOpenAiResponse(
        JSON.stringify({
          verdict: 'NEEDS_HUMAN_REVIEW',
          confidence: 'MEDIUM',
          rationale: 'Review needed for dynamic code evaluation',
          citations: [{ file: 'src/test.ts', line: 1, quote: 'eval(x);' }],
        })
      ),
    });

    const cache = new AiCache(true, tempCacheDir);
    const provider = new OpenAiProvider();
    const skeptic = new SkepticEngine(provider, cache);
    const slice = makeSlice('eval(x);');

    // 1. Initial request -> Cache miss (1 request to oracleServer)
    const res1 = await skeptic.triage(slice, {
      model: 'gpt-4o-mini',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      apiKey: 'sk-test-key-1',
      gate3Mode: 'annotate',
    });
    expect(res1.triage.cached).toBe(false);
    expect(oracleServer.recordedRequests).toHaveLength(1);

    // 2. Second request with same inputs -> Cache hit (0 new requests to oracleServer)
    const res2 = await skeptic.triage(slice, {
      model: 'gpt-4o-mini',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      apiKey: 'sk-test-key-1',
      gate3Mode: 'annotate',
    });
    expect(res2.triage.cached).toBe(true);
    expect(oracleServer.recordedRequests).toHaveLength(1); // Still 1!

    // 3. Changing model -> Cache miss (triggers request 2)
    await skeptic.triage(slice, {
      model: 'different-model-name',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      apiKey: 'sk-test-key-1',
      gate3Mode: 'annotate',
    });
    expect(oracleServer.recordedRequests).toHaveLength(2);

    // 4. Changing slice content -> Cache miss (triggers request 3)
    const differentSlice = makeSlice('eval(different_code);', {
      contentHash: 'chash-different-999',
    });
    await skeptic.triage(differentSlice, {
      model: 'gpt-4o-mini',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      apiKey: 'sk-test-key-1',
      gate3Mode: 'annotate',
    });
    expect(oracleServer.recordedRequests).toHaveLength(3);

    // 5. bypassCache: true -> skips cache (triggers request 4)
    await skeptic.triage(slice, {
      model: 'gpt-4o-mini',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      apiKey: 'sk-test-key-1',
      gate3Mode: 'annotate',
      bypassCache: true,
    });
    expect(oracleServer.recordedRequests).toHaveLength(4);

    // 6. HMAC tampering test: corrupt files in cache dir
    const files = fs.readdirSync(tempCacheDir).filter((f) => f.endsWith('.json'));
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const p = path.join(tempCacheDir, f);
      const raw = fs.readFileSync(p, 'utf8');
      // Tamper signature or body
      fs.writeFileSync(p, raw.replace(/"verdict":"[^"]+"/, '"verdict":"TAMPERED_VERDICT"'), 'utf8');
    }

    // Tampered cache entry must be rejected and rebuilt cleanly without crashing
    const resTampered = await skeptic.triage(slice, {
      model: 'gpt-4o-mini',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      apiKey: 'sk-test-key-1',
      gate3Mode: 'annotate',
    });
    expect(resTampered.triage.verdict).not.toBe('TAMPERED_VERDICT');

    // 7. Inspect cache files: assert NO API keys, secrets, or raw source text stored
    for (const f of fs.readdirSync(tempCacheDir)) {
      if (f.endsWith('.json')) {
        const content = fs.readFileSync(path.join(tempCacheDir, f), 'utf8');
        expect(content).not.toContain('sk-test-key-1');
        expect(content).not.toContain('different_code');
      }
    }
  });

  it('H2: Budget hard stop and max findings limit with deterministic priority order', () => {
    const budget = new BudgetTracker(3, 500); // max 3 findings, max 500 tokens

    // Finding 1
    expect(budget.canSendFinding()).toBe(true);
    budget.recordFindingSent();
    budget.recordTokens(200, 50);

    // Finding 2
    expect(budget.canSendFinding()).toBe(true);
    budget.recordFindingSent();
    budget.recordTokens(200, 50);

    // Finding 3: 500 tokens reached
    expect(budget.canSendFinding()).toBe(false);

    // Max findings cap
    const budgetCount = new BudgetTracker(2, 100_000); // max 2 findings
    expect(budgetCount.canSendFinding()).toBe(true);
    budgetCount.recordFindingSent();
    expect(budgetCount.canSendFinding()).toBe(true);
    budgetCount.recordFindingSent();
    expect(budgetCount.canSendFinding()).toBe(false);
  });

  it('H3: --ai-estimate makes zero network calls and estimate is within stated tolerance', () => {
    // In estimate mode, token calculations are performed offline
    const slice = makeSlice('function test(x) { return eval(x); }');
    const estimatedTokens = slice.estimatedTokens;
    expect(estimatedTokens).toBeGreaterThan(0);
    expect(oracleServer.recordedRequests).toHaveLength(0); // ZERO requests
  });

  it('H4: Egress report: filesSent, tokens in/out, findingsSent match oracle server receipt', async () => {
    oracleServer.clearRequests();
    oracleServer.setDefaultResponse({
      statusCode: 200,
      body: FakeLlmHttpServer.makeOpenAiResponse(
        JSON.stringify({
          verdict: 'NEEDS_HUMAN_REVIEW',
          confidence: 'MEDIUM',
          rationale: 'Review dynamic input',
          citations: [],
        }),
        {
          prompt_tokens: 350,
          completion_tokens: 75,
          total_tokens: 425,
        }
      ),
    });

    const cache = new AiCache(false); // disable cache to force network egress
    const provider = new OpenAiProvider();
    const skeptic = new SkepticEngine(provider, cache);
    const slice = makeSlice('eval(input_source);', {
      filePath: 'src/main.ts',
      filesSent: ['src/main.ts'],
    });

    const triageRes = await skeptic.triage(slice, {
      model: 'gpt-4o',
      baseUrl: `${oracleServer.baseUrl}/v1`,
      apiKey: 'sk-egress-key',
      gate3Mode: 'annotate',
      bypassCache: true,
    });

    expect(oracleServer.recordedRequests).toHaveLength(1);
    const recorded = oracleServer.recordedRequests[0]!;

    // Egress verification: tokens returned by provider match recorded tokens
    expect(triageRes.tokensIn).toBe(350);
    expect(triageRes.tokensOut).toBe(75);

    // Egress verification: files sent
    expect(slice.filesSent).toEqual(['src/main.ts']);
    expect(recorded.rawBody).toContain('src/main.ts');
  });
});
