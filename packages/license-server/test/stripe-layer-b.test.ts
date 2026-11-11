import { describe, it, expect, vi, afterEach } from 'vitest';
import { LicenseWorker, type Env, type LicenseRecord } from '../src/worker.js';
import {
  computeIndependentStripeSignature,
  createCheckoutSessionCompletedEvent,
  DEFAULT_STRIPE_SECRET,
  TEST_RSA_KEYS,
  runDualStoreTest,
} from './stripe-fixtures.js';

describe('LAYER B: Webhook Gate Tests (DEV-2)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const secret = DEFAULT_STRIPE_SECRET;
  const fixedNow = 1770000000;

  // B1: STRIPE_WEBHOOK_SECRET missing: 500 {error:'Stripe webhook secret not configured'}, bodyUsed is false
  it('B1: STRIPE_WEBHOOK_SECRET missing returns 500 and request.bodyUsed remains false', async () => {
    const unconfiguredEnv: Env = {
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: undefined,
    };
    const mockDb = new Map<string, LicenseRecord>();

    const event = createCheckoutSessionCompletedEvent({ now: fixedNow });
    const rawBody = JSON.stringify(event);

    const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: rawBody,
    });

    const res = await LicenseWorker.handleRequest(req, unconfiguredEnv, mockDb);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body).toEqual({ error: 'Stripe webhook secret not configured' });
    expect(req.bodyUsed).toBe(false);
  });

  // B2: Missing signature, wrong signature, replay > 300 s -> 400 Invalid Stripe signature with zero store writes
  it('B2: missing, wrong, and expired signatures return 400 and produce zero store writes', async () => {
    await runDualStoreTest(async (ctx, storeName) => {
      const event = createCheckoutSessionCompletedEvent({ now: fixedNow });
      const rawBody = JSON.stringify(event);

      // B2.1: Missing signature header
      const resMissing = await ctx.dispatchWebhook(rawBody, '');
      expect(resMissing.status).toBe(400);
      expect(await resMissing.json()).toEqual({ error: 'Invalid Stripe signature' });

      // B2.2: Wrong signature
      const badSig = `t=${fixedNow},v1=${'f'.repeat(64)}`;
      const resBad = await ctx.dispatchWebhook(rawBody, badSig);
      expect(resBad.status).toBe(400);
      expect(await resBad.json()).toEqual({ error: 'Invalid Stripe signature' });

      // B2.3: Replay older than 300 s (signed at fixedNow - 301)
      vi.useFakeTimers({ toFake: ['Date'] });
      vi.setSystemTime(fixedNow * 1000);
      const expiredSig = computeIndependentStripeSignature(rawBody, secret, fixedNow - 301).header;
      const resExpired = await ctx.dispatchWebhook(rawBody, expiredSig);
      expect(resExpired.status).toBe(400);
      expect(await resExpired.json()).toEqual({ error: 'Invalid Stripe signature' });
      vi.useRealTimers();

      // Zero store writes asserted on both mock and real-SQL
      if (storeName === 'MockStore') {
        expect(ctx.mockDb!.size).toBe(0);
      } else {
        expect(ctx.recordedSql!.length).toBe(0);
      }
    });
  });

  // B3: Verification precedes parsing
  it('B3.1: invalid signature with non-JSON body returns signature error, not JSON error', async () => {
    const invalidJson = '<<< NOT A VALID JSON STRING >>>';
    const badSig = `t=${fixedNow},v1=${'0'.repeat(64)}`;

    const { mockResult, sqliteResult } = await runDualStoreTest(async (ctx) => {
      const res = await ctx.dispatchWebhook(invalidJson, badSig);
      expect(res.status).toBe(400);
      const body = await res.json();
      expect(body).toEqual({ error: 'Invalid Stripe signature' });
      return res.status;
    });

    expect(mockResult).toBe(400);
    expect(sqliteResult).toBe(400);
  });

  it('B3.2: properly signed body that is not JSON, not an object, or lacks id/type returns 400 Invalid event payload', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx) => {
      // 1. Not valid JSON
      const invalidJson = 'not valid json text';
      const sig1 = computeIndependentStripeSignature(invalidJson, secret, fixedNow).header;
      const res1 = await ctx.dispatchWebhook(invalidJson, sig1);
      expect(res1.status).toBe(400);
      expect(await res1.json()).toEqual({ error: 'Invalid event payload' });

      // 2. Not an object (array)
      const arrayJson = JSON.stringify(['item1', 'item2']);
      const sig2 = computeIndependentStripeSignature(arrayJson, secret, fixedNow).header;
      const res2 = await ctx.dispatchWebhook(arrayJson, sig2);
      expect(res2.status).toBe(400);
      expect(await res2.json()).toEqual({ error: 'Invalid event payload' });

      // 3. Object lacking id
      const noIdJson = JSON.stringify({ type: 'checkout.session.completed', data: {} });
      const sig3 = computeIndependentStripeSignature(noIdJson, secret, fixedNow).header;
      const res3 = await ctx.dispatchWebhook(noIdJson, sig3);
      expect(res3.status).toBe(400);
      expect(await res3.json()).toEqual({ error: 'Invalid event payload' });

      // 4. Object lacking type
      const noTypeJson = JSON.stringify({ id: 'evt_123', data: {} });
      const sig4 = computeIndependentStripeSignature(noTypeJson, secret, fixedNow).header;
      const res4 = await ctx.dispatchWebhook(noTypeJson, sig4);
      expect(res4.status).toBe(400);
      expect(await res4.json()).toEqual({ error: 'Invalid event payload' });
    });

    vi.useRealTimers();
  });

  // B4: Body over 1 MiB gives 413 before verification
  it('B4: body over 1 MiB via content-length or actual payload size gives 413 before verification', async () => {
    const env: Env = {
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };
    const mockDb = new Map<string, LicenseRecord>();

    // 1. Content-Length header > 1 MiB
    const reqCl = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'content-length': '1048577', // 1 MiB + 1 byte
      },
      body: 'short',
    });
    const resCl = await LicenseWorker.handleRequest(reqCl, env, mockDb);
    expect(resCl.status).toBe(413);
    expect(await resCl.json()).toEqual({ error: 'Payload too large' });

    // 2. Actual payload size > 1 MiB (even without content-length header)
    const largePayload = new Uint8Array(1024 * 1024 + 10);
    const reqLarge = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: largePayload,
    });
    const resLarge = await LicenseWorker.handleRequest(reqLarge, env, mockDb);
    expect(resLarge.status).toBe(413);
    expect(await resLarge.json()).toEqual({ error: 'Payload too large' });
  });

  // B5: The ORIGINAL AUDIT EXPLOIT
  it('B5: unsigned checkout.session.completed request gives 400 and creates zero licenses', async () => {
    await runDualStoreTest(async (ctx, storeName) => {
      const exploitEvent = createCheckoutSessionCompletedEvent({
        id: 'evt_exploit_forge_001',
        email: 'attacker@evil.com',
        tier: 'ENTERPRISE',
        seats: 9999,
        orgId: 'forged-org',
        now: fixedNow,
      });
      const rawBody = JSON.stringify(exploitEvent);

      // Unsigned request without stripe-signature header
      const res = await ctx.dispatchWebhook(rawBody, '');
      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: 'Invalid Stripe signature' });

      if (storeName === 'MockStore') {
        expect(ctx.mockDb!.size).toBe(0);
      } else {
        expect(ctx.recordedSql!.length).toBe(0);
      }
    });
  });

  // B6: Signed unknown event type returns 200 {received:true, ignored:true}; unsupported HTTP methods return 404
  it('B6: signed unknown event returns 200 ignored:true, and unsupported HTTP methods return 404', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx) => {
      const unknownEvent = {
        id: 'evt_unknown_999',
        type: 'charge.dispute.funds_withdrawn',
        created: fixedNow,
        data: { object: { id: 'dp_123' } },
      };
      const rawBody = JSON.stringify(unknownEvent);
      const sig = computeIndependentStripeSignature(rawBody, secret, fixedNow).header;

      const res = await ctx.dispatchWebhook(rawBody, sig);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ received: true, ignored: true });

      // Unsupported methods (GET, PUT, DELETE, PATCH)
      for (const m of ['GET', 'PUT', 'DELETE', 'PATCH']) {
        const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
          method: m,
          headers: { 'stripe-signature': sig },
        });
        const mRes = await LicenseWorker.handleRequest(req, ctx.env, ctx.mockDb);
        expect(mRes.status).toBe(404);
        expect(await mRes.json()).toEqual({ error: 'Endpoint not found' });
      }
    });

    vi.useRealTimers();
  });
});
