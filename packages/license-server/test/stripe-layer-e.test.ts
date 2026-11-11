import { describe, it, expect, vi, afterEach } from 'vitest';
import { LicenseWorker, type Env } from '../src/worker.js';
import {
  createCheckoutSessionCompletedEvent,
  createCustomerSubscriptionDeletedEvent,
  DEFAULT_STRIPE_SECRET,
  TEST_RSA_KEYS,
  runDualStoreTest,
  createStripeSqliteDb,
  computeIndependentStripeSignature,
} from './stripe-fixtures.js';

describe('LAYER E: Subscription Revocation Tests (DEV-4)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const secret = DEFAULT_STRIPE_SECRET;
  const fixedNow = 1770000000;

  // E1: A customer with licenses on subscriptions A and B. subscription.deleted for A revokes A only; B stays ACTIVE.
  it('E1: revoking subscription A leaves subscription B in ACTIVE status', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      // Provision license on subscription A
      const eventA = createCheckoutSessionCompletedEvent({
        id: 'evt_sub_a_create',
        sessionId: 'cs_sub_a',
        email: 'multi-sub@corp.com',
        subscriptionId: 'sub_alpha_111',
        tier: 'PRO_TEAM',
        seats: 5,
        now: fixedNow,
      });
      const resA = await ctx.dispatchWebhook(JSON.stringify(eventA));
      expect(resA.status).toBe(200);

      // Provision license on subscription B for same customer
      const eventB = createCheckoutSessionCompletedEvent({
        id: 'evt_sub_b_create',
        sessionId: 'cs_sub_b',
        email: 'multi-sub@corp.com',
        subscriptionId: 'sub_beta_222',
        tier: 'ENTERPRISE',
        seats: 10,
        now: fixedNow,
      });
      const resB = await ctx.dispatchWebhook(JSON.stringify(eventB));
      expect(resB.status).toBe(200);

      // Revoke subscription A
      const deleteA = createCustomerSubscriptionDeletedEvent({
        id: 'evt_del_sub_a',
        subscriptionId: 'sub_alpha_111',
        now: fixedNow + 10,
      });
      const resDel = await ctx.dispatchWebhook(JSON.stringify(deleteA));
      expect(resDel.status).toBe(200);
      const delJson = (await resDel.json()) as {
        received: boolean;
        action: string;
        revoked: number;
      };
      expect(delJson).toEqual({
        received: true,
        action: 'license_revoked',
        revoked: 1,
      });

      // Verify store state: sub A is REVOKED, sub B remains ACTIVE
      if (storeName === 'MockStore') {
        const lics = Array.from(ctx.mockDb!.values());
        expect(lics).toHaveLength(2);
        const licA = lics.find((l) => l.stripe_subscription_id === 'sub_alpha_111')!;
        const licB = lics.find((l) => l.stripe_subscription_id === 'sub_beta_222')!;
        expect(licA.status).toBe('REVOKED');
        expect(licB.status).toBe('ACTIVE');
      } else {
        const lics = ctx
          .sqliteDb!.prepare('SELECT * FROM licenses ORDER BY stripe_subscription_id ASC')
          .all() as Array<{
          stripe_subscription_id: string;
          status: string;
        }>;
        expect(lics).toHaveLength(2);
        expect(lics[0]!.stripe_subscription_id).toBe('sub_alpha_111');
        expect(lics[0]!.status).toBe('REVOKED');
        expect(lics[1]!.stripe_subscription_id).toBe('sub_beta_222');
        expect(lics[1]!.status).toBe('ACTIVE');
      }
    });

    vi.useRealTimers();
  });

  // E2: Duplicate delivery: 200 duplicate:true, no further change, revoked count 0 on 2nd
  it('E2: duplicate delivery returns 200 duplicate:true with no further mutations', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      // Provision license
      const event = createCheckoutSessionCompletedEvent({
        id: 'evt_e2_prov',
        sessionId: 'cs_e2',
        subscriptionId: 'sub_e2_dup',
        email: 'e2@test.com',
        now: fixedNow,
      });
      await ctx.dispatchWebhook(JSON.stringify(event));

      // Revoke once
      const deleteEvent = createCustomerSubscriptionDeletedEvent({
        id: 'evt_e2_del',
        subscriptionId: 'sub_e2_dup',
        now: fixedNow + 5,
      });
      const res1 = await ctx.dispatchWebhook(JSON.stringify(deleteEvent));
      expect(res1.status).toBe(200);
      const json1 = (await res1.json()) as { action: string; revoked: number };
      expect(json1.revoked).toBe(1);

      // Re-deliver same event
      const res2 = await ctx.dispatchWebhook(JSON.stringify(deleteEvent));
      expect(res2.status).toBe(200);
      const json2 = (await res2.json()) as { received: boolean; duplicate: boolean };
      expect(json2).toEqual({ received: true, duplicate: true });

      // Event recorded only once
      if (storeName === 'SqliteRealD1') {
        const evts = ctx
          .sqliteDb!.prepare('SELECT COUNT(*) as cnt FROM stripe_events WHERE id = ?')
          .get('evt_e2_del') as {
          cnt: number;
        };
        expect(evts.cnt).toBe(1);
      }
    });

    vi.useRealTimers();
  });

  // E3: An unknown subscription or missing id gives 200 with no changes
  it('E3: unknown subscription gives revoked: 0, and missing id gives ignored: true with zero changes', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      // 1. Unknown subscription
      const unknownEvent = createCustomerSubscriptionDeletedEvent({
        id: 'evt_unknown_sub_999',
        subscriptionId: 'sub_does_not_exist',
        now: fixedNow,
      });
      const resUnknown = await ctx.dispatchWebhook(JSON.stringify(unknownEvent));
      expect(resUnknown.status).toBe(200);
      const jsonUnknown = (await resUnknown.json()) as { action: string; revoked: number };
      expect(jsonUnknown).toEqual({
        received: true,
        action: 'license_revoked',
        revoked: 0,
      });

      // 2. Missing subscription id
      const missingIdEvent = {
        id: 'evt_missing_sub_id',
        type: 'customer.subscription.deleted',
        created: fixedNow,
        data: {
          object: {
            object: 'subscription',
            // id is omitted
          },
        },
      };
      const resMissing = await ctx.dispatchWebhook(JSON.stringify(missingIdEvent));
      expect(resMissing.status).toBe(200);
      expect(await resMissing.json()).toEqual({ received: true, ignored: true });

      if (storeName === 'MockStore') {
        expect(ctx.mockDb!.size).toBe(0);
      } else {
        const licCount = (
          ctx.sqliteDb!.prepare('SELECT COUNT(*) as cnt FROM licenses').get() as { cnt: number }
        ).cnt;
        expect(licCount).toBe(0);
      }
    });

    vi.useRealTimers();
  });

  // E4: After revocation, /v1/activate returns 403 and /v1/validate returns 403 LICENSE_REVOKED
  it('E4: after revocation, activate returns 403 and validate returns 403 LICENSE_REVOKED', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      // 1. Provision
      const event = createCheckoutSessionCompletedEvent({
        sessionId: 'cs_e4_test',
        subscriptionId: 'sub_e4_integration',
        email: 'e4@corp.com',
        now: fixedNow,
      });
      await ctx.dispatchWebhook(JSON.stringify(event));

      let code: string;
      if (storeName === 'MockStore') {
        code = Array.from(ctx.mockDb!.values())[0]!.activation_code;
      } else {
        const row = ctx.sqliteDb!.prepare('SELECT activation_code FROM licenses').get() as {
          activation_code: string;
        };
        code = row.activation_code;
      }

      // 2. Activate to get valid JWT
      const actReq1 = new Request('https://license.secureship.dev/v1/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          activationCode: code,
          machineFingerprint: 'machine-fingerprint-e4-001',
        }),
      });
      const actRes1 = await LicenseWorker.handleRequest(actReq1, ctx.env, ctx.mockDb);
      expect(actRes1.status).toBe(200);
      const actJson1 = (await actRes1.json()) as { jwt: string };
      const issuedJwt = actJson1.jwt;

      // 3. Validate returns 200 before revocation
      const valReq1 = new Request('https://license.secureship.dev/v1/validate', {
        method: 'GET',
        headers: { Authorization: `Bearer ${issuedJwt}` },
      });
      const valRes1 = await LicenseWorker.handleRequest(valReq1, ctx.env, ctx.mockDb);
      expect(valRes1.status).toBe(200);
      const valJson1 = (await valRes1.json()) as { valid: boolean };
      expect(valJson1.valid).toBe(true);

      // 4. Revoke subscription
      const delEvent = createCustomerSubscriptionDeletedEvent({
        subscriptionId: 'sub_e4_integration',
        now: fixedNow + 10,
      });
      const delRes = await ctx.dispatchWebhook(JSON.stringify(delEvent));
      expect(delRes.status).toBe(200);

      // 5. Attempt activate again -> 403
      const actReq2 = new Request('https://license.secureship.dev/v1/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          activationCode: code,
          machineFingerprint: 'machine-fingerprint-e4-002',
        }),
      });
      const actRes2 = await LicenseWorker.handleRequest(actReq2, ctx.env, ctx.mockDb);
      expect(actRes2.status).toBe(403);
      const actJson2 = (await actRes2.json()) as { error: string };
      expect(actJson2.error).toContain('revoked');

      // 6. Validate with previously issued token -> 403 LICENSE_REVOKED
      const valReq2 = new Request('https://license.secureship.dev/v1/validate', {
        method: 'GET',
        headers: { Authorization: `Bearer ${issuedJwt}` },
      });
      const valRes2 = await LicenseWorker.handleRequest(valReq2, ctx.env, ctx.mockDb);
      expect(valRes2.status).toBe(403);
      const valJson2 = (await valRes2.json()) as { valid: boolean; code: string; error: string };
      expect(valJson2.valid).toBe(false);
      expect(valJson2.code).toBe('LICENSE_REVOKED');
      expect(valJson2.error).toBe('License is revoked');
    });

    vi.useRealTimers();
  });

  // E5: An already REVOKED license is not touched again (updated_at unchanged)
  it('E5: already REVOKED license is not updated again (updated_at preserved)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    const { db: sqliteDb, d1: adapter } = createStripeSqliteDb();
    const env: Env = {
      DB: adapter,
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    // Provision
    const event = createCheckoutSessionCompletedEvent({
      sessionId: 'cs_e5',
      subscriptionId: 'sub_e5_time_check',
      email: 'e5@corp.com',
      now: fixedNow,
    });
    const sig1 = computeIndependentStripeSignature(JSON.stringify(event), secret, fixedNow).header;
    const req1 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig1 },
      body: JSON.stringify(event),
    });
    await LicenseWorker.handleRequest(req1, env);

    // Revoke at t = fixedNow + 100
    vi.setSystemTime((fixedNow + 100) * 1000);
    const deleteEvent1 = createCustomerSubscriptionDeletedEvent({
      id: 'evt_del_first',
      subscriptionId: 'sub_e5_time_check',
      now: fixedNow + 100,
    });
    const sig2 = computeIndependentStripeSignature(
      JSON.stringify(deleteEvent1),
      secret,
      fixedNow + 100
    ).header;
    const req2 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig2 },
      body: JSON.stringify(deleteEvent1),
    });
    await LicenseWorker.handleRequest(req2, env);

    const licAfterRevoke = sqliteDb
      .prepare('SELECT updated_at FROM licenses WHERE stripe_subscription_id = ?')
      .get('sub_e5_time_check') as { updated_at: number };
    const firstUpdatedAt = licAfterRevoke.updated_at;
    expect(firstUpdatedAt).toBe(fixedNow + 100);

    // Another delete event at t = fixedNow + 500 for the same subscription
    vi.setSystemTime((fixedNow + 500) * 1000);
    const deleteEvent2 = createCustomerSubscriptionDeletedEvent({
      id: 'evt_del_second',
      subscriptionId: 'sub_e5_time_check',
      now: fixedNow + 500,
    });
    const sig3 = computeIndependentStripeSignature(
      JSON.stringify(deleteEvent2),
      secret,
      fixedNow + 500
    ).header;
    const req3 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig3 },
      body: JSON.stringify(deleteEvent2),
    });
    const res3 = await LicenseWorker.handleRequest(req3, env);
    expect(res3.status).toBe(200);
    const json3 = (await res3.json()) as { revoked: number };
    expect(json3.revoked).toBe(0); // 0 licenses revoked because already REVOKED!

    const licAfterSecond = sqliteDb
      .prepare('SELECT updated_at FROM licenses WHERE stripe_subscription_id = ?')
      .get('sub_e5_time_check') as { updated_at: number };
    expect(licAfterSecond.updated_at).toBe(firstUpdatedAt); // updated_at was NOT touched!

    vi.useRealTimers();
  });
});
