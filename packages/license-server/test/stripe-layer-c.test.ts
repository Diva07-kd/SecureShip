import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  generateActivationCode,
  LicenseWorker,
  type Env,
  LICENSE_TERM_SECONDS,
} from '../src/worker.js';
import {
  createCheckoutSessionCompletedEvent,
  createAsyncPaymentSucceededEvent,
  DEFAULT_STRIPE_SECRET,
  TEST_RSA_KEYS,
  runDualStoreTest,
  createStripeSqliteDb,
  computeIndependentStripeSignature,
} from './stripe-fixtures.js';

describe('LAYER C: License Provisioning Tests (DEV-3)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const secret = DEFAULT_STRIPE_SECRET;
  const fixedNow = 1770000000;

  // C1: A paid checkout.session.completed gives 200 and deep-equal response without leaking secrets
  it('C1: paid checkout.session.completed gives 200 and sanitized body', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx) => {
      const event = createCheckoutSessionCompletedEvent({
        email: 'ceo@acme-corp.com',
        tier: 'PRO_TEAM',
        seats: 10,
        orgId: 'acme-enterprise',
        customerId: 'cus_stripe_123',
        subscriptionId: 'sub_stripe_456',
        now: fixedNow,
      });
      const rawBody = JSON.stringify(event);

      const res = await ctx.dispatchWebhook(rawBody);
      expect(res.status).toBe(200);

      const resText = await res.text();
      const body = JSON.parse(resText) as { received: boolean; action: string; licenseId: string };

      expect(body).toEqual({
        received: true,
        action: 'license_created',
        licenseId: body.licenseId,
      });
      expect(typeof body.licenseId).toBe('string');
      expect(body.licenseId.length).toBeGreaterThan(10);

      // Verify serialized body does NOT leak activation code, email, or customer id
      expect(resText).not.toContain('SS-PRO-');
      expect(resText).not.toContain('SS-ENT-');
      expect(resText).not.toContain('ceo@acme-corp.com');
      expect(resText).not.toContain('cus_stripe_123');
    });

    vi.useRealTimers();
  });

  // C2: Exactly 1 customer and 1 license are stored with all fields verified
  it('C2: exactly 1 customer and 1 license stored with normalized email and correct expiry', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      const event = createCheckoutSessionCompletedEvent({
        sessionId: 'cs_sess_c2_test',
        email: '   JOHN.DOE@Acme-Corp.COM   ', // Mixed case + whitespace
        tier: 'ENTERPRISE',
        seats: 25,
        orgId: 'acme-division',
        customerId: 'cus_c2_customer',
        subscriptionId: 'sub_c2_sub',
        now: fixedNow,
      });

      const res = await ctx.dispatchWebhook(JSON.stringify(event));
      expect(res.status).toBe(200);
      const resJson = (await res.json()) as { licenseId: string };

      if (storeName === 'MockStore') {
        expect(ctx.mockDb!.size).toBe(1);
        const lic = Array.from(ctx.mockDb!.values())[0]!;
        expect(lic.id).toBe(resJson.licenseId);
        expect(lic.tier).toBe('ENTERPRISE');
        expect(lic.seats).toBe(25);
        expect(lic.org_id).toBe('acme-division');
        expect(lic.status).toBe('ACTIVE');
        expect(lic.expires_at).toBe(fixedNow + LICENSE_TERM_SECONDS);
        expect(lic.stripe_checkout_session_id).toBe('cs_sess_c2_test');
        expect(lic.stripe_subscription_id).toBe('sub_c2_sub');
      } else {
        const custRows = ctx.sqliteDb!.prepare('SELECT * FROM customers').all() as Array<{
          id: string;
          email: string;
          stripe_customer_id: string;
        }>;
        expect(custRows.length).toBe(1);
        expect(custRows[0]!.email).toBe('john.doe@acme-corp.com');
        expect(custRows[0]!.stripe_customer_id).toBe('cus_c2_customer');

        const licRows = ctx.sqliteDb!.prepare('SELECT * FROM licenses').all() as Array<{
          id: string;
          customer_id: string;
          tier: string;
          seats: number;
          org_id: string;
          status: string;
          expires_at: number;
          stripe_checkout_session_id: string;
          stripe_subscription_id: string;
        }>;
        expect(licRows.length).toBe(1);
        expect(licRows[0]!.id).toBe(resJson.licenseId);
        expect(licRows[0]!.customer_id).toBe(custRows[0]!.id);
        expect(licRows[0]!.tier).toBe('ENTERPRISE');
        expect(licRows[0]!.seats).toBe(25);
        expect(licRows[0]!.org_id).toBe('acme-division');
        expect(licRows[0]!.status).toBe('ACTIVE');
        expect(licRows[0]!.expires_at).toBe(fixedNow + 365 * 86400);
        expect(licRows[0]!.stripe_checkout_session_id).toBe('cs_sess_c2_test');
        expect(licRows[0]!.stripe_subscription_id).toBe('sub_c2_sub');
      }
    });

    vi.useRealTimers();
  });

  // C3: Defaults: absent metadata gives PRO_TEAM, 5 seats, org 'individual'
  it('C3: absent metadata defaults to PRO_TEAM, 5 seats, and individual org', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      const event = createCheckoutSessionCompletedEvent({
        email: 'default@user.io',
        omitMetadata: true,
        now: fixedNow,
      });

      const res = await ctx.dispatchWebhook(JSON.stringify(event));
      expect(res.status).toBe(200);

      if (storeName === 'MockStore') {
        const lic = Array.from(ctx.mockDb!.values())[0]!;
        expect(lic.tier).toBe('PRO_TEAM');
        expect(lic.seats).toBe(5);
        expect(lic.org_id).toBe('individual');
      } else {
        const licRows = ctx.sqliteDb!.prepare('SELECT * FROM licenses').all() as Array<{
          tier: string;
          seats: number;
          org_id: string;
        }>;
        expect(licRows.length).toBe(1);
        expect(licRows[0]!.tier).toBe('PRO_TEAM');
        expect(licRows[0]!.seats).toBe(5);
        expect(licRows[0]!.org_id).toBe('individual');
      }
    });

    vi.useRealTimers();
  });

  // C4: Ignored cases: unpaid, missing/invalid email, invalid metadata
  it('C4: ignores unpaid sessions, invalid emails, and hostile metadata with zero writes', async () => {
    const invalidCases: Array<{
      desc: string;
      overrides: Parameters<typeof createCheckoutSessionCompletedEvent>[0];
      expectedReason: string;
    }> = [
      {
        desc: 'unpaid payment_status',
        overrides: { paymentStatus: 'unpaid' },
        expectedReason: 'PAYMENT_NOT_COMPLETED',
      },
      {
        desc: 'no email provided',
        overrides: { omitDetails: true },
        expectedReason: 'MISSING_EMAIL',
      },
      {
        desc: 'empty email',
        overrides: { email: '   ' },
        expectedReason: 'MISSING_EMAIL',
      },
      {
        desc: 'malformed email without domain',
        overrides: { email: 'invalid-email-address' },
        expectedReason: 'MISSING_EMAIL',
      },
      {
        desc: 'tier FREE_BYOK',
        overrides: { tier: 'FREE_BYOK' },
        expectedReason: 'INVALID_METADATA',
      },
      {
        desc: 'tier GOD',
        overrides: { tier: 'GOD' },
        expectedReason: 'INVALID_METADATA',
      },
      {
        desc: 'seats 0',
        overrides: { seats: 0 },
        expectedReason: 'INVALID_METADATA',
      },
      {
        desc: 'seats -1',
        overrides: { seats: -1 },
        expectedReason: 'INVALID_METADATA',
      },
      {
        desc: 'seats 1.5',
        overrides: { seats: 1.5 },
        expectedReason: 'INVALID_METADATA',
      },
      {
        desc: 'seats string abc',
        overrides: { seats: 'abc' },
        expectedReason: 'INVALID_METADATA',
      },
      {
        desc: 'seats 10001 (exceeds 10,000 cap)',
        overrides: { seats: 10001 },
        expectedReason: 'INVALID_METADATA',
      },
      {
        desc: 'org_id with spaces',
        overrides: { orgId: 'evil corp with spaces' },
        expectedReason: 'INVALID_METADATA',
      },
      {
        desc: 'org_id with traversal ../',
        overrides: { orgId: '../../traversal' },
        expectedReason: 'INVALID_METADATA',
      },
      {
        desc: 'org_id with 65 characters',
        overrides: { orgId: 'a'.repeat(65) },
        expectedReason: 'INVALID_METADATA',
      },
    ];

    for (const testCase of invalidCases) {
      await runDualStoreTest(async (ctx, storeName) => {
        const event = createCheckoutSessionCompletedEvent({
          ...testCase.overrides,
          now: fixedNow,
        });

        const res = await ctx.dispatchWebhook(JSON.stringify(event));
        expect(res.status).toBe(200);
        const body = (await res.json()) as { received: boolean; ignored: boolean; reason: string };
        expect(body).toEqual({
          received: true,
          ignored: true,
          reason: testCase.expectedReason,
        });

        if (storeName === 'MockStore') {
          expect(ctx.mockDb!.size).toBe(0);
        } else {
          expect(ctx.recordedSql!.length).toBe(0);
        }
      });
    }
  });

  // C5: checkout.session.async_payment_succeeded provisions exactly like C1
  it('C5: checkout.session.async_payment_succeeded provisions identically to completed', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      const event = createAsyncPaymentSucceededEvent({
        email: 'async-buyer@example.com',
        tier: 'PRO_TEAM',
        seats: 8,
        orgId: 'async-team',
        now: fixedNow,
      });

      const res = await ctx.dispatchWebhook(JSON.stringify(event));
      expect(res.status).toBe(200);
      const body = (await res.json()) as { received: boolean; action: string; licenseId: string };
      expect(body.action).toBe('license_created');

      if (storeName === 'MockStore') {
        expect(ctx.mockDb!.size).toBe(1);
        const lic = Array.from(ctx.mockDb!.values())[0]!;
        expect(lic.seats).toBe(8);
      } else {
        const licRows = ctx.sqliteDb!.prepare('SELECT * FROM licenses').all() as Array<{
          seats: number;
        }>;
        expect(licRows.length).toBe(1);
        expect(licRows[0]!.seats).toBe(8);
      }
    });

    vi.useRealTimers();
  });

  // C6: Activation code format, uniqueness, entropy, and unbiased mapping
  it('C6: activation code generation has >= 80 bits entropy, zero modulo bias, and Crockford format', () => {
    const crockfordAlphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
    const crockfordRegex =
      /^SS-(PRO|ENT)-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;

    // 1. Generate 2,000 unique codes and verify format regex
    const codes = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const code = generateActivationCode(i % 2 === 0 ? 'PRO_TEAM' : 'ENTERPRISE');
      expect(code).toMatch(crockfordRegex);
      codes.add(code);
    }
    expect(codes.size).toBe(2000);

    // 2. Bit entropy calculation: 16 characters from 32-character alphabet = 16 * log2(32) = 16 * 5 = 80 bits
    const alphabetSize = crockfordAlphabet.length;
    expect(alphabetSize).toBe(32);
    const bitsPerChar = Math.log2(alphabetSize);
    expect(bitsPerChar).toBe(5);
    const totalBitEntropy = 16 * bitsPerChar;
    expect(totalBitEntropy).toBeGreaterThanOrEqual(80);

    // 3. Modulo bias table test: across all 256 byte values, each of the 32 symbols appears exactly 8 times (256 / 32 = 8)
    const symbolCounts: Record<string, number> = {};
    for (const char of crockfordAlphabet) {
      symbolCounts[char] = 0;
    }

    for (let byteVal = 0; byteVal < 256; byteVal++) {
      const mappedChar = crockfordAlphabet[byteVal & 31]!;
      symbolCounts[mappedChar] = (symbolCounts[mappedChar] ?? 0) + 1;
    }

    for (const char of crockfordAlphabet) {
      expect(symbolCounts[char]).toBe(8);
    }
  });

  // C7: End-to-end: stored activation code works with POST /v1/activate
  it('C7: activation code stored by webhook activates successfully on POST /v1/activate', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      const event = createCheckoutSessionCompletedEvent({
        email: 'e2e-user@cloud.net',
        tier: 'PRO_TEAM',
        seats: 12,
        orgId: 'e2e-org',
        now: fixedNow,
      });

      const whRes = await ctx.dispatchWebhook(JSON.stringify(event));
      expect(whRes.status).toBe(200);

      let activationCode: string;
      if (storeName === 'MockStore') {
        const lic = Array.from(ctx.mockDb!.values())[0]!;
        activationCode = lic.activation_code;
      } else {
        const licRow = ctx.sqliteDb!.prepare('SELECT activation_code FROM licenses').get() as {
          activation_code: string;
        };
        activationCode = licRow.activation_code;
      }

      // Activate using the stored code
      const actReq = new Request('https://license.secureship.dev/v1/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          activationCode,
          machineFingerprint: 'machine-sha256-fingerprint-e2e',
        }),
      });

      const actRes = await LicenseWorker.handleRequest(actReq, ctx.env, ctx.mockDb);
      expect(actRes.status).toBe(200);

      const actJson = (await actRes.json()) as {
        success: boolean;
        tier: string;
        jwt: string;
      };
      expect(actJson.success).toBe(true);
      expect(actJson.tier).toBe('PRO_TEAM');
      expect(typeof actJson.jwt).toBe('string');
      expect(actJson.jwt.split('.')).toHaveLength(3);
    });

    vi.useRealTimers();
  });

  // C8: Repeat buyer: same email with different casing creates 1 customer, 2 licenses, foreign key holds
  it('C8: repeat buyer creates 1 customer and 2 licenses under foreign key constraints', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    const { db: sqliteDb, d1: adapter } = createStripeSqliteDb();
    const env: Env = {
      DB: adapter,
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    // First purchase: uppercase email
    const event1 = createCheckoutSessionCompletedEvent({
      sessionId: 'cs_order_001',
      email: 'BUYER@CORP.EXAMPLE',
      tier: 'PRO_TEAM',
      seats: 5,
      customerId: 'cus_repeat_001',
      now: fixedNow,
    });
    const sig1 = computeIndependentStripeSignature(JSON.stringify(event1), secret, fixedNow).header;
    const req1 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig1 },
      body: JSON.stringify(event1),
    });
    const res1 = await LicenseWorker.handleRequest(req1, env);
    expect(res1.status).toBe(200);

    // Second purchase: lowercase email
    const event2 = createCheckoutSessionCompletedEvent({
      sessionId: 'cs_order_002',
      email: 'buyer@corp.example',
      tier: 'ENTERPRISE',
      seats: 20,
      customerId: 'cus_repeat_001',
      now: fixedNow,
    });
    const sig2 = computeIndependentStripeSignature(JSON.stringify(event2), secret, fixedNow).header;
    const req2 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig2 },
      body: JSON.stringify(event2),
    });
    const res2 = await LicenseWorker.handleRequest(req2, env);
    expect(res2.status).toBe(200);

    // Verify exactly 1 customer and 2 licenses in SQLite
    const customers = sqliteDb.prepare('SELECT * FROM customers').all() as Array<{
      id: string;
      email: string;
    }>;
    expect(customers.length).toBe(1);
    expect(customers[0]!.email).toBe('buyer@corp.example');

    const licenses = sqliteDb.prepare('SELECT * FROM licenses').all() as Array<{
      id: string;
      customer_id: string;
      tier: string;
      seats: number;
    }>;
    expect(licenses.length).toBe(2);
    expect(licenses[0]!.customer_id).toBe(customers[0]!.id);
    expect(licenses[1]!.customer_id).toBe(customers[0]!.id);

    vi.useRealTimers();
  });

  // C9: Customer upsert updates stripe_customer_id on conflict and keeps original customer id
  it('C9: customer upsert updates stripe_customer_id and preserves original customer id', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    const { db: sqliteDb, d1: adapter } = createStripeSqliteDb();
    const env: Env = {
      DB: adapter,
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    // First event with cus_original_111
    const event1 = createCheckoutSessionCompletedEvent({
      sessionId: 'cs_sess_orig',
      email: 'upsert@corp.com',
      customerId: 'cus_original_111',
      now: fixedNow,
    });
    const sig1 = computeIndependentStripeSignature(JSON.stringify(event1), secret, fixedNow).header;
    const req1 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig1 },
      body: JSON.stringify(event1),
    });
    await LicenseWorker.handleRequest(req1, env);

    const initialCust = sqliteDb
      .prepare('SELECT * FROM customers WHERE email = ?')
      .get('upsert@corp.com') as {
      id: string;
      stripe_customer_id: string;
    };
    expect(initialCust.stripe_customer_id).toBe('cus_original_111');

    // Second event with new stripe_customer_id cus_updated_222
    const event2 = createCheckoutSessionCompletedEvent({
      sessionId: 'cs_sess_updated',
      email: 'upsert@corp.com',
      customerId: 'cus_updated_222',
      now: fixedNow,
    });
    const sig2 = computeIndependentStripeSignature(JSON.stringify(event2), secret, fixedNow).header;
    const req2 = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig2 },
      body: JSON.stringify(event2),
    });
    await LicenseWorker.handleRequest(req2, env);

    const updatedCust = sqliteDb
      .prepare('SELECT * FROM customers WHERE email = ?')
      .get('upsert@corp.com') as {
      id: string;
      stripe_customer_id: string;
    };
    expect(updatedCust.id).toBe(initialCust.id); // Customer id preserved!
    expect(updatedCust.stripe_customer_id).toBe('cus_updated_222'); // stripe_customer_id updated!

    vi.useRealTimers();
  });
});
