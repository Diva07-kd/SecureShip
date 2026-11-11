import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LicenseWorker, type Env } from '../src/worker.js';
import {
  createCheckoutSessionCompletedEvent,
  createAsyncPaymentSucceededEvent,
  DEFAULT_STRIPE_SECRET,
  TEST_RSA_KEYS,
  runDualStoreTest,
  createStripeSqliteDb,
  computeIndependentStripeSignature,
} from './stripe-fixtures.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('LAYER D: Idempotency, Concurrency, and Atomicity Tests (DEV-3)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const secret = DEFAULT_STRIPE_SECRET;
  const fixedNow = 1770000000;

  // D1: Same signed event delivered 3 times sequentially -> 1 license, 1 stripe_events row, duplicate:true on 2nd and 3rd
  it('D1: sequential duplicate deliveries return 200 with duplicate:true and store exactly 1 license', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      const event = createCheckoutSessionCompletedEvent({
        id: 'evt_seq_idemp_001',
        sessionId: 'cs_seq_idemp_001',
        email: 'idemp@corp.com',
        now: fixedNow,
      });
      const rawBody = JSON.stringify(event);

      // Delivery 1
      const res1 = await ctx.dispatchWebhook(rawBody);
      expect(res1.status).toBe(200);
      const body1 = (await res1.json()) as { received: boolean; action: string; licenseId: string };
      expect(body1.action).toBe('license_created');

      // Delivery 2
      const res2 = await ctx.dispatchWebhook(rawBody);
      expect(res2.status).toBe(200);
      const body2 = (await res2.json()) as { received: boolean; duplicate: boolean };
      expect(body2).toEqual({ received: true, duplicate: true });

      // Delivery 3
      const res3 = await ctx.dispatchWebhook(rawBody);
      expect(res3.status).toBe(200);
      const body3 = (await res3.json()) as { received: boolean; duplicate: boolean };
      expect(body3).toEqual({ received: true, duplicate: true });

      // Store checks
      if (storeName === 'MockStore') {
        expect(ctx.mockDb!.size).toBe(1);
      } else {
        const licCount = ctx.sqliteDb!.prepare('SELECT COUNT(*) as cnt FROM licenses').get() as {
          cnt: number;
        };
        expect(licCount.cnt).toBe(1);

        const evtCount = ctx
          .sqliteDb!.prepare('SELECT COUNT(*) as cnt FROM stripe_events')
          .get() as {
          cnt: number;
        };
        expect(evtCount.cnt).toBe(1);
      }
    });

    vi.useRealTimers();
  });

  // D2: Same event delivered 10 times concurrently -> exactly 1 license (repeated 20 times)
  it('D2: 10 concurrent requests result in exactly 1 license (20 iterations)', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    for (let iteration = 0; iteration < 20; iteration++) {
      const { db: sqliteDb, d1: adapter } = createStripeSqliteDb();
      const env: Env = {
        DB: adapter,
        JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
        JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
        STRIPE_WEBHOOK_SECRET: secret,
      };

      const event = createCheckoutSessionCompletedEvent({
        id: `evt_conc_${iteration}`,
        sessionId: `cs_conc_${iteration}`,
        email: `conc_${iteration}@corp.com`,
        now: fixedNow,
      });
      const rawBody = JSON.stringify(event);
      const sig = computeIndependentStripeSignature(rawBody, secret, fixedNow).header;

      // 10 concurrent webhook requests
      const promises = Array.from({ length: 10 }, async () => {
        const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
          body: rawBody,
        });
        const res = await LicenseWorker.handleRequest(req, env);
        const json = (await res.json()) as Record<string, unknown>;
        return { status: res.status, json };
      });

      const results = await Promise.all(promises);

      // All 10 requests must succeed with 200
      for (const r of results) {
        expect(r.status).toBe(200);
      }

      // Exactly 1 response is license_created and 9 are duplicate: true
      const createdCount = results.filter((r) => r.json['action'] === 'license_created').length;
      const dupCount = results.filter((r) => r.json['duplicate'] === true).length;
      expect(createdCount).toBe(1);
      expect(dupCount).toBe(9);

      // Exactly 1 license and 1 stripe_events row in the database
      const licCount = sqliteDb.prepare('SELECT COUNT(*) as cnt FROM licenses').get() as {
        cnt: number;
      };
      expect(licCount.cnt).toBe(1);

      const evtCount = sqliteDb.prepare('SELECT COUNT(*) as cnt FROM stripe_events').get() as {
        cnt: number;
      };
      expect(evtCount.cnt).toBe(1);
    }

    vi.useRealTimers();
  });

  // D3: Two different event ids for the same checkout session -> exactly 1 license
  it('D3: two distinct event ids for same checkout session create exactly 1 license', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    await runDualStoreTest(async (ctx, storeName) => {
      const sharedSessionId = 'cs_shared_session_123';

      // Event 1: checkout.session.completed
      const event1 = createCheckoutSessionCompletedEvent({
        id: 'evt_first_111',
        sessionId: sharedSessionId,
        email: 'shared@acme.com',
        now: fixedNow,
      });
      const res1 = await ctx.dispatchWebhook(JSON.stringify(event1));
      expect(res1.status).toBe(200);
      const body1 = (await res1.json()) as { action: string };
      expect(body1.action).toBe('license_created');

      // Event 2: checkout.session.async_payment_succeeded with different event id but same sessionId
      const event2 = createAsyncPaymentSucceededEvent({
        id: 'evt_second_222',
        sessionId: sharedSessionId,
        email: 'shared@acme.com',
        now: fixedNow,
      });
      const res2 = await ctx.dispatchWebhook(JSON.stringify(event2));
      expect(res2.status).toBe(200);
      const body2 = (await res2.json()) as { duplicate: boolean };
      expect(body2.duplicate).toBe(true);

      // Exactly 1 license created
      if (storeName === 'MockStore') {
        expect(ctx.mockDb!.size).toBe(1);
      } else {
        const count = ctx.sqliteDb!.prepare('SELECT COUNT(*) as cnt FROM licenses').get() as {
          cnt: number;
        };
        expect(count.cnt).toBe(1);
      }
    });

    vi.useRealTimers();
  });

  // D4: Atomicity: inject failure on statement 1, 2, and 3 of the batch
  it('D4: transaction rolls back completely on statement failure and succeeds on retry', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    for (let statementIndex = 0; statementIndex < 3; statementIndex++) {
      const { db: sqliteDb, d1: adapter } = createStripeSqliteDb();
      const env: Env = {
        DB: adapter,
        JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
        JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
        STRIPE_WEBHOOK_SECRET: secret,
      };

      const event = createCheckoutSessionCompletedEvent({
        id: `evt_fault_${statementIndex}`,
        sessionId: `cs_fault_${statementIndex}`,
        email: `fault_${statementIndex}@corp.com`,
        now: fixedNow,
      });
      const rawBody = JSON.stringify(event);
      const sig = computeIndependentStripeSignature(rawBody, secret, fixedNow).header;

      // Inject fault at statementIndex
      adapter.setFaultInjection(statementIndex);

      const failReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
        body: rawBody,
      });

      const failRes = await LicenseWorker.handleRequest(failReq, env);
      expect(failRes.status).toBe(500);
      const failJson = (await failRes.json()) as { error: string };
      expect(failJson).toEqual({ error: 'Webhook processing failed' });
      // Never leak internal fault message
      expect(JSON.stringify(failJson)).not.toContain('Injected fault');

      // Verify zero rows in customers, licenses, and stripe_events (full rollback!)
      const custCnt = (
        sqliteDb.prepare('SELECT COUNT(*) as cnt FROM customers').get() as { cnt: number }
      ).cnt;
      const licCnt = (
        sqliteDb.prepare('SELECT COUNT(*) as cnt FROM licenses').get() as { cnt: number }
      ).cnt;
      const evtCnt = (
        sqliteDb.prepare('SELECT COUNT(*) as cnt FROM stripe_events').get() as { cnt: number }
      ).cnt;
      expect(custCnt).toBe(0);
      expect(licCnt).toBe(0);
      expect(evtCnt).toBe(0);

      // Clear fault injection and retry the same event -> must succeed and create exactly 1 license
      adapter.setFaultInjection(null);

      const retryReq = new Request('https://license.secureship.dev/v1/webhook/stripe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
        body: rawBody,
      });

      const retryRes = await LicenseWorker.handleRequest(retryReq, env);
      expect(retryRes.status).toBe(200);
      const retryJson = (await retryRes.json()) as { action: string };
      expect(retryJson.action).toBe('license_created');

      const finalLicCnt = (
        sqliteDb.prepare('SELECT COUNT(*) as cnt FROM licenses').get() as { cnt: number }
      ).cnt;
      const finalCustCnt = (
        sqliteDb.prepare('SELECT COUNT(*) as cnt FROM customers').get() as { cnt: number }
      ).cnt;
      const finalEvtCnt = (
        sqliteDb.prepare('SELECT COUNT(*) as cnt FROM stripe_events').get() as { cnt: number }
      ).cnt;
      expect(finalLicCnt).toBe(1);
      expect(finalCustCnt).toBe(1);
      expect(finalEvtCnt).toBe(1);
    }

    vi.useRealTimers();
  });

  // D5: Activation-code collision: retries up to 3 times, succeeds if fresh code obtained, fails 500 with zero partial rows if always collides
  it('D5.1: handler retries on code collision and succeeds with a fresh code', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    const { db: sqliteDb, d1: adapter } = createStripeSqliteDb();
    const env: Env = {
      DB: adapter,
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    // Pre-insert an existing license with deterministic code (all 0s maps to SS-PRO-0000-0000-0000-0000)
    const collidingCode = 'SS-PRO-0000-0000-0000-0000';
    sqliteDb
      .prepare('INSERT INTO customers (id, email, created_at) VALUES (?, ?, ?)')
      .run('cust_seed', 'seed@corp.com', fixedNow);
    sqliteDb
      .prepare(
        `INSERT INTO licenses (id, customer_id, activation_code, tier, seats, org_id, status, expires_at, created_at, updated_at)
         VALUES (?, ?, ?, 'PRO_TEAM', 5, 'individual', 'ACTIVE', ?, ?, ?)`
      )
      .run('lic_seed', 'cust_seed', collidingCode, fixedNow + 86400, fixedNow, fixedNow);

    let callCount = 0;
    const globalCrypto = (globalThis as unknown as { crypto: Crypto }).crypto;
    const cryptoProto = Object.getPrototypeOf(globalCrypto) as Crypto;
    vi.spyOn(cryptoProto, 'getRandomValues').mockImplementation(
      <T extends ArrayBufferView | null>(arr: T): T => {
        callCount++;
        if (callCount === 1) {
          // First attempt produces colliding code
          if (arr && 'fill' in arr) (arr as unknown as Uint8Array).fill(0);
          return arr;
        }
        // Second attempt produces fresh code
        if (arr && 'fill' in arr) (arr as unknown as Uint8Array).fill(1);
        return arr;
      }
    );

    const event = createCheckoutSessionCompletedEvent({
      id: 'evt_collision_recover',
      sessionId: 'cs_collision_recover',
      email: 'recover@corp.com',
      now: fixedNow,
    });
    const rawBody = JSON.stringify(event);
    const sig = computeIndependentStripeSignature(rawBody, secret, fixedNow).header;

    const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
      body: rawBody,
    });

    const res = await LicenseWorker.handleRequest(req, env);
    expect(res.status).toBe(200);
    const json = (await res.json()) as { action: string };
    expect(json.action).toBe('license_created');
    expect(callCount).toBe(2);

    vi.useRealTimers();
  });

  it('D5.2: perpetual code collision terminates after 3 attempts with 500 and zero partial rows', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixedNow * 1000);

    const { db: sqliteDb, d1: adapter } = createStripeSqliteDb();
    const env: Env = {
      DB: adapter,
      JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
      JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
      STRIPE_WEBHOOK_SECRET: secret,
    };

    // Pre-insert colliding code
    const collidingCode = 'SS-PRO-0000-0000-0000-0000';
    sqliteDb
      .prepare('INSERT INTO customers (id, email, created_at) VALUES (?, ?, ?)')
      .run('cust_coll_seed', 'coll_seed@corp.com', fixedNow);
    sqliteDb
      .prepare(
        `INSERT INTO licenses (id, customer_id, activation_code, tier, seats, org_id, status, expires_at, created_at, updated_at)
         VALUES (?, ?, ?, 'PRO_TEAM', 5, 'individual', 'ACTIVE', ?, ?, ?)`
      )
      .run('lic_coll_seed', 'cust_coll_seed', collidingCode, fixedNow + 86400, fixedNow, fixedNow);

    let callCount = 0;
    const globalCrypto = (globalThis as unknown as { crypto: Crypto }).crypto;
    const cryptoProto = Object.getPrototypeOf(globalCrypto) as Crypto;
    vi.spyOn(cryptoProto, 'getRandomValues').mockImplementation(
      <T extends ArrayBufferView | null>(arr: T): T => {
        callCount++;
        // Always fill with 0 to perpetually collide
        if (arr && 'fill' in arr) (arr as unknown as Uint8Array).fill(0);
        return arr;
      }
    );

    const event = createCheckoutSessionCompletedEvent({
      id: 'evt_perpetual_coll',
      sessionId: 'cs_perpetual_coll',
      email: 'perpetual@corp.com',
      now: fixedNow,
    });
    const rawBody = JSON.stringify(event);
    const sig = computeIndependentStripeSignature(rawBody, secret, fixedNow).header;

    const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'stripe-signature': sig },
      body: rawBody,
    });

    const res = await LicenseWorker.handleRequest(req, env);
    expect(res.status).toBe(500);
    const json = (await res.json()) as { error: string };
    expect(json).toEqual({ error: 'Webhook processing failed' });
    expect(callCount).toBe(3); // Exactly 3 attempts, no infinite loop!

    // Verify no partial rows for the new customer or event
    const newCust = sqliteDb
      .prepare('SELECT * FROM customers WHERE email = ?')
      .get('perpetual@corp.com');
    expect(newCust).toBeUndefined();

    const newEvt = sqliteDb
      .prepare('SELECT * FROM stripe_events WHERE id = ?')
      .get('evt_perpetual_coll');
    expect(newEvt).toBeUndefined();

    vi.useRealTimers();
  });

  // D6: Static SQL guard
  it('D6: provisioning statements execute in a single batch and license INSERT uses customer subselect', () => {
    const workerPath = path.resolve(__dirname, '../src/worker.ts');
    const content = fs.readFileSync(workerPath, 'utf-8');

    // Locate D1Store implementation of createLicenseFromCheckout
    const d1StoreStart = content.indexOf('export class D1Store');
    expect(d1StoreStart).toBeGreaterThan(-1);

    const fnStart = content.indexOf('async createLicenseFromCheckout', d1StoreStart);
    expect(fnStart).toBeGreaterThan(-1);
    const fnSnippet = content.slice(fnStart, fnStart + 2500);

    // Verify single batch execution
    expect(fnSnippet).toContain('this.db.batch([stmt1, stmt2, stmt3])');

    // Verify license INSERT resolves customer_id via subselect on email
    expect(fnSnippet).toContain('SELECT ?, c.id');
    expect(fnSnippet).toContain('FROM customers c WHERE c.email = ?');
  });
});
