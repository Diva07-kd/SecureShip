import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import {
  type LicenseRecord,
  type Env,
  type D1Database,
  type D1PreparedStatement,
  LicenseWorker,
} from '../src/worker.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const DEFAULT_STRIPE_SECRET = 'whsec_test_stripe_secret_independent_verifier_001';

/**
 * Independent Stripe signature generator.
 * Computes HMAC-SHA256 over `${timestamp}.${rawBody}` using node:crypto.
 * Never imports code under test for signing.
 */
export function computeIndependentStripeSignature(
  rawBody: string | Uint8Array,
  secret: string = DEFAULT_STRIPE_SECRET,
  timestamp: number = Math.floor(Date.now() / 1000)
): { timestamp: number; v1: string; header: string } {
  const bodyBuf =
    typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf-8') : Buffer.from(rawBody);
  const payloadToSign = Buffer.concat([Buffer.from(`${timestamp}.`, 'utf-8'), bodyBuf]);
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payloadToSign);
  const v1 = hmac.digest('hex');
  return {
    timestamp,
    v1,
    header: `t=${timestamp},v1=${v1}`,
  };
}

export interface RealisticStripeEvent {
  id: string;
  type: string;
  created: number;
  data: {
    object: Record<string, unknown>;
  };
}

/**
 * Realistic Stripe event factories
 */
export function createCheckoutSessionCompletedEvent(
  overrides: {
    id?: string;
    sessionId?: string;
    email?: string;
    tier?: string;
    seats?: number | unknown;
    orgId?: string | unknown;
    subscriptionId?: string | null;
    customerId?: string | null;
    paymentStatus?: string;
    now?: number;
    omitMetadata?: boolean;
    omitDetails?: boolean;
    customerEmail?: string;
  } = {}
): RealisticStripeEvent {
  const now = overrides.now ?? Math.floor(Date.now() / 1000);
  const eventId =
    overrides.id ?? `evt_cs_comp_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const sessionId =
    overrides.sessionId ?? `cs_test_${crypto.randomUUID().replace(/-/g, '').slice(0, 20)}`;
  const subscriptionId =
    overrides.subscriptionId !== undefined
      ? overrides.subscriptionId
      : `sub_test_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const customerId =
    overrides.customerId !== undefined
      ? overrides.customerId
      : `cus_test_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

  const metadata: Record<string, unknown> = {};
  if (!overrides.omitMetadata) {
    if (overrides.tier !== undefined) metadata['tier'] = overrides.tier;
    if (overrides.seats !== undefined) metadata['seats'] = overrides.seats;
    if (overrides.orgId !== undefined) metadata['org_id'] = overrides.orgId;
  }

  const sessionObj: Record<string, unknown> = {
    id: sessionId,
    object: 'checkout.session',
    payment_status: overrides.paymentStatus ?? 'paid',
    subscription: subscriptionId,
    customer: customerId,
    created: now,
  };

  if (!overrides.omitDetails) {
    sessionObj['customer_details'] = {
      email: overrides.email ?? 'buyer@acme-corp.com',
      name: 'Acme Corp Admin',
    };
  }

  if (overrides.customerEmail !== undefined) {
    sessionObj['customer_email'] = overrides.customerEmail;
  }

  if (Object.keys(metadata).length > 0) {
    sessionObj['metadata'] = metadata;
  }

  return {
    id: eventId,
    type: 'checkout.session.completed',
    created: now,
    data: { object: sessionObj },
  };
}

export function createCheckoutSessionUnpaidEvent(
  overrides: Parameters<typeof createCheckoutSessionCompletedEvent>[0] = {}
): RealisticStripeEvent {
  return createCheckoutSessionCompletedEvent({
    ...overrides,
    paymentStatus: 'unpaid',
  });
}

export function createAsyncPaymentSucceededEvent(
  overrides: Parameters<typeof createCheckoutSessionCompletedEvent>[0] = {}
): RealisticStripeEvent {
  const event = createCheckoutSessionCompletedEvent(overrides);
  return {
    ...event,
    id: overrides?.id ?? `evt_cs_async_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
    type: 'checkout.session.async_payment_succeeded',
  };
}

export function createCustomerSubscriptionDeletedEvent(
  overrides: {
    id?: string;
    subscriptionId?: string;
    customerId?: string;
    now?: number;
  } = {}
): RealisticStripeEvent {
  const now = overrides.now ?? Math.floor(Date.now() / 1000);
  const eventId =
    overrides.id ?? `evt_sub_del_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const subscriptionId =
    overrides.subscriptionId ?? `sub_test_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

  return {
    id: eventId,
    type: 'customer.subscription.deleted',
    created: now,
    data: {
      object: {
        id: subscriptionId,
        object: 'subscription',
        status: 'canceled',
        customer: overrides.customerId ?? 'cus_test_123',
        canceled_at: now,
      },
    },
  };
}

export function createInvoicePaidEvent(
  linesData: Array<{ periodEnd: number }> = [
    { periodEnd: Math.floor(Date.now() / 1000) + 365 * 86400 },
  ],
  overrides: {
    id?: string;
    subscriptionId?: string;
    customerId?: string;
    now?: number;
  } = {}
): RealisticStripeEvent {
  const now = overrides.now ?? Math.floor(Date.now() / 1000);
  const eventId =
    overrides.id ?? `evt_inv_paid_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const subscriptionId =
    overrides.subscriptionId ?? `sub_test_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

  return {
    id: eventId,
    type: 'invoice.paid',
    created: now,
    data: {
      object: {
        id: `in_test_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
        object: 'invoice',
        paid: true,
        status: 'paid',
        subscription: subscriptionId,
        customer: overrides.customerId ?? 'cus_test_123',
        lines: {
          object: 'list',
          data: linesData.map((l) => ({
            id: `il_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
            period: { end: l.periodEnd },
          })),
        },
      },
    },
  };
}

/**
 * Extended real-SQL D1 adapter wrapping node:sqlite DatabaseSync with batch() and fault injection.
 */
export interface ExtendedSqliteD1Database extends D1Database {
  batch(
    statements: D1PreparedStatement[]
  ): Promise<Array<{ success: boolean; meta?: { changes?: number } }>>;
  setFaultInjection(failAtStatementIndex: number | null): void;
}

export function createExtendedSqliteD1Adapter(
  db: DatabaseSync,
  onPrepare?: (sql: string) => void
): ExtendedSqliteD1Database {
  let faultIndex: number | null = null;

  interface InternalStatementWrapper extends D1PreparedStatement {
    _rawQuery: string;
    _boundParams: unknown[];
  }

  const adapter: ExtendedSqliteD1Database = {
    setFaultInjection(idx: number | null) {
      faultIndex = idx;
    },

    prepare(query: string): D1PreparedStatement {
      onPrepare?.(query);
      const prepared = db.prepare(query);
      let boundParams: unknown[] = [];

      const stmt: InternalStatementWrapper = {
        _rawQuery: query,
        _boundParams: boundParams,
        bind(...values: unknown[]) {
          boundParams = values;
          stmt._boundParams = values;
          return stmt;
        },
        async first<T = unknown>(): Promise<T | null> {
          await new Promise((r) => queueMicrotask(r));
          const row = prepared.get(...(boundParams as Parameters<typeof prepared.get>));
          return (row as T) ?? null;
        },
        async run(): Promise<{ success: boolean; meta?: { changes?: number } }> {
          await new Promise((r) => queueMicrotask(r));
          const res = prepared.run(...(boundParams as Parameters<typeof prepared.run>));
          return {
            success: true,
            meta: { changes: Number(res.changes) },
          };
        },
      };

      return stmt;
    },

    async batch(
      statements: D1PreparedStatement[]
    ): Promise<Array<{ success: boolean; meta?: { changes?: number } }>> {
      await new Promise((r) => queueMicrotask(r));
      db.exec('BEGIN TRANSACTION;');
      const results: Array<{ success: boolean; meta?: { changes?: number } }> = [];

      try {
        for (let i = 0; i < statements.length; i++) {
          if (faultIndex !== null && faultIndex === i) {
            throw new Error(`Injected fault at statement index ${i}`);
          }
          const s = statements[i] as InternalStatementWrapper;
          const prep = db.prepare(s._rawQuery);
          const res = prep.run(...(s._boundParams as Parameters<typeof prep.run>));
          results.push({
            success: true,
            meta: { changes: Number(res.changes) },
          });
        }
        db.exec('COMMIT;');
        return results;
      } catch (err) {
        db.exec('ROLLBACK;');
        throw err;
      }
    },
  };

  return adapter;
}

/**
 * Creates fresh real SQLite DB with schema.sql applied and PRAGMA foreign_keys = ON.
 */
export function createStripeSqliteDb(onPrepare?: (sql: string) => void): {
  db: DatabaseSync;
  d1: ExtendedSqliteD1Database;
  recordedSql: string[];
} {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON;');

  const recordedSql: string[] = [];
  const schemaPath = path.resolve(__dirname, '../schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf-8');
  db.exec(schemaSql);

  const d1 = createExtendedSqliteD1Adapter(db, (sql) => {
    recordedSql.push(sql);
    onPrepare?.(sql);
  });

  return { db, d1, recordedSql };
}

/**
 * Creates an in-process RSA keypair for tests requiring signed JWT assertions.
 */
export const TEST_RSA_KEYS = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

export interface DualTestContext {
  env: Env;
  mockDb?: Map<string, LicenseRecord>;
  sqliteDb?: DatabaseSync;
  recordedSql?: string[];
  adapter?: ExtendedSqliteD1Database;
  dispatchWebhook: (rawBody: string | Uint8Array, sigHeader?: string) => Promise<Response>;
}

/**
 * Runs a test case against BOTH MockStore and Real-SQL adapter.
 */
export async function runDualStoreTest<T>(
  testFn: (ctx: DualTestContext, storeName: 'MockStore' | 'SqliteRealD1') => Promise<T>
): Promise<{ mockResult: T; sqliteResult: T }> {
  // 1. Run with MockStore
  const mockDb = new Map<string, LicenseRecord>();
  const mockEnv: Env = {
    JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
    JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
    STRIPE_WEBHOOK_SECRET: DEFAULT_STRIPE_SECRET,
  };

  const mockContext: DualTestContext = {
    env: mockEnv,
    mockDb,
    dispatchWebhook: async (rawBody: string | Uint8Array, sigHeader?: string) => {
      const headerVal =
        sigHeader !== undefined
          ? sigHeader
          : computeIndependentStripeSignature(rawBody, DEFAULT_STRIPE_SECRET).header;

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (headerVal !== '') {
        headers['stripe-signature'] = headerVal;
      }

      const bodyPayload = typeof rawBody === 'string' ? rawBody : new TextDecoder().decode(rawBody);

      const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
        method: 'POST',
        headers,
        body: bodyPayload,
      });

      return LicenseWorker.handleRequest(req, mockEnv, mockDb);
    },
  };

  const mockResult = await testFn(mockContext, 'MockStore');

  // 2. Run with Real-SQL adapter
  const { db: sqliteDb, d1: adapter, recordedSql } = createStripeSqliteDb();
  const sqliteEnv: Env = {
    DB: adapter,
    JWT_PRIVATE_KEY: TEST_RSA_KEYS.privateKey,
    JWT_PUBLIC_KEY: TEST_RSA_KEYS.publicKey,
    STRIPE_WEBHOOK_SECRET: DEFAULT_STRIPE_SECRET,
  };

  const sqliteContext: DualTestContext = {
    env: sqliteEnv,
    sqliteDb,
    recordedSql,
    adapter,
    dispatchWebhook: async (rawBody: string | Uint8Array, sigHeader?: string) => {
      const headerVal =
        sigHeader !== undefined
          ? sigHeader
          : computeIndependentStripeSignature(rawBody, DEFAULT_STRIPE_SECRET).header;

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (headerVal !== '') {
        headers['stripe-signature'] = headerVal;
      }

      const bodyPayload = typeof rawBody === 'string' ? rawBody : new TextDecoder().decode(rawBody);

      const req = new Request('https://license.secureship.dev/v1/webhook/stripe', {
        method: 'POST',
        headers,
        body: bodyPayload,
      });

      return LicenseWorker.handleRequest(req, sqliteEnv);
    },
  };

  const sqliteResult = await testFn(sqliteContext, 'SqliteRealD1');

  return { mockResult, sqliteResult };
}
