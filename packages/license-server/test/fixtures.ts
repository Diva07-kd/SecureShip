import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  type LicenseRecord,
  type Env,
  type D1Database,
  type D1PreparedStatement,
  LicenseWorker,
} from '../src/worker.js';

// Generate test RSA-2048 keypairs: SERVER and ATTACKER
export const SERVER_KEYS = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

export const ATTACKER_KEYS = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

export function base64UrlEncode(data: string | Buffer | Uint8Array): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Signs arbitrary header and payload with given private key.
 * Allows forging alg ('none', 'HS256', 'PS256', 'rs256', etc.) for security testing.
 */
export function signWith(
  privateKeyPem: string,
  header: Record<string, unknown> | unknown,
  payload: Record<string, unknown> | unknown
): string {
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload =
    typeof payload === 'string' && (payload.startsWith('{') || payload.startsWith('['))
      ? base64UrlEncode(payload)
      : base64UrlEncode(JSON.stringify(payload));
  const messageToSign = `${encodedHeader}.${encodedPayload}`;

  const alg =
    typeof header === 'object' && header !== null && 'alg' in header
      ? String((header as Record<string, unknown>).alg)
      : 'RS256';

  if (alg === 'none') {
    return `${messageToSign}.`;
  }

  if (alg === 'HS256') {
    const hmac = crypto.createHmac('sha256', privateKeyPem);
    hmac.update(messageToSign);
    return `${messageToSign}.${hmac.digest('base64url')}`;
  }

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(messageToSign);
  signer.end();
  const sig = signer.sign(privateKeyPem);
  return `${messageToSign}.${base64UrlEncode(sig)}`;
}

/**
 * Creates and seeds an in-memory mock DB map.
 */
export function createMockDb(
  nowEpoch: number = Math.floor(Date.now() / 1000)
): Map<string, LicenseRecord> {
  const db = new Map<string, LicenseRecord>();

  // 1. Active 2-seat license
  db.set('SS-PRO-ACTIVE-0001', {
    id: 'lic_pro_active',
    customer_id: 'cust_01',
    activation_code: 'SS-PRO-ACTIVE-0001',
    tier: 'PRO_TEAM',
    seats: 2,
    org_id: 'acme-corp',
    status: 'ACTIVE',
    expires_at: nowEpoch + 30 * 86400,
    email: 'pro@acme.com',
  });

  // 2. 2-seat license for Layer D tests
  db.set('SS-PRO-2SEATS-0001', {
    id: 'lic_2seats',
    customer_id: 'cust_02',
    activation_code: 'SS-PRO-2SEATS-0001',
    tier: 'PRO_TEAM',
    seats: 2,
    org_id: 'duo-org',
    status: 'ACTIVE',
    expires_at: nowEpoch + 30 * 86400,
    email: 'duo@team.com',
  });

  // 3. 1-seat license for deactivation tests
  db.set('SS-PRO-1SEAT-0001', {
    id: 'lic_1seat',
    customer_id: 'cust_03',
    activation_code: 'SS-PRO-1SEAT-0001',
    tier: 'PRO_TEAM',
    seats: 1,
    org_id: 'solo-org',
    status: 'ACTIVE',
    expires_at: nowEpoch + 30 * 86400,
    email: 'solo@dev.com',
  });

  // 4. 5-seat license for concurrency tests
  db.set('SS-PRO-5SEATS-0001', {
    id: 'lic_5seats',
    customer_id: 'cust_04',
    activation_code: 'SS-PRO-5SEATS-0001',
    tier: 'PRO_TEAM',
    seats: 5,
    org_id: 'penta-org',
    status: 'ACTIVE',
    expires_at: nowEpoch + 30 * 86400,
    email: 'penta@team.com',
  });

  // 5. Active near-expiry license (3 days remaining)
  db.set('SS-ENT-REFRESH-3D', {
    id: 'lic_refresh_3d',
    customer_id: 'cust_05',
    activation_code: 'SS-ENT-REFRESH-3D',
    tier: 'ENTERPRISE',
    seats: 10,
    org_id: 'refresh-org',
    status: 'ACTIVE',
    expires_at: nowEpoch + 3 * 86400,
    email: 'billing@refresh.com',
  });

  // 6. Active far-future license (365 days remaining)
  db.set('SS-ENT-FAR-FUTURE', {
    id: 'lic_far_future',
    customer_id: 'cust_06',
    activation_code: 'SS-ENT-FAR-FUTURE',
    tier: 'ENTERPRISE',
    seats: 50,
    org_id: 'mega-org',
    status: 'ACTIVE',
    expires_at: nowEpoch + 365 * 86400,
    email: 'billing@mega.com',
  });

  // 7. Revoked license
  db.set('SS-PRO-REVOKED-0001', {
    id: 'lic_revoked',
    customer_id: 'cust_07',
    activation_code: 'SS-PRO-REVOKED-0001',
    tier: 'PRO_TEAM',
    seats: 5,
    org_id: 'bad-corp',
    status: 'REVOKED',
    expires_at: nowEpoch + 30 * 86400,
    email: 'bad@corp.com',
  });

  // 8. Expired license (by status)
  db.set('SS-PRO-EXPIRED-STATUS', {
    id: 'lic_expired_status',
    customer_id: 'cust_08',
    activation_code: 'SS-PRO-EXPIRED-STATUS',
    tier: 'PRO_TEAM',
    seats: 2,
    org_id: 'old-corp',
    status: 'EXPIRED',
    expires_at: nowEpoch + 30 * 86400,
    email: 'expired@old.com',
  });

  // 9. Expired license (by timestamp in the past)
  db.set('SS-PRO-EXPIRED-TIME', {
    id: 'lic_expired_time',
    customer_id: 'cust_09',
    activation_code: 'SS-PRO-EXPIRED-TIME',
    tier: 'PRO_TEAM',
    seats: 2,
    org_id: 'time-corp',
    status: 'ACTIVE',
    expires_at: nowEpoch - 3600,
    email: 'time@expired.com',
  });

  return db;
}

/**
 * Creates an in-process D1Database adapter wrapping node:sqlite DatabaseSync.
 * Awaits a microtask between operations to force interleaving.
 */
export function createSqliteD1Adapter(
  db: DatabaseSync,
  onPrepare?: (sql: string) => void
): D1Database {
  return {
    prepare(query: string): D1PreparedStatement {
      onPrepare?.(query);
      let boundParams: unknown[] = [];
      const prepared = db.prepare(query);
      const stmt: D1PreparedStatement = {
        bind(...values: unknown[]) {
          boundParams = values;
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
  };
}

/**
 * Creates a fresh SQLite in-memory database with schema.sql applied and seeded.
 */
export function createFreshSqliteDb(
  nowEpoch: number = Math.floor(Date.now() / 1000),
  onPrepare?: (sql: string) => void
): { db: DatabaseSync; d1: D1Database; recordedSql: string[] } {
  const db = new DatabaseSync(':memory:');
  const recordedSql: string[] = [];

  const schemaPath = path.resolve(__dirname, '../schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf-8');
  db.exec(schemaSql);

  const mockDb = createMockDb(nowEpoch);
  // Seed customers and licenses into SQLite
  const custStmt = db.prepare(
    'INSERT INTO customers (id, email, stripe_customer_id, created_at) VALUES (?, ?, ?, ?)'
  );
  const licStmt = db.prepare(
    'INSERT INTO licenses (id, customer_id, activation_code, tier, seats, org_id, status, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  );

  const seenCustomers = new Set<string>();
  for (const lic of mockDb.values()) {
    if (!seenCustomers.has(lic.customer_id)) {
      seenCustomers.add(lic.customer_id);
      custStmt.run(lic.customer_id, lic.email ?? `${lic.customer_id}@test.com`, null, nowEpoch);
    }
    licStmt.run(
      lic.id,
      lic.customer_id,
      lic.activation_code,
      lic.tier,
      lic.seats,
      lic.org_id,
      lic.status,
      lic.expires_at,
      nowEpoch,
      nowEpoch
    );
  }

  const d1 = createSqliteD1Adapter(db, (sql) => {
    recordedSql.push(sql);
    onPrepare?.(sql);
  });

  return { db, d1, recordedSql };
}

/**
 * Creates a legacy SQLite database (without migration 0002) containing messy data.
 */
export function createLegacySqliteDb(nowEpoch: number = Math.floor(Date.now() / 1000)): {
  db: DatabaseSync;
  d1: D1Database;
} {
  const db = new DatabaseSync(':memory:');

  // Baseline schema without idx_activations_license_fp or activations idx
  db.exec(`
    CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      stripe_customer_id TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS licenses (
      id TEXT PRIMARY KEY,
      customer_id TEXT NOT NULL,
      activation_code TEXT UNIQUE NOT NULL,
      tier TEXT NOT NULL CHECK(tier IN ('FREE_BYOK', 'PRO_TEAM', 'ENTERPRISE')),
      seats INTEGER NOT NULL DEFAULT 1,
      org_id TEXT NOT NULL DEFAULT 'individual',
      status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      FOREIGN KEY (customer_id) REFERENCES customers(id)
    );

    CREATE TABLE IF NOT EXISTS activations (
      id TEXT PRIMARY KEY,
      license_id TEXT NOT NULL,
      machine_fingerprint TEXT,
      activated_at INTEGER NOT NULL,
      last_validated_at INTEGER NOT NULL,
      FOREIGN KEY (license_id) REFERENCES licenses(id)
    );

    CREATE INDEX IF NOT EXISTS idx_licenses_activation_code ON licenses(activation_code);
    CREATE INDEX IF NOT EXISTS idx_licenses_customer_id ON licenses(customer_id);
  `);

  // Seed customers & licenses
  db.prepare(
    'INSERT INTO customers (id, email, stripe_customer_id, created_at) VALUES (?, ?, ?, ?)'
  ).run('cust_leg_1', 'leg@test.com', null, nowEpoch);

  db.prepare(
    'INSERT INTO licenses (id, customer_id, activation_code, tier, seats, org_id, status, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(
    'lic_leg_1',
    'cust_leg_1',
    'SS-LEGACY-0001',
    'PRO_TEAM',
    5,
    'legacy-org',
    'ACTIVE',
    nowEpoch + 86400,
    nowEpoch,
    nowEpoch
  );

  // Seed messy activations:
  // 1. Earlier row for (lic_leg_1, fp_dup)
  db.prepare(
    'INSERT INTO activations (id, license_id, machine_fingerprint, activated_at, last_validated_at) VALUES (?, ?, ?, ?, ?)'
  ).run('act_dup_1', 'lic_leg_1', 'fp_dup', nowEpoch - 100, nowEpoch - 100);

  // 2. Later duplicate row for (lic_leg_1, fp_dup)
  db.prepare(
    'INSERT INTO activations (id, license_id, machine_fingerprint, activated_at, last_validated_at) VALUES (?, ?, ?, ?, ?)'
  ).run('act_dup_2', 'lic_leg_1', 'fp_dup', nowEpoch - 50, nowEpoch - 50);

  // 3. NULL machine_fingerprint
  db.prepare(
    'INSERT INTO activations (id, license_id, machine_fingerprint, activated_at, last_validated_at) VALUES (?, ?, ?, ?, ?)'
  ).run('act_null_1', 'lic_leg_1', null, nowEpoch - 80, nowEpoch - 80);

  // 4. 'unknown' machine_fingerprint
  db.prepare(
    'INSERT INTO activations (id, license_id, machine_fingerprint, activated_at, last_validated_at) VALUES (?, ?, ?, ?, ?)'
  ).run('act_unk_1', 'lic_leg_1', 'unknown', nowEpoch - 70, nowEpoch - 70);

  // 5. Empty/whitespace machine_fingerprint
  db.prepare(
    'INSERT INTO activations (id, license_id, machine_fingerprint, activated_at, last_validated_at) VALUES (?, ?, ?, ?, ?)'
  ).run('act_white_1', 'lic_leg_1', '   ', nowEpoch - 60, nowEpoch - 60);

  // 6. Legitimate distinct row
  db.prepare(
    'INSERT INTO activations (id, license_id, machine_fingerprint, activated_at, last_validated_at) VALUES (?, ?, ?, ?, ?)'
  ).run('act_valid_1', 'lic_leg_1', 'fp_valid_distinct', nowEpoch - 40, nowEpoch - 40);

  const d1 = createSqliteD1Adapter(db);
  return { db, d1 };
}

/**
 * Activate helper that posts to /v1/activate and returns response status, parsed body, and jwt.
 */
export async function activateHelper(
  env: Env,
  mockDb: Map<string, LicenseRecord> | undefined,
  activationCode: string,
  machineFingerprint?: string
): Promise<{ status: number; body: Record<string, unknown>; jwt?: string }> {
  const req = new Request('https://license.secureship.dev/v1/activate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      activationCode,
      ...(machineFingerprint !== undefined ? { machineFingerprint } : {}),
    }),
  });

  const res = await LicenseWorker.handleRequest(req, env, mockDb);
  const status = res.status;
  const body = (await res.json()) as Record<string, unknown>;
  const jwt = typeof body['jwt'] === 'string' ? body['jwt'] : undefined;
  return { status, body, jwt };
}
