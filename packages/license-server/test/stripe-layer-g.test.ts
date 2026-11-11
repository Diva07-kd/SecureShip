import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('LAYER G: Schema and Migration 0003 Real SQL Tests (DEV-6)', () => {
  const schemaPath = path.resolve(__dirname, '../schema.sql');
  const migration0003Path = path.resolve(__dirname, '../migrations/0003_stripe_webhook.sql');

  // G1: Fresh schema.sql contains stripe_events, new licenses columns, and indexes
  it('G1: fresh schema.sql defines stripe_events table, new columns, and indexes', () => {
    const db = new DatabaseSync(':memory:');
    const schemaSql = fs.readFileSync(schemaPath, 'utf-8');
    db.exec(schemaSql);

    // Verify stripe_events table exists with required columns
    const stripeEventsInfo = db.prepare('PRAGMA table_info(stripe_events)').all() as Array<{
      name: string;
      type: string;
      notnull: number;
    }>;
    const stripeCols = stripeEventsInfo.map((c) => c.name);
    expect(stripeCols).toContain('id');
    expect(stripeCols).toContain('type');
    expect(stripeCols).toContain('received_at');

    // Verify licenses columns include stripe tracking
    const licensesInfo = db.prepare('PRAGMA table_info(licenses)').all() as Array<{
      name: string;
      type: string;
    }>;
    const licenseCols = licensesInfo.map((c) => c.name);
    expect(licenseCols).toContain('stripe_subscription_id');
    expect(licenseCols).toContain('stripe_checkout_session_id');

    // Verify indexes on licenses
    const licenseIndexes = db.prepare('PRAGMA index_list(licenses)').all() as Array<{
      name: string;
      unique: number;
    }>;
    const sessionIdx = licenseIndexes.find((i) => i.name === 'idx_licenses_stripe_session')!;
    expect(sessionIdx).toBeDefined();
    expect(sessionIdx.unique).toBe(1); // UNIQUE index!

    const subIdx = licenseIndexes.find((i) => i.name === 'idx_licenses_stripe_subscription')!;
    expect(subIdx).toBeDefined();
    expect(subIdx.unique).toBe(0);
  });

  // G2: Legacy schema (pre-0003) plus migration 0003 gives identical column & index sets
  it('G2: migration 0003 produces identical schema to fresh schema, preserves existing rows, and permits multiple NULLs', () => {
    // 1. Fresh database schema representation
    const freshDb = new DatabaseSync(':memory:');
    const schemaSql = fs.readFileSync(schemaPath, 'utf-8');
    freshDb.exec(schemaSql);

    // 2. Legacy pre-0003 database
    const legacyDb = new DatabaseSync(':memory:');
    legacyDb.exec(`
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
      CREATE INDEX IF NOT EXISTS idx_activations_license_id ON activations(license_id);
      CREATE UNIQUE INDEX IF NOT EXISTS idx_activations_license_fp ON activations(license_id, machine_fingerprint);
    `);

    // Seed existing pre-migration rows (2 licenses for the customer)
    legacyDb
      .prepare('INSERT INTO customers (id, email, created_at) VALUES (?, ?, ?)')
      .run('cust_leg', 'leg@corp.com', 1700000000);

    legacyDb
      .prepare(
        `INSERT INTO licenses (id, customer_id, activation_code, tier, seats, org_id, status, expires_at, created_at, updated_at)
         VALUES (?, ?, ?, 'PRO_TEAM', 5, 'individual', 'ACTIVE', ?, ?, ?)`
      )
      .run('lic_leg_1', 'cust_leg', 'SS-LEG-0001', 1750000000, 1700000000, 1700000000);

    legacyDb
      .prepare(
        `INSERT INTO licenses (id, customer_id, activation_code, tier, seats, org_id, status, expires_at, created_at, updated_at)
         VALUES (?, ?, ?, 'ENTERPRISE', 10, 'individual', 'ACTIVE', ?, ?, ?)`
      )
      .run('lic_leg_2', 'cust_leg', 'SS-LEG-0002', 1750000000, 1700000000, 1700000000);

    // Apply migration 0003
    const migrationSql = fs.readFileSync(migration0003Path, 'utf-8');
    legacyDb.exec(migrationSql);

    // Verify column sets are identical
    const freshLicensesInfo = freshDb.prepare('PRAGMA table_info(licenses)').all() as Array<{
      cid: number;
      name: string;
      type: string;
    }>;
    const migratedLicensesInfo = legacyDb.prepare('PRAGMA table_info(licenses)').all() as Array<{
      cid: number;
      name: string;
      type: string;
    }>;

    const freshCols = freshLicensesInfo.map((c) => `${c.name}:${c.type}`).sort();
    const migratedCols = migratedLicensesInfo.map((c) => `${c.name}:${c.type}`).sort();
    expect(migratedCols).toEqual(freshCols);

    // Verify index sets are identical
    const freshIndexes = (
      freshDb.prepare('PRAGMA index_list(licenses)').all() as Array<{ name: string }>
    )
      .map((i) => i.name)
      .sort();
    const migratedIndexes = (
      legacyDb.prepare('PRAGMA index_list(licenses)').all() as Array<{ name: string }>
    )
      .map((i) => i.name)
      .sort();
    expect(migratedIndexes).toEqual(freshIndexes);

    // Verify existing rows survived and new columns are NULL
    const survivedRows = legacyDb.prepare('SELECT * FROM licenses ORDER BY id ASC').all() as Array<{
      id: string;
      stripe_subscription_id: string | null;
      stripe_checkout_session_id: string | null;
    }>;
    expect(survivedRows).toHaveLength(2);
    expect(survivedRows[0]!.id).toBe('lic_leg_1');
    expect(survivedRows[0]!.stripe_subscription_id).toBeNull();
    expect(survivedRows[0]!.stripe_checkout_session_id).toBeNull();

    expect(survivedRows[1]!.id).toBe('lic_leg_2');
    expect(survivedRows[1]!.stripe_subscription_id).toBeNull();
    expect(survivedRows[1]!.stripe_checkout_session_id).toBeNull();
  });

  // G3: Unique index rejects duplicate stripe_checkout_session_id
  it('G3: idx_licenses_stripe_session rejects duplicate non-null session id', () => {
    const db = new DatabaseSync(':memory:');
    const schemaSql = fs.readFileSync(schemaPath, 'utf-8');
    db.exec(schemaSql);

    db.prepare('INSERT INTO customers (id, email, created_at) VALUES (?, ?, ?)').run(
      'cust_g3',
      'g3@corp.com',
      1700000000
    );

    const insertStmt = db.prepare(
      `INSERT INTO licenses (id, customer_id, activation_code, tier, seats, org_id, status, expires_at, created_at, updated_at, stripe_checkout_session_id)
       VALUES (?, ?, ?, 'PRO_TEAM', 5, 'individual', 'ACTIVE', 1750000000, 1700000000, 1700000000, ?)`
    );

    // First insert succeeds
    insertStmt.run('lic_g3_1', 'cust_g3', 'SS-G3-0001', 'cs_unique_collision_target');

    // Second insert with duplicate session id must throw UNIQUE constraint failed
    expect(() => {
      insertStmt.run('lic_g3_2', 'cust_g3', 'SS-G3-0002', 'cs_unique_collision_target');
    }).toThrow(/UNIQUE constraint failed: licenses\.stripe_checkout_session_id/);
  });
});
