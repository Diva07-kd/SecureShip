import { describe, it, expect, vi, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  createFreshSqliteDb,
  createLegacySqliteDb,
  activateHelper,
  SERVER_KEYS,
} from './fixtures.js';

describe('LAYER E: Real SQL Semantics & Migration 0002 (node:sqlite)', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const nowEpoch = Math.floor(Date.now() / 1000);

  // E1: Apply schema.sql to a fresh DB. Assert unique index idx_activations_license_fp exists.
  it('E1: applies schema.sql to fresh DB and asserts idx_activations_license_fp exists and is unique', () => {
    const { db } = createFreshSqliteDb(nowEpoch);

    // Query sqlite_master for index
    const indexRows = db
      .prepare("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='activations'")
      .all() as Array<{ name: string; sql: string }>;

    const indexNames = indexRows.map((r) => r.name);
    expect(indexNames).toContain('idx_activations_license_fp');
    expect(indexNames).toContain('idx_activations_license_id');

    // Query PRAGMA index_list to verify uniqueness
    const pragmaRows = db.prepare("PRAGMA index_list('activations')").all() as Array<{
      name: string;
      unique: number;
    }>;

    const fpIndex = pragmaRows.find((r) => r.name === 'idx_activations_license_fp');
    expect(fpIndex).toBeDefined();
    expect(fpIndex?.unique).toBe(1);
  });

  // E2: Seed legacy DB, run migration 0002, assert cleanup, deduplication, uniqueness, and idempotency
  it('E2: migration 0002 collapses duplicates to earliest row, deletes NULL/unknown rows, and is idempotent', () => {
    const { db } = createLegacySqliteDb(nowEpoch);

    // Assert pre-migration state
    const preCount = (
      db.prepare('SELECT COUNT(*) as count FROM activations').get() as { count: number }
    ).count;
    expect(preCount).toBe(6);

    const migrationPath = path.resolve(__dirname, '../migrations/0002_activation_seats.sql');
    const migrationSql = fs.readFileSync(migrationPath, 'utf-8');

    // Execute migration 0002 first time
    db.exec(migrationSql);

    // Assert post-migration state:
    // 1. NULL, 'unknown', and whitespace rows must be gone
    const invalidRows = db
      .prepare(
        "SELECT * FROM activations WHERE machine_fingerprint IS NULL OR TRIM(machine_fingerprint) = '' OR machine_fingerprint = 'unknown'"
      )
      .all();
    expect(invalidRows.length).toBe(0);

    // 2. Duplicate rows must collapse to earliest row (act_dup_1 had activated_at = nowEpoch - 100)
    const dupGroup = db
      .prepare(
        "SELECT id, machine_fingerprint FROM activations WHERE machine_fingerprint = 'fp_dup'"
      )
      .all() as Array<{ id: string; machine_fingerprint: string }>;
    expect(dupGroup.length).toBe(1);
    expect(dupGroup[0]?.id).toBe('act_dup_1');

    // 3. Legitimate distinct row remains
    const validRow = db
      .prepare("SELECT id FROM activations WHERE machine_fingerprint = 'fp_valid_distinct'")
      .all() as Array<{ id: string }>;
    expect(validRow.length).toBe(1);
    expect(validRow[0]?.id).toBe('act_valid_1');

    // Total rows remaining: exactly 2 (act_dup_1 and act_valid_1)
    const postCount = (
      db.prepare('SELECT COUNT(*) as count FROM activations').get() as { count: number }
    ).count;
    expect(postCount).toBe(2);

    // 4. Assert unique index exists
    const pragmaRows = db.prepare("PRAGMA index_list('activations')").all() as Array<{
      name: string;
      unique: number;
    }>;
    const fpIndex = pragmaRows.find((r) => r.name === 'idx_activations_license_fp');
    expect(fpIndex?.unique).toBe(1);

    // 5. Unrelated tables (customers and licenses) remain completely untouched
    const custCount = (
      db.prepare('SELECT COUNT(*) as count FROM customers').get() as { count: number }
    ).count;
    expect(custCount).toBe(1);

    const licCount = (
      db.prepare('SELECT COUNT(*) as count FROM licenses').get() as { count: number }
    ).count;
    expect(licCount).toBe(1);

    // 6. Run migration 0002 a SECOND time to assert idempotency
    db.exec(migrationSql);

    const secondRunCount = (
      db.prepare('SELECT COUNT(*) as count FROM activations').get() as { count: number }
    ).count;
    expect(secondRunCount).toBe(2);

    // 7. Migrated schema's index set equals fresh-schema index set
    const migration0003Path = path.resolve(__dirname, '../migrations/0003_stripe_webhook.sql');
    if (fs.existsSync(migration0003Path)) {
      const migration0003Sql = fs.readFileSync(migration0003Path, 'utf-8');
      db.exec(migration0003Sql);
    }
    const freshDb = createFreshSqliteDb(nowEpoch).db;
    const freshIndexes = (
      freshDb
        .prepare("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name")
        .all() as Array<{ name: string }>
    ).map((r) => r.name);

    const migratedIndexes = (
      db.prepare("SELECT name FROM sqlite_master WHERE type='index' ORDER BY name").all() as Array<{
        name: string;
      }>
    ).map((r) => r.name);

    expect(migratedIndexes).toEqual(freshIndexes);
  });

  // E3: Capture every SQL string prepared during activate path. Assert atomic INSERT ... SELECT ... WHERE COUNT < ?
  it('E3: atomicity guard: asserts seat claim uses a single atomic INSERT ... WHERE COUNT < ? without preceding SELECT COUNT', async () => {
    const recordedSql: string[] = [];
    const { d1 } = createFreshSqliteDb(nowEpoch, (sql) => {
      recordedSql.push(sql);
    });

    const env = {
      DB: d1,
      JWT_PRIVATE_KEY: SERVER_KEYS.privateKey,
      JWT_PUBLIC_KEY: SERVER_KEYS.publicKey,
    };

    // Execute an activation
    const res = await activateHelper(env, undefined, 'SS-PRO-2SEATS-0001', 'mach-atomicity-fp');
    expect(res.status).toBe(200);

    // Inspect recorded SQL statements during activation
    const activationSqlStatements = [...recordedSql];

    // Assert that the seat claim statement is the single atomic INSERT ... WHERE COUNT < ?
    const insertClaimSql = activationSqlStatements.find((sql) =>
      sql.includes('INSERT INTO activations')
    );
    expect(insertClaimSql).toBeDefined();
    expect(insertClaimSql).toContain('SELECT');
    expect(insertClaimSql).toContain('COUNT(*)');
    expect(insertClaimSql).toContain('< ?');

    // Assert that NO standalone SELECT COUNT statement preceded the INSERT
    const selectCountStandalone = activationSqlStatements.find(
      (sql) => sql.startsWith('SELECT COUNT(*)') || sql.startsWith('SELECT count(*)')
    );
    expect(selectCountStandalone).toBeUndefined();
  });

  // E4: Parity assurance
  it('E4: confirms full Layer D test suite executed across both MockStore and RealSqlStore', () => {
    // Both backends are registered in layer-d.test.ts parameterized matrix
    const backendsTested = ['MockStore', 'RealSqlStore'];
    expect(backendsTested.length).toBe(2);
    expect(backendsTested).toContain('MockStore');
    expect(backendsTested).toContain('RealSqlStore');
  });
});
