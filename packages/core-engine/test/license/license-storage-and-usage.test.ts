import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  readLicenseFile,
  writeLicenseFile,
  deleteLicenseFile,
} from '../../src/license/license-storage.js';
import {
  getMonthlyAiUsage,
  recordAiFixExecution,
  canPerformAiFix,
  getCurrentMonthKey,
} from '../../src/license/ai-usage-ledger.js';

describe('License File Storage and AI Usage Ledger', () => {
  let tempDir: string;
  let licenseFilePath: string;
  let usageFilePath: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-lic-test-'));
    licenseFilePath = path.join(tempDir, 'license.jwt');
    usageFilePath = path.join(tempDir, 'ai-usage.json');
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Cleanup best effort
    }
  });

  it('reads null when license file does not exist', () => {
    expect(readLicenseFile(licenseFilePath)).toBeNull();
  });

  it('atomically writes and reads license token content', () => {
    const mockJwt = 'header.payload.signature';
    writeLicenseFile(mockJwt, licenseFilePath);

    const readBack = readLicenseFile(licenseFilePath);
    expect(readBack).toBe(mockJwt);
  });

  it('deletes license token file cleanly', () => {
    writeLicenseFile('token-to-delete', licenseFilePath);
    expect(fs.existsSync(licenseFilePath)).toBe(true);

    const deleted = deleteLicenseFile(licenseFilePath);
    expect(deleted).toBe(true);
    expect(fs.existsSync(licenseFilePath)).toBe(false);
    expect(readLicenseFile(licenseFilePath)).toBeNull();
  });

  it('initializes fresh monthly AI usage ledger with zero count', () => {
    const usage = getMonthlyAiUsage(usageFilePath, new Date('2026-10-15T12:00:00Z'));
    expect(usage.month).toBe('2026-10');
    expect(usage.fixesUsed).toBe(0);
  });

  it('records AI fix execution by incrementing monthly count', () => {
    const testDate = new Date('2026-10-15T12:00:00Z');
    recordAiFixExecution(usageFilePath, testDate);
    recordAiFixExecution(usageFilePath, testDate);
    const updated = recordAiFixExecution(usageFilePath, testDate);

    expect(updated.fixesUsed).toBe(3);
    expect(updated.month).toBe('2026-10');
  });

  it('automatically resets fix count when month boundary is crossed', () => {
    // Month 1: October 2026 (15 fixes used)
    const octDate = new Date('2026-10-31T23:59:00Z');
    for (let i = 0; i < 15; i++) {
      recordAiFixExecution(usageFilePath, octDate);
    }
    const octUsage = getMonthlyAiUsage(usageFilePath, octDate);
    expect(octUsage.fixesUsed).toBe(15);
    expect(octUsage.month).toBe('2026-10');

    // Month 2: November 2026 (New month -> resets to 0)
    const novDate = new Date('2026-11-01T00:01:00Z');
    const novUsage = getMonthlyAiUsage(usageFilePath, novDate);
    expect(novUsage.fixesUsed).toBe(0);
    expect(novUsage.month).toBe('2026-11');
  });

  it('enforces FREE_BYOK quota limits correctly', () => {
    const testDate = new Date('2026-10-23T08:00:00Z');
    const freeTierLimit = 15;

    // First 14 fixes are permitted
    for (let i = 0; i < 14; i++) {
      recordAiFixExecution(usageFilePath, testDate);
    }
    let check = canPerformAiFix(freeTierLimit, usageFilePath, testDate);
    expect(check.allowed).toBe(true);
    expect(check.fixesUsed).toBe(14);
    expect(check.remaining).toBe(1);

    // 15th fix reaches the cap
    recordAiFixExecution(usageFilePath, testDate);
    check = canPerformAiFix(freeTierLimit, usageFilePath, testDate);
    expect(check.allowed).toBe(false);
    expect(check.fixesUsed).toBe(15);
    expect(check.remaining).toBe(0);
  });

  it('allows unlimited fixes when limit is null (ENTERPRISE tier)', () => {
    const testDate = new Date('2026-10-23T08:00:00Z');
    for (let i = 0; i < 250; i++) {
      recordAiFixExecution(usageFilePath, testDate);
    }

    const check = canPerformAiFix(null, usageFilePath, testDate);
    expect(check.allowed).toBe(true);
    expect(check.fixesUsed).toBe(250);
    expect(check.limit).toBeNull();
    expect(check.remaining).toBeNull();
  });

  it('correctly formats month keys via getCurrentMonthKey', () => {
    expect(getCurrentMonthKey(new Date('2026-01-05T00:00:00Z'))).toBe('2026-01');
    expect(getCurrentMonthKey(new Date('2026-12-25T00:00:00Z'))).toBe('2026-12');
  });

  it('handles edge cases in license storage: empty file, delete nonexistent, and env path override', () => {
    // 1. Empty license file returns null
    const emptyFile = path.join(tempDir, 'empty.jwt');
    fs.writeFileSync(emptyFile, '   \n  ');
    expect(readLicenseFile(emptyFile)).toBeNull();

    // 2. Deleting nonexistent file returns false
    const nonExistent = path.join(tempDir, 'does-not-exist.jwt');
    expect(deleteLicenseFile(nonExistent)).toBe(false);

    // 3. SECURESHIP_LICENSE_PATH environment variable override
    const originalEnv = process.env.SECURESHIP_LICENSE_PATH;
    try {
      const customPath = path.join(tempDir, 'custom.jwt');
      process.env.SECURESHIP_LICENSE_PATH = customPath;
      writeLicenseFile('env-token');
      expect(readLicenseFile()).toBe('env-token');
      expect(deleteLicenseFile()).toBe(true);
    } finally {
      if (originalEnv !== undefined) {
        process.env.SECURESHIP_LICENSE_PATH = originalEnv;
      } else {
        delete process.env.SECURESHIP_LICENSE_PATH;
      }
    }
  });
});
