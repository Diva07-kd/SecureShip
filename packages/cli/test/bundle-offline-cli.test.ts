import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { BundleOfflineCommand } from '../src/commands/bundle-offline.js';
import { ImportOfflineCommand } from '../src/commands/import-offline.js';
import { generateEd25519KeyPair } from '@secureship/core-engine';

describe('CLI bundle-offline & import-offline commands', () => {
  let tempDir: string;
  let keyPair: { publicKeyPem: string; privateKeyPem: string };
  let privKeyPath: string;
  let pubKeyPath: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-cli-offline-test-'));
    keyPair = generateEd25519KeyPair();
    privKeyPath = path.join(tempDir, 'ed25519-private.pem');
    pubKeyPath = path.join(tempDir, 'ed25519-public.pem');
    fs.writeFileSync(privKeyPath, keyPair.privateKeyPem);
    fs.writeFileSync(pubKeyPath, keyPair.publicKeyPem);

    // Populate test database fixtures in tempDir for createBundle tests
    const trivyDir = path.join(tempDir, 'trivy', 'db');
    fs.mkdirSync(trivyDir, { recursive: true });
    fs.writeFileSync(path.join(trivyDir, 'trivy.db'), 'TRIVY_FIXTURE_DATABASE_V2');
    fs.writeFileSync(
      path.join(trivyDir, 'metadata.json'),
      JSON.stringify({ Version: 2, UpdatedAt: '2026-03-01T00:00:00.000Z' })
    );

    for (const eco of ['npm', 'PyPI', 'Go', 'Maven']) {
      const ecoDir = path.join(tempDir, 'osv', eco);
      fs.mkdirSync(ecoDir, { recursive: true });
      fs.writeFileSync(path.join(ecoDir, 'all.zip'), 'PK\x05\x06' + '\x00'.repeat(18));
    }
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('runs bundle-offline with --json and creates a signed bundle', async () => {
    const bundlePath = path.join(tempDir, 'signed-bundle.tar.gz');
    const logs: string[] = [];
    const logSpy = vi.spyOn(console, 'log').mockImplementation((msg) => {
      logs.push(String(msg));
    });

    const exitCode = await BundleOfflineCommand.run({
      output: bundlePath,
      signKey: privKeyPath,
      keyId: 'cli-test-key',
      workDir: tempDir,
      tools: false,
      skipDownload: true,
      json: true,
      force: true,
    });

    logSpy.mockRestore();

    expect(exitCode).toBe(0);
    expect(fs.existsSync(bundlePath)).toBe(true);

    const jsonOutput = JSON.parse(logs[0] ?? '{}');
    expect(jsonOutput.success).toBe(true);
    expect(jsonOutput.signed).toBe(true);
    expect(jsonOutput.manifest.keyId).toBe('cli-test-key');
  });

  it('handles bundle-offline failure gracefully when key file does not exist', async () => {
    const errLogs: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((msg) => {
      errLogs.push(String(msg));
    });

    const exitCode = await BundleOfflineCommand.run({
      signKey: path.join(tempDir, 'non-existent-key.pem'),
      workDir: tempDir,
      tools: false,
      skipDownload: true,
      json: false,
    });

    errSpy.mockRestore();

    expect(exitCode).toBe(1);
    expect(errLogs.some((l) => l.includes('Signing key file not found'))).toBe(true);
  });

  it('verifies and imports an offline bundle via CLI', async () => {
    const bundlePath = path.join(tempDir, 'bundle-to-import.tar.gz');
    await BundleOfflineCommand.run({
      output: bundlePath,
      signKey: privKeyPath,
      keyId: 'import-key',
      workDir: tempDir,
      tools: false,
      skipDownload: true,
      force: true,
      json: true,
    });

    const dbDir = path.join(tempDir, 'cli-db');

    // 1. Verify-only
    const verifyCode = await ImportOfflineCommand.run(bundlePath, {
      trustKey: [pubKeyPath],
      verifyOnly: true,
      dbDir,
      json: true,
    });
    expect(verifyCode).toBe(0);

    // 2. Dry-run
    const dryRunCode = await ImportOfflineCommand.run(bundlePath, {
      trustKey: [pubKeyPath],
      dryRun: true,
      dbDir,
      json: true,
    });
    expect(dryRunCode).toBe(0);
    expect(fs.existsSync(path.join(dbDir, 'CURRENT'))).toBe(false);

    // 3. Real import
    const importCode = await ImportOfflineCommand.run(bundlePath, {
      trustKey: [pubKeyPath],
      dbDir,
      json: true,
    });
    expect(importCode).toBe(0);
    expect(fs.existsSync(path.join(dbDir, 'CURRENT'))).toBe(true);
  });

  it('handles missing bundle argument or invalid path in import-offline', async () => {
    const errLogs: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((msg) => {
      errLogs.push(String(msg));
    });

    const exit1 = await ImportOfflineCommand.run(undefined, {});
    expect(exit1).toBe(1);

    const exit2 = await ImportOfflineCommand.run(path.join(tempDir, 'does-not-exist.tar.gz'), {});
    expect(exit2).toBe(1);

    errSpy.mockRestore();
    expect(errLogs.some((l) => l.includes('Missing bundle argument'))).toBe(true);
    expect(errLogs.some((l) => l.includes('Bundle file not found'))).toBe(true);
  });

  it('handles rollback via import-offline --rollback', async () => {
    const dbDir = path.join(tempDir, 'rollback-db');
    fs.mkdirSync(dbDir, { recursive: true });

    // Without PREVIOUS, fails gracefully
    const errLogs: string[] = [];
    const errSpy = vi.spyOn(console, 'error').mockImplementation((msg) => {
      errLogs.push(String(msg));
    });

    const exitCode = await ImportOfflineCommand.run(undefined, {
      rollback: true,
      dbDir,
    });

    errSpy.mockRestore();
    expect(exitCode).toBe(1);
    expect(errLogs.some((l) => l.includes('No previous generation found'))).toBe(true);
  });
});
