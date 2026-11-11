import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import nodeCrypto from 'node:crypto';
import {
  canonicalJsonStringify,
  signEd25519,
  verifyEd25519,
  generateEd25519KeyPair,
  DeterministicTarWriter,
  SafeTarReader,
  OfflineBundleService,
  DbLocator,
} from '../src/offline/index.js';

describe('Offline Bundle System (WP-C5 & WP-C6)', () => {
  let tempDir: string;
  let keyPair: { publicKeyPem: string; privateKeyPem: string };

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-bundle-test-'));
    keyPair = generateEd25519KeyPair();

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

  describe('RFC 8785 Canonical JSON & Ed25519 Signatures', () => {
    it('canonicalizes object keys in strict sorted order without whitespace', () => {
      const obj = { z: 1, a: 2, m: { c: true, b: 'hello' } };
      const canonical = canonicalJsonStringify(obj);
      expect(canonical).toBe('{"a":2,"m":{"b":"hello","c":true},"z":1}');
    });

    it('handles arrays, primitives, and nulls properly', () => {
      expect(canonicalJsonStringify(null)).toBe('null');
      expect(canonicalJsonStringify(42)).toBe('42');
      expect(canonicalJsonStringify('test')).toBe('"test"');
      expect(canonicalJsonStringify([3, 1, 2])).toBe('[3,1,2]');
      expect(canonicalJsonStringify([{ b: 1, a: 2 }])).toBe('[{"a":2,"b":1}]');
    });

    it('signs and verifies payload successfully with Ed25519', () => {
      const payload = canonicalJsonStringify({ name: 'test', version: '1.0.0' });
      const signature = signEd25519(payload, keyPair.privateKeyPem);
      expect(typeof signature).toBe('string');
      expect(signature.length).toBeGreaterThan(20);

      const isValid = verifyEd25519(payload, signature, keyPair.publicKeyPem);
      expect(isValid).toBe(true);
    });

    it('rejects tampered data or wrong key in Ed25519 verification', () => {
      const payload = canonicalJsonStringify({ name: 'test', version: '1.0.0' });
      const signature = signEd25519(payload, keyPair.privateKeyPem);

      // Tampered payload
      const tampered = canonicalJsonStringify({ name: 'test', version: '1.0.1' });
      expect(verifyEd25519(tampered, signature, keyPair.publicKeyPem)).toBe(false);

      // Different key
      const otherKeyPair = generateEd25519KeyPair();
      expect(verifyEd25519(payload, signature, otherKeyPair.publicKeyPem)).toBe(false);

      // Corrupt signature
      expect(verifyEd25519(payload, 'invalid-signature-base64', keyPair.publicKeyPem)).toBe(false);
    });
  });

  describe('DeterministicTarWriter & SafeTarReader', () => {
    it('writes and safely extracts standard and PAX long-path entries', async () => {
      const tarGzPath = path.join(tempDir, 'test-archive.tar.gz');
      const writer = new DeterministicTarWriter(tarGzPath);

      // Normal short path entry
      writer.addBufferEntry('short.txt', Buffer.from('hello world', 'utf8'));

      // Long path entry (>100 characters triggers PAX header)
      const longPath = 'nested/' + 'a'.repeat(60) + '/' + 'b'.repeat(60) + '/long-file.json';
      writer.addBufferEntry(longPath, Buffer.from('{"long": true}', 'utf8'));

      // File entry from disk
      const diskFilePath = path.join(tempDir, 'source.bin');
      fs.writeFileSync(diskFilePath, Buffer.from([1, 2, 3, 4, 5, 6, 7, 8]));
      await writer.addFileEntry('dir/from-disk.bin', diskFilePath);

      await writer.finalize();
      expect(fs.existsSync(tarGzPath)).toBe(true);

      // Extract
      const destDir = path.join(tempDir, 'extracted');
      const entries = await SafeTarReader.extractAll(tarGzPath, destDir);

      expect(entries.length).toBe(3);
      expect(entries.some((e) => e.path === 'short.txt')).toBe(true);
      expect(entries.some((e) => e.path === longPath)).toBe(true);
      expect(entries.some((e) => e.path === 'dir/from-disk.bin')).toBe(true);

      expect(fs.readFileSync(path.join(destDir, 'short.txt'), 'utf8')).toBe('hello world');
      expect(fs.readFileSync(path.join(destDir, longPath), 'utf8')).toBe('{"long": true}');
    });

    it('rejects path traversal attempts in archive extraction', async () => {
      const tarGzPath = path.join(tempDir, 'traversal.tar.gz');
      const writer = new DeterministicTarWriter(tarGzPath);
      writer.addBufferEntry('../escaped.txt', Buffer.from('evil', 'utf8'));
      await writer.finalize();

      const destDir = path.join(tempDir, 'extract-traversal');
      await expect(SafeTarReader.extractAll(tarGzPath, destDir)).rejects.toThrow(
        /Security violation: Prohibited path traversal/
      );
    });

    it('rejects absolute paths in archive extraction', async () => {
      const tarGzPath = path.join(tempDir, 'absolute.tar.gz');
      const writer = new DeterministicTarWriter(tarGzPath);
      writer.addBufferEntry('C:/Windows/System32/cmd.exe', Buffer.from('malicious', 'utf8'));
      await writer.finalize();

      const destDir = path.join(tempDir, 'extract-absolute');
      await expect(SafeTarReader.extractAll(tarGzPath, destDir)).rejects.toThrow(
        /Security violation/
      );
    });
  });

  describe('OfflineBundleService.createBundle & importBundle', () => {
    it('creates a signed bundle and verifies its contents', async () => {
      const bundlePath = path.join(tempDir, 'bundle.tar.gz');
      const now = new Date('2026-03-01T12:00:00.000Z');

      const result = await OfflineBundleService.createBundle({
        outputPath: bundlePath,
        signKeyPem: keyPair.privateKeyPem,
        keyId: 'test-key-1',
        workDir: tempDir,
        noTools: true,
        skipDownload: true,
        now: () => now,
        cliVersion: '1.0.0-test',
      });

      expect(result.outputPath).toBe(bundlePath);
      expect(result.signed).toBe(true);
      expect(result.manifest.signature).toBeDefined();
      expect(result.manifest.keyId).toBe('test-key-1');
      expect(result.manifest.components.length).toBeGreaterThanOrEqual(2);

      // Overwrite without force fails
      await expect(
        OfflineBundleService.createBundle({
          outputPath: bundlePath,
          workDir: tempDir,
          skipDownload: true,
        })
      ).rejects.toThrow(/already exists/);

      // Verify-only mode
      const verifyResult = await OfflineBundleService.importBundle({
        bundlePath,
        trustKeyPems: [keyPair.publicKeyPem],
        verifyOnly: true,
      });

      expect(verifyResult.success).toBe(true);
      expect(verifyResult.trust).toBe('VERIFIED');
    });

    it('rejects unsigned bundle when trusted keys are required or allowUnsigned is false', async () => {
      const unsignedBundlePath = path.join(tempDir, 'unsigned.tar.gz');
      await OfflineBundleService.createBundle({
        outputPath: unsignedBundlePath,
        workDir: tempDir,
        noTools: true,
        skipDownload: true,
      });

      const dbDir = path.join(tempDir, 'secureship-db');

      // Reject when trust keys given for unsigned bundle
      await expect(
        OfflineBundleService.importBundle({
          bundlePath: unsignedBundlePath,
          trustKeyPems: [keyPair.publicKeyPem],
          dbDir,
        })
      ).rejects.toThrow(/Bundle '.*' is unsigned, but trusted keys were specified/);

      // Reject when no trust keys and allowUnsigned is false
      await expect(
        OfflineBundleService.importBundle({
          bundlePath: unsignedBundlePath,
          allowUnsigned: false,
          dbDir,
        })
      ).rejects.toThrow(/Use --allow-unsigned/);

      // Import succeeds with --allow-unsigned
      const importResult = await OfflineBundleService.importBundle({
        bundlePath: unsignedBundlePath,
        allowUnsigned: true,
        dbDir,
      });

      expect(importResult.success).toBe(true);
      expect(importResult.trust).toBe('UNSIGNED');
      expect(importResult.generationId).toBeDefined();

      const activeGen = DbLocator.getActiveGeneration(dbDir);
      expect(activeGen?.id).toBe(importResult.generationId);
      expect(activeGen?.manifest.trust).toBe('UNSIGNED');
    });

    it('rejects bundle signed with untrusted key', async () => {
      const bundlePath = path.join(tempDir, 'signed-evil.tar.gz');
      const evilKeyPair = generateEd25519KeyPair();

      await OfflineBundleService.createBundle({
        outputPath: bundlePath,
        signKeyPem: evilKeyPair.privateKeyPem,
        keyId: 'evil-key',
        workDir: tempDir,
        noTools: true,
        skipDownload: true,
      });

      const dbDir = path.join(tempDir, 'secureship-db');

      await expect(
        OfflineBundleService.importBundle({
          bundlePath,
          trustKeyPems: [keyPair.publicKeyPem], // Trusting only our key
          dbDir,
        })
      ).rejects.toThrow(/Signature verification failed/);
    });

    it('enforces anti-rollback protection unless --allow-downgrade is passed', async () => {
      const dbDir = path.join(tempDir, 'db-anti-rollback');
      const now1 = new Date('2026-03-01T10:00:00Z');
      const now2 = new Date('2026-03-02T10:00:00Z');

      const bundle1 = path.join(tempDir, 'bundle-v1.tar.gz');
      const bundle2 = path.join(tempDir, 'bundle-v2.tar.gz');

      await OfflineBundleService.createBundle({
        outputPath: bundle1,
        workDir: tempDir,
        now: () => now1,
        noTools: true,
        skipDownload: true,
      });

      await OfflineBundleService.createBundle({
        outputPath: bundle2,
        workDir: tempDir,
        now: () => now2,
        noTools: true,
        skipDownload: true,
      });

      // Import bundle 2 first (newer)
      const res2 = await OfflineBundleService.importBundle({
        bundlePath: bundle2,
        allowUnsigned: true,
        dbDir,
        now: () => now2,
      });
      expect(res2.success).toBe(true);

      // Attempt importing bundle 1 (older) -> should be rejected by anti-rollback
      await expect(
        OfflineBundleService.importBundle({
          bundlePath: bundle1,
          allowUnsigned: true,
          dbDir,
          now: () => now2,
        })
      ).rejects.toThrow(
        /Anti-rollback rejected: Bundle timestamp .* is older than installed generation/
      );

      // Overriding with allowDowngrade works
      const downgradeRes = await OfflineBundleService.importBundle({
        bundlePath: bundle1,
        allowUnsigned: true,
        allowDowngrade: true,
        dbDir,
        now: () => now2,
      });
      expect(downgradeRes.success).toBe(true);
    });

    it('performs rollback to previous generation successfully', async () => {
      const dbDir = path.join(tempDir, 'db-rollback');
      const bundle1 = path.join(tempDir, 'bundle-1.tar.gz');
      const bundle2 = path.join(tempDir, 'bundle-2.tar.gz');

      await OfflineBundleService.createBundle({
        outputPath: bundle1,
        workDir: tempDir,
        noTools: true,
        skipDownload: true,
        now: () => new Date('2026-03-01T10:00:00Z'),
      });

      await OfflineBundleService.createBundle({
        outputPath: bundle2,
        workDir: tempDir,
        noTools: true,
        skipDownload: true,
        now: () => new Date('2026-03-02T10:00:00Z'),
      });

      const res1 = await OfflineBundleService.importBundle({
        bundlePath: bundle1,
        allowUnsigned: true,
        dbDir,
      });

      const res2 = await OfflineBundleService.importBundle({
        bundlePath: bundle2,
        allowUnsigned: true,
        dbDir,
      });

      expect(DbLocator.getCurrentGenerationId(dbDir)).toBe(res2.generationId);

      // Rollback
      const rollbackRes = await OfflineBundleService.rollback(dbDir);
      expect(rollbackRes.success).toBe(true);
      expect(rollbackRes.activeGeneration).toBe(res1.generationId);
      expect(DbLocator.getCurrentGenerationId(dbDir)).toBe(res1.generationId);
    });

    it('dryRun does not modify database directory', async () => {
      const dbDir = path.join(tempDir, 'db-dryrun');
      const bundle = path.join(tempDir, 'bundle-dryrun.tar.gz');

      await OfflineBundleService.createBundle({
        outputPath: bundle,
        workDir: tempDir,
        noTools: true,
        skipDownload: true,
      });

      const dryRunRes = await OfflineBundleService.importBundle({
        bundlePath: bundle,
        allowUnsigned: true,
        dryRun: true,
        dbDir,
      });

      expect(dryRunRes.success).toBe(true);
      expect(dryRunRes.dryRun).toBe(true);
      expect(fs.existsSync(path.join(dbDir, 'CURRENT'))).toBe(false);
      expect(DbLocator.getActiveGeneration(dbDir)).toBeNull();
    });

    it('rejects bundled tools when binary hash violates tool pins', async () => {
      const bundle = path.join(tempDir, 'tool-bundle.tar.gz');

      // Create a bundle with a mock tool component
      const toolBytes = Buffer.alloc(10, 0x90);
      const toolHash = nodeCrypto.createHash('sha256').update(toolBytes).digest('hex');
      const rawManifest = {
        schemaVersion: 1,
        createdAt: new Date().toISOString(),
        cliVersion: '1.0.0',
        bundleId: 'bundle-fake-tool',
        platforms: ['linux-x64'],
        toolPins: {},
        totalSize: 10,
        components: [
          {
            id: 'fake-tool',
            kind: 'tool' as const,
            version: '1.0.0',
            upstreamUpdatedAt: new Date().toISOString(),
            totalSizeBytes: 10,
            files: [
              {
                path: 'tools/malicious-engine',
                size: 10,
                sha256: toolHash,
                mode: 0o755,
              },
            ],
          },
        ],
      };

      const writer = new DeterministicTarWriter(bundle);
      writer.addBufferEntry('manifest.json', Buffer.from(JSON.stringify(rawManifest)));
      writer.addBufferEntry('tools/malicious-engine', toolBytes);
      await writer.finalize();

      const dbDir = path.join(tempDir, 'db-tool-check');

      await expect(
        OfflineBundleService.importBundle({
          bundlePath: bundle,
          allowUnsigned: true,
          dbDir,
          verifyToolBinary: (_filePath, sha256) => sha256 === 'expected-hash-does-not-match',
        })
      ).rejects.toThrow(/Security Violation.*does not match any cryptographic pin/);
    });

    it('enforces import concurrency lock and recovers from stale lock', async () => {
      const bundlePath = path.join(tempDir, 'lock-test-bundle.tar.gz');
      await OfflineBundleService.createBundle({
        outputPath: bundlePath,
        workDir: tempDir,
        noTools: true,
        skipDownload: true,
      });

      const dbDir = path.join(tempDir, 'db-locking-test');
      const stagingBase = path.join(dbDir, 'staging');
      fs.mkdirSync(stagingBase, { recursive: true });
      const lockFile = path.join(stagingBase, 'import.lock');

      // 1. Simulate active import by current process PID
      fs.writeFileSync(lockFile, JSON.stringify({ pid: process.pid, startedAt: Date.now() }));

      await expect(
        OfflineBundleService.importBundle({
          bundlePath,
          allowUnsigned: true,
          dbDir,
        })
      ).rejects.toThrow(/Concurrent import operation is in progress/);

      // 2. Simulate stale lock (e.g. process from 2 hours ago)
      fs.writeFileSync(
        lockFile,
        JSON.stringify({ pid: process.pid, startedAt: Date.now() - 2 * 60 * 60 * 1000 })
      );

      // Import succeeds by reclaiming the stale lock
      const result = await OfflineBundleService.importBundle({
        bundlePath,
        allowUnsigned: true,
        dbDir,
      });

      expect(result.success).toBe(true);
      expect(fs.existsSync(lockFile)).toBe(false);
    });

    it('produces byte-identical bundles from identical inputs across separate invocations (determinism)', async () => {
      const b1 = path.join(tempDir, 'deterministic-1.tar.gz');
      const b2 = path.join(tempDir, 'deterministic-2.tar.gz');
      const fixedTime = () => new Date('2026-03-01T12:00:00.000Z');

      const res1 = await OfflineBundleService.createBundle({
        outputPath: b1,
        workDir: tempDir,
        noTools: true,
        skipDownload: true,
        now: fixedTime,
      });

      const res2 = await OfflineBundleService.createBundle({
        outputPath: b2,
        workDir: tempDir,
        noTools: true,
        skipDownload: true,
        now: fixedTime,
      });

      const h1 = nodeCrypto.createHash('sha256').update(fs.readFileSync(b1)).digest('hex');
      const h2 = nodeCrypto.createHash('sha256').update(fs.readFileSync(b2)).digest('hex');

      expect(res1.bundleId).toBe(res2.bundleId);
      expect(h1).toBe(h2);
    });
  });
});
