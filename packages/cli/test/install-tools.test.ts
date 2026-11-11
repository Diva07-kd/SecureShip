import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import {
  InstallToolsCommand,
  KNOWN_TOOLS,
  type PlatformAsset,
  type ToolDefinition,
} from '../src/commands/install-tools.js';

describe('InstallToolsCommand — Hardened Production Installer Suite (Phase C)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-test-tools-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // Best effort cleanup in test isolation
      }
    }
    vi.restoreAllMocks();
  });

  it('validates all known tool definitions and manifests against SSoT lock', () => {
    const knownKeys = Object.keys(KNOWN_TOOLS);
    expect(knownKeys.length).toBe(5);
    expect(knownKeys).toContain('opengrep');
    expect(knownKeys).toContain('gitleaks');
    expect(knownKeys).toContain('trivy');
    expect(knownKeys).toContain('osv-scanner');
    expect(knownKeys).toContain('checkov');

    for (const [name, def] of Object.entries(KNOWN_TOOLS)) {
      expect(def.name).toBe(name);
      expect(def.version.length).toBeGreaterThan(0);
      expect(def.binaryName.length).toBeGreaterThan(0);
    }
  });

  it('detects current platform and architecture accurately', () => {
    const key = InstallToolsCommand.getCurrentPlatformKey();
    if (
      ['win32', 'darwin', 'linux'].includes(process.platform) &&
      ['x64', 'arm64'].includes(process.arch)
    ) {
      expect(key).toBe(`${process.platform}-${process.arch}`);
    } else {
      expect(key).toBeNull();
    }
  });

  it('executes dry-run cleanly without writing files to disk', async () => {
    const exitCode = await InstallToolsCommand.run({
      dir: tempDir,
      tools: ['opengrep'],
      dryRun: true,
      json: true,
    });

    expect(exitCode).toBe(0);
    const filesWritten = fs.readdirSync(tempDir);
    expect(filesWritten.length).toBe(0);
  });

  it('aborts installation and removes temp file on SHA-256 integrity mismatch', async () => {
    const fakeContent = Buffer.from('malicious payload content');
    const wrongSha = '0000000000000000000000000000000000000000000000000000000000000000';

    const asset: PlatformAsset = {
      url: 'https://github.com/secureship/test/fake-binary',
      archiveType: 'binary',
      sha256: wrongSha,
    };

    const destBinary = path.join(tempDir, 'test-binary');

    vi.stubGlobal('fetch', async () => {
      return new Response(fakeContent, { status: 200, statusText: 'OK' });
    });

    await expect(
      InstallToolsCommand.downloadAndInstallAsset(asset, destBinary, tempDir)
    ).rejects.toThrow('Cryptographic checksum mismatch');

    // Confirm destination was never written and temp file was unlinked
    expect(fs.existsSync(destBinary)).toBe(false);
    const lingeringFiles = fs.readdirSync(tempDir);
    expect(lingeringFiles.filter((f) => f.startsWith('.tmp-')).length).toBe(0);
  });

  it('Defect D1 Defense: fails hard when remote manifest hash does not match authoritative pin', async () => {
    const binaryContent = Buffer.from('verified-tool-content');
    const trueSha = crypto.createHash('sha256').update(binaryContent).digest('hex');
    const attackerManifestHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

    const manifestUrl = 'https://github.com/secureship/test/SHA256SUMS';
    const assetUrl = 'https://github.com/secureship/test/mytool-linux-x64';

    const asset: PlatformAsset = {
      url: assetUrl,
      archiveType: 'binary',
      sha256: trueSha, // Authoritative pin
    };

    const toolDef: ToolDefinition = {
      name: 'opengrep',
      description: 'Test SAST tool',
      version: '1.31.0',
      binaryName: 'mytool',
      sha256ManifestUrl: manifestUrl,
      platforms: {
        'linux-x64': asset,
      },
    };

    const destBinary = path.join(tempDir, 'mytool');

    vi.stubGlobal('fetch', async (url: string | URL) => {
      const u = url.toString();
      if (u === manifestUrl) {
        // Attacker-controlled remote manifest with mismatched hash
        return new Response(`${attackerManifestHash}  mytool-linux-x64\n`, { status: 200 });
      }
      return new Response(binaryContent, { status: 200 });
    });

    // Must throw security violation and NEVER override bundled pin
    await expect(
      InstallToolsCommand.downloadAndInstallAsset(asset, destBinary, tempDir, toolDef)
    ).rejects.toThrow(
      /Security violation: Remote checksum manifest .* does not match authoritative bundled pin/
    );

    expect(fs.existsSync(destBinary)).toBe(false);
  });

  it('Defect D3 Defense: rejects redirect to unauthorized external host', async () => {
    const asset: PlatformAsset = {
      url: 'https://github.com/secureship/test/tool',
      archiveType: 'binary',
      sha256: 'deadbeef',
    };
    const destBinary = path.join(tempDir, 'evil-redirect');

    vi.stubGlobal('fetch', async (url: string | URL) => {
      const u = url.toString();
      if (u.includes('github.com')) {
        return new Response(null, {
          status: 302,
          headers: { location: 'https://evil-attacker-site.com/exploit.bin' },
        });
      }
      return new Response(Buffer.from('payload'), { status: 200 });
    });

    await expect(
      InstallToolsCommand.downloadAndInstallAsset(asset, destBinary, tempDir)
    ).rejects.toThrow(
      /Security violation: Redirect to unauthorized host 'evil-attacker-site.com' is blocked/
    );
  });

  it('Defect D3 Defense: fails when download size is truncated relative to Content-Length header', async () => {
    const partialContent = Buffer.from('only-part-of-it');
    const fakeSha = crypto.createHash('sha256').update(partialContent).digest('hex');

    const asset: PlatformAsset = {
      url: 'https://github.com/secureship/test/tool-truncated',
      archiveType: 'binary',
      sha256: fakeSha,
    };
    const destBinary = path.join(tempDir, 'truncated-tool');

    vi.stubGlobal('fetch', async () => {
      return new Response(partialContent, {
        status: 200,
        headers: { 'content-length': '999999' }, // Declared size much larger than payload
      });
    });

    await expect(
      InstallToolsCommand.downloadAndInstallAsset(asset, destBinary, tempDir)
    ).rejects.toThrow(/Asset download truncated: expected 999999 bytes/);
  });

  it('Defect D3 Defense: rejects downloads exceeding maximum size limit', async () => {
    const asset: PlatformAsset = {
      url: 'https://github.com/secureship/test/oversized-tool',
      archiveType: 'binary',
      sha256: 'dummy',
    };
    const destBinary = path.join(tempDir, 'oversized-tool');

    vi.stubGlobal('fetch', async () => {
      return new Response(Buffer.from('payload'), {
        status: 200,
        headers: { 'content-length': '300000000' }, // 300 MB > 200 MB limit
      });
    });

    await expect(
      InstallToolsCommand.downloadAndInstallAsset(asset, destBinary, tempDir)
    ).rejects.toThrow(/Security violation: Download size .* exceeds maximum allowed limit/);
  });

  it('successfully installs and sets executable permissions on verified binary download', async () => {
    const binaryContent = Buffer.from('#!/bin/sh\necho "SecureShip Scanner OK"\n');
    const trueSha = crypto.createHash('sha256').update(binaryContent).digest('hex');

    const asset: PlatformAsset = {
      url: 'https://github.com/secureship/test/valid-tool',
      archiveType: 'binary',
      sha256: trueSha,
    };

    const ext = process.platform === 'win32' ? '.exe' : '';
    const destBinary = path.join(tempDir, `valid-tool${ext}`);

    vi.stubGlobal('fetch', async () => {
      return new Response(binaryContent, { status: 200, statusText: 'OK' });
    });

    await InstallToolsCommand.downloadAndInstallAsset(asset, destBinary, tempDir);

    expect(fs.existsSync(destBinary)).toBe(true);
    const stat = fs.statSync(destBinary);
    expect(stat.size).toBe(binaryContent.length);

    if (process.platform !== 'win32') {
      expect(stat.mode & 0o111).toBeGreaterThan(0);
    }
  });

  it('skips existing tool binary unless --force is specified', async () => {
    const ext = process.platform === 'win32' ? '.exe' : '';
    const dummyPath = path.join(tempDir, `opengrep${ext}`);
    fs.writeFileSync(dummyPath, 'existing binary');

    const exitCodeNoForce = await InstallToolsCommand.run({
      dir: tempDir,
      tools: ['opengrep'],
      force: false,
      json: true,
    });

    expect(exitCodeNoForce).toBe(0);
    expect(fs.readFileSync(dummyPath, 'utf-8')).toBe('existing binary');
  });

  it('handles cross-platform install option --target-platform linux-arm64 --libc musl', async () => {
    const exitCode = await InstallToolsCommand.run({
      dir: tempDir,
      tools: ['opengrep'],
      targetPlatform: 'linux-arm64',
      libc: 'musl',
      dryRun: true,
      json: true,
    });

    expect(exitCode).toBe(0);
  });

  it('handles checkov with manual-required recommendation status', async () => {
    const exitCode = await InstallToolsCommand.run({
      dir: tempDir,
      tools: ['checkov'],
      dryRun: false,
      json: true,
    });

    expect(exitCode).toBe(0);
  });

  it('aborts on non-writable target directory with clear error message', async () => {
    const dummyFile = path.join(tempDir, 'dummy.txt');
    fs.writeFileSync(dummyFile, 'cannot-mkdir-inside-file');
    const blockedDir = path.join(dummyFile, 'sub');

    const exitCode = await InstallToolsCommand.run({
      dir: blockedDir,
      tools: ['opengrep'],
      dryRun: false,
      json: true,
    });

    expect(exitCode).toBe(1);
  });
});
