import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import {
  InstallToolsCommand,
  type PlatformAsset,
  type ToolDefinition,
} from '../../src/commands/install-tools.js';

describe('InstallToolsCommand — Dynamic SHA256 Verification & Manifest Parser', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-sha-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // Cleanup best effort
      }
    }
    vi.restoreAllMocks();
  });

  // 1. fetchRemoteSha256() correctly parses standard SHA256SUMS format (hash  filename)
  it('correctly parses standard SHA256SUMS format (hash  filename)', async () => {
    const validHash = '98d752c0c7a31548e64c1aa5bb9e8d35687fe48d08795da3c6dbb69389f41df1';
    const manifestContent = [
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  secureship-linux-x64',
      `${validHash}  opengrep-linux-x64`,
      '0be4a4f895c024508ec39ea2fcf262a7146524eaee6cfc8ef6ce1c4109789fcf  opengrep-darwin-arm64',
    ].join('\n');

    vi.stubGlobal('fetch', async () => {
      return new Response(manifestContent, { status: 200, statusText: 'OK' });
    });

    const parsedHash = await InstallToolsCommand.fetchRemoteSha256(
      'https://github.com/opengrep/opengrep/releases/download/v1.31.0/SHA256SUMS',
      'opengrep-linux-x64'
    );

    expect(parsedHash).toBe(validHash.toLowerCase());
  });

  // 2. fetchRemoteSha256() handles checksums.txt format with paths (hash  ./path/binary)
  it('handles checksums.txt format with paths (hash  ./path/binary)', async () => {
    const validHash = '197063dbe6f7c18080f5d5fb5fbc29e612807e3ea2a23e9352e04eb92f750c18';
    const manifestContent = [
      `${validHash}  ./dist/gitleaks_8.24.0_linux_x64.tar.gz`,
      '8870ae86ee7ca70c53d0fc77d8531776957388cf1e8cb82894178385da4b87ae  ./build/gitleaks_8.24.0_windows_x64.zip',
    ].join('\n');

    vi.stubGlobal('fetch', async () => {
      return new Response(manifestContent, { status: 200, statusText: 'OK' });
    });

    const parsedHash = await InstallToolsCommand.fetchRemoteSha256(
      'https://github.com/gitleaks/gitleaks/releases/download/v8.24.0/checksums.txt',
      'gitleaks_8.24.0_linux_x64.tar.gz'
    );

    expect(parsedHash).toBe(validHash.toLowerCase());
  });

  // 3. fetchRemoteSha256() returns null gracefully on network failure (AbortSignal.timeout fires)
  it('returns null gracefully on network failure (AbortSignal.timeout fires)', async () => {
    vi.stubGlobal('fetch', async () => {
      const err = new Error('The operation was aborted due to timeout');
      err.name = 'TimeoutError';
      throw err;
    });

    const parsedHash = await InstallToolsCommand.fetchRemoteSha256(
      'https://example.com/unreachable/SHA256SUMS',
      'opengrep-linux-x64'
    );

    expect(parsedHash).toBeNull();
  });

  // 4. fetchRemoteSha256() returns null when binary name not found in manifest
  it('returns null when binary name not found in manifest', async () => {
    const manifestContent = [
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  secureship-linux-x64',
      '0be4a4f895c024508ec39ea2fcf262a7146524eaee6cfc8ef6ce1c4109789fcf  opengrep-darwin-arm64',
    ].join('\n');

    vi.stubGlobal('fetch', async () => {
      return new Response(manifestContent, { status: 200, statusText: 'OK' });
    });

    const parsedHash = await InstallToolsCommand.fetchRemoteSha256(
      'https://example.com/SHA256SUMS',
      'non-existent-binary-x64'
    );

    expect(parsedHash).toBeNull();
  });

  // 5. fetchRemoteSha256() rejects malformed hashes (not 64 hex chars)
  it('rejects malformed hashes (not 64 hex chars)', async () => {
    const manifestContent = [
      'not-a-valid-sha256-hash  target-binary',
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85555  target-binary-toolong',
      '123456  target-binary-tooshort',
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz  target-binary-nonhex',
    ].join('\n');

    vi.stubGlobal('fetch', async () => {
      return new Response(manifestContent, { status: 200, statusText: 'OK' });
    });

    const res1 = await InstallToolsCommand.fetchRemoteSha256(
      'https://example.com/SHA256SUMS',
      'target-binary'
    );
    expect(res1).toBeNull();

    const res2 = await InstallToolsCommand.fetchRemoteSha256(
      'https://example.com/SHA256SUMS',
      'target-binary-nonhex'
    );
    expect(res2).toBeNull();
  });

  // End-to-end integration: Fix D1 - remote manifest mismatch hard fails, never overrides pin
  it('strictly rejects install when upstream manifest mismatches authoritative pin (Fix D1)', async () => {
    const binaryContent = Buffer.from('#!/bin/sh\necho "Updated upstream binary"\n');
    const freshSha = crypto.createHash('sha256').update(binaryContent).digest('hex');
    const staleSha = '0000000000000000000000000000000000000000000000000000000000000000';

    const manifestContent = `${freshSha}  upstream-tool-linux-x64\n`;

    const toolDef: ToolDefinition = {
      name: 'opengrep',
      description: 'Opengrep SAST',
      version: '1.31.0',
      binaryName: 'opengrep',
      sha256ManifestUrl: 'https://example.com/upstream/SHA256SUMS',
      platforms: {},
    };

    const asset: PlatformAsset = {
      url: 'https://example.com/downloads/upstream-tool-linux-x64',
      archiveType: 'binary',
      sha256: staleSha, // Authoritative bundled hash
    };

    const destBinary = path.join(tempDir, 'opengrep');

    vi.stubGlobal('fetch', async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes('SHA256SUMS')) {
        return new Response(manifestContent, { status: 200, statusText: 'OK' });
      }
      return new Response(binaryContent, { status: 200, statusText: 'OK' });
    });

    // Must hard fail with explicit security violation to prevent trust downgrade
    await expect(
      InstallToolsCommand.downloadAndInstallAsset(asset, destBinary, tempDir, toolDef, {
        json: true,
      })
    ).rejects.toThrow(/does not match authoritative bundled pin/);

    expect(fs.existsSync(destBinary)).toBe(false);
  });

  // End-to-end integration: falls back to bundled hash when manifest fetch fails
  it('falls back to bundled hash when upstream manifest fetch fails', async () => {
    const binaryContent = Buffer.from('#!/bin/sh\necho "Bundled verified binary"\n');
    const trueSha = crypto.createHash('sha256').update(binaryContent).digest('hex');

    const toolDef: ToolDefinition = {
      name: 'opengrep',
      description: 'Opengrep SAST',
      version: '1.31.0',
      binaryName: 'opengrep',
      sha256ManifestUrl: 'https://example.com/failing/SHA256SUMS',
      platforms: {},
    };

    const asset: PlatformAsset = {
      url: 'https://example.com/downloads/bundled-tool-linux-x64',
      archiveType: 'binary',
      sha256: trueSha, // Valid bundled hash
    };

    const destBinary = path.join(tempDir, 'opengrep');

    vi.stubGlobal('fetch', async (url: string | URL | Request) => {
      const urlStr = url.toString();
      if (urlStr.includes('SHA256SUMS')) {
        return new Response('Not Found', { status: 404, statusText: 'Not Found' });
      }
      return new Response(binaryContent, { status: 200, statusText: 'OK' });
    });

    await InstallToolsCommand.downloadAndInstallAsset(asset, destBinary, tempDir, toolDef, {
      json: true,
    });

    expect(fs.existsSync(destBinary)).toBe(true);
    expect(fs.readFileSync(destBinary).toString()).toBe(binaryContent.toString());
  });
});
