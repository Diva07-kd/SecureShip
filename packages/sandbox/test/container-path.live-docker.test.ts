/**
 * LAYER F: Live Docker Desktop Windows Verification Suite (Gated)
 *
 * Gating Mechanism:
 * - Requires SECURESHIP_LIVE_DOCKER=1 environment variable.
 * - Skipped on CI runners without nested virtualization or when docker daemon is absent.
 * - When enabled, asserts preconditions as real assertions (never silent skips).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { ContainerBackend, ContainerPathError } from '../src/backends/container-backend.js';
import { SandboxConfigSchema } from '@secureship/contracts';

const isLiveDockerEnabled = process.env.SECURESHIP_LIVE_DOCKER === '1';

describe.skipIf(!isLiveDockerEnabled)(
  'Layer F: Live Docker Desktop Windows Mount Verification (Gated)',
  () => {
    let tempShadow: string;
    const defaultConfig = SandboxConfigSchema.parse({});
    const pinnedImage =
      'node:20-alpine@sha256:4f04642c676d95da5753ec91ac64a590623a31c51a7b45fcf3a137adcb3989c6';

    beforeEach(() => {
      tempShadow = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-live-docker-'));
    });

    afterEach(() => {
      try {
        fs.rmSync(tempShadow, { recursive: true, force: true });
      } catch {}
    });

    // Preconditions when Layer F is enabled
    it('F0: Docker Preconditions (Linux Containers mode & Pinned Image present)', () => {
      const osType = execSync('docker info --format "{{.OSType}}"', {
        encoding: 'utf8',
      }).trim();
      console.log(`Layer F Precondition: Docker OSType = ${osType}`);
      expect(osType).toBe('linux');

      // Pinned image must be inspectable (pre-pulled)
      expect(() => {
        execSync(`docker image inspect ${pinnedImage}`, { stdio: 'pipe' });
      }).not.toThrow();
    });

    // F1: Defect Repro (Red)
    it('F1: Defect Repro: Legacy /c/... mount fails with local volume name rejection', () => {
      const legacyPath =
        '/' +
        tempShadow.substring(0, 1).toLowerCase() +
        tempShadow.substring(2).replace(/\\/g, '/');

      let dockerError = '';
      try {
        execSync(
          `docker run --rm --pull=never "-v=${legacyPath}:/work:rw" ${pinnedImage} ls /work`,
          {
            stdio: 'pipe',
            encoding: 'utf8',
          }
        );
      } catch (err: unknown) {
        const e = err as { stderr?: string; message?: string };
        dockerError = e.stderr || e.message || '';
      }

      expect(dockerError).toContain('includes invalid characters for a local volume name');
    });

    // F2: Fix (Green)
    it('F2: Remediated ContainerBackend writes file to Windows host mount end-to-end', async () => {
      const backend = new ContainerBackend({
        shadowDir: tempShadow,
        config: defaultConfig,
        fallbackToNative: false, // Strict container test!
      });

      const res = await backend.run('node', [
        '-e',
        "require('fs').writeFileSync('/work/proof.txt', 'ok')",
      ]);
      expect(res.exitCode).toBe(0);
      expect(backend.getMetadata().backend).toBe('container');

      const proofFile = path.join(tempShadow, 'proof.txt');
      expect(fs.existsSync(proofFile)).toBe(true);
      expect(fs.readFileSync(proofFile, 'utf8')).toBe('ok');
    });

    // F3: Seeded read
    it('F3: Container reads host-seeded file through forward-slash mount', async () => {
      const seedFile = path.join(tempShadow, 'seed.txt');
      fs.writeFileSync(seedFile, 'seeded-data-content');

      const backend = new ContainerBackend({
        shadowDir: tempShadow,
        config: defaultConfig,
        fallbackToNative: false,
      });

      const res = await backend.run('cat', ['/work/seed.txt']);
      expect(res.exitCode).toBe(0);
      expect(res.stdout).toContain('seeded-data-content');
    });

    // F4: Permissions (User 1000:1000 write capability)
    it('F4: Unprivileged user 1000:1000 successfully creates directories and files', async () => {
      const backend = new ContainerBackend({
        shadowDir: tempShadow,
        config: defaultConfig,
        fallbackToNative: false,
      });

      const res = await backend.run('node', [
        '-e',
        "require('fs').mkdirSync('/work/sub'); require('fs').writeFileSync('/work/sub/data.json', '{\"status\":\"ok\"}')",
      ]);
      expect(res.exitCode).toBe(0);

      const createdData = path.join(tempShadow, 'sub', 'data.json');
      expect(fs.existsSync(createdData)).toBe(true);
      expect(fs.readFileSync(createdData, 'utf8')).toBe('{"status":"ok"}');
    });

    // F5: UNC fails closed before Docker execution
    it('F5: UNC path throws ContainerPathError before Docker is invoked', async () => {
      const uncBackend = new ContainerBackend({
        shadowDir: '\\\\localhost\\C$\\temp\\shadow',
        config: defaultConfig,
        fallbackToNative: false,
      });

      await expect(uncBackend.run('node', ['-v'])).rejects.toThrow(ContainerPathError);
    });
  }
);
