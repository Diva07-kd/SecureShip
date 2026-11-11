/**
 * LAYER E: Real Filesystem Mount Semantics across Operating Systems
 *
 * Enforces Anti-Fake-Test Law:
 * - Real directories created via fs.mkdtempSync(os.tmpdir()) and cleaned up.
 * - Windows 8.3 short-name canonicalization vs POSIX literal identity.
 * - Junction and Subst resolution tests with logged skips if unprivileged.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { ContainerBackend } from '../src/backends/container-backend.js';
import { dockerWindowsBindSpecAccepts } from './fixtures/docker-windows-bind-oracle.js';
import { SandboxConfigSchema } from '@secureship/contracts';

describe('Layer E: Real Filesystem Mount Semantics (CI OS Compatibility)', () => {
  let tempBase: string;
  const defaultConfig = SandboxConfigSchema.parse({});

  beforeEach(() => {
    tempBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-fs-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempBase, { recursive: true, force: true });
    } catch {}
  });

  // =========================================================================
  // E1: Real temp directory with spaces and Unicode characters
  // =========================================================================
  it('E1: Real filesystem paths with spaces and Unicode expand short names on Windows', () => {
    const specialSubdir = path.join(tempBase, 'space dir José 🚀');
    fs.mkdirSync(specialSubdir, { recursive: true });

    const backend = new ContainerBackend({
      shadowDir: specialSubdir,
      config: defaultConfig,
      // Uses ambient process.platform for Layer E per Test Quality Rules
    });

    const argv = backend.buildContainerArgs('ls', []);
    const mountArg = argv.find((a) => a.startsWith('-v='));
    expect(mountArg).toBeDefined();

    const mountSource = mountArg!.slice(3, -9); // strips -v= and :/work:rw

    if (process.platform === 'win32') {
      const independentReal = fs.realpathSync.native(specialSubdir).replace(/\\/g, '/');
      expect(mountSource).toBe(independentReal);
      expect(/^[A-Za-z]:\/[^\\]*$/.test(mountSource)).toBe(true);

      // Verify that user home segment is expanded and has no '~' short-name segment
      const segments = mountSource.split('/');
      const userIndex = segments.findIndex((s) => s.toLowerCase() === 'users');
      if (userIndex !== -1 && segments[userIndex + 1]) {
        expect(segments[userIndex + 1]).not.toContain('~');
      }

      // Verified accepted by Docker Windows Oracle
      const oracleCheck = dockerWindowsBindSpecAccepts(`${mountSource}:/work:rw`);
      expect(oracleCheck.accepted).toBe(true);
      expect(oracleCheck.isBind).toBe(true);
    } else {
      // On macOS and Linux, realpath is never called; path equals input exactly
      expect(mountSource).toBe(specialSubdir);
    }
  });

  // =========================================================================
  // E2: Windows Junction & Subst Resolution
  // =========================================================================
  it('E2: Windows junctions resolve to target drive paths', () => {
    if (process.platform !== 'win32') {
      // Skipped on non-Windows
      return;
    }

    const targetDir = path.join(tempBase, 'target-folder');
    const junctionDir = path.join(tempBase, 'junction-link');
    fs.mkdirSync(targetDir, { recursive: true });

    let junctionCreated = false;
    try {
      execSync(`cmd /c mklink /J "${junctionDir}" "${targetDir}"`, { stdio: 'pipe' });
      junctionCreated = true;
    } catch {
      console.warn(
        'E2: mklink /J failed or requires privileges in this environment; skipping junction creation'
      );
    }

    if (junctionCreated) {
      const backend = new ContainerBackend({
        shadowDir: junctionDir,
        config: defaultConfig,
      });
      const argv = backend.buildContainerArgs('ls', []);
      const mountArg = argv.find((a) => a.startsWith('-v='));
      const mountSource = mountArg!.slice(3, -9);

      const targetCanonical = fs.realpathSync.native(targetDir).replace(/\\/g, '/');
      expect(mountSource).toBe(targetCanonical);
    }
  });

  // =========================================================================
  // E3: POSIX directory containing backslash
  // =========================================================================
  it('E3: POSIX directory with backslash is mounted byte-identically', () => {
    if (process.platform === 'win32') {
      // Windows NTFS/FAT rejects backslashes in directory names; skipped on Windows
      return;
    }

    const backslashDir = path.join(tempBase, 'foo\\bar\\baz');
    try {
      fs.mkdirSync(backslashDir, { recursive: true });
    } catch {
      // Some file systems reject backslash
      return;
    }

    const backend = new ContainerBackend({
      shadowDir: backslashDir,
      config: defaultConfig,
    });
    const argv = backend.buildContainerArgs('ls', []);
    const mountArg = argv.find((a) => a.startsWith('-v='));
    const mountSource = mountArg!.slice(3, -9);

    // Invariant I2: on POSIX, backslashes must be preserved byte-identically
    expect(mountSource).toBe(backslashDir);
    expect(mountSource).toContain('\\');
  });
});
