import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { tmpdir, homedir } from 'node:os';
import { mkdtempSync, writeFileSync, rmSync, existsSync, mkdirSync, unlinkSync } from 'node:fs';
import { BinaryResolver } from '../src/binary-resolver.js';

describe('BinaryResolver Suite', () => {
  it('resolves common system executables from PATH honoring PATHEXT', () => {
    const gitResolved = BinaryResolver.resolveOnPath('git');
    expect(gitResolved).not.toBeNull();
    expect(typeof gitResolved).toBe('string');

    const nodeResolved = BinaryResolver.resolveOnPath('node');
    expect(nodeResolved).not.toBeNull();
  });

  it('resolves binary with explicit extension already provided', () => {
    const ext = process.platform === 'win32' ? '.exe' : '';
    const nodeResolved = BinaryResolver.resolveOnPath(`node${ext}`);
    expect(nodeResolved).not.toBeNull();
    expect(typeof nodeResolved).toBe('string');
  });

  it('returns null when binary does not exist on PATH', () => {
    const nonExistent = BinaryResolver.resolveOnPath('non_existent_scanner_xyz_9999');
    expect(nonExistent).toBeNull();
  });

  it('returns null when binary cannot be resolved in resolve()', () => {
    const nonExistent = BinaryResolver.resolve('non_existent_scanner_xyz_9999', tmpdir());
    expect(nonExistent).toBeNull();
  });

  it('honors explicit binary override paths', () => {
    const nodePath = BinaryResolver.resolveOnPath('node')!;
    const resolved = BinaryResolver.resolve('gitleaks', tmpdir(), { gitleaks: nodePath });
    expect(resolved).toBe(nodePath);
  });

  it('returns null when explicit override path does not exist on disk', () => {
    const resolved = BinaryResolver.resolve('gitleaks', tmpdir(), {
      gitleaks: path.join(tmpdir(), 'missing-gitleaks-binary-override'),
    });
    expect(resolved).toBeNull();
  });

  it('blocks execution with security error if binary resides inside target directory', () => {
    const tempTarget = mkdtempSync(path.join(tmpdir(), 'planted-bin-target-'));
    const plantedBin = path.join(tempTarget, 'fake-gitleaks.exe');
    writeFileSync(plantedBin, 'dummy-content');

    try {
      expect(() => {
        BinaryResolver.resolve('gitleaks', tempTarget, { gitleaks: plantedBin });
      }).toThrow(/Security violation: Scanner binary .* resides inside target directory/);
    } finally {
      try {
        rmSync(tempTarget, { recursive: true, force: true });
      } catch {
        // Best effort
      }
    }
  });

  it('safely handles non-existent paths in assertNotInsideTarget without throwing security error', () => {
    expect(() => {
      BinaryResolver.assertNotInsideTarget(
        path.join(tmpdir(), 'non-existent-binary-123'),
        path.join(tmpdir(), 'non-existent-target-123')
      );
    }).not.toThrow();
  });

  it('resolves system executable without overrides and applies boundary check', () => {
    const tempTarget = mkdtempSync(path.join(tmpdir(), 'clean-target-'));
    try {
      const resolved = BinaryResolver.resolve('node', tempTarget);
      expect(resolved).not.toBeNull();
      expect(resolved).not.toContain(tempTarget);
    } finally {
      try {
        rmSync(tempTarget, { recursive: true, force: true });
      } catch {
        // Best effort
      }
    }
  });

  it('exercises getUserPathWindows caching on repeated calls', () => {
    const dirs1 = BinaryResolver.getUserPathWindows();
    const dirs2 = BinaryResolver.getUserPathWindows();
    expect(dirs1).toEqual(dirs2);
    expect(dirs1).toBe(dirs2);
  });

  it('resolves binary from ~/.secureship/bin directory automatically', () => {
    const ext = process.platform === 'win32' ? '.exe' : '';
    const userBinDir = path.join(homedir(), '.secureship', 'bin');
    mkdirSync(userBinDir, { recursive: true });

    const mockTool = path.join(userBinDir, `mock-binary-resolver-test-tool${ext}`);
    writeFileSync(mockTool, 'mock resolver binary');

    try {
      const resolved = BinaryResolver.resolveOnPath('mock-binary-resolver-test-tool');
      expect(resolved).not.toBeNull();
      expect(resolved?.toLowerCase()).toBe(path.resolve(mockTool).toLowerCase());
    } finally {
      if (existsSync(mockTool)) {
        try {
          unlinkSync(mockTool);
        } catch {
          // Best effort
        }
      }
    }
  });
});
