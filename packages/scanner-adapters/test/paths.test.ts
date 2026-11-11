import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  resolveSecureshipHome,
  resolveToolDirs,
  getDefaultToolDir,
  resolveDbDir,
  isContainerEnvironment,
  checkDirWritable,
  assertNotInsideTarget,
} from '../src/paths.js';

describe('Paths & Environment Resolution Suite (Phase C)', () => {
  const origEnv = { ...process.env };
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-paths-test-'));
  });

  afterEach(() => {
    process.env = { ...origEnv };
    if (fs.existsSync(tempDir)) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // Best effort
      }
    }
  });

  it('resolveSecureshipHome honors SECURESHIP_HOME and falls back to homedir/.secureship', () => {
    delete process.env.SECURESHIP_HOME;
    expect(resolveSecureshipHome()).toBe(path.join(os.homedir(), '.secureship'));

    const customHome = path.join(tempDir, 'custom-home');
    process.env.SECURESHIP_HOME = customHome;
    expect(resolveSecureshipHome()).toBe(path.resolve(customHome));
  });

  it('resolveToolDirs follows strict precedence order', () => {
    const explicitDir = path.join(tempDir, 'explicit-bin');
    const envBinDir = path.join(tempDir, 'env-bin');
    process.env.SECURESHIP_BIN_DIR = envBinDir;

    const dirs = resolveToolDirs({ explicitDir });
    expect(dirs[0]).toBe(path.resolve(explicitDir));
    expect(dirs[1]).toBe(path.resolve(envBinDir));
    expect(dirs).toContain(path.join(resolveSecureshipHome(), 'bin'));
  });

  it('resolveDbDir honors SECURESHIP_DB_DIR and explicit argument', () => {
    delete process.env.SECURESHIP_DB_DIR;
    delete process.env.SECURESHIP_HOME;
    expect(resolveDbDir()).toBe(path.join(os.homedir(), '.secureship', 'db'));

    process.env.SECURESHIP_DB_DIR = path.join(tempDir, 'env-db');
    expect(resolveDbDir()).toBe(path.resolve(tempDir, 'env-db'));

    expect(resolveDbDir(path.join(tempDir, 'explicit-db'))).toBe(
      path.resolve(tempDir, 'explicit-db')
    );
  });

  it('detects container environment when SECURESHIP_CONTAINER is set', () => {
    delete process.env.SECURESHIP_CONTAINER;
    delete process.env.CONTAINER;

    process.env.SECURESHIP_CONTAINER = '1';
    expect(isContainerEnvironment()).toBe(true);

    delete process.env.SECURESHIP_CONTAINER;
    process.env.CONTAINER = 'true';
    expect(isContainerEnvironment()).toBe(true);
  });

  it('checkDirWritable checks directory writability and returns actionable guidance on failure', () => {
    const writableDir = path.join(tempDir, 'writable-sub');
    const res = checkDirWritable(writableDir);
    expect(res.writable).toBe(true);
    expect(res.error).toBeUndefined();

    // On non-writable directory (simulate with mock or invalid path)
    const invalidPath = path.join(tempDir, 'file.txt');
    fs.writeFileSync(invalidPath, 'dummy');
    // Trying to mkdir/access inside a file path fails
    const failingDir = path.join(invalidPath, 'nested');
    const failRes = checkDirWritable(failingDir);
    expect(failRes.writable).toBe(false);
    expect(failRes.error).toContain('is not writable');
    expect(failRes.error).toContain('SECURESHIP_HOME');
  });

  it('assertNotInsideTarget throws security violation when tool resides inside targetDir', () => {
    const targetDir = path.join(tempDir, 'repo');
    fs.mkdirSync(targetDir, { recursive: true });

    const plantedBin = path.join(targetDir, 'tool.exe');
    fs.writeFileSync(plantedBin, 'fake');

    expect(() => {
      assertNotInsideTarget(plantedBin, targetDir);
    }).toThrow(/Security violation: Scanner binary .* resides inside target directory/);

    expect(() => {
      assertNotInsideTarget(targetDir, targetDir);
    }).toThrow(/Security violation/);

    // Outside path succeeds
    const outsideBin = path.join(tempDir, 'outside-bin');
    expect(() => {
      assertNotInsideTarget(outsideBin, targetDir);
    }).not.toThrow();
  });

  it('getDefaultToolDir returns first candidate', () => {
    const dir = getDefaultToolDir();
    expect(typeof dir).toBe('string');
    expect(dir.length).toBeGreaterThan(0);
  });
});
