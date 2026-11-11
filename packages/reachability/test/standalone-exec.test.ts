import { describe, it, expect, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { getStandaloneExecDir } from '../src/standalone-exec.js';

describe('DEV-1: getStandaloneExecDir (Layer A)', () => {
  const tempDirs: string[] = [];

  function makeTempDir(prefix: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  afterEach(() => {
    for (const d of tempDirs) {
      try {
        fs.rmSync(d, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
    tempDirs.length = 0;
  });

  describe('A1: Standalone case', () => {
    it('returns the realpath directory when bunVersion is set and execPath is secureship', () => {
      const fakeDir = path.resolve('/opt/secureship/bin');
      const fakeExecPath = path.join(fakeDir, 'secureship');
      const realTargetDir = path.resolve('/opt/secureship/dist');
      const realTarget = path.join(realTargetDir, 'secureship');

      const result = getStandaloneExecDir({
        execPath: fakeExecPath,
        bunVersion: '1.4.3',
        realpath: (p) => (p === fakeExecPath ? realTarget : p),
      });

      expect(result).toBe(realTargetDir);
    });

    it('returns the realpath directory when bunVersion is set and execPath is secureship.exe', () => {
      const fakeDir = path.resolve('C:\\secureship\\bin');
      const fakeExecPath = path.join(fakeDir, 'secureship.exe');
      const realTargetDir = path.resolve('C:\\secureship\\release');
      const realTarget = path.join(realTargetDir, 'secureship.exe');

      const result = getStandaloneExecDir({
        execPath: fakeExecPath,
        bunVersion: '1.4.3',
        realpath: (p) => (p === fakeExecPath ? realTarget : p),
      });

      expect(result).toBe(realTargetDir);
    });
  });

  describe('A2: Not standalone case', () => {
    it('returns null when bunVersion is undefined (running under Node.js)', () => {
      const result = getStandaloneExecDir({
        execPath: '/usr/local/bin/secureship',
        bunVersion: undefined,
      });
      expect(result).toBeNull();
    });

    it('returns null when binary basename is bun', () => {
      const result = getStandaloneExecDir({
        execPath: '/usr/local/bin/bun',
        bunVersion: '1.4.3',
      });
      expect(result).toBeNull();
    });

    it('returns null when binary basename is bun.exe', () => {
      const result = getStandaloneExecDir({
        execPath: 'C:\\Users\\user\\.bun\\bin\\bun.exe',
        bunVersion: '1.4.3',
      });
      expect(result).toBeNull();
    });

    it('returns null when binary basename is node', () => {
      const result = getStandaloneExecDir({
        execPath: '/usr/local/bin/node',
        bunVersion: '1.4.3',
      });
      expect(result).toBeNull();
    });

    it('returns null when binary basename is node.exe', () => {
      const result = getStandaloneExecDir({
        execPath: 'C:\\Program Files\\nodejs\\node.exe',
        bunVersion: '1.4.3',
      });
      expect(result).toBeNull();
    });
  });

  describe('A3: Symlink resolution & error resilience', () => {
    it('resolves symlink to real directory when realpath succeeds', () => {
      const fakeSymlink = path.resolve('/usr/local/bin/secureship');
      const fakeRealDir = path.resolve('/opt/secureship-1.0.0/dist');
      const fakeRealBin = path.join(fakeRealDir, 'secureship');

      const result = getStandaloneExecDir({
        execPath: fakeSymlink,
        bunVersion: '1.4.3',
        realpath: (p) => (p === fakeSymlink ? fakeRealBin : p),
      });

      expect(result).toBe(fakeRealDir);
    });

    it('resolves real symlinks on filesystem when OS symlink creation succeeds', () => {
      const tempDir = makeTempDir('secureship-symlink-test-');
      const realDir = path.join(tempDir, 'real');
      const symlinkDir = path.join(tempDir, 'symlink-bin');
      fs.mkdirSync(realDir, { recursive: true });
      fs.mkdirSync(symlinkDir, { recursive: true });

      const realBin = path.join(realDir, 'secureship');
      fs.writeFileSync(realBin, '#!/bin/sh\necho "test"\n');
      const symlinkBin = path.join(symlinkDir, 'secureship');

      let symlinkCreated = false;
      try {
        fs.symlinkSync(realBin, symlinkBin, 'file');
        symlinkCreated = true;
      } catch {
        // Windows without developer mode/admin may disallow symlinks
      }

      if (symlinkCreated) {
        const result = getStandaloneExecDir({
          execPath: symlinkBin,
          bunVersion: '1.4.3',
        });
        expect(result).toBe(path.resolve(realDir));
      } else {
        // Fallback verification for non-privileged Windows environments
        const mockResult = getStandaloneExecDir({
          execPath: symlinkBin,
          bunVersion: '1.4.3',
          realpath: () => realBin,
        });
        expect(mockResult).toBe(path.resolve(realDir));
      }
    });

    it('falls back to path.dirname(execPath) when realpath throws', () => {
      const fakeExecPath = path.resolve('/opt/secureship/secureship');
      const result = getStandaloneExecDir({
        execPath: fakeExecPath,
        bunVersion: '1.4.3',
        realpath: () => {
          throw new Error('EACCES: permission denied');
        },
      });
      expect(result).toBe(path.dirname(fakeExecPath));
    });

    it('never throws on empty, null, undefined, or throwing inputs', () => {
      expect(getStandaloneExecDir({ execPath: '' })).toBeNull();
      expect(getStandaloneExecDir({ execPath: undefined, bunVersion: '1.4.3' })).toBeNull();
      expect(getStandaloneExecDir(undefined)).toBeNull();
      expect(
        getStandaloneExecDir({
          execPath: '/some/path',
          bunVersion: '1.4.3',
          realpath: () => {
            throw 'string error';
          },
        })
      ).toBe(path.dirname('/some/path'));
    });
  });
});
