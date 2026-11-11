/**
 * LAYER A: ContainerBackend.translateHostPath Verification Suite
 *
 * Enforces Anti-Fake-Test Law:
 * - Hand-written constants and exact expected strings/error codes.
 * - Platform-parameterised tests running on EVERY OS.
 * - Property tests via seeded deterministic PRNG (500+ iterations).
 * - Differential red proof against baseline fixture.
 */

import { describe, it, expect } from 'vitest';
import path from 'node:path';
import {
  ContainerBackend,
  ContainerPathError,
  type ContainerPathErrorCode,
} from '../src/backends/container-backend.js';
import { baselineTranslateHostPath } from './fixtures/translate-host-path.baseline.js';

describe('Layer A: ContainerBackend.translateHostPath Specification Suite', () => {
  // =========================================================================
  // A1: win32 accepted rows (exact hand-written outputs)
  // =========================================================================
  it('A1: win32 accepted paths produce exact hand-written canonical outputs', () => {
    // Generate a 40-segment deep path
    const segments = Array.from({ length: 40 }, (_, i) => `seg${i}`);
    const deepInput = `C:\\${segments.join('\\')}`;
    const deepExpected = `C:/${segments.join('/')}`;

    const testVectors: Array<{ input: string; expected: string }> = [
      { input: 'C:\\Users\\dev\\project', expected: 'C:/Users/dev/project' },
      { input: 'c:\\Users\\dev', expected: 'c:/Users/dev' }, // case preserved
      { input: 'd:\\data\\app', expected: 'd:/data/app' },
      { input: 'D:/data/app', expected: 'D:/data/app' },
      { input: 'C:\\Program Files\\Project', expected: 'C:/Program Files/Project' },
      { input: 'C:\\Users\\José\\Проект\\项目', expected: 'C:/Users/José/Проект/项目' },
      { input: 'C:\\a\\b\\', expected: 'C:/a/b' },
      { input: 'C:\\', expected: 'C:/' },
      { input: 'C:/', expected: 'C:/' },
      { input: 'C:\\a\\\\b', expected: 'C:/a/b' },
      { input: 'C:\\a\\.\\b', expected: 'C:/a/b' },
      { input: 'C:\\a\\..\\b', expected: 'C:/b' },
      { input: 'C:/a\\b/c', expected: 'C:/a/b/c' },
      { input: '\\\\?\\C:\\Users\\x', expected: 'C:/Users/x' },
      {
        input: 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\ss-1',
        expected: 'C:/Users/RUNNER~1/AppData/Local/Temp/ss-1',
      },
      { input: deepInput, expected: deepExpected },
    ];

    expect(testVectors).toHaveLength(16);

    for (const { input, expected } of testVectors) {
      const result = ContainerBackend.translateHostPath(input, 'win32');
      expect(result).toBe(expected);
      // Ensure invariant I1 holds: never begins with /c/ or lowercase slash-drive
      expect(result.startsWith('/c/')).toBe(false);
      expect(result.startsWith('/d/')).toBe(false);
      expect(/^[A-Za-z]:\//.test(result)).toBe(true);
    }
  });

  // =========================================================================
  // A2: win32 rejected rows (exact error codes and messages)
  // =========================================================================
  it('A2: win32 rejected paths throw ContainerPathError with exact codes', () => {
    const errorVectors: Array<{
      input: string;
      expectedCode: ContainerPathErrorCode;
      messageSubstring?: string;
    }> = [
      // UNC_UNSUPPORTED
      { input: '\\\\server\\share\\x', expectedCode: 'UNC_UNSUPPORTED' },
      { input: '//server/share/x', expectedCode: 'UNC_UNSUPPORTED' },
      { input: '\\\\localhost\\C$\\x', expectedCode: 'UNC_UNSUPPORTED' },
      { input: '\\\\?\\UNC\\server\\share', expectedCode: 'UNC_UNSUPPORTED' },
      // DEVICE_PATH_UNSUPPORTED
      { input: '\\\\.\\pipe\\docker_engine', expectedCode: 'DEVICE_PATH_UNSUPPORTED' },
      { input: '//./pipe/docker_engine', expectedCode: 'DEVICE_PATH_UNSUPPORTED' },
      // DRIVE_RELATIVE
      { input: 'C:foo', expectedCode: 'DRIVE_RELATIVE' },
      { input: 'C:', expectedCode: 'DRIVE_RELATIVE' },
      // POSIX_STYLE_ON_WINDOWS
      {
        input: '/c/Users/x',
        expectedCode: 'POSIX_STYLE_ON_WINDOWS',
        messageSubstring: 'C:/',
      },
      {
        input: '\\Users\\x',
        expectedCode: 'POSIX_STYLE_ON_WINDOWS',
        messageSubstring: 'C:/',
      },
      {
        input: '/mnt/c/Users/x',
        expectedCode: 'POSIX_STYLE_ON_WINDOWS',
        messageSubstring: 'C:/',
      },
      // NOT_ABSOLUTE
      { input: 'relative\\path', expectedCode: 'NOT_ABSOLUTE' },
      { input: '.\\x', expectedCode: 'NOT_ABSOLUTE' },
      { input: 'x', expectedCode: 'NOT_ABSOLUTE' },
      // EMPTY
      { input: '', expectedCode: 'EMPTY' },
      // ILLEGAL_CHARS
      { input: 'C:\\test\0null', expectedCode: 'ILLEGAL_CHARS' },
      { input: 'C:\\test\nnewline', expectedCode: 'ILLEGAL_CHARS' },
      { input: 'C:\\test\ttab', expectedCode: 'ILLEGAL_CHARS' },
      { input: 'C:\\a|b', expectedCode: 'ILLEGAL_CHARS' },
      { input: 'C:\\a?b', expectedCode: 'ILLEGAL_CHARS' },
      { input: 'C:\\a*b', expectedCode: 'ILLEGAL_CHARS' },
      { input: 'C:\\a<b', expectedCode: 'ILLEGAL_CHARS' },
      { input: 'C:\\a>b', expectedCode: 'ILLEGAL_CHARS' },
      { input: 'C:\\a"b', expectedCode: 'ILLEGAL_CHARS' },
      // COLON_IN_PATH
      { input: 'C:\\a:b', expectedCode: 'COLON_IN_PATH' },
      { input: 'C:\\a\\b:stream', expectedCode: 'COLON_IN_PATH' },
    ];

    expect(errorVectors.length).toBeGreaterThanOrEqual(25);

    for (const { input, expectedCode, messageSubstring } of errorVectors) {
      let thrown: unknown = null;
      try {
        ContainerBackend.translateHostPath(input, 'win32');
      } catch (err) {
        thrown = err;
      }

      expect(thrown).toBeInstanceOf(ContainerPathError);
      const cpe = thrown as ContainerPathError;
      expect(cpe.code).toBe(expectedCode);
      if (messageSubstring) {
        expect(cpe.message).toContain(messageSubstring);
      }
    }
  });

  // =========================================================================
  // A3: Non-win32 platforms (linux, darwin, freebsd)
  // =========================================================================
  it('A3: Non-win32 platforms preserve byte-identical paths or fail closed', () => {
    const nonWinPlatforms: NodeJS.Platform[] = ['linux', 'darwin', 'freebsd'];

    const byteIdenticalCases = [
      '/home/user/project',
      '/tmp/shadow',
      '/',
      '/tmp/with space',
      '/tmp/unicode-é',
      '/tmp/trailing/',
      '/tmp/a/../b',
      '/tmp/back\\slash', // Invariant I2: backslash preserved
    ];

    for (const plat of nonWinPlatforms) {
      // 1. Byte-identical cases
      for (const p of byteIdenticalCases) {
        const out = ContainerBackend.translateHostPath(p, plat);
        expect(out).toBe(p);
      }

      // 2. Colon in POSIX path fails
      expect(() => ContainerBackend.translateHostPath('/tmp/a:b', plat)).toThrowError(
        expect.objectContaining({ code: 'COLON_IN_PATH' })
      );

      // 3. Relative or Windows-style paths fail NOT_ABSOLUTE
      expect(() => ContainerBackend.translateHostPath('rel/path', plat)).toThrowError(
        expect.objectContaining({ code: 'NOT_ABSOLUTE' })
      );
      expect(() => ContainerBackend.translateHostPath('./x', plat)).toThrowError(
        expect.objectContaining({ code: 'NOT_ABSOLUTE' })
      );
      expect(() => ContainerBackend.translateHostPath('C:\\Users\\x', plat)).toThrowError(
        expect.objectContaining({ code: 'NOT_ABSOLUTE' })
      );

      // 4. Empty fails EMPTY
      expect(() => ContainerBackend.translateHostPath('', plat)).toThrowError(
        expect.objectContaining({ code: 'EMPTY' })
      );

      // 5. Control chars fail ILLEGAL_CHARS
      expect(() => ContainerBackend.translateHostPath('/tmp/a\0b', plat)).toThrowError(
        expect.objectContaining({ code: 'ILLEGAL_CHARS' })
      );
      expect(() => ContainerBackend.translateHostPath('/tmp/a\nb', plat)).toThrowError(
        expect.objectContaining({ code: 'ILLEGAL_CHARS' })
      );
    }
  });

  // =========================================================================
  // A4: Property tests with deterministic PRNG (500 cases each)
  // =========================================================================
  it('A4: Property-based fuzzing with deterministic PRNG', () => {
    // Simple Mulberry32 deterministic PRNG
    let seed = 0x1337cafe;
    function prng(): number {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    }

    const driveLetters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const validCharPool = 'abcdefghijklmnopqrstuvwxyz0123456789 _-.JoséПроект';

    // (i) 500 valid win32 paths produce format /^[A-Za-z]:\// with no backslash
    for (let i = 0; i < 500; i++) {
      const drive = driveLetters[Math.floor(prng() * driveLetters.length)];
      const numSegments = 1 + Math.floor(prng() * 12);
      const segs: string[] = [];
      for (let s = 0; s < numSegments; s++) {
        const len = 1 + Math.floor(prng() * 10);
        let seg = '';
        for (let c = 0; c < len; c++) {
          seg += validCharPool[Math.floor(prng() * validCharPool.length)];
        }
        segs.push(seg);
      }
      const rawPath = `${drive}:\\${segs.join('\\')}`;
      const out = ContainerBackend.translateHostPath(rawPath, 'win32');

      // Rule (i): Matches /^[A-Za-z]:\//
      expect(/^[A-Za-z]:\//.test(out)).toBe(true);
      // Rule (i): No backslash
      expect(out.includes('\\')).toBe(false);
      // Rule (i): Never starts with /<letter>/
      expect(/^\/[A-Za-z]\//.test(out)).toBe(false);

      // Rule (ii): Idempotence translate(translate(x)) === translate(x)
      const out2 = ContainerBackend.translateHostPath(out, 'win32');
      expect(out2).toBe(out);

      // Rule (iii): Round-trip: replacing / with \ equals path.win32.normalize(input) without trailing slash
      const backslashed = out.replace(/\//g, '\\');
      let expectedNorm = path.win32.normalize(rawPath);
      while (expectedNorm.length > 3 && expectedNorm.endsWith('\\')) {
        expectedNorm = expectedNorm.slice(0, -1);
      }
      expect(backslashed).toBe(expectedNorm);

      // Rule (iv): Drive letter and case are preserved
      expect(out[0]).toBe(drive);
    }

    // (v) 500 valid POSIX paths without ':' or control chars: output === input
    for (let i = 0; i < 500; i++) {
      const numSegments = 1 + Math.floor(prng() * 8);
      const segs: string[] = [];
      for (let s = 0; s < numSegments; s++) {
        const len = 1 + Math.floor(prng() * 8);
        let seg = '';
        for (let c = 0; c < len; c++) {
          seg += validCharPool[Math.floor(prng() * validCharPool.length)];
        }
        segs.push(seg);
      }
      const posixPath = `/${segs.join('/')}`;
      const out = ContainerBackend.translateHostPath(posixPath, 'linux');
      expect(out).toBe(posixPath);
    }
  });

  // =========================================================================
  // A5: Differential red proof against baseline function
  // =========================================================================
  it('A5: Differential red proof proves baseline defect vs remediated implementation', () => {
    const driveInputs = [
      'C:\\Users\\dev\\project',
      'c:\\Users\\dev',
      'd:\\data\\app',
      'D:/data/app',
      'C:\\Program Files\\Project',
      'C:\\a\\b\\',
    ];

    for (const input of driveInputs) {
      const baselineResult = baselineTranslateHostPath(input);
      const newResult = ContainerBackend.translateHostPath(input, 'win32');

      // The baseline was defective: produced legacy /c/... or /d/...
      expect(baselineResult).toMatch(/^\/[a-z]\//);
      // The new function preserves drive and colon: C:/...
      expect(newResult).toMatch(/^[a-zA-Z]:\//);
      expect(newResult.startsWith('/c/')).toBe(false);
      expect(newResult.startsWith('/d/')).toBe(false);
    }

    // Defect 2 in baseline: backslashes were corrupted on non-win32 paths
    const posixWithBackslash = '/tmp/back\\slash';
    const baselinePosix = baselineTranslateHostPath(posixWithBackslash);
    const newPosix = ContainerBackend.translateHostPath(posixWithBackslash, 'linux');

    // Baseline corrupts \ into /
    expect(baselinePosix).toBe('/tmp/back/slash');
    // New function preserves \ byte-identically
    expect(newPosix).toBe('/tmp/back\\slash');
  });

  // =========================================================================
  // A6: Single-argument backward compatibility
  // =========================================================================
  it('A6: Single argument call defaults to process.platform semantics', () => {
    const testCases =
      process.platform === 'win32'
        ? ['C:\\Users\\dev\\project', 'd:\\data\\app', 'C:\\Program Files\\app']
        : ['/home/user/project', '/tmp/shadow', '/var/log/audit.log'];

    for (const p of testCases) {
      const defaultCall = ContainerBackend.translateHostPath(p);
      const explicitCall = ContainerBackend.translateHostPath(p, process.platform);
      expect(defaultCall).toBe(explicitCall);
    }
  });

  // =========================================================================
  // A7: ContainerPathError specifications & type-level exhaustiveness
  // =========================================================================
  it('A7: ContainerPathError is instance of Error, secret-free, and type-exhaustive', () => {
    const err = new ContainerPathError('EMPTY', 'Host path cannot be empty.');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ContainerPathError);
    expect(err.name).toBe('ContainerPathError');
    expect(err.code).toBe('EMPTY');
    expect(err.message).toBe('Host path cannot be empty.');

    // UNC error message must contain actionable guidance mentioning TEMP/TMP/TMPDIR
    let uncErr: ContainerPathError | null = null;
    try {
      ContainerBackend.translateHostPath('\\\\server\\share\\shadow', 'win32');
    } catch (e) {
      uncErr = e as ContainerPathError;
    }
    expect(uncErr).not.toBeNull();
    expect(uncErr?.code).toBe('UNC_UNSUPPORTED');
    expect(uncErr?.message).toContain('\\\\server\\share\\shadow');
    expect(uncErr?.message).toContain('TEMP/TMP (Windows) or TMPDIR (POSIX)');
    expect(uncErr?.message).not.toContain('at ContainerBackend'); // No stack trace in message!

    // Type-level exhaustiveness test:
    // Ensures all 10 error codes exist in ContainerPathErrorCode union
    const allCodes: Record<ContainerPathErrorCode, true> = {
      EMPTY: true,
      ILLEGAL_CHARS: true,
      UNC_UNSUPPORTED: true,
      DEVICE_PATH_UNSUPPORTED: true,
      DRIVE_RELATIVE: true,
      POSIX_STYLE_ON_WINDOWS: true,
      NOT_ABSOLUTE: true,
      COLON_IN_PATH: true,
      ROOT_MOUNT_REFUSED: true,
      HOME_MOUNT_REFUSED: true,
    };
    expect(Object.keys(allCodes)).toHaveLength(10);
  });
});
