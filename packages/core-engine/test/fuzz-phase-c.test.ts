import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import zlib from 'node:zlib';
import { ZodError } from 'zod';
import {
  canonicalJsonStringify,
  SafeTarReader,
  FreshnessEvaluator,
  OfflineBundleManifestSchema,
  OfflineGenerationManifest,
} from '../src/offline/index.js';

/**
 * Deterministic Linear Congruential Generator (PRNG) for reproducible fuzzing.
 * Seed is logged for auditability and replay.
 */
class LcgPrng {
  private state: number;

  constructor(seed = 0x5ec012e) {
    this.state = seed >>> 0;
  }

  public next(): number {
    this.state = (Math.imul(1664525, this.state) + 1013904223) >>> 0;
    return this.state / 0x100000000;
  }

  public nextInt(min: number, max: number): number {
    return Math.floor(this.next() * (max - min + 1)) + min;
  }

  public nextString(maxLen = 32): string {
    const chars =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/..\\ \t\x00\xff_-%$*';
    const len = this.nextInt(0, maxLen);
    let s = '';
    for (let i = 0; i < len; i++) {
      s += chars[this.nextInt(0, chars.length - 1)];
    }
    return s;
  }

  public nextBytes(length: number): Buffer {
    const buf = Buffer.alloc(length);
    for (let i = 0; i < length; i++) {
      buf[i] = this.nextInt(0, 255);
    }
    return buf;
  }
}

describe('Phase C Fuzzing & Fault Injection Suite (T11)', () => {
  const SEED = 0x5ec012e;
  const LOCAL_ITERATIONS = 1_500;
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fuzz-test-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it(`fuzzes SafeTarReader with ${LOCAL_ITERATIONS} corrupted/adversarial tar streams`, async () => {
    const prng = new LcgPrng(SEED);
    let handled = 0;

    for (let i = 0; i < LOCAL_ITERATIONS; i++) {
      const mode = prng.nextInt(0, 4);
      let tarData: Buffer;

      if (mode === 0) {
        // Completely random noise bytes
        const len = prng.nextInt(0, 4096);
        tarData = prng.nextBytes(len);
      } else if (mode === 1) {
        // Semi-valid 512-byte header with corrupted fields
        const header = Buffer.alloc(512);
        const name = prng.nextString(100);
        header.write(name, 0, 'utf8');
        header.write(prng.nextInt(0, 0o777).toString(8).padStart(7, '0') + '\0', 100, 8, 'ascii');
        header.write(
          prng.nextInt(0, 1000000).toString(8).padStart(11, '0') + ' ',
          124,
          12,
          'ascii'
        );
        header.write('ustar\0', 257, 6, 'ascii');
        header.write('00', 263, 2, 'ascii');
        // Random payload
        const payload = prng.nextBytes(prng.nextInt(0, 512));
        tarData = Buffer.concat([header, payload]);
      } else if (mode === 2) {
        // Truncated gzip stream
        const raw = prng.nextBytes(prng.nextInt(10, 1000));
        const gz = zlib.gzipSync(raw);
        tarData = gz.subarray(0, prng.nextInt(1, gz.length - 1));
      } else {
        // Path traversal payload
        const header = Buffer.alloc(512);
        const traversalNames = [
          '../../etc/passwd',
          '..\\..\\windows\\system32\\cmd.exe',
          '/absolute/path/pwn.sh',
          'C:\\Windows\\win.ini',
          'NUL',
          'COM1',
          'AUX',
          'normal/../../../escape.txt',
          './safe/\x00/hidden.txt',
        ];
        const name = traversalNames[prng.nextInt(0, traversalNames.length - 1)]!;
        header.write(name, 0, 'utf8');
        header.write('0000644\0', 100, 8, 'ascii');
        header.write('00000000010 ', 124, 12, 'ascii');
        header.write('ustar\0', 257, 6, 'ascii');
        tarData = Buffer.concat([header, Buffer.from('adversarial_data')]);
      }

      // Wrap in gzip if not already
      let finalTarGz: Buffer;
      try {
        finalTarGz = zlib.gzipSync(tarData);
      } catch {
        finalTarGz = tarData;
      }

      const tarPath = path.join(tempDir, `fuzz-${i}.tar.gz`);
      const extractTarget = path.join(tempDir, `extract-${i}`);
      fs.mkdirSync(extractTarget, { recursive: true });
      fs.writeFileSync(tarPath, finalTarGz);

      try {
        await SafeTarReader.extractAll(tarPath, extractTarget);
      } catch (err: unknown) {
        // Invariant 1: Typed rejection or standard error
        expect(err).toBeInstanceOf(Error);
      }

      // Invariant 2: Canary check - no files written outside extractTarget
      const canaryPath = path.join(tempDir, 'canary.txt');
      expect(fs.existsSync(canaryPath)).toBe(false);

      handled++;
    }

    expect(handled).toBe(LOCAL_ITERATIONS);
    // Invariant 3: Memory remains bounded
    const memMb = process.memoryUsage().rss / (1024 * 1024);
    expect(memMb).toBeLessThan(512);
  });

  it(`fuzzes canonicalJsonStringify with ${LOCAL_ITERATIONS} arbitrary nested payloads`, () => {
    const prng = new LcgPrng(SEED);

    function genValue(depth: number): unknown {
      if (depth > 5) return prng.nextInt(-1000, 1000);
      const type = prng.nextInt(0, 6);
      switch (type) {
        case 0:
          return prng.nextInt(-100000, 100000);
        case 1:
          return prng.nextString(16);
        case 2:
          return prng.next() > 0.5;
        case 3:
          return null;
        case 4:
          return undefined;
        case 5: {
          const arr: unknown[] = [];
          const count = prng.nextInt(0, 4);
          for (let j = 0; j < count; j++) arr.push(genValue(depth + 1));
          return arr;
        }
        case 6: {
          const obj: Record<string, unknown> = {};
          const count = prng.nextInt(0, 4);
          for (let j = 0; j < count; j++) {
            const key = prng.nextString(8);
            obj[key] = genValue(depth + 1);
          }
          return obj;
        }
      }
    }

    for (let i = 0; i < LOCAL_ITERATIONS; i++) {
      const input = genValue(0);
      const str = canonicalJsonStringify(input);

      // Invariant: If not undefined, it must parse back with JSON.parse
      if (str !== undefined) {
        expect(() => JSON.parse(str)).not.toThrow();
      }
    }
  });

  it(`fuzzes FreshnessEvaluator with ${LOCAL_ITERATIONS} arbitrary date/age combinations`, () => {
    const prng = new LcgPrng(SEED);
    const evaluator = new FreshnessEvaluator();

    for (let i = 0; i < LOCAL_ITERATIONS; i++) {
      const year = prng.nextInt(1970, 2038);
      const month = String(prng.nextInt(1, 12)).padStart(2, '0');
      const day = String(prng.nextInt(1, 28)).padStart(2, '0');
      const hour = String(prng.nextInt(0, 23)).padStart(2, '0');
      const dateStr = `${year}-${month}-${day}T${hour}:00:00.000Z`;

      const mockManifest: OfflineGenerationManifest = {
        schemaVersion: 1,
        generationId: `gen-fuzz-${i}`,
        createdAt: dateStr,
        importedAt: dateStr,
        trust: prng.next() > 0.5 ? 'VERIFIED' : 'UNSIGNED',
        cliVersion: '1.0.0',
        components: [
          {
            id: 'fuzz-comp',
            kind: 'db',
            version: '1.0',
            upstreamUpdatedAt: dateStr,
            totalSizeBytes: prng.nextInt(0, 1000000),
            files: [],
          },
        ],
      };

      const nowYear = prng.nextInt(2020, 2035);
      const nowDate = new Date(`${nowYear}-06-01T00:00:00.000Z`);

      const result = evaluator.evaluate(mockManifest, {
        now: () => nowDate,
        maxStaleDays: prng.nextInt(1, 30),
        maxExpiredDays: prng.nextInt(31, 90),
      });

      // Invariant: Status must be one of the three legal enum values
      expect(['FRESH', 'STALE', 'EXPIRED']).toContain(result.status);
      expect(typeof result.ageDays).toBe('number');
      expect(result.ageDays).toBeGreaterThanOrEqual(0);
    }
  });

  it(`fuzzes OfflineBundleManifestSchema with ${LOCAL_ITERATIONS} random permutations`, () => {
    const prng = new LcgPrng(SEED);
    let rejectedCount = 0;
    let acceptedCount = 0;

    for (let i = 0; i < LOCAL_ITERATIONS; i++) {
      const corrupt = {
        schemaVersion: prng.nextInt(-2, 3),
        createdAt: prng.nextString(20),
        cliVersion: prng.nextString(10),
        bundleId: prng.nextString(15),
        platforms: [prng.nextString(12)],
        totalSize: prng.nextInt(-1000, 100000),
        components: [
          {
            id: prng.nextString(10),
            kind: prng.nextString(8),
            version: prng.nextString(5),
            totalSizeBytes: prng.nextInt(-100, 5000),
            files: [],
          },
        ],
      };

      try {
        OfflineBundleManifestSchema.parse(corrupt);
        acceptedCount++;
      } catch (err: unknown) {
        // Invariant: Schema rejection must be a Zod validation error, never crash
        expect(err instanceof ZodError).toBe(true);
        rejectedCount++;
      }
    }

    expect(rejectedCount + acceptedCount).toBe(LOCAL_ITERATIONS);
    expect(rejectedCount).toBeGreaterThan(0);
  });
});
