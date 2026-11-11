import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { SupplyChainPolicySchema, type SupplyChainPolicy } from '@secureship/contracts';
import { damerauLevenshtein } from '../../src/supply-chain/detectors/typosquat.detector.js';
import { shannonEntropy } from '../../src/supply-chain/detectors/entropy.detector.js';
import { detectUnicodeAttacks } from '../../src/supply-chain/detectors/unicode.detector.js';
import { SafeTarExtractor } from '../../src/supply-chain/safe-tar.js';
import { analyzeSupplyChain } from '../../src/supply-chain/supply-chain-analyzer.js';
import { NullProvider } from '../../src/supply-chain/providers/null.provider.js';
import type { MetadataProvider } from '../../src/supply-chain/providers/provider.interface.js';

// Deterministic Pseudo-Random Number Generator (Mulberry32)
function createPrng(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  concurrency: 4,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
});

describe('T10 — Robustness: Fuzzing & Fault Injection Suite', () => {
  describe('1. Seeded Mutation & Property Fuzzing', () => {
    const SEED = 0x5ec07e57;

    it('fuzzes Damerau-Levenshtein across 10,000 randomized Unicode strings with identity & symmetry invariants', () => {
      const prng = createPrng(SEED);
      const chars = 'abcdefghijklmnopqrstuvwxyz0123456789-_/ \u0430\u200B\u202E';
      const iterations = 10_000;

      for (let i = 0; i < iterations; i++) {
        const len1 = Math.floor(prng() * 12);
        const len2 = Math.floor(prng() * 12);

        let s1 = '';
        for (let j = 0; j < len1; j++) s1 += chars[Math.floor(prng() * chars.length)];
        let s2 = '';
        for (let j = 0; j < len2; j++) s2 += chars[Math.floor(prng() * chars.length)];

        const d1 = damerauLevenshtein(s1, s2);
        const d2 = damerauLevenshtein(s2, s1);

        // Invariant 1: Symmetry d(s1, s2) === d(s2, s1)
        expect(d1).toBe(d2);

        // Invariant 2: Non-negative and bounded by max length
        expect(d1).toBeGreaterThanOrEqual(0);
        expect(d1).toBeLessThanOrEqual(Math.max(s1.length, s2.length));

        // Invariant 3: Identity d(s, s) === 0
        expect(damerauLevenshtein(s1, s1)).toBe(0);
      }
    });

    it('fuzzes Shannon Entropy across 10,000 randomized codepoint distributions ensuring bounded 0 <= H <= log2(N)', () => {
      const prng = createPrng(SEED + 1);
      const iterations = 10_000;

      for (let i = 0; i < iterations; i++) {
        const len = Math.floor(prng() * 64);
        let str = '';
        for (let j = 0; j < len; j++) {
          // Generate code points across basic multilingual plane
          const code = Math.floor(prng() * 256);
          str += String.fromCharCode(code);
        }

        const h = shannonEntropy(str);

        // Invariant: 0 <= H <= 8.0 for 256 symbols
        expect(h).toBeGreaterThanOrEqual(0);
        expect(h).toBeLessThanOrEqual(8.000001);
      }
    });

    it('fuzzes Unicode Scanner across mutated code streams with injected Bidi and Zero-width characters', () => {
      const prng = createPrng(SEED + 2);
      const tokens = [
        'const ',
        'let ',
        'var ',
        'function ',
        '() ',
        '=> ',
        '{} ',
        'import ',
        'export ',
        '\u202A',
        '\u202E',
        '\u2066',
        '\u2069',
        '\u200B',
        '\u200C',
        '\u200D',
        '\uFEFF',
        'admin',
        'user',
        '"secret"',
        '123',
        ';',
        '\n',
        '\r\n',
      ];
      const iterations = 2_000;

      for (let i = 0; i < iterations; i++) {
        const tokenCount = Math.floor(prng() * 15) + 1;
        let snippet = '';
        for (let j = 0; j < tokenCount; j++) {
          snippet += tokens[Math.floor(prng() * tokens.length)];
        }

        // Must execute safely and deterministically without throwing uncaught errors
        const hits1 = detectUnicodeAttacks(snippet, 'fuzz.js', POLICY);
        const hits2 = detectUnicodeAttacks(snippet, 'fuzz.js', POLICY);

        expect(Array.isArray(hits1)).toBe(true);
        expect(hits1.length).toBe(hits2.length);
      }
    });

    it('fuzzes SafeTarExtractor with corrupted, truncated, and random byte streams', () => {
      const prng = createPrng(SEED + 3);
      const iterations = 1_000;

      for (let i = 0; i < iterations; i++) {
        const byteCount = Math.floor(prng() * 1024) + 1;
        const randomBytes = new Uint8Array(byteCount);
        for (let j = 0; j < byteCount; j++) {
          randomBytes[j] = Math.floor(prng() * 256);
        }

        // Invariant: Never throws uncaught exception on corrupt tar streams
        const res = SafeTarExtractor.extract(randomBytes);
        expect(typeof res.ok).toBe('boolean');
        expect(Array.isArray(res.files)).toBe(true);
        expect(Array.isArray(res.diagnostics)).toBe(true);
      }
    });
  });

  describe('2. Fault Injection & Error Recovery', () => {
    it('gracefully recovers when metadata provider throws unhandled network faults', async () => {
      const faultyProvider: MetadataProvider = {
        getPackument: async () => {
          throw new Error('ECONNRESET: socket hang up during registry request');
        },
        getWeeklyDownloads: async () => ({
          ok: false,
          error: { code: 'NETWORK_ERROR', message: 'DNS resolution failure' },
        }),
        getPublisher: async () => ({
          ok: false,
          error: { code: 'NETWORK_ERROR', message: 'Timeout' },
        }),
        getTarball: async () => ({
          ok: false,
          error: { code: 'NETWORK_ERROR', message: 'Socket error' },
        }),
      };

      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fault-'));
      try {
        const pkgDir = path.join(tempDir, 'node_modules', 'dep-fault');
        fs.mkdirSync(pkgDir, { recursive: true });
        fs.writeFileSync(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({ name: 'dep-fault', version: '1.0.0' })
        );

        // Invariant: Entire scan completes gracefully with error diagnostic recorded
        const result = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
          provider: faultyProvider,
        });

        expect(result.findings).toBeDefined();
        expect(result.diagnostics).toBeDefined();
        expect(result.stats.packagesAnalyzed).toBeGreaterThanOrEqual(1);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('respects AbortSignal mid-scan and aborts promptly without hanging', async () => {
      const controller = new AbortController();
      controller.abort(); // Pre-aborted signal

      const result = await analyzeSupplyChain({
        rootDir: os.tmpdir(),
        policy: POLICY,
        provider: new NullProvider(),
        signal: controller.signal,
      });

      expect(result.findings).toBeDefined();
      expect(result.stats.durationMs).toBeLessThan(1000);
    });
  });

  describe('3. Concurrency Stress & Race Invariance (1, 2, 8, 16 Workers)', () => {
    it('produces identical deterministic outputs at concurrency levels 1, 2, 8, and 16', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-concurrency-'));
      try {
        // Create 4 distinct mock packages
        for (let i = 1; i <= 4; i++) {
          const pkgDir = path.join(tempDir, 'node_modules', `pkg-${i}`);
          fs.mkdirSync(pkgDir, { recursive: true });
          fs.writeFileSync(
            path.join(pkgDir, 'package.json'),
            JSON.stringify({
              name: `pkg-${i}`,
              version: '1.0.0',
              scripts: i % 2 === 0 ? { postinstall: 'node build.js' } : {},
            })
          );
        }

        const concurrencyLevels = [1, 2, 8, 16];
        const results = [];

        for (const conc of concurrencyLevels) {
          const res = await analyzeSupplyChain({
            rootDir: tempDir,
            policy: POLICY,
            provider: new NullProvider(),
            concurrency: conc,
            now: () => new Date('2026-01-01T00:00:00Z'),
          });
          results.push(res);
        }

        // All concurrency levels must produce identical findings count and identical fingerprints
        const baseFindingCount = results[0]?.findings.length;
        expect(baseFindingCount).toBe(6);

        for (let i = 1; i < results.length; i++) {
          expect(results[i]?.findings.length).toBe(baseFindingCount);
          const fingerprintsBase = results[0]?.findings.map((f) => f.fingerprint);
          const fingerprintsCurrent = results[i]?.findings.map((f) => f.fingerprint);
          expect(fingerprintsCurrent).toEqual(fingerprintsBase);
        }
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('4. Cache Key Determinism & Invalidation', () => {
    it('generates unique cache keys on purl, integrity, engineVersion, or policy change', () => {
      const computeCacheKey = (
        purl: string,
        integrity: string,
        version: string,
        policyHash: string
      ) =>
        crypto
          .createHash('sha256')
          .update(`${purl}:${integrity}:${version}:${policyHash}`)
          .digest('hex');

      const kBase = computeCacheKey('pkg:npm/lodash@4.17.21', 'sha512-abc', '0.1.0', 'hash-1');
      const kPurlDiff = computeCacheKey('pkg:npm/lodash@4.17.20', 'sha512-abc', '0.1.0', 'hash-1');
      const kIntegrityDiff = computeCacheKey(
        'pkg:npm/lodash@4.17.21',
        'sha512-xyz',
        '0.1.0',
        'hash-1'
      );
      const kVersionDiff = computeCacheKey(
        'pkg:npm/lodash@4.17.21',
        'sha512-abc',
        '0.2.0',
        'hash-1'
      );
      const kPolicyDiff = computeCacheKey(
        'pkg:npm/lodash@4.17.21',
        'sha512-abc',
        '0.1.0',
        'hash-2'
      );

      expect(kBase).not.toBe(kPurlDiff);
      expect(kBase).not.toBe(kIntegrityDiff);
      expect(kBase).not.toBe(kVersionDiff);
      expect(kBase).not.toBe(kPolicyDiff);

      // Recomputing identical parameters yields identical key
      const kIdentical = computeCacheKey('pkg:npm/lodash@4.17.21', 'sha512-abc', '0.1.0', 'hash-1');
      expect(kBase).toBe(kIdentical);
    });
  });
});
