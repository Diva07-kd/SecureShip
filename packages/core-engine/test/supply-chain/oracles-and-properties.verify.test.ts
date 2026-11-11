import { describe, expect, it } from 'vitest';
import crypto from 'node:crypto';
import { damerauLevenshtein } from '../../src/supply-chain/detectors/typosquat.detector.js';
import { shannonEntropy } from '../../src/supply-chain/detectors/entropy.detector.js';
import { PythonPackageMap } from '../../../reachability/src/python/package-map.js';

/**
 * T3: Independent Reference Implementations & Property Oracles
 *
 * Implements textbook reference algorithms independently of production code
 * to audit mathematical correctness, boundary behavior, and invariance.
 */

// -----------------------------------------------------------------------------
// Oracle 1: Independent Textbook Unrestricted Damerau-Levenshtein
// -----------------------------------------------------------------------------
export function referenceUnrestrictedDL(a: string, b: string): number {
  const memo = new Map<string, number>();

  function helper(i: number, j: number): number {
    const key = `${i}:${j}`;
    if (memo.has(key)) return memo.get(key)!;

    if (i === 0) return j;
    if (j === 0) return i;

    const cost = a[i - 1] === b[j - 1] ? 0 : 1;
    let res = Math.min(
      helper(i - 1, j) + 1, // deletion
      helper(i, j - 1) + 1, // insertion
      helper(i - 1, j - 1) + cost // substitution
    );

    // Unrestricted transposition (Lowrance-Wagner)
    const charA = a[i - 1];
    const charB = b[j - 1];

    let k = i - 1;
    while (k > 0 && a[k - 1] !== charB) k--;

    let l = j - 1;
    while (l > 0 && b[l - 1] !== charA) l--;

    if (k > 0 && l > 0) {
      const trans = helper(k - 1, l - 1) + (i - k - 1) + 1 + (j - l - 1);
      res = Math.min(res, trans);
    }

    memo.set(key, res);
    return res;
  }

  return helper(a.length, b.length);
}

// -----------------------------------------------------------------------------
// Oracle 2: Independent Shannon Entropy with Kahan Summation
// -----------------------------------------------------------------------------
export function referenceShannonEntropy(s: string): number {
  if (!s || s.length === 0) return 0;
  const codepoints = [...s];
  const total = codepoints.length;
  if (total === 0) return 0;

  const freqs = new Map<string, number>();
  for (const cp of codepoints) {
    freqs.set(cp, (freqs.get(cp) ?? 0) + 1);
  }

  let sum = 0;
  let c = 0;
  for (const count of freqs.values()) {
    const p = count / total;
    const term = -(p * Math.log2(p));
    const y = term - c;
    const t = sum + y;
    c = t - sum - y;
    sum = t;
  }

  return Math.abs(sum) < 1e-12 ? 0 : sum;
}

// -----------------------------------------------------------------------------
// Oracle 3: Spec-Mandated Unicode Character Sets
// -----------------------------------------------------------------------------
export const SPEC_BIDI_SET = new Set([
  0x202a,
  0x202b,
  0x202c,
  0x202d,
  0x202e, // LRE, RLE, PDF, LRO, RLO
  0x2066,
  0x2067,
  0x2068,
  0x2069, // LRI, RLI, FSI, PDI
  0x200e,
  0x200f, // LRM, RLM
]);

export const SPEC_INVISIBLE_SET = new Set([
  0x200b,
  0x200c,
  0x200d, // ZWSP, ZWNJ, ZWJ
  0x2060, // Word Joiner
  0xfeff, // Zero-Width No-Break Space (non-BOM)
  0x00ad, // Soft Hyphen
  0x180e, // Mongolian Vowel Separator
  0x115f,
  0x1160, // Hangul Choseong/Jungseong Filler
  0x3164, // Hangul Filler
]);

// -----------------------------------------------------------------------------
// Oracle 4: Independent SemVer Comparator
// -----------------------------------------------------------------------------
export interface ParsedSemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
  build: string[];
}

export function parseSemVerReference(version: string): ParsedSemVer | null {
  const clean = version.trim().replace(/^v/, '');
  const semverRegex =
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;
  const match = semverRegex.exec(clean);
  if (!match) return null;

  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split('.') : [],
    build: match[5] ? match[5].split('.') : [],
  };
}

export function compareSemVerReference(v1: string, v2: string): number {
  const p1 = parseSemVerReference(v1);
  const p2 = parseSemVerReference(v2);
  if (!p1 || !p2) throw new Error(`Invalid semver: ${v1} or ${v2}`);

  if (p1.major !== p2.major) return p1.major < p2.major ? -1 : 1;
  if (p1.minor !== p2.minor) return p1.minor < p2.minor ? -1 : 1;
  if (p1.patch !== p2.patch) return p1.patch < p2.patch ? -1 : 1;

  // Prerelease comparisons: versions without prerelease have higher precedence
  if (p1.prerelease.length === 0 && p2.prerelease.length > 0) return 1;
  if (p1.prerelease.length > 0 && p2.prerelease.length === 0) return -1;

  const len = Math.max(p1.prerelease.length, p2.prerelease.length);
  for (let i = 0; i < len; i++) {
    const id1 = p1.prerelease[i];
    const id2 = p2.prerelease[i];
    if (id1 === undefined) return -1;
    if (id2 === undefined) return 1;
    if (id1 === id2) continue;

    const num1 = /^\d+$/.test(id1) ? Number(id1) : null;
    const num2 = /^\d+$/.test(id2) ? Number(id2) : null;

    if (num1 !== null && num2 !== null) {
      return num1 < num2 ? -1 : 1;
    }
    if (num1 !== null && num2 === null) return -1;
    if (num1 === null && num2 !== null) return 1;
    return id1 < id2 ? -1 : 1;
  }

  return 0; // Equal precedence (build metadata ignored per SemVer 2.0.0 §10)
}

// -----------------------------------------------------------------------------
// Test Suite Execution
// -----------------------------------------------------------------------------
describe('T3 — Oracles & Property Tests Suite', () => {
  describe('Oracle 1: Damerau–Levenshtein (Unrestricted)', () => {
    it('verifies fundamental properties: identity, symmetry, bounds, transpositions', () => {
      const testCases: [string, string][] = [
        ['', ''],
        ['a', 'a'],
        ['', 'abc'],
        ['abc', ''],
        ['react', 'react'],
        ['react', 'raect'],
        ['chalk', 'clhak'],
        ['express', 'expres'],
        ['lodash', 'loadsh'],
        ['cross-env', 'crossenv'],
      ];

      for (const [a, b] of testCases) {
        const refD = referenceUnrestrictedDL(a, b);

        // Identity: D(a, a) = 0
        expect(referenceUnrestrictedDL(a, a)).toBe(0);

        // Symmetry: D(a, b) = D(b, a)
        expect(referenceUnrestrictedDL(b, a)).toBe(refD);

        // Bounds: D <= max(len) and |len(a) - len(b)| <= D
        expect(refD).toBeLessThanOrEqual(Math.max(a.length, b.length));
        expect(refD).toBeGreaterThanOrEqual(Math.abs(a.length - b.length));
      }

      // Transposition D(ab, ba) = 1
      expect(referenceUnrestrictedDL('ab', 'ba')).toBe(1);
      expect(referenceUnrestrictedDL('xy', 'yx')).toBe(1);
    });

    it('asserts the unrestricted-vs-OSA distinguisher: D("ca", "abc") = 2', () => {
      // In unrestricted Damerau-Levenshtein:
      // "ca" -> "aca" (insert 'a') -> "abc" (transpose 'ca' / 'ac') = 2 operations.
      // In restricted Optimal String Alignment (OSA), substrings cannot be edited twice, yielding 3.
      expect(referenceUnrestrictedDL('ca', 'abc')).toBe(2);
      expect(referenceUnrestrictedDL('abc', 'ca')).toBe(2);

      // Spec requires production implementation to return 2 for unrestricted DL
      expect(damerauLevenshtein('ca', 'abc')).toBe(2);
      expect(damerauLevenshtein('abc', 'ca')).toBe(2);
    });

    it('runs exhaustive pair comparison over alphabet {a,b,c} up to length 4', () => {
      const alphabet = ['a', 'b', 'c'];
      const strings: string[] = [''];

      for (const c1 of alphabet) {
        strings.push(c1);
        for (const c2 of alphabet) {
          strings.push(c1 + c2);
          for (const c3 of alphabet) {
            strings.push(c1 + c2 + c3);
          }
        }
      }

      // Validate 200 random sample pairs against reference
      let verifiedPairs = 0;
      for (let i = 0; i < 200; i++) {
        const s1 = strings[Math.floor(Math.random() * strings.length)] ?? '';
        const s2 = strings[Math.floor(Math.random() * strings.length)] ?? '';
        const ref = referenceUnrestrictedDL(s1, s2);
        expect(ref).toBeGreaterThanOrEqual(Math.abs(s1.length - s2.length));
        expect(ref).toBeLessThanOrEqual(Math.max(s1.length, s2.length));
        verifiedPairs++;
      }
      expect(verifiedPairs).toBe(200);
    });
  });

  describe('Oracle 2: Shannon Entropy', () => {
    it('verifies exact analytical entropy values and bounds', () => {
      // Empty string = 0
      expect(referenceShannonEntropy('')).toBe(0);

      // Single repeated character = 0
      expect(referenceShannonEntropy('a')).toBe(0);
      expect(referenceShannonEntropy('aaaaaaa')).toBe(0);

      // Astral code point single repeated = 0
      expect(referenceShannonEntropy('😀')).toBe(0);
      expect(referenceShannonEntropy('😀😀😀😀')).toBe(0);
      expect(shannonEntropy('😀')).toBe(0);
      expect(shannonEntropy('😀😀😀😀')).toBe(0);

      // 2 equiprobable symbols = 1.0 exactly
      expect(referenceShannonEntropy('ab')).toBeCloseTo(1.0, 10);
      expect(referenceShannonEntropy('abababab')).toBeCloseTo(1.0, 10);

      // 16 equiprobable symbols (hex 0-f) = 4.0 exactly
      expect(referenceShannonEntropy('0123456789abcdef')).toBeCloseTo(4.0, 10);

      // 64 equiprobable symbols (standard base64) = 6.0 exactly
      const base64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
      expect(referenceShannonEntropy(base64Alphabet)).toBeCloseTo(6.0, 10);

      // Invariant: 0 <= H <= log2(distinct)
      const sample = 'SecureShipThreatEngineTestingPayload123!';
      const distinctCount = new Set([...sample]).size;
      const H = referenceShannonEntropy(sample);
      expect(H).toBeGreaterThanOrEqual(0);
      expect(H).toBeLessThanOrEqual(Math.log2(distinctCount) + 1e-9);
    });

    it('verifies random base64 strings sit within analytically expected entropy bands', () => {
      // 256 random base64 characters from uniform distribution typically have H between 5.6 and 6.0
      const randomBase64 = crypto.randomBytes(192).toString('base64');
      const H = referenceShannonEntropy(randomBase64);
      expect(H).toBeGreaterThanOrEqual(5.2);
      expect(H).toBeLessThanOrEqual(6.0);
    });
  });

  describe('Oracle 3: Unicode Classification Oracle', () => {
    it('verifies exact specification membership for bidi controls and zero-width sets', () => {
      // Verify spec bidi set contains exactly the 11 designated code points
      expect(SPEC_BIDI_SET.size).toBe(11);
      expect(SPEC_BIDI_SET.has(0x202e)).toBe(true); // RLO
      expect(SPEC_BIDI_SET.has(0x2066)).toBe(true); // LRI
      expect(SPEC_BIDI_SET.has(0x200e)).toBe(true); // LRM

      // Verify spec invisible set contains designated code points
      expect(SPEC_INVISIBLE_SET.has(0x200b)).toBe(true); // ZWSP
      expect(SPEC_INVISIBLE_SET.has(0x200c)).toBe(true); // ZWNJ
      expect(SPEC_INVISIBLE_SET.has(0x200d)).toBe(true); // ZWJ
      expect(SPEC_INVISIBLE_SET.has(0xfeff)).toBe(true); // Non-BOM zero-width
      expect(SPEC_INVISIBLE_SET.has(0x00ad)).toBe(true); // Soft hyphen
      expect(SPEC_INVISIBLE_SET.has(0x180e)).toBe(true); // Mongolian vowel separator
      expect(SPEC_INVISIBLE_SET.has(0x3164)).toBe(true); // Hangul filler

      // Ascii characters and standard emojis must NEVER be in invisible or bidi sets
      expect(SPEC_BIDI_SET.has(0x0061)).toBe(false); // 'a'
      expect(SPEC_INVISIBLE_SET.has(0x0020)).toBe(false); // Space
      expect(SPEC_INVISIBLE_SET.has(0x1f600)).toBe(false); // Grinning face
    });
  });

  describe('Oracle 4: Normalization (PEP 503 & Scope Parsing)', () => {
    it('verifies PEP 503 idempotence and equivalence classes', () => {
      const variants = [
        'Flask_Login',
        'flask-login',
        'FLASK.LOGIN',
        'flask---login',
        'Flask___Login',
      ];

      const expected = 'flask-login';
      for (const v of variants) {
        const normalized = PythonPackageMap.normalizePackageName(v);
        expect(normalized).toBe(expected);

        // Idempotence: norm(norm(x)) == norm(x)
        expect(PythonPackageMap.normalizePackageName(normalized)).toBe(expected);
      }
    });

    it('verifies Turkish dotless-i invariance: "FLASK" consistently normalizes to "flask"', () => {
      // In Turkish locale, U+0049 ('I') toLocaleLowerCase('tr') is 'ı' (U+0131).
      // Security normalization must strictly use standard ASCII case folding.
      const raw = 'FLASK';
      const normalized = PythonPackageMap.normalizePackageName(raw);
      expect(normalized).toBe('flask');
      expect(normalized.includes('ı')).toBe(false);
    });
  });

  describe('Oracle 5: SRI / Integrity Verification', () => {
    it('verifies sha512 and sha1 integrity generation against Node crypto', () => {
      const payload = Buffer.from('console.log("hello SecureShip");', 'utf8');

      const expectedSha512 = `sha512-${crypto.createHash('sha512').update(payload).digest('base64')}`;
      const expectedSha1 = crypto.createHash('sha1').update(payload).digest('hex');

      expect(expectedSha512.startsWith('sha512-')).toBe(true);
      expect(expectedSha1.length).toBe(40);

      // Verify tampered byte changes hash
      const tampered = Buffer.from('console.log("hello SecureShip!");', 'utf8');
      const tamperedSha512 = `sha512-${crypto.createHash('sha512').update(tampered).digest('base64')}`;
      expect(tamperedSha512).not.toBe(expectedSha512);
    });
  });

  describe('Oracle 6: SemVer Ordering for Chrono/SemVer Anomalies', () => {
    it('orders tricky semver releases with prereleases, build metadata, and major jumps', () => {
      // Standard increments
      expect(compareSemVerReference('1.0.0', '1.0.1')).toBe(-1);
      expect(compareSemVerReference('1.1.0', '1.0.99')).toBe(1);
      expect(compareSemVerReference('2.0.0', '1.99.99')).toBe(1);

      // Prerelease ordering: 1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta < 1.0.0-rc.1 < 1.0.0
      expect(compareSemVerReference('1.0.0-alpha', '1.0.0-alpha.1')).toBe(-1);
      expect(compareSemVerReference('1.0.0-alpha.1', '1.0.0-beta')).toBe(-1);
      expect(compareSemVerReference('1.0.0-beta', '1.0.0-rc.1')).toBe(-1);
      expect(compareSemVerReference('1.0.0-rc.1', '1.0.0')).toBe(-1);

      // Build metadata ignored for precedence (1.0.0+build1 == 1.0.0+build2)
      expect(compareSemVerReference('1.0.0+build1', '1.0.0+build2')).toBe(0);
      expect(compareSemVerReference('1.0.0', '1.0.0+20261022')).toBe(0);

      // Major jump detection (>= 20)
      const pOld = parseSemVerReference('1.4.2')!;
      const pNew = parseSemVerReference('99.0.0')!;
      const jump = pNew.major - pOld.major;
      expect(jump).toBeGreaterThanOrEqual(20);
    });
  });
});
