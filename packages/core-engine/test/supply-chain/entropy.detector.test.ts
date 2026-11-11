import { describe, expect, it } from 'vitest';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import {
  detectHighEntropy,
  shannonEntropy,
} from '../../src/supply-chain/detectors/entropy.detector.js';

describe('EntropyDetector (SC-OBF-*)', () => {
  const policy = SupplyChainPolicySchema.parse({});

  describe('shannonEntropy formula', () => {
    it('returns 0 for empty string or homogeneous characters', () => {
      expect(shannonEntropy('')).toBe(0);
      expect(shannonEntropy('AAAAAAAAAA')).toBe(0);
    });

    it('calculates expected entropy for varied characters', () => {
      // 4 equally probable characters -> log2(4) = 2.0
      expect(shannonEntropy('ABCD')).toBeCloseTo(2.0, 2);
    });

    it('yields high entropy for random base64 strings', () => {
      const highEntropySample = '7b9fG81kLmZqP3rXwY0vNtCsEhJ2aD4uIo6eQ8yU';
      expect(shannonEntropy(highEntropySample)).toBeGreaterThan(4.5);
    });
  });

  describe('detectHighEntropy rules', () => {
    it('reports zero hits for clean source code', () => {
      const code = `
        const message = "Hello, world!";
        const url = "https://example.com/api/v1/users";
        console.log(message, url);
      `;
      expect(detectHighEntropy(code, 'src/clean.js', policy)).toHaveLength(0);
    });

    it('flags high Shannon entropy string literal >= 64 characters (SC-OBF-001)', () => {
      // 64-char random Base64 payload
      const payload = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6a7b8c9d0e1f2';
      const code = `const shellcode = "${payload}";`;

      const hits = detectHighEntropy(code, 'src/loader.js', policy);
      expect(hits.some((h) => h.ruleId === 'SC-OBF-001')).toBe(true);
      const hit = hits.find((h) => h.ruleId === 'SC-OBF-001')!;
      expect(hit.severity).toBe('HIGH');
    });

    it('enforces length boundary: ignores high-entropy string of length 63', () => {
      // Exactly 63 chars
      const payload63 = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6a7b8c9d0e1f';
      expect(payload63.length).toBe(63);
      const code = `const token = "${payload63}";`;

      const hits = detectHighEntropy(code, 'src/short.js', policy);
      expect(hits.some((h) => h.ruleId === 'SC-OBF-001')).toBe(false);
    });

    it('excludes legitimate Subresource Integrity (SRI) hashes', () => {
      const sri = 'sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC';
      const code = `const hash = "${sri}";`;

      const hits = detectHighEntropy(code, 'src/sri.js', policy);
      expect(hits).toHaveLength(0);
    });

    it('excludes data URIs and source mapping URLs', () => {
      const dataUri =
        'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
      const sourceMap =
        '//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiIn0=';
      const code = `const img = "${dataUri}";\n${sourceMap}`;

      const hits = detectHighEntropy(code, 'src/data.js', policy);
      expect(hits).toHaveLength(0);
    });

    it('detects massive unbroken minified lines > 1000 characters (SC-OBF-002)', () => {
      const longPackedLine = 'a' + 'x=1;y=2;z=3;'.repeat(100);
      expect(longPackedLine.length).toBeGreaterThan(1000);

      const hits = detectHighEntropy(longPackedLine, 'src/packed.js', policy);
      expect(hits.some((h) => h.ruleId === 'SC-OBF-002')).toBe(true);
      const hit = hits.find((h) => h.ruleId === 'SC-OBF-002')!;
      expect(hit.severity).toBe('MEDIUM');
    });
  });
});
