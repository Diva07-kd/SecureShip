import { describe, expect, it } from 'vitest';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import { detectUnicodeAttacks } from '../../src/supply-chain/detectors/unicode.detector.js';

describe('UnicodeDetector (SC-UNI-*)', () => {
  const policy = SupplyChainPolicySchema.parse({});

  it('reports zero hits for clean ASCII source code', () => {
    const code = `
      function authenticate(user, password) {
        if (!user || !password) return false;
        return true;
      }
    `;

    const hits = detectUnicodeAttacks(code, 'src/auth.js', policy);
    expect(hits).toHaveLength(0);
  });

  it('detects Bidirectional Trojan Source override characters (SC-UNI-001)', () => {
    // Trojan Source example: accessLevel check inverted with RLO
    const code = `
      const isAdmin = false;
      /* \u202E } \u2066 if (isAdmin) \u2069 \u2026 begin admin only */
      console.log("Admin code executed");
    `;

    const hits = detectUnicodeAttacks(code, 'src/admin.js', policy);
    expect(hits.some((h) => h.ruleId === 'SC-UNI-001')).toBe(true);

    const hit = hits.find((h) => h.ruleId === 'SC-UNI-001')!;
    expect(hit.severity).toBe('CRITICAL');
    expect(hit.blocking).toBe(true);

    // Verify escaped evidence representation
    expect(hit.evidence[0]!.note).toContain('U+202E');
  });

  it('detects zero-width and invisible characters in logic (SC-UNI-002)', () => {
    // Variable with zero-width space
    const code = 'const user\u200BName = "admin";';

    const hits = detectUnicodeAttacks(code, 'src/user.js', policy);
    expect(hits.some((h) => h.ruleId === 'SC-UNI-002')).toBe(true);

    const hit = hits.find((h) => h.ruleId === 'SC-UNI-002')!;
    expect(hit.severity).toBe('HIGH');
    expect(hit.evidence[0]!.note).toContain('U+200B');
  });

  it('allows UTF-8 BOM at the very start of line 1', () => {
    const codeWithBOM = '\uFEFFconst clean = 1;';
    const hits = detectUnicodeAttacks(codeWithBOM, 'src/clean.js', policy);
    expect(hits).toHaveLength(0);
  });

  it('detects UTF-8 BOM mid-line or on subsequent lines', () => {
    const codeWithHiddenBOM = 'const a = 1;\nconst b = \uFEFF2;';
    const hits = detectUnicodeAttacks(codeWithHiddenBOM, 'src/bom.js', policy);
    expect(hits.some((h) => h.ruleId === 'SC-UNI-002')).toBe(true);
  });

  it('detects mixed-script confusable homoglyphs in identifiers (SC-UNI-003)', () => {
    // Cyrillic small 'а' (U+0430) embedded inside 'pass'
    const code = 'function checkP\u0430ssword(input) { return true; }';

    const hits = detectUnicodeAttacks(code, 'src/spoof.js', policy);
    expect(hits.some((h) => h.ruleId === 'SC-UNI-003')).toBe(true);

    const hit = hits.find((h) => h.ruleId === 'SC-UNI-003')!;
    expect(hit.severity).toBe('HIGH');
    expect(hit.evidence[0]!.note).toContain('U+0430');
    expect(hit.evidence[0]!.note).toContain('Latin');
  });
});
