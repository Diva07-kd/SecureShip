import { describe, it, expect } from 'vitest';
import { OutputSanitizer } from '../src/sanitize/output-sanitizer.js';

describe('OutputSanitizer Suite (A7)', () => {
  it('strips ANSI color escapes', () => {
    const raw = '\x1b[31mRed Alert\x1b[0m and \x1b[1;34mBold Blue\x1b[0m';
    const clean = OutputSanitizer.sanitizeText(raw);
    expect(clean).toBe('Red Alert and Bold Blue');
  });

  it('strips bidirectional override characters (Trojan Source)', () => {
    // Unicode \u202E is Right-to-Left Override, \u2066 is Left-to-Right Isolate
    const raw = 'Access granted \u202E admin = true \u202C check passed';
    const clean = OutputSanitizer.sanitizeText(raw);
    expect(clean).not.toContain('\u202E');
    expect(clean).not.toContain('\u202C');
    expect(clean).toBe('Access granted  admin = true  check passed');
  });

  it('strips zero-width and invisible characters', () => {
    // \u200B zero-width space, \uFEFF BOM
    const raw = 'Hello\u200BWorld\uFEFF!';
    const clean = OutputSanitizer.sanitizeText(raw);
    expect(clean).toBe('HelloWorld!');
  });

  it('strips control characters while preserving tabs and newlines', () => {
    const raw = 'Line 1\x00\x07\n\tLine 2\x1F';
    const clean = OutputSanitizer.sanitizeText(raw);
    expect(clean).toBe('Line 1\n\tLine 2');
  });

  it('neutralizes dangerous markdown link schemes', () => {
    const raw = 'Click [here](javascript:stealData()) or [download](data:text/html;base64,xxx)';
    const clean = OutputSanitizer.sanitizeText(raw);
    expect(clean).not.toContain('javascript:');
    expect(clean).not.toContain('data:');
    expect(clean).toContain('[here](advisory-neutralized)');
    expect(clean).toContain('[download](advisory-neutralized)');
  });

  it('enforces post-sanitization length caps', () => {
    const longText = 'A'.repeat(1000);
    const sanitized = OutputSanitizer.sanitizeRationale(longText);
    expect(sanitized.length).toBe(600);

    const longNotes = 'B'.repeat(500);
    const sanitizedNotes = OutputSanitizer.sanitizeExploitabilityNotes(longNotes);
    expect(sanitizedNotes?.length).toBe(300);

    const longQuote = 'C'.repeat(300);
    const sanitizedQuote = OutputSanitizer.sanitizeQuote(longQuote);
    expect(sanitizedQuote.length).toBe(200);
  });
});
