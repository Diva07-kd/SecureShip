import { describe, expect, it } from 'vitest';
import { sanitizeTerminalOutput } from '../src/utils/sanitize-output.js';

describe('Terminal Output Sanitizer (WP8)', () => {
  it('strips ANSI color and cursor escape sequences', () => {
    const raw = '\x1b[31mRed Alert\x1b[0m \x1b[2JClearing';
    const clean = sanitizeTerminalOutput(raw);
    expect(clean).toBe('Red Alert Clearing');
    expect(clean).not.toContain('\x1b');
  });

  it('strips OSC escape sequences (window title, hyperlinks)', () => {
    const raw = '\x1b]0;Evil Title\x07Hello\x1b]8;;https://malware.site\x1b\\Click\x1b]8;;\x1b\\';
    const clean = sanitizeTerminalOutput(raw);
    expect(clean).toBe('HelloClick');
    expect(clean).not.toContain('\x1b');
    expect(clean).not.toContain('Evil Title');
  });

  it('escapes Trojan Source Bidi controls into visual representation', () => {
    // U+202E is RLO, U+202A is LRE
    const bidiRaw = 'user \u202Efdrowssap\u202C = true';
    const clean = sanitizeTerminalOutput(bidiRaw);
    expect(clean).toBe('user \\u202Efdrowssap\\u202C = true');
    expect(clean).not.toContain('\u202E');
    expect(clean).not.toContain('\u202C');
  });

  it('escapes zero-width and invisible characters', () => {
    // U+200B is ZWSP, U+FEFF is ZWNBSP/BOM, U+3164 is Hangul Filler
    const invisibleRaw = 'fake\u200Bvar\uFEFFname\u3164evil';
    const clean = sanitizeTerminalOutput(invisibleRaw);
    expect(clean).toBe('fake\\u200Bvar\\uFEFFname\\u3164evil');
    expect(clean).not.toContain('\u200B');
    expect(clean).not.toContain('\uFEFF');
    expect(clean).not.toContain('\u3164');
  });

  it('leaves benign alphanumeric and standard punctuation unchanged', () => {
    const normal = 'Dependency "react@18.2.0" contains no vulnerabilities: status = OK!';
    expect(sanitizeTerminalOutput(normal)).toBe(normal);
  });

  it('handles empty string gracefully', () => {
    expect(sanitizeTerminalOutput('')).toBe('');
  });
});
