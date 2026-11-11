/**
 * Visual escaping and terminal output sanitizer.
 * Neutralizes ANSI/OSC escape sequences, Bidi overrides, and invisible/zero-width
 * characters from text to prevent terminal spoofing and Trojan Source Unicode attacks.
 */

// Bidi overrides and embeddings (Trojan Source CVE-2021-42574)
// U+202A..U+202E, U+2066..U+2069, U+200E, U+200F
// Zero-width & invisible characters: U+200B..U+200D, U+2060, U+FEFF, U+00AD, U+180E, U+115F, U+1160, U+3164

export function sanitizeTerminalOutput(input: string): string {
  if (!input) return '';

  // 1. Strip ANSI escape sequences & OSC sequences
  const strippedAnsi = input
    // CSI sequences: ESC [ ... [letter]
    .replace(/\x1b\[[0-9;?]*[a-zA-Z]/g, '')
    // OSC sequences: ESC ] ... (BEL | ESC \)
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
    // Stray escape chars
    .replace(/\x1b/g, '');

  // 2. Escape Bidi and Invisible characters to visually explicit \uXXXX representation
  return [...strippedAnsi]
    .map((ch) => {
      const code = ch.codePointAt(0);
      if (!code) return ch;
      if (
        (code >= 0x202a && code <= 0x202e) || // LRE, RLE, PDF, LRO, RLO
        (code >= 0x2066 && code <= 0x2069) || // LRI, RLI, FSI, PDI
        code === 0x200e || // LRM
        code === 0x200f || // RLM
        (code >= 0x200b && code <= 0x200d) || // ZWSP, ZWNJ, ZWJ
        code === 0x2060 || // Word Joiner
        code === 0xfeff || // BOM / ZWNBSP
        code === 0x00ad || // Soft Hyphen
        code === 0x180e || // MVS
        code === 0x115f || // Hangul Choseong Filler
        code === 0x1160 || // Hangul Jungseong Filler
        code === 0x3164 // Hangul Filler
      ) {
        return `\\u${code.toString(16).toUpperCase().padStart(4, '0')}`;
      }
      return ch;
    })
    .join('');
}
