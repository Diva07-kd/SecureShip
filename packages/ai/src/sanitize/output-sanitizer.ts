export class OutputSanitizer {
  // ANSI escapes: CSI sequences and OSC sequences
  private static readonly ANSI_ESCAPE_REGEX =
    /\x1b\[[0-9;]*[a-zA-Z]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g;

  // Control characters except \t (\x09), \n (\x0A), \r (\x0D)
  private static readonly CONTROL_CHARS_REGEX = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

  // Bidirectional override / direction manipulation characters (Trojan Source defense)
  private static readonly BIDI_OVERRIDES_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

  // Zero-width and hidden characters
  private static readonly ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u00AD\u2060]/g;

  // Executable or dangerous markdown link schemes
  private static readonly DANGEROUS_LINK_SCHEMES_REGEX =
    /\[([^\]]+)\]\((javascript|data|vbscript|file):[^)]*\)/gi;

  /**
   * Strips ANSI escapes, control chars, bidi overrides, zero-width characters,
   * and neutralizes dangerous link schemes from text produced by the model.
   */
  public static sanitizeText(text: string, maxLength?: number): string {
    if (!text || typeof text !== 'string') return '';

    let clean = text
      .replace(OutputSanitizer.ANSI_ESCAPE_REGEX, '')
      .replace(OutputSanitizer.BIDI_OVERRIDES_REGEX, '')
      .replace(OutputSanitizer.ZERO_WIDTH_REGEX, '')
      .replace(OutputSanitizer.CONTROL_CHARS_REGEX, '')
      .replace(OutputSanitizer.DANGEROUS_LINK_SCHEMES_REGEX, '[$1](advisory-neutralized)');

    // Strip carriage returns to normalize line endings
    clean = clean.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

    if (maxLength !== undefined && clean.length > maxLength) {
      clean = clean.slice(0, maxLength);
    }

    return clean;
  }

  /**
   * Sanitizes a model rationale (capped at 600 chars).
   */
  public static sanitizeRationale(rationale: string): string {
    return OutputSanitizer.sanitizeText(rationale, 600);
  }

  /**
   * Sanitizes exploitability notes (capped at 300 chars).
   */
  public static sanitizeExploitabilityNotes(notes?: string): string | undefined {
    if (!notes) return undefined;
    return OutputSanitizer.sanitizeText(notes, 300);
  }

  /**
   * Sanitizes a citation quote (capped at 200 chars).
   */
  public static sanitizeQuote(quote: string): string {
    return OutputSanitizer.sanitizeText(quote, 200);
  }
}
