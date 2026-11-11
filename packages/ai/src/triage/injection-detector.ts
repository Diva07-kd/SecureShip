export interface InjectionScanResult {
  detected: boolean;
  patternMatched?: string;
}

export class InjectionDetector {
  private static readonly INJECTION_PATTERNS: Array<{ name: string; regex: RegExp }> = [
    {
      name: 'IGNORE_INSTRUCTIONS',
      regex:
        /ignore\s+(?:all\s+)?(?:previous\s+|prior\s+|security\s+)?(?:instructions?|rules?|commands?|alerts?|directives?|flag)/i,
    },
    {
      name: 'SYSTEM_PROMPT_REFERENCE',
      regex: /(?:system|ai)\s+(?:instruction|prompt|notice|directive)\s*:/i,
    },
    {
      name: 'MODE_OR_PERSONA_OVERRIDE',
      regex:
        /(?:you\s+are\s+now|now\s+act\s+as)\s+(?:in\s+)?(?:developer|maintenance|god|jailbreak|dan)\b/i,
    },
    {
      name: 'FORCE_VERDICT',
      regex:
        /(?:mark|classify|set|return|output|conclude|treat)\s+(?:.*?\s+)?(?:as\s+)?(?:likely_false_positive|false\s+positive|benign)/i,
    },
    {
      name: 'DISREGARD_RULES',
      regex:
        /disregard\s+(?:all\s+)?(?:security|audit|scanner|prior|previous)\s+(?:rules?|findings?|alerts?)/i,
    },
    {
      name: 'ASSISTANT_OVERRIDE',
      regex: /(?:assistant|ai|developer\s+debug)\s*[:(]?\s*(?:override|always\s+output|conclude)/i,
    },
    {
      name: 'DELIMITER_ESCAPE_ATTEMPT',
      regex:
        /(?:<<<.*?(?:END_)?(?:UNTRUSTED|NEUTRALIZED|SECURESHIP|CODE_SLICE).*?>>>|===+\s*END\s+OF\s+.*(?:SLICE|SOURCE)\s*===+)/i,
    },
    {
      name: 'TAG_INJECTION',
      regex: /<\/(?:finding|context|slice)>\s*<verdict>/i,
    },
    {
      name: 'ENCODED_OR_BASE64_COMMAND',
      regex: /(?:base64\s+(?:command|instruction)\s*:|SWdub3Jl)/i,
    },
  ];

  /**
   * Scans text for heuristic prompt injection indicators.
   */
  public static scan(text: string): InjectionScanResult {
    if (!text || typeof text !== 'string') {
      return { detected: false };
    }

    const normalized = text.normalize('NFKD').replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '');

    for (const pattern of InjectionDetector.INJECTION_PATTERNS) {
      if (pattern.regex.test(text) || pattern.regex.test(normalized)) {
        return {
          detected: true,
          patternMatched: pattern.name,
        };
      }
    }

    return { detected: false };
  }

  /**
   * Alias for scan returning hasSuspiciousPattern.
   */
  public static detect(text: string): {
    hasSuspiciousPattern: boolean;
    detected: boolean;
    patternMatched?: string;
  } {
    const res = InjectionDetector.scan(text);
    return {
      hasSuspiciousPattern: res.detected,
      detected: res.detected,
      patternMatched: res.patternMatched,
    };
  }
}
