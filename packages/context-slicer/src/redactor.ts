export class SecretRedactor {
  private static readonly PATTERNS: Array<{
    name: string;
    regex: RegExp;
    replacer: (match: string, ...groups: string[]) => string;
  }> = [
    // Private Key blocks
    {
      name: 'PRIVATE_KEY',
      regex:
        /-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----/g,
      replacer: () => '[REDACTED_PRIVATE_KEY]',
    },
    // AWS Access Key ID
    {
      name: 'AWS_ACCESS_KEY',
      regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
      replacer: (match) => `${match.slice(0, 4)}...[REDACTED]`,
    },
    // GitHub Tokens
    {
      name: 'GITHUB_TOKEN',
      regex: /\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b/g,
      replacer: (match) => `${match.slice(0, 4)}...[REDACTED]`,
    },
    {
      name: 'GITHUB_PAT',
      regex: /\bgithub_pat_[a-zA-Z0-9_]{80,100}\b/g,
      replacer: () => 'github_pat_...[REDACTED]',
    },
    // Slack Tokens
    {
      name: 'SLACK_TOKEN',
      regex: /\bxox[baprs]-[0-9a-zA-Z-]{10,72}\b/g,
      replacer: (match) => `${match.slice(0, 5)}...[REDACTED]`,
    },
    // Stripe Live Keys
    {
      name: 'STRIPE_KEY',
      regex: /\b(sk|rk)_live_[0-9a-zA-Z]{20,99}\b/g,
      replacer: (match) => `${match.slice(0, 7)}...[REDACTED]`,
    },
    // Google AIza API Keys
    {
      name: 'GOOGLE_API_KEY',
      regex: /\bAIza[0-9A-Za-z-_]{35}\b/g,
      replacer: (match) => `${match.slice(0, 4)}...[REDACTED]`,
    },
    // npm Tokens
    {
      name: 'NPM_TOKEN',
      regex: /\bnpm_[A-Za-z0-9_-]{36,64}\b/g,
      replacer: () => 'npm_...[REDACTED]',
    },
    // Credentialed Connection URLs (postgres://user:pass@host...)
    {
      name: 'CREDENTIALED_URL',
      regex:
        /\b([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s"']+)@([a-zA-Z0-9_.-]+(?::\d+)?(?:\/[^\s"']*)?)/g,
      replacer: (_match, scheme, user, _pass, rest) =>
        `${scheme}${user}:[REDACTED_PASSWORD]@${rest}`,
    },
    // Bearer Tokens
    {
      name: 'BEARER_TOKEN',
      regex: /(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)/gi,
      replacer: (_match, prefix) => `${prefix}[REDACTED_TOKEN]`,
    },
    // String-literal assignments: const password = "..." or password = '...'
    {
      name: 'VARIABLE_ASSIGNMENT_SECRET',
      regex:
        /\b((?:(?:const|let|var|val|\$)?\s*)?(?:api[_-]?key|apikey|secret|password|passwd|pwd|token|auth[_-]?token|access[_-]?token)\s*(?::=|=)\s*)(["'])([^"'\r\n]{4,})\2/gi,
      replacer: (_match, prefix, quote, val) =>
        val.includes('[REDACTED') ? _match : `${prefix}${quote}[REDACTED_SECRET]${quote}`,
    },
    // Generic Key/Token assignments in text or JSON
    {
      name: 'KEY_VALUE_SECRET',
      regex:
        /((?:api[_-]?key|secret|password|token|access[_-]?token|auth[_-]?token|passwd|pwd)\s*[:=]\s*["'])([^"'\s]{6,})(["'])/gi,
      replacer: (_match, prefix, secret, suffix) =>
        secret.includes('[REDACTED') ? _match : `${prefix}[REDACTED_SECRET]${suffix}`,
    },
  ];

  private static readonly SENSITIVE_KEY_NAMES = new Set([
    'password',
    'passwd',
    'pwd',
    'secret',
    'api_key',
    'apikey',
    'access_token',
    'auth_token',
    'token',
    'private_key',
    'privatekey',
    'client_secret',
    'secret_key',
  ]);

  /**
   * Computes Shannon entropy of a string.
   */
  public static calculateEntropy(str: string): number {
    if (!str || str.length === 0) return 0;
    const freqs = new Map<string, number>();
    for (const ch of str) {
      freqs.set(ch, (freqs.get(ch) || 0) + 1);
    }
    let entropy = 0;
    const len = str.length;
    for (const count of freqs.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Redacts sensitive secrets and tokens from a string.
   */
  public static redactText(input: string): string {
    if (!input || typeof input !== 'string') {
      return '';
    }

    let result = input;
    for (const pattern of SecretRedactor.PATTERNS) {
      result = result.replace(pattern.regex, pattern.replacer);
    }

    // Redact high-entropy string literals (>= 32 chars) inside quotes
    result = result.replace(/(["'])([^"'\r\n\s]{32,})\1/g, (match, quote, inner) => {
      if (
        !inner.startsWith('http://') &&
        !inner.startsWith('https://') &&
        !inner.includes('[REDACTED') &&
        SecretRedactor.calculateEntropy(inner) >= 3.6
      ) {
        return `${quote}[REDACTED_HIGH_ENTROPY]${quote}`;
      }
      return match;
    });

    return result;
  }

  /**
   * Recursively traverses and redacts an object or array.
   */
  public static redactObject<T>(input: T): T {
    if (input === null || input === undefined) {
      return input;
    }

    if (typeof input === 'string') {
      return SecretRedactor.redactText(input) as unknown as T;
    }

    if (Array.isArray(input)) {
      return input.map((item) => SecretRedactor.redactObject(item)) as unknown as T;
    }

    if (typeof input === 'object') {
      const copy: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
        const lowerKey = key.toLowerCase();
        if (SecretRedactor.SENSITIVE_KEY_NAMES.has(lowerKey)) {
          copy[key] = '[REDACTED_KEY_VALUE]';
        } else {
          copy[key] = SecretRedactor.redactObject(value);
        }
      }
      return copy as T;
    }

    return input;
  }

  /**
   * Checks if an environment variable or key is potentially sensitive.
   */
  public static isSensitiveKey(key: string): boolean {
    const lower = key.toLowerCase();
    for (const item of SecretRedactor.SENSITIVE_KEY_NAMES) {
      if (lower.includes(item)) {
        return true;
      }
    }
    return false;
  }
}
