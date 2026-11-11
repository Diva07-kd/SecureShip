import { describe, it, expect } from 'vitest';
import { SecretRedactor } from '../src/redactor.js';

describe('SecretRedactor Comprehensive Unit Suite (A4)', () => {
  it('redacts Slack tokens', () => {
    const text = 'slackToken = "' + 'xox' + 'b-1234567890-1234567890123-abcdefghijklmnopqrstuv"';
    const redacted = SecretRedactor.redactText(text);
    expect(redacted).not.toContain('abcdefghijklmnopqrstuv');
    expect(redacted).toContain('xoxb-...[REDACTED]');
  });

  it('redacts Stripe live secret and restricted keys', () => {
    const sk = 'stripe_key = "' + 'sk_' + 'live_51Abcd1234567890abcdefghijklmnopqrstuv"';
    const rk = 'restricted = "' + 'rk_' + 'live_51Abcd1234567890abcdefghijklmnopqrstuv"';
    expect(SecretRedactor.redactText(sk)).toContain('sk_live...[REDACTED]');
    expect(SecretRedactor.redactText(rk)).toContain('rk_live...[REDACTED]');
  });

  it('redacts Google AIza API keys', () => {
    const text = 'const key = "AIzaSyD-1234567890abcdefghijklmnopqrstU";';
    const redacted = SecretRedactor.redactText(text);
    expect(redacted).not.toContain('AIzaSyD-1234567890abcdefghijklmnopqrstU');
    expect(redacted).toContain('AIza...[REDACTED]');
  });

  it('redacts npm tokens', () => {
    const text = 'const token = "npm_1234567890abcdefghijklmnopqrstuvwxyz123456";';
    const redacted = SecretRedactor.redactText(text);
    expect(redacted).not.toContain('npm_1234567890abcdefghijklmnopqrstuvwxyz123456');
    expect(redacted).toContain('npm_...[REDACTED]');
  });

  it('redacts credentialed connection URLs', () => {
    const text =
      'const dbUrl = "postgres://postgres:SuperSecretP@ssword@database.local:5432/mydb";';
    const redacted = SecretRedactor.redactText(text);
    expect(redacted).not.toContain('SuperSecretP@ssword');
    expect(redacted).toContain('postgres://postgres:[REDACTED_PASSWORD]@database.local:5432/mydb');
  });

  it('redacts bearer tokens', () => {
    const text = 'Authorization: Bearer abcdef1234567890==';
    const redacted = SecretRedactor.redactText(text);
    expect(redacted).toContain('Bearer [REDACTED_TOKEN]');
  });

  it('redacts variable assignments with secret names', () => {
    const text = 'const password = "myPlaintextPassword123";';
    const redacted = SecretRedactor.redactText(text);
    expect(redacted).toContain('const password = "[REDACTED_SECRET]";');
  });

  it('redacts high-entropy string literals', () => {
    // 40 random base64 chars with high Shannon entropy
    const highEntropy = '"4f9a7b8c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a"';
    const redacted = SecretRedactor.redactText(highEntropy);
    expect(redacted).toBe('"[REDACTED_HIGH_ENTROPY]"');
  });

  it('preserves URLs and non-sensitive strings', () => {
    const normal = 'const url = "https://example.com/api/v1/users";';
    expect(SecretRedactor.redactText(normal)).toBe(normal);
  });

  it('handles empty, null, and non-string inputs safely', () => {
    expect(SecretRedactor.redactText('')).toBe('');
    expect(SecretRedactor.redactText(null as unknown as string)).toBe('');
    expect(SecretRedactor.redactText(undefined as unknown as string)).toBe('');
  });

  it('redacts objects recursively including sensitive keys', () => {
    const obj = {
      user: 'alice',
      password: 'super-secret-password',
      nested: {
        api_key: 'key-12345',
        tags: ['public', 'Bearer my-token-123'],
      },
    };

    const redacted = SecretRedactor.redactObject(obj);
    expect(redacted.user).toBe('alice');
    expect(redacted.password).toBe('[REDACTED_KEY_VALUE]');
    expect(redacted.nested.api_key).toBe('[REDACTED_KEY_VALUE]');
    expect(redacted.nested.tags[1]).toContain('Bearer [REDACTED_TOKEN]');
  });

  it('identifies sensitive key names', () => {
    expect(SecretRedactor.isSensitiveKey('user_password')).toBe(true);
    expect(SecretRedactor.isSensitiveKey('CLIENT_SECRET')).toBe(true);
    expect(SecretRedactor.isSensitiveKey('username')).toBe(false);
  });
});
