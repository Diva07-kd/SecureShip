import { describe, it, expect } from 'vitest';
import { SecretRedactor } from '../src/security/secret-redactor.js';

describe('SecretRedactor', () => {
  it('should redact AWS Access Key IDs', () => {
    const raw = 'Configured AWS key: AKIAIOSFODNN7EXAMPLE in profile';
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(redacted).toContain('AKIA...[REDACTED]');
  });

  it('should redact GitHub Personal Access Tokens', () => {
    const raw = 'GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyzAB';
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).not.toContain('ghp_1234567890abcdefghijklmnopqrstuvwxyzAB');
    expect(redacted).toContain('ghp_...[REDACTED]');
  });

  it('should redact Bearer authorization tokens', () => {
    const raw = 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID';
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).toContain('Bearer [REDACTED_TOKEN]');
  });

  it('should redact Private Key PEM blocks', () => {
    const raw = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1p1+J+examplekeycontent1234567890abcdef
MIIEowIBAAKCAQEA0Y1p1+J+morekeycontent
-----END RSA PRIVATE KEY-----
`;
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).not.toContain('MIIEowIBAAKCAQEA0Y1p1');
    expect(redacted).toContain('[REDACTED_PRIVATE_KEY]');
  });

  it('should redact key-value secret assignments', () => {
    const raw = 'const dbConfig = { password: "SuperSecretPassword123!" };';
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).not.toContain('SuperSecretPassword123!');
    expect(redacted).toContain('[REDACTED_SECRET]');
  });

  it('should recursively redact objects and arrays', () => {
    const sensitiveObj = {
      user: 'alice',
      password: 'MyPassword123',
      apiKey: 'secret_api_key_value',
      headers: {
        authorization: 'Bearer token123456',
      },
      tokens: ['ghp_111111111111111111111111111111111111', 'harmless_tag'],
    };

    const redacted = SecretRedactor.redactObject(sensitiveObj);
    expect(redacted.password).toBe('[REDACTED_KEY_VALUE]');
    expect(redacted.apiKey).toBe('[REDACTED_KEY_VALUE]');
    expect(redacted.headers.authorization).toContain('[REDACTED_TOKEN]');
    expect(redacted.tokens[0]).toBe('ghp_...[REDACTED]');
    expect(redacted.tokens[1]).toBe('harmless_tag');
    expect(redacted.user).toBe('alice');
  });

  it('should detect sensitive keys', () => {
    expect(SecretRedactor.isSensitiveKey('AWS_SECRET_ACCESS_KEY')).toBe(true);
    expect(SecretRedactor.isSensitiveKey('DB_PASSWORD')).toBe(true);
    expect(SecretRedactor.isSensitiveKey('PATH')).toBe(false);
    expect(SecretRedactor.isSensitiveKey('NODE_ENV')).toBe(false);
  });

  it('should redact Google AIza keys', () => {
    const raw = 'key = "AIzaSyD-1234567890abcdefghijklmnopqrstU"';
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).not.toContain('AIzaSyD-1234567890abcdefghijklmnopqrstU');
    expect(redacted).toContain('AIza...[REDACTED]');
  });

  it('should redact npm tokens', () => {
    const raw = '//registry.npmjs.org/:_authToken=npm_abcdef1234567890abcdef1234567890abcd';
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).not.toContain('npm_abcdef1234567890abcdef1234567890abcd');
    expect(redacted).toContain('npm_...[REDACTED]');
  });

  it('should redact credentialed database connection URLs', () => {
    const raw = 'DATABASE_URL="postgres://admin:SuperSecretPass123@db.internal:5432/production"';
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).not.toContain('SuperSecretPass123');
    expect(redacted).toContain('postgres://admin:[REDACTED_PASSWORD]@db.internal:5432/production');
  });

  it('should redact variable assignment secrets', () => {
    const raw = `const password = "myVerySecretPassword123!";
let secret = 'anotherSecretToken';
var apikey = "super-secret-key-assignment";`;
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).not.toContain('myVerySecretPassword123!');
    expect(redacted).not.toContain('anotherSecretToken');
    expect(redacted).not.toContain('super-secret-key-assignment');
    expect(redacted).toContain('"[REDACTED_SECRET]"');
  });

  it('should redact high-entropy string literals (>= 32 chars) inside slices', () => {
    // 40 random hex characters (entropy ~ 4.0)
    const raw = 'const secretToken = "3a8f9b2c7e1d4a5b6c7d8e9f0a1b2c3d4e5f6a7b";';
    const redacted = SecretRedactor.redactText(raw);
    expect(redacted).not.toContain('3a8f9b2c7e1d4a5b6c7d8e9f0a1b2c3d4e5f6a7b');
    expect(redacted).toContain('[REDACTED_');
  });

  it('should calculate Shannon entropy correctly', () => {
    expect(SecretRedactor.calculateEntropy('')).toBe(0);
    // Single repeating char -> entropy 0
    expect(SecretRedactor.calculateEntropy('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')).toBe(0);
    // Hex string -> entropy around 4.0
    const hexEntropy = SecretRedactor.calculateEntropy('0123456789abcdef0123456789abcdef');
    expect(hexEntropy).toBeGreaterThan(3.5);
  });
});
