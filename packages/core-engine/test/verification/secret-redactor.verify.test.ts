import { describe, it, expect } from 'vitest';
import { SecretRedactor } from '../../src/security/secret-redactor.js';

describe('Part C Verification: SecretRedactor', () => {
  const FAKE_AWS = 'AKIAIOSFODNN7EXAMPLE';
  const FAKE_GHP = 'ghp_' + 'A'.repeat(36);
  const FAKE_PAT = 'github_pat_' + 'B'.repeat(82);
  const FAKE_BEARER =
    'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature';
  const FAKE_PEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y1p1+J+fakekeycontent1234567890abcdef
-----END RSA PRIVATE KEY-----`;

  it('C1: redacts each documented secret category without leaking raw secrets', () => {
    // AWS
    const awsRedacted = SecretRedactor.redactText(`aws_key: ${FAKE_AWS}`);
    expect(awsRedacted).not.toContain(FAKE_AWS);
    expect(awsRedacted).toContain('AKIA...[REDACTED]');

    // GHP
    const ghpRedacted = SecretRedactor.redactText(`token: ${FAKE_GHP}`);
    expect(ghpRedacted).not.toContain(FAKE_GHP);
    expect(ghpRedacted).toContain('ghp_...[REDACTED]');

    // GITHUB_PAT
    const patRedacted = SecretRedactor.redactText(`pat: ${FAKE_PAT}`);
    expect(patRedacted).not.toContain(FAKE_PAT);
    expect(patRedacted).toContain('github_pat_...[REDACTED]');

    // Bearer
    const bearerRedacted = SecretRedactor.redactText(`Auth: ${FAKE_BEARER}`);
    expect(bearerRedacted).not.toContain('doNotLeakThisSignature');
    expect(bearerRedacted).toContain('Bearer [REDACTED_TOKEN]');

    // Generic key-value
    const genericRedacted = SecretRedactor.redactText('api_key="super_secret_secret_value_123"');
    expect(genericRedacted).not.toContain('super_secret_secret_value_123');
    expect(genericRedacted).toContain('[REDACTED_SECRET]');

    // PEM block
    const pemRedacted = SecretRedactor.redactText(`Key follows:\n${FAKE_PEM}`);
    expect(pemRedacted).not.toContain('fakekeycontent1234567890abcdef');
    expect(pemRedacted).toContain('[REDACTED_PRIVATE_KEY]');
  });

  it('C2: preserves surrounding text in sentences, JSON, and multiple secrets per line', () => {
    const sentence = `Deploying service with key ${FAKE_AWS} to production cluster.`;
    const sRedacted = SecretRedactor.redactText(sentence);
    expect(sRedacted.startsWith('Deploying service with key ')).toBe(true);
    expect(sRedacted.endsWith(' to production cluster.')).toBe(true);

    const jsonText = `{"service": "auth", "token": "${FAKE_GHP}", "active": true}`;
    const jRedacted = SecretRedactor.redactText(jsonText);
    expect(jRedacted).toContain('"service": "auth"');
    expect(jRedacted).toContain('"active": true');
    expect(jRedacted).not.toContain(FAKE_GHP);

    const twoSecrets = `Primary: ${FAKE_AWS} and Backup: ${FAKE_GHP}`;
    const twoRedacted = SecretRedactor.redactText(twoSecrets);
    expect(twoRedacted).not.toContain(FAKE_AWS);
    expect(twoRedacted).not.toContain(FAKE_GHP);
    expect(twoRedacted).toContain('Primary: ');
    expect(twoRedacted).toContain(' and Backup: ');
  });

  it('C3: preserves benign non-secrets untouched', () => {
    const benignProse = 'The quick brown fox jumps over the lazy dog.';
    expect(SecretRedactor.redactText(benignProse)).toBe(benignProse);

    const gitCommitSha = 'Commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904 merged cleanly';
    expect(SecretRedactor.redactText(gitCommitSha)).toBe(gitCommitSha);

    const uuid = 'User id 123e4567-e89b-12d3-a456-426614174000 created';
    expect(SecretRedactor.redactText(uuid)).toBe(uuid);

    const version = 'Upgraded dependency from 1.2.3 to 2.0.0';
    expect(SecretRedactor.redactText(version)).toBe(version);

    const codeSnippet = 'const token = getToken(); if (token) validate(token);';
    expect(SecretRedactor.redactText(codeSnippet)).toBe(codeSnippet);
  });

  it('C4: idempotency holds across repeated redaction', () => {
    const sample = `Key: ${FAKE_AWS}, Secret: "my_long_secret_value_123"`;
    const once = SecretRedactor.redactText(sample);
    const twice = SecretRedactor.redactText(once);
    expect(twice).toBe(once);
  });

  it('C5: redactObject deeply redacts without mutating input and handles types', () => {
    const original = {
      name: 'prod-cluster',
      count: 42,
      active: true,
      createdAt: new Date('2026-01-01T00:00:00Z'),
      metadata: {
        password: 'UnsafePassword123!',
        notes: `Use ${FAKE_AWS} for emergencies`,
      },
      tags: ['security', FAKE_GHP],
    };

    const redacted = SecretRedactor.redactObject(original);

    // Original must not be mutated
    expect(original.metadata.password).toBe('UnsafePassword123!');
    expect(original.tags[1]).toBe(FAKE_GHP);

    // Deep copy has masked values
    expect(redacted.metadata.password).toBe('[REDACTED_KEY_VALUE]');
    expect(redacted.metadata.notes).not.toContain(FAKE_AWS);
    expect(redacted.tags[1]).toContain('ghp_...[REDACTED]');
    expect(redacted.count).toBe(42);
    expect(redacted.active).toBe(true);
  });

  it('C6: ReDoS resistance on 1MB payloads', () => {
    const t0 = Date.now();
    const oneMbA = 'A'.repeat(1_000_000);
    SecretRedactor.redactText(oneMbA);
    const d1 = Date.now() - t0;
    expect(d1).toBeLessThan(2000);

    const t1 = Date.now();
    const oneMbAkia = 'AKIA'.repeat(250_000);
    SecretRedactor.redactText(oneMbAkia);
    const d2 = Date.now() - t1;
    expect(d2).toBeLessThan(2000);

    const t2 = Date.now();
    const hundredKbBegins = '-----BEGIN SOMETHING '.repeat(5_000);
    SecretRedactor.redactText(hundredKbBegins);
    const d3 = Date.now() - t2;
    expect(d3).toBeLessThan(2000);
  });

  it('C7: prefix exposure verification', () => {
    const redacted = SecretRedactor.redactText(FAKE_AWS);
    // Preserves only prefix 'AKIA' for diagnostic identification + '[REDACTED]'
    expect(redacted).toBe('AKIA...[REDACTED]');
  });
});
