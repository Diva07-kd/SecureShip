import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { ConsentManager } from '../src/consent/consent-manager.js';

describe('ConsentManager Suite (A3)', () => {
  let tempDir: string;
  let consentPath: string;
  let manager: ConsentManager;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-consent-test-'));
    consentPath = path.join(tempDir, 'ai-consent.json');
    manager = new ConsentManager(consentPath);
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('reports no consent when consent file is absent', () => {
    const status = manager.hasConsent('openai', 'http://localhost:11434/v1');
    expect(status.consented).toBe(false);
    expect(status.reason).toContain('Consent not granted');
  });

  it('records consent binding scheme + host + port and validates matching requests', () => {
    const record = manager.recordConsent('openai', 'llama3:8b', 'http://localhost:11434/v1');
    expect(record.endpointBinding).toBe('http://localhost:11434');

    const check = manager.hasConsent('openai', 'http://localhost:11434/v1/chat');
    expect(check.consented).toBe(true);
    expect(check.record?.model).toBe('llama3:8b');
  });

  it('detects endpoint or port changes and requires re-consent', () => {
    manager.recordConsent('openai', 'gpt-4o', 'https://api.openai.com/v1');

    // Different port
    const checkPort = manager.hasConsent('openai', 'https://api.openai.com:8443/v1');
    expect(checkPort.consented).toBe(false);
    expect(checkPort.reason).toContain('Endpoint binding change detected');

    // Different host
    const checkHost = manager.hasConsent('openai', 'https://other-endpoint.com/v1');
    expect(checkHost.consented).toBe(false);
    expect(checkHost.reason).toContain('Endpoint binding change detected');

    // Different provider
    const checkProvider = manager.hasConsent('anthropic', 'https://api.openai.com/v1');
    expect(checkProvider.consented).toBe(false);
    expect(checkProvider.reason).toContain('Provider change detected');
  });

  it('revokes consent cleanly', () => {
    manager.recordConsent('openai', 'model-x', 'http://localhost:8080');
    expect(fs.existsSync(consentPath)).toBe(true);

    const revoked = manager.revokeConsent();
    expect(revoked).toBe(true);
    expect(fs.existsSync(consentPath)).toBe(false);

    // Second revoke returns false
    expect(manager.revokeConsent()).toBe(false);
  });

  it('handles corrupted JSON consent file gracefully', () => {
    fs.writeFileSync(consentPath, 'Not JSON at all');
    const check = manager.hasConsent('openai', 'http://localhost:8080');
    expect(check.consented).toBe(false);
    expect(check.reason).toContain('could not be read or parsed');
  });

  it('exposes getter and default consent path', () => {
    expect(manager.getConsentPath()).toBe(consentPath);
    const defaultPath = ConsentManager.getDefaultConsentPath();
    expect(typeof defaultPath).toBe('string');
    expect(defaultPath).toContain('ai-consent.json');
  });

  it('supports static checkConsent and recordConsent helpers', () => {
    const staticRecord = ConsentManager.recordConsent(
      'http://localhost:8080/v1',
      'llama3',
      'openai',
      consentPath
    );
    expect(staticRecord.boundOrigin).toBe('http://localhost:8080');

    const staticCheck = ConsentManager.checkConsent(
      'http://localhost:8080/v1',
      'openai',
      consentPath
    );
    expect(staticCheck.consented).toBe(true);
    expect(staticCheck.boundOrigin).toBe('http://localhost:8080');
  });
});
