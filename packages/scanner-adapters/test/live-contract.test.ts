import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { OpengrepAdapter } from '../src/adapters/opengrep.adapter.js';
import { GitleaksAdapter } from '../src/adapters/gitleaks.adapter.js';
import { TrivyAdapter } from '../src/adapters/trivy.adapter.js';
import { OsvScannerAdapter } from '../src/adapters/osv-scanner.adapter.js';
import { CheckovAdapter } from '../src/adapters/checkov.adapter.js';

describe('Live Scanner Contract Suite (Auto-skips when binary absent)', () => {
  it('opengrep live contract test', async () => {
    const adapter = new OpengrepAdapter();
    const available = await adapter.isAvailable();
    if (!available) {
      console.log('Skipping opengrep live contract test: binary not found on PATH.');
      return;
    }

    const version = await adapter.version();
    expect(version).not.toBe('Unknown');
    expect(version).not.toBe('Not installed');

    const scanTarget = path.resolve('packages/scanner-adapters');
    const res = await adapter.scan(scanTarget, { timeoutMs: 120_000 });
    expect(res.status).toBe('SUCCESS');
  }, 120_000);

  it('gitleaks live contract test', async () => {
    const adapter = new GitleaksAdapter();
    const available = await adapter.isAvailable();
    if (!available) {
      console.log('Skipping gitleaks live contract test: binary not found on PATH.');
      return;
    }

    const version = await adapter.version();
    expect(version).not.toBe('Unknown');
    expect(version).not.toBe('Not installed');

    const scanTarget = path.resolve('packages/scanner-adapters');
    const res = await adapter.scan(scanTarget, { timeoutMs: 120_000 });
    expect(res.status).toBe('SUCCESS');
  }, 120_000);

  it('trivy live contract test', async () => {
    const adapter = new TrivyAdapter();
    const available = await adapter.isAvailable();
    if (!available) {
      console.log('Skipping trivy live contract test: binary not found on PATH.');
      return;
    }

    const version = await adapter.version();
    expect(version).not.toBe('Unknown');

    const scanTarget = path.resolve('packages/scanner-adapters');
    const res = await adapter.scan(scanTarget, { timeoutMs: 120_000 });
    expect(res.status).toBe('SUCCESS');
  }, 120_000);

  it('osv-scanner live contract test', async () => {
    const adapter = new OsvScannerAdapter();
    const available = await adapter.isAvailable();
    if (!available) {
      console.log('Skipping osv-scanner live contract test: binary not found on PATH.');
      return;
    }

    const version = await adapter.version();
    expect(version).not.toBe('Unknown');

    const scanTarget = path.resolve('packages/scanner-adapters');
    const res = await adapter.scan(scanTarget, { timeoutMs: 120_000 });
    expect(res.status).toBe('SUCCESS');
  }, 120_000);

  it('checkov live contract test', async () => {
    const adapter = new CheckovAdapter();
    const available = await adapter.isAvailable();
    if (!available) {
      console.log('Skipping checkov live contract test: binary not found on PATH.');
      return;
    }

    const version = await adapter.version();
    expect(version).not.toBe('Unknown');

    const scanTarget = path.resolve('packages/scanner-adapters');
    const res = await adapter.scan(scanTarget, { timeoutMs: 120_000 });
    expect(res.status).toBe('SUCCESS');
  }, 120_000);
});
