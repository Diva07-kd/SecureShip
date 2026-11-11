import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { OpengrepAdapter } from '../src/adapters/opengrep.adapter.js';
import { GitleaksAdapter } from '../src/adapters/gitleaks.adapter.js';
import { TrivyAdapter } from '../src/adapters/trivy.adapter.js';
import { OsvScannerAdapter } from '../src/adapters/osv-scanner.adapter.js';
import { CheckovAdapter } from '../src/adapters/checkov.adapter.js';

describe('Scanner Adapters Error & Malformed Payload Resilience Suite', () => {
  let shimDir: string;

  beforeEach(() => {
    shimDir = mkdtempSync(path.join(tmpdir(), 'scanner-err-shims-'));
  });

  afterEach(() => {
    try {
      rmSync(shimDir, { recursive: true, force: true });
    } catch {}
  });

  function createShim(name: string, scriptJs: string): string {
    const jsPath = path.join(shimDir, `${name}.cjs`);
    writeFileSync(jsPath, scriptJs, 'utf-8');
    return jsPath;
  }

  it('OpengrepAdapter returns ERROR when process fails without writing SARIF', async () => {
    const shim = createShim(
      'opengrep',
      `
      console.error('Fatal opengrep configuration failure');
      process.exit(2);
      `
    );

    const adapter = new OpengrepAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('ERROR');
    expect(res.exitCode).toBe(2);
    expect(res.errorMessage).toContain('Scanner failed with exit code 2');
  });

  it('OpengrepAdapter returns PARTIAL_FAILURE when SARIF file contains corrupted JSON', async () => {
    const shim = createShim(
      'opengrep',
      `
      const fs = require('fs');
      let outPath = null;
      for (const a of process.argv) {
        if (a.startsWith('--sarif-output=')) {
          outPath = a.split('=')[1];
        }
      }
      const outIdx = process.argv.indexOf('--output');
      if (outIdx !== -1 && process.argv[outIdx + 1]) {
        outPath = process.argv[outIdx + 1];
      }
      if (outPath) {
        fs.writeFileSync(outPath, '{ CORRUPTED_SARIF_JSON: ');
      }
      process.exit(0);
      `
    );

    const adapter = new OpengrepAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('PARTIAL_FAILURE');
    expect(res.errorMessage).toContain('Failed to parse SAST SARIF output');
  });

  it('GitleaksAdapter returns ERROR when exit code > 1 without report file', async () => {
    const shim = createShim(
      'gitleaks',
      `
      console.error('gitleaks crashed unexpectedly');
      process.exit(2);
      `
    );

    const adapter = new GitleaksAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('ERROR');
    expect(res.exitCode).toBe(2);
    expect(res.errorMessage).toContain('Gitleaks failed with exit code 2');
  });

  it('GitleaksAdapter returns PARTIAL_FAILURE on corrupted SARIF file', async () => {
    const shim = createShim(
      'gitleaks',
      `
      const fs = require('fs');
      const repIdx = process.argv.indexOf('--report-path');
      if (repIdx !== -1 && process.argv[repIdx + 1]) {
        fs.writeFileSync(process.argv[repIdx + 1], 'BAD_JSON');
      }
      process.exit(0);
      `
    );

    const adapter = new GitleaksAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('PARTIAL_FAILURE');
    expect(res.errorMessage).toContain('Failed to parse Gitleaks SARIF');
  });

  it('TrivyAdapter returns ERROR when process fails without writing SARIF', async () => {
    const shim = createShim(
      'trivy',
      `
      console.error('trivy fatal error');
      process.exit(1);
      `
    );

    const adapter = new TrivyAdapter({ binaryOverride: shim, offline: false });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('ERROR');
    expect(res.errorMessage).toContain('Trivy failed with exit code 1');
  });

  it('TrivyAdapter returns PARTIAL_FAILURE on corrupted SARIF report', async () => {
    const shim = createShim(
      'trivy',
      `
      const fs = require('fs');
      const outIdx = process.argv.indexOf('--output');
      if (outIdx !== -1 && process.argv[outIdx + 1]) {
        fs.writeFileSync(process.argv[outIdx + 1], 'INVALID_SARIF_TRIVY');
      }
      process.exit(0);
      `
    );

    const adapter = new TrivyAdapter({ binaryOverride: shim, offline: false });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('PARTIAL_FAILURE');
    expect(res.errorMessage).toContain('Failed to parse Trivy SARIF');
  });

  it('OsvScannerAdapter returns ERROR on unexpected exit code without SARIF', async () => {
    const shim = createShim(
      'osv-scanner',
      `
      console.error('osv-scanner internal error');
      process.exit(2);
      `
    );

    const adapter = new OsvScannerAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('ERROR');
    expect(res.errorMessage).toContain('osv-scanner failed with exit code 2');
  });

  it('OsvScannerAdapter returns PARTIAL_FAILURE on corrupted SARIF report', async () => {
    const shim = createShim(
      'osv-scanner',
      `
      const fs = require('fs');
      const outIdx = process.argv.indexOf('--output');
      if (outIdx !== -1 && process.argv[outIdx + 1]) {
        fs.writeFileSync(process.argv[outIdx + 1], 'MALFORMED_OSV_SARIF');
      }
      process.exit(1);
      `
    );

    const adapter = new OsvScannerAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('PARTIAL_FAILURE');
    expect(res.errorMessage).toContain('Failed to parse osv-scanner SARIF');
  });

  it('CheckovAdapter returns ERROR on non-zero exit without SARIF output', async () => {
    const shim = createShim(
      'checkov',
      `
      console.error('checkov failed with syntax error in config');
      process.exit(2);
      `
    );

    const adapter = new CheckovAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('ERROR');
    expect(res.errorMessage).toContain('Checkov failed with exit code 2');
  });

  it('CheckovAdapter returns PARTIAL_FAILURE on corrupted SARIF output', async () => {
    const shim = createShim(
      'checkov',
      `
      const fs = require('fs');
      const path = require('path');
      const outIdx = process.argv.indexOf('--output-file-path');
      if (outIdx !== -1 && process.argv[outIdx + 1]) {
        const outDir = process.argv[outIdx + 1];
        fs.writeFileSync(path.join(outDir, 'results_sarif.sarif'), 'CORRUPTED_CHECKOV');
      }
      process.exit(0);
      `
    );

    const adapter = new CheckovAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('PARTIAL_FAILURE');
    expect(res.errorMessage).toContain('Failed to parse Checkov SARIF');
  });
});
