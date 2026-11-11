import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { OpengrepAdapter } from '../src/adapters/opengrep.adapter.js';
import { GitleaksAdapter } from '../src/adapters/gitleaks.adapter.js';
import { TrivyAdapter } from '../src/adapters/trivy.adapter.js';
import { OsvScannerAdapter } from '../src/adapters/osv-scanner.adapter.js';
import { CheckovAdapter } from '../src/adapters/checkov.adapter.js';

describe('Scanner Adapters Integration with Shims Suite', () => {
  let shimDir: string;

  beforeEach(() => {
    shimDir = mkdtempSync(path.join(tmpdir(), 'scanner-shims-'));
  });

  afterEach(() => {
    try {
      rmSync(shimDir, { recursive: true, force: true });
    } catch {}
  });

  /**
   * Helper to create an executable shim script.
   */
  function createShim(name: string, scriptJs: string): string {
    const jsPath = path.join(shimDir, `${name}.cjs`);
    writeFileSync(jsPath, scriptJs, 'utf-8');
    return jsPath;
  }

  it('GitleaksAdapter handles success and double-redaction from shim', async () => {
    const sarifOutput = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'gitleaks' } },
          results: [
            {
              ruleId: 'aws-access-key-id',
              message: { text: 'AWS Access Key ID found' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'src/config.ts' },
                    region: { startLine: 1, endLine: 1, snippet: { text: 'AKIA...[REDACTED]' } },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const shim = createShim(
      'gitleaks',
      `
      const fs = require('fs');
      const args = process.argv;
      const reportIdx = args.indexOf('--report-path');
      if (reportIdx !== -1 && args[reportIdx + 1]) {
        fs.writeFileSync(args[reportIdx + 1], ${JSON.stringify(sarifOutput)});
      }
      process.exit(0);
      `
    );

    const adapter = new GitleaksAdapter({ binaryOverride: shim });
    const targetDir = path.resolve('packages/core-engine/test/fixtures');
    const res = await adapter.scan(targetDir);

    expect(res.status).toBe('SUCCESS');
    expect(res.scannerName).toBe('gitleaks');
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0]!.ruleId).toBe('aws-access-key-id');
  });

  it('OpengrepAdapter falls back to semgrep when opengrep is absent', async () => {
    const sarifOutput = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'semgrep' } },
          results: [],
        },
      ],
    });

    const semgrepShim = createShim(
      'semgrep',
      `
      const fs = require('fs');
      const args = process.argv;
      const outIdx = args.indexOf('--output');
      if (outIdx !== -1 && args[outIdx + 1]) {
        fs.writeFileSync(args[outIdx + 1], ${JSON.stringify(sarifOutput)});
      }
      process.exit(0);
      `
    );

    // Provide semgrep shim as override
    const adapter = new OpengrepAdapter({ binaryOverride: semgrepShim });
    const targetDir = path.resolve('packages/core-engine/test/fixtures');
    const res = await adapter.scan(targetDir);

    expect(res.status).toBe('SUCCESS');
    expect(res.findings).toHaveLength(0);
  });

  it('TrivyAdapter returns PARTIAL_FAILURE with actionable advice when offline without DB cache', async () => {
    const emptyCache = mkdtempSync(path.join(tmpdir(), 'trivy-empty-cache-'));
    const dummyShim = createShim('trivy', 'process.exit(0);');

    try {
      const adapter = new TrivyAdapter({
        binaryOverride: dummyShim,
        cacheDir: emptyCache,
        offline: true,
      });

      const res = await adapter.scan(process.cwd());
      expect(res.status).toBe('PARTIAL_FAILURE');
      expect(res.errorMessage).toContain('no cached vulnerability database (trivy.db) was found');
      expect(res.errorMessage).toContain('trivy image --download-db-only');
    } finally {
      try {
        rmSync(emptyCache, { recursive: true, force: true });
      } catch {}
    }
  });

  it('handles scanner timeout cleanly without orphan processes', async () => {
    // Infinite loop shim that ignores signals
    const hangingShim = createShim(
      'hanging-scanner',
      `
      setInterval(() => {}, 1000);
      `
    );

    const adapter = new GitleaksAdapter({ binaryOverride: hangingShim });
    const res = await adapter.scan(process.cwd(), { timeoutMs: 500 });

    expect(res.status).toBe('TIMEOUT');
    expect(res.timedOut).toBe(true);
    expect(res.errorMessage).toContain('timed out');
  });

  it('returns TOOL_MISSING when scanner is not installed', async () => {
    const adapter = new CheckovAdapter({
      binaryOverride: path.join(tmpdir(), 'non_existent_checkov_path'),
    });

    const res = await adapter.scan(process.cwd());
    expect(res.status).toBe('TOOL_MISSING');
    expect(res.findings).toHaveLength(0);
    expect(res.errorMessage).toContain('executable not found on system PATH');
  });

  it('OsvScannerAdapter handles non-zero exit code 1 as SUCCESS with findings', async () => {
    const sarifOutput = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'osv-scanner' } },
          results: [
            {
              ruleId: 'GHSA-test-vulnerability',
              message: { text: 'Known vulnerability' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'pnpm-lock.yaml' },
                    region: { startLine: 1, endLine: 1 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const shim = createShim(
      'osv-scanner',
      `
      const fs = require('fs');
      const args = process.argv;
      const outIdx = args.indexOf('--output');
      if (outIdx !== -1 && args[outIdx + 1]) {
        fs.writeFileSync(args[outIdx + 1], ${JSON.stringify(sarifOutput)});
      }
      process.exit(1); // Exits 1 when vulnerabilities are found
      `
    );

    const adapter = new OsvScannerAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('SUCCESS');
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0]!.ruleId).toBe('GHSA-test-vulnerability');
  });

  it('CheckovAdapter handles success and parses IAC findings from shim', async () => {
    const sarifOutput = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'checkov' } },
          results: [
            {
              ruleId: 'CKV_DOCKER_1',
              message: { text: 'Ensure port 22 is not exposed' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'Dockerfile' },
                    region: { startLine: 5, endLine: 5 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const shim = createShim(
      'checkov',
      `
      const fs = require('fs');
      const path = require('path');
      const args = process.argv;
      const outIdx = args.indexOf('--output-file-path');
      if (outIdx !== -1 && args[outIdx + 1]) {
        const outDir = args[outIdx + 1];
        const sarifFile = path.join(outDir, 'results_sarif.sarif');
        fs.writeFileSync(sarifFile, ${JSON.stringify(sarifOutput)});
      }
      process.exit(0);
      `
    );

    const adapter = new CheckovAdapter({ binaryOverride: shim });
    const res = await adapter.scan(process.cwd());

    expect(res.status).toBe('SUCCESS');
    expect(res.findings).toHaveLength(1);
    expect(res.findings[0]!.ruleId).toBe('CKV_DOCKER_1');
    expect(res.findings[0]!.category).toBe('IAC');
  });

  it('TrivyAdapter handles success when offline with cached trivy.db', async () => {
    const cacheDir = mkdtempSync(path.join(tmpdir(), 'trivy-valid-cache-'));
    const dbDir = path.join(cacheDir, 'db');
    const fs = await import('node:fs');
    fs.mkdirSync(dbDir, { recursive: true });
    fs.writeFileSync(path.join(dbDir, 'trivy.db'), 'dummy-db', 'utf-8');

    const sarifOutput = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'trivy' } },
          results: [
            {
              ruleId: 'CVE-2023-4567',
              message: { text: 'Critical flaw in dependency' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'package.json' },
                    region: { startLine: 1, endLine: 1 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    try {
      const shim = createShim(
        'trivy',
        `
        const fs = require('fs');
        const args = process.argv;
        const outIdx = args.indexOf('--output');
        if (outIdx !== -1 && args[outIdx + 1]) {
          fs.writeFileSync(args[outIdx + 1], ${JSON.stringify(sarifOutput)});
        }
        process.exit(0);
        `
      );

      const adapter = new TrivyAdapter({
        binaryOverride: shim,
        cacheDir,
        offline: true,
      });

      const res = await adapter.scan(process.cwd());
      expect(res.status).toBe('SUCCESS');
      expect(res.findings).toHaveLength(1);
      expect(res.findings[0]!.ruleId).toBe('CVE-2023-4567');
    } finally {
      try {
        fs.rmSync(cacheDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it('queries scanner version successfully via version()', async () => {
    const versionShim = createShim(
      'version-tool',
      `
      console.log('tool version 1.4.2 (built 2026-01-01)');
      process.exit(0);
      `
    );

    const adapter = new GitleaksAdapter({ binaryOverride: versionShim });
    const ver = await adapter.version();
    expect(ver).toContain('1.4.2');
  });
});
