import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { InitCommand, InitOptionsSchema } from '../src/commands/init.js';
import { ConfigSchema, type SecureShipConfig } from '@secureship/contracts';

describe('InitCommand — Project Onboarding Wizard Suite (Phase 2)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-test-init-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('validates InitOptionsSchema defaults accurately', () => {
    const parsed = InitOptionsSchema.parse({});
    expect(parsed.failOn).toBe('HIGH');
    expect(parsed.gate2).toBe('annotate');
    expect(parsed.generateAction).toBe(true);
    expect(parsed.createBaseline).toBe(false);
    expect(parsed.yes).toBe(false);
    expect(parsed.force).toBe(false);
    expect(parsed.scanners).toContain('opengrep');
    expect(parsed.scanners).toContain('gitleaks');
    expect(parsed.scanners).toContain('trivy');
    expect(parsed.scanners).toContain('osv-scanner');
  });

  it('generates a valid secureship.config.json in non-interactive --yes mode', async () => {
    const exitCode = await InitCommand.run(tempDir, { yes: true, generateAction: false });
    expect(exitCode).toBe(0);

    const configPath = path.join(tempDir, 'secureship.config.json');
    expect(fs.existsSync(configPath)).toBe(true);

    const content = fs.readFileSync(configPath, 'utf-8');
    const parsedJson = JSON.parse(content) as SecureShipConfig;

    const validation = ConfigSchema.safeParse(parsedJson);
    expect(validation.success).toBe(true);
    expect(parsedJson.failOn).toBe('HIGH');
    expect(parsedJson.gate2?.mode).toBe('annotate');
    expect(parsedJson.scanners?.['opengrep']).toBe(true);
    expect(parsedJson.scanners?.['checkov']).toBe(false);
  });

  it('scaffolds GitHub Actions workflow when generateAction is true', async () => {
    const exitCode = await InitCommand.run(tempDir, { yes: true, generateAction: true });
    expect(exitCode).toBe(0);

    const workflowPath = path.join(tempDir, '.github', 'workflows', 'secureship.yml');
    expect(fs.existsSync(workflowPath)).toBe(true);

    const content = fs.readFileSync(workflowPath, 'utf-8');
    expect(content).toContain('name: SecureShip Security Verification');
    expect(content).toContain('secureship install-tools');
    expect(content).toContain('--sarif secureship.sarif');
    expect(content).toContain('upload-sarif@v3');
    expect(content).toContain('--new-only');
  });

  it('respects custom CLI options for severity, gate2 mode, and scanners', async () => {
    const exitCode = await InitCommand.run(tempDir, {
      yes: true,
      failOn: 'CRITICAL',
      gate2: 'suppress',
      scanners: ['opengrep', 'checkov'],
      generateAction: false,
    });
    expect(exitCode).toBe(0);

    const configPath = path.join(tempDir, 'secureship.config.json');
    const parsedJson = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as SecureShipConfig;

    expect(parsedJson.failOn).toBe('CRITICAL');
    expect(parsedJson.gate2?.mode).toBe('suppress');
    expect(parsedJson.scanners?.['opengrep']).toBe(true);
    expect(parsedJson.scanners?.['checkov']).toBe(true);
    expect(parsedJson.scanners?.['gitleaks']).toBe(false);
    expect(parsedJson.scanners?.['trivy']).toBe(false);
  });

  it('aborts without overwriting existing config unless --force is specified', async () => {
    const configPath = path.join(tempDir, 'secureship.config.json');
    fs.writeFileSync(configPath, JSON.stringify({ failOn: 'LOW', scanners: {} }, null, 2));

    // Run without force -> should fail
    const exitCodeFail = await InitCommand.run(tempDir, { yes: true, force: false });
    expect(exitCodeFail).toBe(1);

    const preservedContent = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as SecureShipConfig;
    expect(preservedContent.failOn).toBe('LOW');

    // Run with force -> should succeed and overwrite
    const exitCodeSuccess = await InitCommand.run(tempDir, {
      yes: true,
      force: true,
      failOn: 'CRITICAL',
    });
    expect(exitCodeSuccess).toBe(0);

    const overwrittenContent = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as SecureShipConfig;
    expect(overwrittenContent.failOn).toBe('CRITICAL');
  });

  it('initializes .secureship/baseline.json when createBaseline is requested', async () => {
    const exitCode = await InitCommand.run(tempDir, {
      yes: true,
      createBaseline: true,
      generateAction: false,
    });
    expect(exitCode).toBe(0);

    const baselinePath = path.join(tempDir, '.secureship', 'baseline.json');
    expect(fs.existsSync(baselinePath)).toBe(true);

    const baselineContent = JSON.parse(fs.readFileSync(baselinePath, 'utf-8')) as {
      schemaVersion: string;
      findings: unknown[];
    };
    expect(baselineContent.schemaVersion).toBe('1.0');
    expect(Array.isArray(baselineContent.findings)).toBe(true);
  });
});
