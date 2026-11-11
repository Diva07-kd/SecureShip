import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { InitCommand } from '../../src/commands/init.js';
import { select, checkbox, confirm } from '@inquirer/prompts';
import { type SecureShipConfig } from '@secureship/contracts';

vi.mock('@inquirer/prompts', () => ({
  select: vi.fn(),
  checkbox: vi.fn(),
  confirm: vi.fn(),
  input: vi.fn(),
}));

describe('InitCommand — @inquirer/prompts Integration Suite (Phase 2)', () => {
  let tempDir: string;
  let originalIsTTY: boolean | undefined;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-init-inquirer-'));
    originalIsTTY = process.stdin.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
    vi.clearAllMocks();
  });

  afterEach(() => {
    Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, configurable: true });
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('init --yes skips interactive prompts entirely and uses defaults', async () => {
    const exitCode = await InitCommand.run(tempDir, { yes: true, generateAction: false });
    expect(exitCode).toBe(0);

    expect(select).not.toHaveBeenCalled();
    expect(checkbox).not.toHaveBeenCalled();
    expect(confirm).not.toHaveBeenCalled();

    const configPath = path.join(tempDir, 'secureship.config.json');
    expect(fs.existsSync(configPath)).toBe(true);

    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as SecureShipConfig;
    expect(config.failOn).toBe('HIGH');
    expect(config.scanners?.['opengrep']).toBe(true);
    expect(config.gate2?.mode).toBe('annotate');
  });

  it('init writes correct failOn from select() response', async () => {
    vi.mocked(select).mockResolvedValueOnce('CRITICAL').mockResolvedValueOnce('annotate');
    vi.mocked(checkbox).mockResolvedValueOnce(['opengrep', 'gitleaks', 'trivy', 'osv-scanner']);
    vi.mocked(confirm).mockResolvedValueOnce(false).mockResolvedValueOnce(false);

    const exitCode = await InitCommand.run(tempDir, { yes: false });
    expect(exitCode).toBe(0);

    expect(select).toHaveBeenCalled();
    const configPath = path.join(tempDir, 'secureship.config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as SecureShipConfig;
    expect(config.failOn).toBe('CRITICAL');
  });

  it('init writes correct scanners from checkbox() response', async () => {
    vi.mocked(select).mockResolvedValueOnce('HIGH').mockResolvedValueOnce('annotate');
    vi.mocked(checkbox).mockResolvedValueOnce(['opengrep', 'trivy']);
    vi.mocked(confirm).mockResolvedValueOnce(false).mockResolvedValueOnce(false);

    const exitCode = await InitCommand.run(tempDir, { yes: false });
    expect(exitCode).toBe(0);

    expect(checkbox).toHaveBeenCalled();
    const configPath = path.join(tempDir, 'secureship.config.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as SecureShipConfig;
    expect(config.scanners?.['opengrep']).toBe(true);
    expect(config.scanners?.['trivy']).toBe(true);
    expect(config.scanners?.['gitleaks']).toBe(false);
    expect(config.scanners?.['osv-scanner']).toBe(false);
    expect(config.scanners?.['checkov']).toBe(false);
  });

  it('Generated secureship.yml contains --baseline flag in PR scan step', () => {
    InitCommand.scaffoldGithubActionWorkflow(tempDir);

    const workflowPath = path.join(tempDir, '.github', 'workflows', 'secureship.yml');
    expect(fs.existsSync(workflowPath)).toBe(true);

    const content = fs.readFileSync(workflowPath, 'utf-8');
    expect(content).toContain('--baseline .secureship/baseline.json');
    expect(content).toContain('--new-only');
    expect(content).toContain('continue-on-error: true');
    expect(content).toContain('name: SecureShip Security Verification');
  });
});
