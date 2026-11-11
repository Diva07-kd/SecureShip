import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { SafeProcessRunner } from '@secureship/core-engine';
import { ProjectProfileSchema } from '@secureship/contracts';

describe('Part H Verification: CLI Commands', () => {
  const cliEntry = path.resolve('packages/cli/dist/index.js');

  function createTempDir(): string {
    return mkdtempSync(path.join(tmpdir(), 'secureship-cli-test-'));
  }

  function cleanup(dir: string): void {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {}
  }

  it('H1: --help and --version return exitCode 0, and unknown commands exit non-zero', async () => {
    const helpRes = await SafeProcessRunner.run(process.execPath, [cliEntry, '--help']);
    expect(helpRes.exitCode).toBe(0);
    expect(helpRes.stdout).toContain('Usage: secureship');

    const verRes = await SafeProcessRunner.run(process.execPath, [cliEntry, '--version']);
    expect(verRes.exitCode).toBe(0);
    expect(verRes.stdout).toContain('1.0.0-beta.1');

    const unknownRes = await SafeProcessRunner.run(process.execPath, [
      cliEntry,
      'invalid_command_xyz',
    ]);
    expect(unknownRes.exitCode).not.toBe(0);
  });

  it('H2: doctor command displays diagnostic table without crashing', async () => {
    const res = await SafeProcessRunner.run(process.execPath, [cliEntry, 'doctor']);
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('SecureShip Environment & Security Doctor');
    expect(res.stdout).toContain('Node.js:');
    expect(res.stdout).toContain('Git:');
    expect(res.stdout).toContain('SecureShip Deep AST Engine');
    expect(res.stdout).toContain('SecureShip Credential Sentinel');
    expect(res.stdout).toContain('SecureShip Component Auditor');
    expect(res.stdout).toContain('SecureShip Threat Intelligence');
    expect(res.stdout).toContain('SecureShip Infrastructure Guard');
  });

  it('H3: detect command supports human output and clean pure JSON mode', async () => {
    // Human mode on workspace
    const humanRes = await SafeProcessRunner.run(process.execPath, [cliEntry, 'detect', '.']);
    expect(humanRes.exitCode).toBe(0);
    expect(humanRes.stdout).toContain('SecureShip Project Intelligence Profile');
    expect(humanRes.stdout).toContain('Languages');

    // JSON mode on workspace
    const jsonRes = await SafeProcessRunner.run(process.execPath, [
      cliEntry,
      'detect',
      '.',
      '--json',
    ]);
    expect(jsonRes.exitCode).toBe(0);
    const parsed = JSON.parse(jsonRes.stdout.trim());
    expect(ProjectProfileSchema.safeParse(parsed).success).toBe(true);

    // Non-existent directory returns non-zero error
    const nonExistRes = await SafeProcessRunner.run(process.execPath, [
      cliEntry,
      'detect',
      'c:\\path_that_does_not_exist_9999',
    ]);
    expect(nonExistRes.exitCode).not.toBe(0);
  });

  it('H4: status command displays FREE_BYOK tier and AI fix status', async () => {
    const res = await SafeProcessRunner.run(process.execPath, [cliEntry, 'status']);
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('FREE_BYOK');
    expect(res.stdout).toContain('Verified remediation (BYOK)');
    expect(res.stdout).toContain('commercial tier limits not enforced');
  });

  it('H5: runs cleanly from a different working directory', async () => {
    const tempDir = createTempDir();
    try {
      const res = await SafeProcessRunner.run(process.execPath, [cliEntry, 'status'], {
        cwd: tempDir,
      });
      expect(res.exitCode).toBe(0);
      expect(res.stdout).toContain('Active Tier');
    } finally {
      cleanup(tempDir);
    }
  });

  it('H6: never prints sensitive ambient environment variables or secrets', async () => {
    process.env.LEAKY_SECRET_TOKEN = 'ghp_DO_NOT_PRINT_THIS_TOKEN_EVER_1234';

    const res = await SafeProcessRunner.run(process.execPath, [cliEntry, 'doctor']);
    delete process.env.LEAKY_SECRET_TOKEN;

    expect(res.stdout).not.toContain('ghp_DO_NOT_PRINT_THIS_TOKEN_EVER_1234');
    expect(res.stderr).not.toContain('ghp_DO_NOT_PRINT_THIS_TOKEN_EVER_1234');
  });
});
