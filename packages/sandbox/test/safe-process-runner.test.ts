import { describe, it, expect } from 'vitest';
import { SafeProcessRunner } from '../src/runner/safe-process-runner.js';

describe('SafeProcessRunner (Sandbox Package)', () => {
  it('should execute a safe command and capture stdout', async () => {
    const res = await SafeProcessRunner.run(process.execPath, [
      '-e',
      'console.log("hello from sandbox safe runner")',
    ]);

    expect(res.exitCode).toBe(0);
    expect(res.stdout.trim()).toBe('hello from sandbox safe runner');
    expect(res.timedOut).toBe(false);
    expect(res.truncated).toBe(false);
    expect(res.durationMs).toBeGreaterThan(0);
  });

  it('should capture stderr when child process fails', async () => {
    const res = await SafeProcessRunner.run(process.execPath, [
      '-e',
      'console.error("sandbox fatal error"); process.exit(42);',
    ]);

    expect(res.exitCode).toBe(42);
    expect(res.stderr.trim()).toContain('sandbox fatal error');
    expect(res.timedOut).toBe(false);
  });

  it('should enforce timeout and terminate long-running processes', async () => {
    const res = await SafeProcessRunner.run(
      process.execPath,
      ['-e', 'setTimeout(() => {}, 15000)'],
      { timeoutMs: 300 }
    );

    expect(res.timedOut).toBe(true);
  });

  it('should truncate output when maxBufferBytes limit is exceeded', async () => {
    const res = await SafeProcessRunner.run(
      process.execPath,
      ['-e', 'console.log("B".repeat(1000))'],
      { maxBufferBytes: 100 }
    );

    expect(res.truncated).toBe(true);
    expect(res.stdout.length).toBeLessThanOrEqual(200);
  });

  it('should sanitize ambient environment variables by default and allow explicit vars', async () => {
    process.env.TEST_SANDBOX_SECRET = 'leak_secret_value_123';

    const res = await SafeProcessRunner.run(
      process.execPath,
      [
        '-e',
        'console.log(JSON.stringify({ secret: process.env.TEST_SANDBOX_SECRET, custom: process.env.CUSTOM_VAL }))',
      ],
      {
        env: { CUSTOM_VAL: 'allowed_val' },
      }
    );

    delete process.env.TEST_SANDBOX_SECRET;

    expect(res.exitCode).toBe(0);
    const childEnv = JSON.parse(res.stdout.trim());
    expect(childEnv.secret).toBeUndefined();
    expect(childEnv.custom).toBe('allowed_val');
  });

  it('should reject invalid or missing working directory', async () => {
    await expect(
      SafeProcessRunner.run(process.execPath, ['-v'], {
        cwd: 'c:\\non_existent_folder_xyz_12345',
      })
    ).rejects.toThrow();
  });

  it('should safely execute .cjs scripts directly via host Node runtime', async () => {
    const { tmpdir } = await import('node:os');
    const { writeFileSync, rmSync } = await import('node:fs');
    const path = await import('node:path');

    const tempScript = path.join(tmpdir(), `test-script-${Date.now()}.cjs`);
    writeFileSync(
      tempScript,
      'console.log("direct cjs execution success"); process.exit(0);',
      'utf-8'
    );

    try {
      const res = await SafeProcessRunner.run(tempScript);
      expect(res.exitCode).toBe(0);
      expect(res.stdout.trim()).toBe('direct cjs execution success');
    } finally {
      try {
        rmSync(tempScript, { force: true });
      } catch {}
    }
  });
});
