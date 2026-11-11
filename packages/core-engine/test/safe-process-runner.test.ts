import { describe, it, expect } from 'vitest';
import { SafeProcessRunner } from '../src/sandbox/safe-process-runner.js';

describe('SafeProcessRunner', () => {
  it('should execute a safe command and capture stdout', async () => {
    const res = await SafeProcessRunner.run(process.execPath, [
      '-e',
      'console.log("hello from secureship")',
    ]);

    expect(res.exitCode).toBe(0);
    expect(res.stdout.trim()).toBe('hello from secureship');
    expect(res.timedOut).toBe(false);
    expect(res.truncated).toBe(false);
    expect(res.durationMs).toBeGreaterThan(0);
  });

  it('should capture stderr when child process fails', async () => {
    const res = await SafeProcessRunner.run(process.execPath, [
      '-e',
      'console.error("fatal error occurred"); process.exit(42);',
    ]);

    expect(res.exitCode).toBe(42);
    expect(res.stderr.trim()).toContain('fatal error occurred');
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
    // Generate 1000 characters with a maxBufferBytes cap of 100 bytes
    const res = await SafeProcessRunner.run(
      process.execPath,
      ['-e', 'console.log("A".repeat(1000))'],
      { maxBufferBytes: 100 }
    );

    expect(res.truncated).toBe(true);
    expect(res.stdout.length).toBeLessThanOrEqual(200);
  });

  it('should sanitize ambient environment variables by default', async () => {
    // Temporarily inject sensitive ambient environment variable into current process
    process.env.SUPER_SECRET_TOKEN = 'top_secret_12345';
    process.env.HARMFUL_KEY = 'evil_key';

    const res = await SafeProcessRunner.run(process.execPath, [
      '-e',
      'console.log(JSON.stringify({ token: process.env.SUPER_SECRET_TOKEN, key: process.env.HARMFUL_KEY, path: !!process.env.PATH }))',
    ]);

    delete process.env.SUPER_SECRET_TOKEN;
    delete process.env.HARMFUL_KEY;

    expect(res.exitCode).toBe(0);
    const childEnv = JSON.parse(res.stdout.trim());
    expect(childEnv.token).toBeUndefined();
    expect(childEnv.key).toBeUndefined();
    expect(childEnv.path).toBe(true); // Safe OS PATH should still be passed
  });

  it('should reject invalid or missing working directory', async () => {
    await expect(
      SafeProcessRunner.run(process.execPath, ['-v'], {
        cwd: 'c:\\non_existent_folder_xyz_12345',
      })
    ).rejects.toThrow();
  });
});
