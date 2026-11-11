import { describe, it, expect } from 'vitest';
import { platform } from 'node:os';
import {
  writeFileSync,
  unlinkSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { SafeProcessRunner } from '../../src/sandbox/safe-process-runner.js';

describe('Part D Verification: SafeProcessRunner', () => {
  const isWindows = platform() === 'win32';

  it('D1: runs simple command and captures telemetry', async () => {
    const res = await SafeProcessRunner.run(process.execPath, [
      '-e',
      'console.log("hi"); console.error("err_msg");',
    ]);

    expect(res.stdout.trim()).toBe('hi');
    expect(res.stderr.trim()).toBe('err_msg');
    expect(res.exitCode).toBe(0);
    expect(res.durationMs).toBeGreaterThan(0);
    expect(res.timedOut).toBe(false);
    expect(res.truncated).toBe(false);
  });

  it('D2: returns non-zero exit code as data and rejects missing binary cleanly', async () => {
    const res = await SafeProcessRunner.run(process.execPath, ['-e', 'process.exit(17);']);
    expect(res.exitCode).toBe(17);
    expect(res.timedOut).toBe(false);

    await expect(SafeProcessRunner.run('non_existent_binary_xyz_123456789.exe')).rejects.toThrow();
  });

  it('D3: argument injection payloads are treated as literal arguments', async () => {
    const payload1 = '; echo PWNED';
    const payload2 = '$(whoami)';
    const payload3 = '&& dir';

    const res = await SafeProcessRunner.run(process.execPath, [
      '-e',
      'console.log(JSON.stringify(process.argv.slice(1)));',
      payload1,
      payload2,
      payload3,
    ]);

    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(res.stdout.trim());
    expect(parsed[0]).toBe(payload1);
    expect(parsed[1]).toBe(payload2);
    expect(parsed[2]).toBe(payload3);
  });

  it('D4: timeout terminates process within deadline and marks timedOut flag', async () => {
    const start = Date.now();
    const res = await SafeProcessRunner.run(
      process.execPath,
      ['-e', 'setTimeout(() => {}, 60000);'],
      { timeoutMs: 1500 }
    );
    const elapsed = Date.now() - start;

    expect(res.timedOut).toBe(true);
    expect(elapsed).toBeLessThan(4000);
  });

  it('D5: process tree termination cleans up child processes', async () => {
    // Child creates a grandchild process
    const script = `
      const { spawn } = require('child_process');
      const grandchild = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], {
        stdio: 'ignore',
        detached: ${!isWindows}
      });
      console.log('GC_PID:' + grandchild.pid);
      setTimeout(() => {}, 60000);
    `;

    const res = await SafeProcessRunner.run(process.execPath, ['-e', script], { timeoutMs: 1500 });

    expect(res.timedOut).toBe(true);

    const match = res.stdout.match(/GC_PID:(\d+)/);
    if (match && match[1]) {
      const gcPid = parseInt(match[1], 10);
      // Wait a moment for OS signal propagation
      await new Promise((r) => setTimeout(r, 500));
      let isAlive = false;
      try {
        process.kill(gcPid, 0); // test if PID exists
        isAlive = true;
      } catch {
        isAlive = false;
      }
      expect(isAlive).toBe(false);
    }
  });

  it('D6: buffer cap truncates output when maxBufferBytes is exceeded', async () => {
    // Print 5 MB with a 1 MB buffer limit
    const res = await SafeProcessRunner.run(
      process.execPath,
      ['-e', 'for (let i = 0; i < 50; i++) console.log("X".repeat(100000));'],
      { maxBufferBytes: 1024 * 1024 }
    );

    expect(res.truncated).toBe(true);
    expect(res.stdout.length).toBeLessThanOrEqual(1.5 * 1024 * 1024);
  });

  it('D7: buffer cap applies to stderr', async () => {
    const res = await SafeProcessRunner.run(
      process.execPath,
      ['-e', 'for (let i = 0; i < 20; i++) console.error("E".repeat(100000));'],
      { maxBufferBytes: 512 * 1024 }
    );

    expect(res.truncated).toBe(true);
    expect(res.stderr.length).toBeLessThanOrEqual(800 * 1024);
  });

  it('D8: environment sanitization strips ambient secrets and preserves OS PATH', async () => {
    process.env.SECRET_TEST_TOKEN = 'abc123';
    process.env.AWS_SECRET_ACCESS_KEY = 'fake_key';
    process.env.GITHUB_TOKEN = 'fake_token';

    const res = await SafeProcessRunner.run(process.execPath, [
      '-e',
      'console.log(JSON.stringify({ secret: process.env.SECRET_TEST_TOKEN, aws: process.env.AWS_SECRET_ACCESS_KEY, path: !!process.env.PATH }));',
    ]);

    delete process.env.SECRET_TEST_TOKEN;
    delete process.env.AWS_SECRET_ACCESS_KEY;
    delete process.env.GITHUB_TOKEN;

    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(res.stdout.trim());
    expect(parsed.secret).toBeUndefined();
    expect(parsed.aws).toBeUndefined();
    expect(parsed.path).toBe(true);

    // Explicit override test
    const overrideRes = await SafeProcessRunner.run(
      process.execPath,
      ['-e', 'console.log(process.env.CUSTOM_ALLOWED_VAR);'],
      { env: { CUSTOM_ALLOWED_VAR: 'allowed_value' } }
    );
    expect(overrideRes.stdout.trim()).toBe('allowed_value');
  });

  it('D9: handles child process exit signals', async () => {
    if (isWindows) {
      // Windows doesn't support POSIX SIGKILL via process.kill, returns code
      const res = await SafeProcessRunner.run(process.execPath, ['-e', 'process.exit(137);']);
      expect(res.exitCode).toBe(137);
    } else {
      const res = await SafeProcessRunner.run(process.execPath, [
        '-e',
        'process.kill(process.pid, "SIGKILL");',
      ]);
      expect(res.signal).toBe('SIGKILL');
    }
  });

  it('D10: concurrency test running 20 commands in parallel', async () => {
    const promises = Array.from({ length: 20 }, (_, i) =>
      SafeProcessRunner.run(process.execPath, ['-e', `console.log("ITEM_${i}");`])
    );

    const results = await Promise.all(promises);
    expect(results).toHaveLength(20);
    results.forEach((r, idx) => {
      expect(r.exitCode).toBe(0);
      expect(r.stdout.trim()).toBe(`ITEM_${idx}`);
    });
  });

  it('D11: handles UTF-8 characters and errors on nonexistent cwd', async () => {
    const utf8Text = 'SecureShip 🛡️ தமிழ் 測試 123';
    const res = await SafeProcessRunner.run(process.execPath, [
      '-e',
      `console.log(${JSON.stringify(utf8Text)});`,
    ]);
    expect(res.stdout.trim()).toBe(utf8Text);

    await expect(
      SafeProcessRunner.run(process.execPath, ['-v'], {
        cwd: 'c:\\non_existent_dir_random_123',
      })
    ).rejects.toThrow();
  });

  it('D12: handles Windows batch file spawning behavior', async () => {
    if (!isWindows) return;

    // Create a temporary .cmd file
    const batPath = path.join(tmpdir(), 'test_runner_probe.cmd');
    writeFileSync(batPath, '@echo off\r\necho HELLO_CMD\r\n');

    try {
      // Spawning .cmd directly in Node >= 18 on Windows requires shell or cmd.exe.
      // Under P7, SafeProcessRunner strictly forbids .cmd/.bat execution.
      let failedSafely = false;
      try {
        await SafeProcessRunner.run(batPath);
      } catch (err: unknown) {
        if (
          err instanceof Error &&
          (err.message.includes('forbidden') ||
            err.message.includes('EINVAL') ||
            (err as { code?: string }).code === 'EINVAL')
        ) {
          failedSafely = true;
        }
      }
      expect(failedSafely).toBe(true);
    } finally {
      try {
        unlinkSync(batPath);
      } catch {}
    }
  });

  it('D13: Windows target paths containing &, |, ^, %PATH%, quotes, spaces, and newlines never create canary files', async () => {
    const canaryDir = mkdtempSync(path.join(tmpdir(), 'secureship-canaries-'));

    try {
      const maliciousTargets = [
        `& echo CANARY > "${path.join(canaryDir, 'canary1.txt')}" &`,
        `| echo CANARY > "${path.join(canaryDir, 'canary2.txt')}" |`,
        `^ echo CANARY > "${path.join(canaryDir, 'canary3.txt')}"`,
        `"%PATH%" & echo CANARY > "${path.join(canaryDir, 'canary4.txt')}"`,
        `path with spaces & echo CANARY > "${path.join(canaryDir, 'canary5.txt')}" &`,
        `"quote_dir" & echo CANARY > "${path.join(canaryDir, 'canary6.txt')}" &`,
        `newline\ndir & echo CANARY > "${path.join(canaryDir, 'canary7.txt')}" &`,
      ];

      for (const target of maliciousTargets) {
        try {
          await SafeProcessRunner.run(
            process.execPath,
            ['-e', 'console.log(process.argv[1]);', target],
            { timeoutMs: 3000 }
          );
        } catch {
          // Process failures are acceptable; command execution/canary creation is strictly forbidden
        }
      }

      // Check all possible canary files in canaryDir
      const createdCanaries = readdirSync(canaryDir);
      expect(createdCanaries).toHaveLength(0);
    } finally {
      try {
        rmSync(canaryDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it('D14: static-grep gate matches shell\\s*: with any value and shell: set from variables across production code', () => {
    const repoRoot = path.resolve(__dirname, '../../../../');
    const packagesDir = path.join(repoRoot, 'packages');
    const srcFiles: string[] = [];

    function findSrcFiles(dir: string) {
      if (!existsSync(dir)) return;
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (
            entry.name === 'node_modules' ||
            entry.name === 'dist' ||
            entry.name === 'test' ||
            entry.name === '__tests__'
          ) {
            continue;
          }
          findSrcFiles(full);
        } else if (
          entry.isFile() &&
          (entry.name.endsWith('.ts') || entry.name.endsWith('.js')) &&
          !entry.name.endsWith('.d.ts')
        ) {
          if (full.includes(`${path.sep}src${path.sep}`)) {
            srcFiles.push(full);
          }
        }
      }
    }

    findSrcFiles(packagesDir);
    expect(srcFiles.length).toBeGreaterThan(20);

    // Regex matching shell: with any value, spacing, or variables
    const shellPattern = /\bshell\s*:/i;

    const violations: Array<{ file: string; line: number; match: string }> = [];

    for (const file of srcFiles) {
      const content = readFileSync(file, 'utf8');
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        const trimmed = line.trim();
        // Ignore single-line comments or block comment continuations
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
          continue;
        }
        if (shellPattern.test(line)) {
          violations.push({
            file: path.relative(repoRoot, file),
            line: i + 1,
            match: trimmed,
          });
        }
      }
    }

    // Must have zero violations in production code
    expect(violations).toEqual([]);

    // Positive assertion on the regex itself: must catch all variants
    expect(shellPattern.test('shell: true')).toBe(true);
    expect(shellPattern.test('shell: false')).toBe(true);
    expect(shellPattern.test('shell: process.platform === "win32"')).toBe(true);
    expect(shellPattern.test('shell: useShell')).toBe(true);
    expect(shellPattern.test('shell: opts.shell')).toBe(true);
    expect(shellPattern.test('shell   :    variable')).toBe(true);
  });
});
