import { describe, it, expect } from 'vitest';
import { FakeSandboxBackend } from '../src/backends/fake-backend.js';
import { BaselineRunner } from '../src/runner/baseline-runner.js';

describe('BaselineRunner Dynamic Stage Comparative Verification', () => {
  it('returns SKIPPED when no command is detected', async () => {
    const unpatched = new FakeSandboxBackend();
    const patched = new FakeSandboxBackend();

    const res = await BaselineRunner.runStage({
      stageId: 'TEST',
      command: undefined,
      unpatchedBackend: unpatched,
      patchedBackend: patched,
    });

    expect(res.outcome).toBe('SKIPPED');
    expect(res.detail).toContain('No test command detected');
  });

  it('returns PASS when both baseline and patched succeed', async () => {
    const unpatched = new FakeSandboxBackend();
    const patched = new FakeSandboxBackend();

    const res = await BaselineRunner.runStage({
      stageId: 'BUILD',
      command: { command: 'npm', args: ['run', 'build'] },
      unpatchedBackend: unpatched,
      patchedBackend: patched,
    });

    expect(res.outcome).toBe('PASS');
    expect(res.exitCode).toBe(0);
    expect(res.baselineExitCode).toBe(0);
    expect(res.flakyRerun).toBeUndefined();
  });

  it('returns INCONCLUSIVE when baseline fails', async () => {
    const unpatched = new FakeSandboxBackend();
    unpatched.setDefaultResponse({ exitCode: 1, stderr: 'broken build in baseline' });
    const patched = new FakeSandboxBackend();

    const res = await BaselineRunner.runStage({
      stageId: 'BUILD',
      command: { command: 'npm', args: ['run', 'build'] },
      unpatchedBackend: unpatched,
      patchedBackend: patched,
    });

    expect(res.outcome).toBe('INCONCLUSIVE');
    expect(res.baselineExitCode).toBe(1);
    expect(res.detail).toContain('Cannot verify regression without clean baseline');
  });

  it('returns FAIL when baseline passes and patched fails on rerun', async () => {
    const unpatched = new FakeSandboxBackend();
    const patched = new FakeSandboxBackend();
    patched.setDefaultResponse({ exitCode: 2, stderr: 'test regression' });

    const res = await BaselineRunner.runStage({
      stageId: 'TEST',
      command: { command: 'npm', args: ['test'] },
      unpatchedBackend: unpatched,
      patchedBackend: patched,
    });

    expect(res.outcome).toBe('FAIL');
    expect(res.exitCode).toBe(2);
    expect(res.baselineExitCode).toBe(0);
    expect(res.detail).toContain('introducing a regression');
  });

  it('returns PASS with flakyRerun=true when patched fails first but passes on rerun', async () => {
    const unpatched = new FakeSandboxBackend();
    const patched = new FakeSandboxBackend();

    // First call to patched fails, second succeeds
    let callCount = 0;
    patched.run = async (cmd, args, _opts) => {
      callCount++;
      if (callCount === 1) {
        return {
          exitCode: 1,
          timedOut: false,
          durationMs: 10,
          stdout: '',
          stderr: 'flaky network timeout',
          outputSha256: 'abc',
          outputTail: 'flaky',
          command: cmd,
          argv: args,
        };
      }
      return {
        exitCode: 0,
        timedOut: false,
        durationMs: 10,
        stdout: 'passed on rerun',
        stderr: '',
        outputSha256: 'def',
        outputTail: 'passed',
        command: cmd,
        argv: args,
      };
    };

    const res = await BaselineRunner.runStage({
      stageId: 'TEST',
      command: { command: 'npm', args: ['test'] },
      unpatchedBackend: unpatched,
      patchedBackend: patched,
    });

    expect(res.outcome).toBe('PASS');
    expect(res.flakyRerun).toBe(true);
    expect(res.detail).toContain('flakiness resolved');
  });
});
