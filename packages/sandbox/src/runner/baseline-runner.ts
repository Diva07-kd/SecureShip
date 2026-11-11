import type { StageId, StageResult } from '@secureship/contracts';
import {
  type ISandboxBackend,
  type SandboxRunOptions,
  type SandboxRunResult,
} from '../backends/sandbox-backend.interface.js';
import { type DetectedStageCommand } from '../detector/command-detector.js';

export interface DynamicStageRunOptions {
  stageId: StageId;
  command?: DetectedStageCommand;
  unpatchedBackend: ISandboxBackend;
  patchedBackend: ISandboxBackend;
  timeoutMs?: number;
}

export class BaselineRunner {
  /**
   * Executes a dynamic stage comparing baseline (unpatched) vs patched shadow copies.
   */
  public static async runStage(options: DynamicStageRunOptions): Promise<StageResult> {
    const { stageId, command, unpatchedBackend, patchedBackend, timeoutMs } = options;

    if (!command) {
      return {
        id: stageId,
        outcome: 'SKIPPED',
        detail: `No ${stageId.toLowerCase()} command detected in repository`,
        durationMs: 0,
      };
    }

    const runOpts: SandboxRunOptions = {
      stageName: stageId,
      timeoutMs,
    };

    const startTime = Date.now();

    // 1. Run Baseline on Unpatched Shadow Copy
    let baselineResult: SandboxRunResult;
    try {
      baselineResult = await unpatchedBackend.run(command.command, command.args, runOpts);
    } catch (err: unknown) {
      return {
        id: stageId,
        outcome: 'INCONCLUSIVE',
        detail: `Baseline execution failed to launch: ${err instanceof Error ? err.message : String(err)}`,
        durationMs: Date.now() - startTime,
        argv: [command.command, ...command.args],
      };
    }

    if (baselineResult.timedOut || baselineResult.exitCode !== 0) {
      return {
        id: stageId,
        outcome: 'INCONCLUSIVE',
        detail: `Baseline ${stageId} failed or timed out (exit code ${baselineResult.exitCode}). Cannot verify regression without clean baseline.`,
        durationMs: Date.now() - startTime,
        argv: [command.command, ...command.args],
        exitCode: null,
        baselineExitCode: baselineResult.exitCode,
        outputSha256: baselineResult.outputSha256,
        outputTail: baselineResult.outputTail,
      };
    }

    // 2. Baseline Passed: Run Patched Copy
    let patchedResult: SandboxRunResult;
    try {
      patchedResult = await patchedBackend.run(command.command, command.args, runOpts);
    } catch (err: unknown) {
      return {
        id: stageId,
        outcome: 'FAIL',
        detail: `Patched execution failed: ${err instanceof Error ? err.message : String(err)}`,
        durationMs: Date.now() - startTime,
        argv: [command.command, ...command.args],
        baselineExitCode: baselineResult.exitCode,
      };
    }

    if (patchedResult.exitCode === 0 && !patchedResult.timedOut) {
      return {
        id: stageId,
        outcome: 'PASS',
        detail: `Both baseline and patched ${stageId} passed successfully`,
        durationMs: Date.now() - startTime,
        argv: [command.command, ...command.args],
        exitCode: 0,
        baselineExitCode: 0,
        outputSha256: patchedResult.outputSha256,
        outputTail: patchedResult.outputTail,
      };
    }

    // 3. Patched Failed: Rerun once to detect flakiness
    let rerunResult: SandboxRunResult | null = null;
    try {
      rerunResult = await patchedBackend.run(command.command, command.args, runOpts);
    } catch {
      // Keep original failure
    }

    if (rerunResult && rerunResult.exitCode === 0 && !rerunResult.timedOut) {
      return {
        id: stageId,
        outcome: 'PASS',
        detail: `Patched ${stageId} passed on re-run (flakiness resolved)`,
        durationMs: Date.now() - startTime,
        argv: [command.command, ...command.args],
        exitCode: 0,
        baselineExitCode: 0,
        flakyRerun: true,
        outputSha256: rerunResult.outputSha256,
        outputTail: rerunResult.outputTail,
      };
    }

    // Still fails => FAIL (regression detected)
    return {
      id: stageId,
      outcome: 'FAIL',
      detail: `Patched ${stageId} failed (exit code ${patchedResult.exitCode}), introducing a regression against clean baseline`,
      durationMs: Date.now() - startTime,
      argv: [command.command, ...command.args],
      exitCode: patchedResult.exitCode,
      baselineExitCode: baselineResult.exitCode,
      outputSha256: patchedResult.outputSha256,
      outputTail: patchedResult.outputTail,
    };
  }
}
