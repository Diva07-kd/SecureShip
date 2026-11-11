import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import EventEmitter from 'node:events';
import { describe, expect, it, beforeEach, afterEach, vi, type MockInstance } from 'vitest';
import { ScanCommand, type ScanCommandOptions } from '../../src/commands/scan.js';

class MockFSWatcher extends EventEmitter {
  public close = vi.fn().mockImplementation(() => Promise.resolve());
}

let activeMockWatcher: MockFSWatcher;

vi.mock('chokidar', () => {
  return {
    watch: vi.fn(() => activeMockWatcher),
    default: {
      watch: vi.fn(() => activeMockWatcher),
    },
  };
});

describe('Watch Mode Engine Suite — chokidar Integration (Phase 2)', () => {
  let tempDir: string;
  let runSpy: MockInstance<typeof ScanCommand.run>;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-watch-mode-'));
    activeMockWatcher = new MockFSWatcher();
    runSpy = vi.spyOn(ScanCommand, 'run').mockResolvedValue(0);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('runWatch() calls initial full scan before starting watcher', async () => {
    const watchPromise = ScanCommand.runWatch(tempDir, { noColor: true });

    await vi.waitFor(() => {
      expect(runSpy).toHaveBeenCalledTimes(1);
    });
    expect(runSpy).toHaveBeenCalledWith(tempDir, expect.objectContaining({ watch: false }));

    process.emit('SIGINT');
    const exitCode = await watchPromise;
    expect(exitCode).toBe(0);
  });

  it('runWatch() triggers rescan with supplyChainOnly:true when package.json changes', async () => {
    const watchPromise = ScanCommand.runWatch(tempDir, { noColor: true });

    await vi.waitFor(() => {
      expect(runSpy).toHaveBeenCalledTimes(1);
    });

    vi.useFakeTimers();

    const pkgPath = path.resolve(tempDir, 'package.json');
    activeMockWatcher.emit('change', pkgPath);

    expect(runSpy).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(350);

    expect(runSpy).toHaveBeenCalledTimes(2);
    expect(runSpy).toHaveBeenLastCalledWith(
      tempDir,
      expect.objectContaining({
        watch: false,
        supplyChainOnly: true,
      })
    );

    vi.useRealTimers();
    process.emit('SIGINT');
    const exitCode = await watchPromise;
    expect(exitCode).toBe(0);
  });

  it('runWatch() triggers full rescan when .ts file changes', async () => {
    const watchPromise = ScanCommand.runWatch(tempDir, { noColor: true });

    await vi.waitFor(() => {
      expect(runSpy).toHaveBeenCalledTimes(1);
    });

    vi.useFakeTimers();

    const tsPath = path.resolve(tempDir, 'src/index.ts');
    activeMockWatcher.emit('change', tsPath);

    await vi.advanceTimersByTimeAsync(350);

    expect(runSpy).toHaveBeenCalledTimes(2);
    const secondCall = runSpy.mock.calls[1];
    expect(secondCall).toBeDefined();
    const secondCallOpts = secondCall![1] as ScanCommandOptions;
    expect(secondCallOpts.watch).toBe(false);
    expect(secondCallOpts.supplyChainOnly).toBeUndefined();

    vi.useRealTimers();
    process.emit('SIGINT');
    const exitCode = await watchPromise;
    expect(exitCode).toBe(0);
  });

  it('runWatch() debounces rapid file events to single scan', async () => {
    const watchPromise = ScanCommand.runWatch(tempDir, { noColor: true });

    await vi.waitFor(() => {
      expect(runSpy).toHaveBeenCalledTimes(1);
    });

    vi.useFakeTimers();

    activeMockWatcher.emit('change', path.resolve(tempDir, 'src/a.ts'));
    vi.advanceTimersByTime(50);
    activeMockWatcher.emit('change', path.resolve(tempDir, 'src/b.ts'));
    vi.advanceTimersByTime(50);
    activeMockWatcher.emit('change', path.resolve(tempDir, 'src/c.ts'));
    vi.advanceTimersByTime(50);
    activeMockWatcher.emit('change', path.resolve(tempDir, 'src/d.ts'));
    vi.advanceTimersByTime(50);
    activeMockWatcher.emit('change', path.resolve(tempDir, 'src/e.ts'));

    expect(runSpy).toHaveBeenCalledTimes(1);

    await vi.advanceTimersByTimeAsync(350);

    expect(runSpy).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
    process.emit('SIGINT');
    const exitCode = await watchPromise;
    expect(exitCode).toBe(0);
  });

  it('runWatch() resolves on SIGINT without dangling timers', async () => {
    const watchPromise = ScanCommand.runWatch(tempDir, { noColor: true });

    await vi.waitFor(() => {
      expect(runSpy).toHaveBeenCalledTimes(1);
    });

    process.emit('SIGINT');

    const exitCode = await watchPromise;
    expect(exitCode).toBe(0);
    expect(activeMockWatcher.close).toHaveBeenCalledTimes(1);
  });
});
