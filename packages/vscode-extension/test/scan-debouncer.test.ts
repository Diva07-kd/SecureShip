import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ScanDebouncer } from '../src/scanner/scan-debouncer.js';

describe('ScanDebouncer', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('calls callback exactly once after debounce delay', async () => {
    const debouncer = new ScanDebouncer(300);
    let callCount = 0;

    debouncer.schedule(() => {
      callCount++;
    });

    expect(callCount).toBe(0);

    await vi.advanceTimersByTimeAsync(350);

    expect(callCount).toBe(1);
  });

  it('coalesces 5 rapid triggers into exactly 1 callback execution', async () => {
    const debouncer = new ScanDebouncer(300);
    let callCount = 0;

    for (let i = 0; i < 5; i++) {
      debouncer.schedule(() => {
        callCount++;
      });
      await vi.advanceTimersByTimeAsync(50);
    }

    // 250ms elapsed, delay is 300ms from last schedule
    expect(callCount).toBe(0);

    await vi.advanceTimersByTimeAsync(400);

    expect(callCount).toBe(1);
  });

  it('does NOT call callback after cancelAll() before timer fires', async () => {
    const debouncer = new ScanDebouncer(300);
    let callCount = 0;

    debouncer.schedule(() => {
      callCount++;
    });

    debouncer.cancelAll();

    await vi.advanceTimersByTimeAsync(500);

    expect(callCount).toBe(0);
  });

  it('AbortSignal is NOT aborted during normal execution', async () => {
    const debouncer = new ScanDebouncer(200);
    let capturedAborted: boolean | null = null;

    debouncer.schedule((signal) => {
      capturedAborted = signal.aborted;
    });

    await vi.advanceTimersByTimeAsync(250);

    expect(capturedAborted).toBe(false);
  });

  it('AbortSignal IS aborted when second scan triggers before first completes', async () => {
    const debouncer = new ScanDebouncer(200);
    let firstSignal: AbortSignal | null = null;
    let resolveFirstScan: () => void = () => {};
    const firstScanPromise = new Promise<void>((resolve) => {
      resolveFirstScan = resolve;
    });

    debouncer.schedule(async (signal) => {
      firstSignal = signal;
      await firstScanPromise;
    });

    // Advance past delay to start first scan
    await vi.advanceTimersByTimeAsync(250);
    expect(firstSignal).not.toBeNull();
    expect((firstSignal as unknown as AbortSignal).aborted).toBe(false);

    // Trigger second scan while first is blocked
    let secondRan = false;
    debouncer.schedule(() => {
      secondRan = true;
    });

    // The first signal should be aborted immediately upon scheduling
    expect((firstSignal as unknown as AbortSignal).aborted).toBe(true);

    // Advance timers so second scan runs
    await vi.advanceTimersByTimeAsync(250);
    resolveFirstScan();

    expect(secondRan).toBe(true);
    expect((firstSignal as unknown as AbortSignal).aborted).toBe(true);
  });

  it("independent ScanDebouncer instances don't interfere with each other", async () => {
    const debouncer1 = new ScanDebouncer(150);
    const debouncer2 = new ScanDebouncer(250);

    let count1 = 0;
    let count2 = 0;

    debouncer1.schedule(() => {
      count1++;
    });
    debouncer2.schedule(() => {
      count2++;
    });

    await vi.advanceTimersByTimeAsync(180);
    expect(count1).toBe(1);
    expect(count2).toBe(0);

    await vi.advanceTimersByTimeAsync(100);
    expect(count1).toBe(1);
    expect(count2).toBe(1);
    expect(count1 + count2).toBe(2);
  });
});
