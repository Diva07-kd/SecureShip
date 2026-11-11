/**
 * Manages debounced scan scheduling with AbortSignal cancellation.
 * Ensures in-flight scans are aborted if a new scan triggers before
 * the previous one finishes.
 */
export class ScanDebouncer {
  private timer: NodeJS.Timeout | null = null;
  private runningController: AbortController | null = null;
  private pendingController: AbortController | null = null;

  constructor(private readonly delayMs: number) {}

  /**
   * Schedules a scan callback after the configured debounce delay.
   * If an in-flight execution is currently active, it is immediately aborted.
   * If a timer is already pending, it is reset.
   */
  public schedule(callback: (signal: AbortSignal) => Promise<void> | void): void {
    if (this.runningController) {
      this.runningController.abort();
      this.runningController = null;
    }

    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.pendingController) {
      this.pendingController.abort();
      this.pendingController = null;
    }

    const controller = new AbortController();
    this.pendingController = controller;

    this.timer = setTimeout(async () => {
      this.timer = null;
      this.pendingController = null;
      this.runningController = controller;

      try {
        await callback(controller.signal);
      } finally {
        if (this.runningController === controller) {
          this.runningController = null;
        }
      }
    }, this.delayMs);
  }

  /**
   * Cancels any pending debounced timer and aborts active in-flight executions.
   */
  public cancelAll(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.pendingController) {
      this.pendingController.abort();
      this.pendingController = null;
    }

    if (this.runningController) {
      this.runningController.abort();
      this.runningController = null;
    }
  }
}
