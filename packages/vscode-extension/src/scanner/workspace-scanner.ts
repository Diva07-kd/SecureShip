import * as vscode from 'vscode';
import { runScan, type RunScanOptions } from '../cli/cli-runner.js';
import type { ScanState } from '../types/extension-types.js';
import { ScanDebouncer } from './scan-debouncer.js';

/**
 * Orchestrates security scans across the active workspace, manages
 * scan states, and notifies observers of changes.
 */
export class WorkspaceScanner implements vscode.Disposable {
  private state: ScanState = { status: 'idle', lastReport: null };
  private listeners: Array<(state: ScanState) => void> = [];
  private debouncer: ScanDebouncer;
  private immediateAbortController: AbortController | null = null;

  constructor(
    public readonly cliPath: string,
    public readonly workspaceRoot: string
  ) {
    const config = vscode.workspace.getConfiguration('secureship');
    const debounceMs = config.get<number>('scanDebounceMs') ?? 1500;
    this.debouncer = new ScanDebouncer(debounceMs);
  }

  /**
   * Registers a listener for scan state transitions.
   */
  public onStateChange(listener: (state: ScanState) => void): vscode.Disposable {
    this.listeners.push(listener);
    // Immediate callback with current state
    listener(this.state);
    return {
      dispose: () => {
        const index = this.listeners.indexOf(listener);
        if (index >= 0) {
          this.listeners.splice(index, 1);
        }
      },
    };
  }

  public getState(): ScanState {
    return this.state;
  }

  private setState(nextState: ScanState): void {
    this.state = nextState;
    for (const listener of this.listeners) {
      try {
        listener(this.state);
      } catch {
        // Observers should not crash scanner
      }
    }
  }

  /**
   * Schedules a scan debounced by `secureship.scanDebounceMs`.
   * Respects the `secureship.autoScanOnSave` setting.
   */
  public scheduleDebounced(): void {
    const config = vscode.workspace.getConfiguration('secureship');
    const autoScan = config.get<boolean>('autoScanOnSave') ?? true;
    if (!autoScan) {
      return;
    }

    this.debouncer.schedule((signal) => this.executeScan(signal));
  }

  /**
   * Immediately triggers a workspace scan, bypassing debounce timers.
   */
  public async scanNow(): Promise<void> {
    this.debouncer.cancelAll();

    if (this.immediateAbortController) {
      this.immediateAbortController.abort();
    }
    this.immediateAbortController = new AbortController();
    const signal = this.immediateAbortController.signal;

    try {
      await this.executeScan(signal);
    } finally {
      if (this.immediateAbortController?.signal === signal) {
        this.immediateAbortController = null;
      }
    }
  }

  /**
   * Core scan execution pipeline.
   */
  public async executeScan(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) {
      return;
    }

    this.setState({
      status: 'scanning',
      lastReport: this.state.lastReport,
      lastScanAt: this.state.lastScanAt,
    });

    const config = vscode.workspace.getConfiguration('secureship');
    const gate2Mode = config.get<'annotate' | 'suppress' | 'off'>('gate2Mode') ?? 'annotate';
    const supplyChainOnly = config.get<boolean>('supplyChainOnly') ?? false;

    const options: RunScanOptions = {
      gate2Mode,
      supplyChainOnly,
    };

    const report = await runScan(this.cliPath, this.workspaceRoot, signal, options);

    if (signal?.aborted) {
      return;
    }

    if (report !== null) {
      this.setState({
        status: 'complete',
        lastReport: report,
        lastScanAt: new Date(),
      });
    } else {
      this.setState({
        status: 'error',
        errorMessage: 'Security analysis failed or timed out',
        lastReport: this.state.lastReport,
      });
    }
  }

  /**
   * Cancels in-flight and scheduled scans.
   */
  public cancelAll(): void {
    this.debouncer.cancelAll();
    if (this.immediateAbortController) {
      this.immediateAbortController.abort();
      this.immediateAbortController = null;
    }
  }

  public dispose(): void {
    this.cancelAll();
    this.listeners = [];
  }
}
