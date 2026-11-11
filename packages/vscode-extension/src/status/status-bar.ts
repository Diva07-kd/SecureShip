import * as vscode from 'vscode';
import type { ExtLicenseTier, ScanState } from '../types/extension-types.js';

export function formatTierLabel(tier?: ExtLicenseTier): string {
  switch (tier) {
    case 'ENTERPRISE':
      return 'ENT';
    case 'PRO_TEAM':
      return 'PRO';
    case 'FREE_BYOK':
    default:
      return 'FREE';
  }
}

/**
 * Manages the SecureShip persistent status bar indicator, updating its
 * Codicon icon, severity badge, and license tier in real-time.
 */
export class SecureShipStatusBar implements vscode.Disposable {
  private readonly item: vscode.StatusBarItem;
  private tierLabel: string = 'FREE';

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.item.command = 'secureship.openFindings';
    this.item.text = '$(shield) SecureShip';
    this.item.tooltip = 'SecureShip: Ready to scan';
    this.item.show();
  }

  /**
   * Sets the active license tier badge label ('FREE' | 'PRO' | 'ENT').
   */
  public setTier(tier?: ExtLicenseTier): void {
    this.tierLabel = formatTierLabel(tier);
  }

  /**
   * Synchronizes status bar text, theme-adaptive background accents,
   * and tooltips based on current ScanState.
   */
  public updateFromScanState(state: ScanState): void {
    switch (state.status) {
      case 'idle':
        this.item.text = '$(shield) SecureShip';
        this.item.backgroundColor = undefined;
        this.item.tooltip = 'SecureShip: Ready to scan';
        break;

      case 'scanning':
        this.item.text = '$(sync~spin) SecureShip: Scanning...';
        this.item.backgroundColor = undefined;
        this.item.tooltip = 'SecureShip: Analysis in progress...';
        break;

      case 'error':
        this.item.text = '$(error) SecureShip: Scan failed';
        this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        this.item.tooltip = state.errorMessage ?? 'SecureShip scan failed';
        break;

      case 'complete': {
        const findings = state.lastReport?.findings ?? [];
        const crits = findings.filter((f) => f.severity === 'CRITICAL').length;
        const highs = findings.filter((f) => f.severity === 'HIGH').length;
        const total = findings.length;

        if (crits > 0) {
          this.item.text = `$(error) SecureShip: ${crits} CRITICAL, ${highs} HIGH | ${this.tierLabel}`;
          this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
          this.item.tooltip = `${total} finding(s) detected (${crits} CRITICAL, ${highs} HIGH)`;
        } else if (highs > 0) {
          this.item.text = `$(warning) SecureShip: ${highs} HIGH | ${this.tierLabel}`;
          this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
          this.item.tooltip = `${total} finding(s) detected (${highs} HIGH)`;
        } else if (total > 0) {
          this.item.text = `$(shield) SecureShip: ${total} finding(s) | ${this.tierLabel}`;
          this.item.backgroundColor = undefined;
          this.item.tooltip = `${total} non-critical finding(s) detected`;
        } else {
          this.item.text = `$(pass) SecureShip: No findings | ${this.tierLabel}`;
          this.item.backgroundColor = undefined;
          this.item.tooltip = 'SecureShip: Clean workspace, no findings detected';
        }
        break;
      }
    }
  }

  public dispose(): void {
    this.item.dispose();
  }
}
