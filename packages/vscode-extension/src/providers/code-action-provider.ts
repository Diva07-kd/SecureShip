import * as vscode from 'vscode';
import type { ExtNormalizedFinding } from '../types/extension-types.js';

/**
 * Provides quick-fix and investigation code actions for SecureShip diagnostics.
 */
export class SecureShipCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
    vscode.CodeActionKind.Empty,
  ];

  private findings: ExtNormalizedFinding[] = [];

  /**
   * Updates cached findings from the latest scan report.
   */
  public updateFindings(findings: ExtNormalizedFinding[]): void {
    this.findings = findings;
  }

  public provideCodeActions(
    _document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    const secureshipDiags = context.diagnostics.filter(
      (d) => d.source && d.source.startsWith('SecureShip')
    );

    for (const diag of secureshipDiags) {
      let ruleId = 'Security Issue';
      if (typeof diag.code === 'string') {
        ruleId = diag.code;
      } else if (diag.code && typeof diag.code === 'object' && 'value' in diag.code) {
        ruleId = String(diag.code.value);
      }

      // Find matching finding by ruleId and approximate line
      const lineNum = diag.range.start.line + 1; // 1-indexed
      const matchingFinding = this.findings.find(
        (f) => f.ruleId === ruleId && Math.abs(f.location.startLine - lineNum) <= 1
      );

      // Action 1: Explain finding with AI Triage
      const explainAction = new vscode.CodeAction(
        `SecureShip: Explain finding (${ruleId})`,
        vscode.CodeActionKind.QuickFix
      );
      explainAction.diagnostics = [diag];
      explainAction.isPreferred = false;
      explainAction.command = {
        command: 'secureship.explainFinding',
        title: 'Explain with SecureShip',
        arguments: [matchingFinding || diag],
      };
      actions.push(explainAction);

      // Action 2: Quick-Fix if fix recommendation exists
      if (matchingFinding?.fixRecommendation) {
        const fixAction = new vscode.CodeAction(
          `SecureShip: Quick-fix with Gate 4 Sandbox (${ruleId})`,
          vscode.CodeActionKind.QuickFix
        );
        fixAction.diagnostics = [diag];
        fixAction.isPreferred = true;
        fixAction.command = {
          command: 'secureship.fixFinding',
          title: 'Quick-fix with SecureShip Sandbox',
          arguments: [matchingFinding],
        };
        actions.push(fixAction);
      }

      // Action 3: Focus Findings View in sidebar
      const viewAction = new vscode.CodeAction(
        'SecureShip: View in Findings Panel',
        vscode.CodeActionKind.Empty
      );
      viewAction.command = {
        command: 'secureship.openFindings',
        title: 'Focus Findings Panel',
      };
      actions.push(viewAction);
    }

    return actions;
  }
}
