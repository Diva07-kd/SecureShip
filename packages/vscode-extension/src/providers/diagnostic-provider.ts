import * as path from 'node:path';
import * as vscode from 'vscode';
import type { ExtNormalizedFinding, ExtSeverity } from '../types/extension-types.js';

const SEVERITY_MAP: Record<ExtSeverity, vscode.DiagnosticSeverity> = {
  CRITICAL: vscode.DiagnosticSeverity.Error,
  HIGH: vscode.DiagnosticSeverity.Error,
  MEDIUM: vscode.DiagnosticSeverity.Warning,
  LOW: vscode.DiagnosticSeverity.Information,
  INFO: vscode.DiagnosticSeverity.Hint,
};

const SEVERITY_RANK: Record<ExtSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

/**
 * Transforms NormalizedFinding instances into VS Code Diagnostic squiggles
 * and publishes them to the editor.
 */
export class SecureShipDiagnosticProvider implements vscode.Disposable {
  private readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection('secureship');
  }

  /**
   * Publishes findings to the diagnostic collection.
   * Filters findings below `minSeverity` threshold.
   */
  public publish(
    findings: ExtNormalizedFinding[],
    workspaceRoot: string,
    minSeverity: ExtSeverity = 'INFO'
  ): void {
    this.collection.clear();

    const minRank = SEVERITY_RANK[minSeverity] ?? SEVERITY_RANK.INFO;
    const qualifying = findings.filter((f) => (SEVERITY_RANK[f.severity] ?? 0) >= minRank);

    if (qualifying.length === 0) {
      return;
    }

    const grouped = new Map<string, { uri: vscode.Uri; diags: vscode.Diagnostic[] }>();

    for (const finding of qualifying) {
      const fullPath = path.isAbsolute(finding.location.filePath)
        ? finding.location.filePath
        : path.resolve(workspaceRoot, finding.location.filePath);

      const uri = vscode.Uri.file(fullPath);
      const uriKey = uri.fsPath || fullPath;

      const startLine = Math.max(0, (finding.location.startLine || 1) - 1);
      const endLine = Math.max(
        startLine,
        (finding.location.endLine || finding.location.startLine || 1) - 1
      );
      const startCol = finding.location.startColumn ?? 0;
      const endCol = finding.location.endColumn ?? Number.MAX_SAFE_INTEGER;

      const range = new vscode.Range(startLine, startCol, endLine, endCol);
      const message = finding.title
        ? `${finding.title}: ${finding.description}`
        : finding.description;

      const diagnostic = new vscode.Diagnostic(range, message, SEVERITY_MAP[finding.severity]);

      diagnostic.source = `SecureShip (${finding.scannerName})`;
      diagnostic.code = {
        value: finding.ruleId,
        target: vscode.Uri.parse(
          `https://secureship.dev/rules/${encodeURIComponent(finding.ruleId)}`
        ),
      };

      let entry = grouped.get(uriKey);
      if (!entry) {
        entry = { uri, diags: [] };
        grouped.set(uriKey, entry);
      }
      entry.diags.push(diagnostic);
    }

    for (const entry of grouped.values()) {
      this.collection.set(entry.uri, entry.diags);
    }
  }

  /**
   * Clears all diagnostic squiggles from the editor.
   */
  public clear(): void {
    this.collection.clear();
  }

  public dispose(): void {
    this.collection.dispose();
  }
}
