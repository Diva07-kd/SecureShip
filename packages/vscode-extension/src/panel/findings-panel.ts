import * as path from 'node:path';
import * as vscode from 'vscode';
import type { ExtNormalizedFinding, ExtScanReport, ExtSeverity } from '../types/extension-types.js';

const SEVERITY_ORDER: ExtSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/**
 * TreeItem representation for either a severity category header
 * or a single security vulnerability finding.
 */
export class FindingsTreeItem extends vscode.TreeItem {
  public override label: string;

  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly finding?: ExtNormalizedFinding,
    public readonly severity?: ExtSeverity
  ) {
    super(label, collapsibleState);
    this.label = label;

    if (finding) {
      // Truncate finding title so ruleId + ': ' + title is at most 60 + ruleId chars
      const shortTitle =
        finding.title.length > 58 ? `${finding.title.slice(0, 55)}...` : finding.title;
      this.label = `${finding.ruleId}: ${shortTitle}`;

      this.tooltip = `${finding.ruleId}\n${finding.description}`;
      const fileName = path.basename(finding.location.filePath);
      this.description = `${finding.scannerName} • ${fileName}:${finding.location.startLine}`;

      // Native Codicons with VS Code ThemeColors
      if (finding.severity === 'CRITICAL') {
        this.iconPath = new vscode.ThemeIcon(
          'error',
          new vscode.ThemeColor('editorError.foreground')
        );
      } else if (finding.severity === 'HIGH') {
        this.iconPath = new vscode.ThemeIcon(
          'warning',
          new vscode.ThemeColor('editorWarning.foreground')
        );
      } else if (finding.category === 'SECRET') {
        this.iconPath = new vscode.ThemeIcon('key');
      } else if (finding.category === 'SUPPLY_CHAIN') {
        this.iconPath = new vscode.ThemeIcon('package');
      } else if (finding.severity === 'MEDIUM') {
        this.iconPath = new vscode.ThemeIcon('warning');
      } else {
        this.iconPath = new vscode.ThemeIcon('info');
      }

      // Navigation command on click
      const startLine = Math.max(0, (finding.location.startLine || 1) - 1);
      const endLine = Math.max(
        startLine,
        (finding.location.endLine || finding.location.startLine || 1) - 1
      );
      const startCol = finding.location.startColumn ?? 0;
      const endCol = finding.location.endColumn ?? 0;

      this.command = {
        command: 'vscode.open',
        title: 'Open Finding',
        arguments: [
          vscode.Uri.file(finding.location.filePath),
          {
            selection: new vscode.Range(startLine, startCol, endLine, endCol),
          },
        ],
      };
      this.contextValue = 'secureshipFinding';
    } else if (severity) {
      this.iconPath = new vscode.ThemeIcon('shield');
      this.contextValue = 'secureshipSeverityGroup';
    }
  }
}

/**
 * Provides hierarchical tree data for the SecureShip Explorer findings panel.
 */
export class FindingsPanelProvider implements vscode.TreeDataProvider<FindingsTreeItem> {
  private report: ExtScanReport | null = null;
  private readonly groupedFindings = new Map<ExtSeverity, ExtNormalizedFinding[]>();

  private readonly _onDidChangeTreeData = new vscode.EventEmitter<
    FindingsTreeItem | undefined | void
  >();
  public readonly onDidChangeTreeData: vscode.Event<FindingsTreeItem | undefined | void> =
    this._onDidChangeTreeData.event;

  /**
   * Updates findings from a new ScanReport and refreshes the tree.
   */
  public updateReport(report: ExtScanReport | null): void {
    this.report = report;
    this.groupedFindings.clear();

    if (report && report.findings) {
      for (const severity of SEVERITY_ORDER) {
        const matching = report.findings.filter((f) => f.severity === severity);
        if (matching.length > 0) {
          this.groupedFindings.set(severity, matching);
        }
      }
    }

    this._onDidChangeTreeData.fire();
  }

  public getTreeItem(element: FindingsTreeItem): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: FindingsTreeItem): vscode.ProviderResult<FindingsTreeItem[]> {
    if (element === undefined) {
      // Root level: return severity groups or placeholder
      if (this.report === null) {
        return [new FindingsTreeItem('No scan results', vscode.TreeItemCollapsibleState.None)];
      }

      if (this.report.findings.length === 0) {
        return [new FindingsTreeItem('No findings', vscode.TreeItemCollapsibleState.None)];
      }

      const groups: FindingsTreeItem[] = [];
      for (const severity of SEVERITY_ORDER) {
        const items = this.groupedFindings.get(severity);
        if (items && items.length > 0) {
          const header = new FindingsTreeItem(
            `${severity} (${items.length})`,
            vscode.TreeItemCollapsibleState.Expanded,
            undefined,
            severity
          );
          groups.push(header);
        }
      }
      return groups;
    }

    // Child level: return findings within the clicked severity group
    if (element.severity) {
      const items = this.groupedFindings.get(element.severity) ?? [];
      return items.map(
        (finding) =>
          new FindingsTreeItem(finding.title, vscode.TreeItemCollapsibleState.None, finding)
      );
    }

    return [];
  }
}
