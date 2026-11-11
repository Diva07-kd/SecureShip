import * as vscode from 'vscode';
import { findSecureShipCli, promptCliInstall } from './cli/cli-locator.js';
import { runStatusCheck } from './cli/cli-runner.js';
import { SecureShipCodeActionProvider } from './providers/code-action-provider.js';
import { SecureShipDiagnosticProvider } from './providers/diagnostic-provider.js';
import { SecureShipHoverProvider } from './providers/hover-provider.js';
import { FindingsPanelProvider } from './panel/findings-panel.js';
import { WorkspaceScanner } from './scanner/workspace-scanner.js';
import { SecureShipStatusBar } from './status/status-bar.js';
import type { ExtSeverity } from './types/extension-types.js';

let activeScanner: WorkspaceScanner | undefined;
let activeDiagnosticProvider: SecureShipDiagnosticProvider | undefined;

/**
 * Extension entry point activated according to activationEvents in package.json.
 */
export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const cliPath = await findSecureShipCli();

  // Graceful degradation when CLI is missing
  if (!cliPath) {
    promptCliInstall();

    const missingCliBar = new SecureShipStatusBar();
    missingCliBar.updateFromScanState({
      status: 'error',
      errorMessage: 'SecureShip CLI not found. Run "npm install -g @secureship/cli"',
    });
    context.subscriptions.push(missingCliBar);

    context.subscriptions.push(
      vscode.commands.registerCommand('secureship.installCli', () => {
        promptCliInstall();
      }),
      vscode.commands.registerCommand('secureship.scanWorkspace', () => {
        promptCliInstall();
      }),
      vscode.commands.registerCommand('secureship.openFindings', () => {
        promptCliInstall();
      }),
      vscode.commands.registerCommand('secureship.showStatus', () => {
        promptCliInstall();
      })
    );
    return;
  }

  // 1. Instantiate core engine providers
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd();

  const diagnosticProvider = new SecureShipDiagnosticProvider();
  activeDiagnosticProvider = diagnosticProvider;

  const hoverProvider = new SecureShipHoverProvider();
  const codeActionProvider = new SecureShipCodeActionProvider();
  const statusBar = new SecureShipStatusBar();
  const findingsPanel = new FindingsPanelProvider();
  const scanner = new WorkspaceScanner(cliPath, workspaceRoot);
  activeScanner = scanner;

  // 2. Register Views
  const treeView = vscode.window.registerTreeDataProvider('secureship.findingsView', findingsPanel);

  // 3. Register Language Providers
  const HOVER_LANGUAGES: vscode.DocumentSelector = [
    { language: 'typescript' },
    { language: 'javascript' },
    { language: 'typescriptreact' },
    { language: 'javascriptreact' },
    { language: 'json' },
  ];

  const CODE_ACTION_LANGUAGES: vscode.DocumentSelector = [
    { language: 'typescript' },
    { language: 'javascript' },
    { language: 'typescriptreact' },
    { language: 'javascriptreact' },
    { language: 'python' },
  ];

  const hoverReg = vscode.languages.registerHoverProvider(HOVER_LANGUAGES, hoverProvider);

  const codeActionReg = vscode.languages.registerCodeActionsProvider(
    CODE_ACTION_LANGUAGES,
    codeActionProvider,
    {
      providedCodeActionKinds: SecureShipCodeActionProvider.providedCodeActionKinds,
    }
  );

  // 4. Register Commands
  const cmdScan = vscode.commands.registerCommand('secureship.scanWorkspace', () => {
    void scanner.scanNow();
  });

  const cmdOpenFindings = vscode.commands.registerCommand('secureship.openFindings', () => {
    void vscode.commands.executeCommand('secureship.findingsView.focus');
  });

  const cmdInstallCli = vscode.commands.registerCommand('secureship.installCli', () => {
    const terminal = vscode.window.createTerminal('SecureShip CLI Install');
    terminal.show();
    terminal.sendText('npm install -g @secureship/cli');
  });

  const cmdShowStatus = vscode.commands.registerCommand('secureship.showStatus', async () => {
    const status = await runStatusCheck(cliPath, workspaceRoot);
    if (status) {
      statusBar.setTier(status.tier);
      const usage = status.monthlyAiUsage
        ? ` (AI usage: ${status.monthlyAiUsage.used}/${status.monthlyAiUsage.limit})`
        : '';
      void vscode.window.showInformationMessage(
        `SecureShip License: ${status.tier} | Status: ${status.status}${usage}`
      );
    } else {
      void vscode.window.showWarningMessage(
        'SecureShip: Unable to retrieve license tier status from CLI.'
      );
    }
  });

  const cmdExplainFinding = vscode.commands.registerCommand(
    'secureship.explainFinding',
    (arg: unknown) => {
      let target = '';
      if (typeof arg === 'string') {
        target = arg;
      } else if (arg && typeof arg === 'object') {
        const anyArg = arg as Record<string, unknown>;
        target =
          (anyArg.fingerprint as string) ||
          (anyArg.id as string) ||
          (anyArg.ruleId as string) ||
          '';
      }

      const terminal = vscode.window.createTerminal('SecureShip Explain');
      terminal.show();
      terminal.sendText(`secureship explain ${target}`.trim());
    }
  );

  const cmdFixFinding = vscode.commands.registerCommand('secureship.fixFinding', (arg: unknown) => {
    let target = '';
    if (typeof arg === 'string') {
      target = arg;
    } else if (arg && typeof arg === 'object') {
      const anyArg = arg as Record<string, unknown>;
      target =
        (anyArg.fingerprint as string) || (anyArg.id as string) || (anyArg.ruleId as string) || '';
    }

    const terminal = vscode.window.createTerminal('SecureShip Sandbox Fix');
    terminal.show();
    terminal.sendText(`secureship fix ${target}`.trim());
  });

  // 5. Connect scanner state events to all UI providers
  const stateSub = scanner.onStateChange((state) => {
    statusBar.updateFromScanState(state);

    if (state.status === 'complete' && state.lastReport) {
      const config = vscode.workspace.getConfiguration('secureship');
      const minSeverity = config.get<ExtSeverity>('failOnSeverity') ?? 'HIGH';

      diagnosticProvider.publish(state.lastReport.findings, workspaceRoot, minSeverity);
      hoverProvider.updateFindings(state.lastReport.findings);
      codeActionProvider.updateFindings(state.lastReport.findings);
      findingsPanel.updateReport(state.lastReport);
    } else if (state.status === 'error') {
      findingsPanel.updateReport(null);
    }
  });

  // 6. Rescan on save (excluding ignored directories)
  const saveSub = vscode.workspace.onDidSaveTextDocument((doc) => {
    const p = doc.uri.fsPath.replace(/\\/g, '/');
    if (
      p.includes('/node_modules/') ||
      p.includes('/.git/') ||
      p.includes('/dist/') ||
      p.includes('/.secureship/')
    ) {
      return;
    }
    scanner.scheduleDebounced();
  });

  // 7. Background status and initial scan
  void runStatusCheck(cliPath, workspaceRoot).then((status) => {
    if (status) {
      statusBar.setTier(status.tier);
    }
  });

  void scanner.scanNow();

  // 8. Welcome notification
  void vscode.window
    .showInformationMessage('SecureShip Security Engine is active.', 'Scan Now')
    .then((choice) => {
      if (choice === 'Scan Now') {
        void scanner.scanNow();
      }
    });

  // 9. Push all disposables
  context.subscriptions.push(
    diagnosticProvider,
    statusBar,
    scanner,
    treeView,
    hoverReg,
    codeActionReg,
    cmdScan,
    cmdOpenFindings,
    cmdInstallCli,
    cmdShowStatus,
    cmdExplainFinding,
    cmdFixFinding,
    stateSub,
    saveSub
  );
}

/**
 * Cleanly cancels active scans and purges editor diagnostics upon extension deactivation.
 */
export function deactivate(): void {
  activeScanner?.cancelAll();
  activeDiagnosticProvider?.clear();
}
