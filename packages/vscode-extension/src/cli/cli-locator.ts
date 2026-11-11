import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import * as vscode from 'vscode';

/**
 * Resolves the path to the `secureship` CLI binary.
 *
 * Priority order:
 * 1. VSCode setting `secureship.cliPath` (if configured and file exists)
 * 2. `~/.secureship/bin/secureship[.exe]` (Phase 1 install-tools default)
 * 3. System PATH via `which secureship` / `where secureship`
 */
export async function findSecureShipCli(): Promise<string | null> {
  // 1. Check user configuration
  const config = vscode.workspace.getConfiguration('secureship');
  const userPath = config.get<string>('cliPath')?.trim();
  if (userPath && fs.existsSync(userPath)) {
    return userPath;
  }

  // 2. Check ~/.secureship/bin
  const home = os.homedir();
  const binDir = path.join(home, '.secureship', 'bin');
  const primaryBin = path.join(
    binDir,
    process.platform === 'win32' ? 'secureship.exe' : 'secureship'
  );
  const fallbackBin = path.join(binDir, 'secureship');

  if (fs.existsSync(primaryBin)) {
    return primaryBin;
  }
  if (primaryBin !== fallbackBin && fs.existsSync(fallbackBin)) {
    return fallbackBin;
  }

  // 3. Fallback to system PATH
  try {
    let resolved: string | null = null;
    try {
      const out = execSync('which secureship', {
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'ignore'],
      }).trim();
      if (out) {
        resolved = out.split(/\r?\n/)[0]?.trim() || null;
      }
    } catch {
      if (process.platform === 'win32') {
        try {
          const out = execSync('where secureship', {
            encoding: 'utf-8',
            stdio: ['pipe', 'pipe', 'ignore'],
          }).trim();
          if (out) {
            resolved = out.split(/\r?\n/)[0]?.trim() || null;
          }
        } catch {
          resolved = null;
        }
      }
    }

    if (resolved && fs.existsSync(resolved)) {
      return resolved;
    }
  } catch {
    // Exec failed or binary not found on PATH
  }

  return null;
}

/**
 * Prompts the user with installation actions when the CLI is not found.
 */
export function promptCliInstall(): void {
  void vscode.window
    .showWarningMessage(
      'SecureShip CLI is required for security scans but was not found.',
      'Install via npm',
      'Open Install Docs'
    )
    .then((selection) => {
      if (selection === 'Install via npm') {
        const terminal = vscode.window.createTerminal('SecureShip Install');
        terminal.show();
        terminal.sendText('npm install -g @secureship/cli');
      } else if (selection === 'Open Install Docs') {
        void vscode.env.openExternal(vscode.Uri.parse('https://secureship.dev/docs/installation'));
      }
    });
}
