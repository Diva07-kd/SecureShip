# SecureShip Security & Threat Engine

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![VS Code](https://img.shields.io/badge/vscode-^1.85.0-blueviolet.svg)](https://code.visualstudio.com/)

**SecureShip** is an enterprise-grade, real-time SAST, SCA, Secrets, and Supply-Chain security scanning extension for Visual Studio Code. Powered by the local SecureShip intelligence engine, it features AST reachability analysis (Gate 2) and automated sandbox fixes (Gate 4) to eliminate alert fatigue and fix vulnerabilities instantly.

---

## Key Features

- **Inline Diagnostic Squiggles**: Highlights vulnerabilities in your code in real-time as you write and save files, color-coded by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Interactive Supply-Chain Threat Cards**: Hover over any dependency import (`import x from 'package'` or `require('package')`) to view an interactive threat card with vulnerability metrics, installed vs safe versions, and quick-fix actions.
- **AST Reachability Verification (Gate 2)**: Automatically distinguishes between reachable vulnerable functions and inert dead code, drastically reducing false positives.
- **Automated Sandbox Fixes (Gate 4)**: One-click AI remediation tested in an isolated sandbox before applying diffs to your workspace.
- **Findings Sidebar Panel**: Dedicated view in the Activity Bar grouping vulnerabilities hierarchically by severity with direct file navigation.
- **Status Bar Integration**: Real-time scan indicators, issue counts, and tier badges right on your status bar.
- **Zero Telemetry & 100% Privacy**: All analysis executes strictly on your local machine using the SecureShip CLI child process. Your source code never leaves your workstation.

---

## Extension Settings

| Setting                      | Type      | Default      | Description                                                                                          |
| :--------------------------- | :-------- | :----------- | :--------------------------------------------------------------------------------------------------- |
| `secureship.cliPath`         | `string`  | `""`         | Path to `secureship` binary. If empty, automatically resolves from `~/.secureship/bin` or `PATH`.    |
| `secureship.autoScanOnSave`  | `boolean` | `true`       | Automatically trigger background security scans when source files are saved.                         |
| `secureship.scanDebounceMs`  | `number`  | `1500`       | Debounce delay in milliseconds before scanning on save.                                              |
| `secureship.failOnSeverity`  | `string`  | `"HIGH"`     | Minimum severity threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).                            |
| `secureship.gate2Mode`       | `string`  | `"annotate"` | Reachability mode: `annotate` (mark reachable/unreachable), `suppress` (hide unreachable), or `off`. |
| `secureship.supplyChainOnly` | `boolean` | `false`      | Run supply-chain threat engine exclusively without invoking external SAST scanners.                  |

---

## Commands

- `SecureShip: Scan Workspace` (`secureship.scanWorkspace`): Immediately triggers a full workspace security scan.
- `SecureShip: Focus Findings Panel` (`secureship.openFindings`): Focuses the vulnerability tree view in the sidebar.
- `SecureShip: Show License & Tier Status` (`secureship.showStatus`): Displays current license tier and monthly AI usage.
- `SecureShip: Install CLI Tools` (`secureship.installCli`): Opens an integrated terminal to install the SecureShip CLI.

---

## Design System & Theme Adaptivity

The SecureShip extension conforms strictly to the VS Code UI Design System:

- **Zero Hardcoded Colors**: All colors dynamically bind to official VS Code Theme tokens (`var(--vscode-editor-background)`, `var(--vscode-editorError-foreground)`, etc.), ensuring flawless presentation in dark, light, and high-contrast themes.
- **Native Microsoft Codicons**: Built-in vector icons provide crisp, sharp rendering across all display resolutions.

---

## License

SecureShip is licensed under the [Apache-2.0 License](https://www.apache.org/licenses/LICENSE-2.0).
