# Changelog

All notable changes to the **SecureShip Security & Threat Engine** extension will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-beta.1] - 2026-10-23

### Added

- **Core Security Engine Integration**:
  - Integrated with local `secureship` CLI runtime for zero-telemetry, fully private security analysis.
  - Multi-engine SAST, SCA, Secrets, and Supply-Chain vulnerability detection.
  - AST-based reachability filtering (Gate 2) to eliminate false positives in downstream dependencies.
- **Real-Time Editor Experience**:
  - Background scanning on document save with 1500ms debounce and AbortSignal cancellation.
  - Inline diagnostic squiggly underlines classified by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - Direct rule documentation links embedded in diagnostic codes (`https://secureship.dev/rules/<ruleId>`).
- **Interactive Supply-Chain Threat Hover Cards**:
  - Rich GitHub-Flavored Markdown table displaying package name, installed version, safe version, and highest severity.
  - Interactive Gate 4 sandbox quick-fix trigger and rule documentation links directly in hover popups.
- **Code Actions & AI Remediation**:
  - Quick-fix code actions for Gate 4 sandbox patch generation.
  - "SecureShip: Explain finding" action triggering contextual AI triage in integrated terminal.
- **Activity Bar & Findings Tree Panel**:
  - Dedicated "SecureShip Security" activity bar container.
  - Hierarchical findings panel grouped by severity (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO`).
  - Native Microsoft Codicons with theme-adaptive accents (`$(shield)`, `$(error)`, `$(warning)`, `$(key)`, `$(package)`, `$(sparkle)`).
- **Theme-Adaptive Status Bar**:
  - Persistent status bar indicator showing scan status, active high/critical counts, and license tier (`FREE`, `PRO`, `ENT`).
  - Strict adherence to VS Code CSS custom properties with zero hardcoded colors.
- **Graceful CLI Detection & Installation**:
  - Priority chain resolution (`secureship.cliPath` setting > `~/.secureship/bin` > system `PATH`).
  - Automatic prompt to install CLI via npm or open documentation if binary is missing.
