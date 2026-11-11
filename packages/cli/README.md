# @secureship/cli

> Zero-False-Positive DevSecOps Intelligence Engine & Verification Platform

The CLI for SecureShip provides automated security scanning, reachability-based triage, automated tooling provisioning (`secureship install-tools`), and AI-assisted remediation.

## Installation

```bash
npm install -g @secureship/cli
```

Or run via npx:

```bash
npx @secureship/cli doctor
```

## Commands Overview

- `secureship doctor`: Run system diagnostics, verify Node/Git environment, check scanner binaries, and inspect AI configuration.
- `secureship install-tools`: Zero-telemetry, cross-platform installer for external security scanners (`opengrep`, `gitleaks`, `trivy`, `osv-scanner`).
- `secureship scan [path]`: Run multi-scanner security analysis pipeline with Gate 1 scope filtering, Gate 2 reachability, and Gate 3 AI triage.
- `secureship detect [path]`: Analyze project stack, languages, lockfiles, and test/mock folders.
- `secureship graph [path]`: Build and inspect whole-repository import dependency graph.
- `secureship fix`: Generate and verify remediation patches for security findings.

## License

Apache-2.0
