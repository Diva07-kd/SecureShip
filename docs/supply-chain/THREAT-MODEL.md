# Supply-Chain Threat Model & Detection Boundaries

This document defines the security threat model, detection capabilities, and known evasion limitations of the SecureShip Supply-Chain Threat Engine.

---

## 1. Threat Vectors Addressed

### Vector A: Installation-Time Compromise

- **Attacker Goal**: Execute arbitrary code on developer workstations or CI/CD builders during dependency resolution (`npm install`, `pnpm install`, `yarn`).
- **Detection**:
  - `SC-INSTALL-001`: Scans lifecycle hooks (`preinstall`, `install`, `postinstall`).
  - `SC-INSTALL-002`: Detects native compiler builds (`binding.gyp`) executed implicitly.
  - `SC-INSTALL-003`: Identifies dangerous remote downloads (`curl`, `wget`), reverse shells, and exfiltration loops.

### Vector B: Identifier and Trojan Source Manipulation

- **Attacker Goal**: Introduce visually indistinguishable malicious logic via Unicode manipulation (CVE-2021-42574 Trojan Source) or homoglyph confusion.
- **Detection**:
  - `SC-UNI-001`: Validates bidirectional embedding balance (RLO, LRO, PDI).
  - `SC-UNI-002`: Identifies invisible/zero-width space characters embedded inside logic tokens.
  - `SC-UNI-003`: Flags mixed-script confusable homoglyphs (e.g. Cyrillic `а` in place of Latin `a`).

### Vector C: Typosquatting and Dependency Confusion

- **Attacker Goal**: Trick developers into installing malicious lookalike packages or hijacking internal package scopes.
- **Detection**:
  - `SC-TYPO-001`: Length-bucketed Damerau-Levenshtein comparison against popular verified packages.
  - `SC-TYPO-002`: Combosquatting detection for suffixes (`-js`, `-node`, `-cli`).
  - `SC-TYPO-003`: Separator collapse (`cross-env` vs `crossenv`).
  - `SC-META-002`: Major version jumps on public registries exceeding internal scope baselines.

### Vector D: Packed and Obfuscated Payloads

- **Attacker Goal**: Hide malicious shellcode or downloader stagers using encryption or minified string encoding.
- **Detection**:
  - `SC-OBF-001`: Shannon entropy filtering on string literals $\ge 64$ characters ($H \ge 4.5$).
  - `SC-OBF-002`: Massive single-line packing ($> 1000$ characters without whitespace).

### Vector E: Metadata and Account Takeover (Governance)

- **Attacker Goal**: Publish backdoored updates to previously reputable packages following maintainer account compromise.
- **Detection**:
  - `SC-META-001`: Backdated or out-of-order release versions.
  - `SC-META-003`: Desynchronization between published tarball `package.json` and registry packument.
  - `SC-GOV-001`: New maintainers publishing packages with newly added install scripts or high capabilities.

---

## 2. Evasion Limitations & Boundaries

| Evasion Technique                                         | Phase 1 Status                                    | Phase 2 Mitigation (Implemented)                                                                                |
| :-------------------------------------------------------- | :------------------------------------------------ | :-------------------------------------------------------------------------------------------------------------- |
| **String concatenation** (`"cu" + "rl"`, `cp['ex'+'ec']`) | Partial detection (regex based)                   | **Mitigated**: Tree-sitter constant-folding and alias tracking in `ast-capability-analyzer.ts`.                 |
| **Pure native C/C++ binaries** (`.node`)                  | Flagged via `SC-INSTALL-002` / `binding.gyp`      | **Mitigated**: Pre-install security gate forbids implicit install scripts; Gate 4 enforces isolated sandbox.    |
| **Time-delayed execution** (sleep 7 days)                 | Flagged via presence of script (`SC-INSTALL-001`) | **Mitigated**: Pre-install gate forbids untrusted install scripts unconditionally on target versions.           |
| **Custom dynamic reflection**                             | Flagged by dynamic eval detector                  | **Mitigated**: Dynamic `require`, `eval`, and debug intern bindings mapped to `SC-CAP-005..007` & combinations. |
| **Air-gapped metadata missing**                           | `metadataUnavailable: true`                       | **Mitigated**: Pure detectors degrade gracefully; `SnapshotProvider` serves deterministic snapshots.            |

---

## 3. AST Capabilities & Combination Alerts (WP4 & WP5)

Lone capabilities (e.g., standard HTTP client or file read) are common in legitimate packages and emit INFO diagnostics (`SC-CAP-001` through `SC-CAP-007`). Zero-day malware relies on lethal combinations:

- `SC-CAP-100` (Network + Environment Access): Exfiltration of environment variables and secrets (HIGH).
- `SC-CAP-101` (Network + Sensitive Filesystem): Exfiltration of credentials (`~/.ssh`, `~/.aws`, `.npmrc`) (CRITICAL).
- `SC-CAP-102` (Shell Execution + Network): Reverse shell or remote stager (HIGH).
- `SC-CAP-103` (Shell Execution + Dynamic Eval): Dynamic shell payload generation (HIGH).
- `SC-CAP-104` (Dynamic Eval/Require + Obfuscation): Hidden malicious loader stager (CRITICAL).
- `SC-CAP-105` (Install Script + Environment Access): Harvests environment secrets at install time (HIGH).
- `SC-CAP-106` (Install Script + Sensitive Filesystem): Harvests SSH/AWS credentials at install time (CRITICAL).

### Reachability Escalation to Invariant P1

When a dangerous combination (`SC-CAP-100+`) is determined to be reachable from user-code entrypoints, it escalates to **P1 CRITICAL**. If present in dependencies but not reachable, it is classified as `DEP_REACHABLE_ONLY`. Install scripts and Unicode attacks execute outside user runtime and are strictly classified as `NOT_APPLICABLE` (never suppressed by reachability).
