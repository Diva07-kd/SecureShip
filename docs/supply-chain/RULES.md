# Supply-Chain Threat Engine Rules Reference

This document catalogs all 29 supply-chain threat rules supported by the SecureShip Supply-Chain Threat Engine.

---

## Rule Index

| Rule ID          | Threat Type                | Default Severity | Reachability Gated | Title                                                                            |
| :--------------- | :------------------------- | :--------------- | :----------------- | :------------------------------------------------------------------------------- |
| `SC-INSTALL-001` | `INSTALL_SCRIPT`           | `MEDIUM`         | No                 | Install Script Lifecycle Hook Present                                            |
| `SC-INSTALL-002` | `INSTALL_SCRIPT`           | `MEDIUM`         | No                 | Implicit Native Build (`binding.gyp`) Without Script                             |
| `SC-INSTALL-003` | `INSTALL_SCRIPT`           | `CRITICAL`       | No                 | Dangerous Remote Execution or Exfiltration in Install Script                     |
| `SC-BIN-001`     | `BIN_CONFUSION`            | `HIGH`           | No                 | Path Traversal in Package Binary Specification                                   |
| `SC-BIN-002`     | `BIN_CONFUSION`            | `HIGH`           | No                 | System Command Shadowing Collision                                               |
| `SC-CAP-001`     | `CAPABILITY_VIOLATION`     | `HIGH`           | Yes                | Unauthorized Process Execution / Shell Spawn                                     |
| `SC-CAP-002`     | `CAPABILITY_VIOLATION`     | `HIGH`           | Yes                | Outbound Network Socket Activity                                                 |
| `SC-CAP-003`     | `CAPABILITY_VIOLATION`     | `MEDIUM`         | Yes                | Sensitive Environment Variable Harvesting                                        |
| `SC-CAP-004`     | `CAPABILITY_VIOLATION`     | `HIGH`           | Yes                | Sensitive Filesystem Access                                                      |
| `SC-CAP-005`     | `CAPABILITY_VIOLATION`     | `HIGH`           | Yes                | Dynamic Code Execution via `eval` / `Function`                                   |
| `SC-CAP-006`     | `CAPABILITY_VIOLATION`     | `MEDIUM`         | Yes                | Dynamic Require / Dynamic Import Reflection                                      |
| `SC-CAP-007`     | `CAPABILITY_VIOLATION`     | `MEDIUM`         | Yes                | Anti-Analysis / Debugger Internals Detection                                     |
| `SC-CAP-100`     | `CAPABILITY_VIOLATION`     | `HIGH`           | Yes                | Dangerous Capability Combination: Network + Environment Secret Exfiltration      |
| `SC-CAP-101`     | `CAPABILITY_VIOLATION`     | `CRITICAL`       | Yes                | Lethal Capability Combination: Network + Sensitive Filesystem Credential Harvest |
| `SC-CAP-102`     | `CAPABILITY_VIOLATION`     | `HIGH`           | Yes                | Dangerous Capability Combination: Shell Execution + Outbound Network Access      |
| `SC-CAP-103`     | `CAPABILITY_VIOLATION`     | `HIGH`           | Yes                | Dangerous Capability Combination: Shell Execution + Dynamic Code Eval            |
| `SC-CAP-104`     | `CAPABILITY_VIOLATION`     | `CRITICAL`       | Yes                | Lethal Capability Combination: Dynamic Eval/Require + Obfuscated Payload         |
| `SC-CAP-105`     | `CAPABILITY_VIOLATION`     | `HIGH`           | No                 | Install Script Hook with Environment Secret Harvesting                           |
| `SC-CAP-106`     | `CAPABILITY_VIOLATION`     | `CRITICAL`       | No                 | Install Script Hook with Sensitive Filesystem Access                             |
| `SC-TYPO-001`    | `TYPOSQUAT`                | `HIGH`           | No                 | Levenshtein Distance Typosquat Against Popular Package                           |
| `SC-TYPO-002`    | `TYPOSQUAT`                | `MEDIUM`         | No                 | Combosquatting / Suffix Inflation Confusion                                      |
| `SC-TYPO-003`    | `TYPOSQUAT`                | `MEDIUM`         | No                 | Separator-Collapse Name Squatting                                                |
| `SC-HALL-001`    | `AI_HALLUCINATION`         | `HIGH`           | No                 | Unregistered / AI-Hallucinated Target Risk                                       |
| `SC-PKG-001`     | `EMPTY_OR_MISSING_TARBALL` | `MEDIUM`         | No                 | Package Contains No Executable Code Artifacts                                    |
| `SC-PKG-002`     | `EMPTY_OR_MISSING_TARBALL` | `HIGH`           | No                 | Package Missing Upstream Registry Tarball                                        |
| `SC-UNI-001`     | `BIDI_TROJAN`              | `CRITICAL`       | No                 | Bidirectional Unicode Control Override (CVE-2021-42574)                          |
| `SC-UNI-002`     | `OBFUSCATION`              | `HIGH`           | No                 | Zero-Width or Invisible Code Characters                                          |
| `SC-UNI-003`     | `OBFUSCATION`              | `HIGH`           | No                 | Mixed-Script Identifiers and Confusable Homoglyphs                               |
| `SC-OBF-001`     | `HIGH_ENTROPY`             | `HIGH`           | No                 | High Shannon Entropy Packed or Encrypted String Literal                          |
| `SC-OBF-002`     | `OBFUSCATION`              | `MEDIUM`         | No                 | Massive Unbroken Minified / Obfuscated Line                                      |
| `SC-META-001`    | `CHRONO_ANOMALY`           | `MEDIUM`         | No                 | Anachronistic or Out-of-Sequence Release Timestamp                               |
| `SC-META-002`    | `SEMVER_ANOMALY`           | `HIGH`           | No                 | Major SemVer Jump Indicating Dependency Confusion                                |
| `SC-META-003`    | `MANIFEST_CONFUSION`       | `HIGH`           | No                 | Discrepancy Between Local Manifest and Registry Metadata                         |
| `SC-GOV-001`     | `GOVERNANCE_RISK`          | `HIGH`           | No                 | Sudden Maintainer Ownership Change With Privilege Escalation                     |
| `SC-GOV-002`     | `GOVERNANCE_RISK`          | `MEDIUM`         | No                 | Abandoned or Unclaimed Publisher Account                                         |
| `SC-GOV-003`     | `PROTESTWARE`              | `CRITICAL`       | No                 | Protestware Heuristics / Destructive Geo-Targeted Behavior                       |

---

## Detailed Rule Specifications

### 1. Install Scripts (`SC-INSTALL-*`)

Detects execution hooks during `npm install` (`preinstall`, `install`, `postinstall`).

- `SC-INSTALL-001`: Flags presence of scripts; medium severity.
- `SC-INSTALL-002`: Flags implicit compilation via `binding.gyp` when neither `install` nor `preinstall` script is declared (SPEC-GAP-3).
- `SC-INSTALL-003`: Flags weaponized shell scripts utilizing `curl`, `wget`, reverse shells, base64 pipes, or credential harvest loops.

### 2. Binary Confusion (`SC-BIN-*`)

Detects path traversal and system utility collisions in `package.json#bin`.

- `SC-BIN-001`: Entry paths pointing to `../` or root filesystem.
- `SC-BIN-002`: Bin keys matching system commands (`git`, `ssh`, `node`, `curl`, `sh`, `bash`).

### 3. Typosquats & Hallucinations (`SC-TYPO-*`, `SC-HALL-*`)

Detects impersonation of ecosystem staples.

- `SC-TYPO-001`: Damerau-Levenshtein distance $\le 2$ against popular seeds with similarity score $\ge 0.82$, or $D = 1$ against popular names of length $\ge 5$ (SPEC-GAP-1).
- `SC-TYPO-002`: Suffix appendages (`-js`, `-node`, `-lib`, `-helper`).
- `SC-TYPO-003`: Hyphen/dot stripping (`cross-env` vs `crossenv`).
- `SC-HALL-001`: Newly minted dependencies with minimal version count and zero downloads.

### 4. Unicode Attacks (`SC-UNI-*`)

Detects invisible and Trojan Source manipulations.

- `SC-UNI-001`: Unbalanced Bidi override characters (LRO, RLO, LRE, RLE, PDF, LRI, RLI, FSI, PDI).
- `SC-UNI-002`: Zero-width spaces, joiners, non-joiners in source files.
- `SC-UNI-003`: Mixed Latin/Cyrillic/Greek confusables in exported identifiers.

### 5. Obfuscation & Entropy (`SC-OBF-*`)

Detects encrypted payloads, payload loaders, and packed blobs.

- `SC-OBF-001`: String literals $\ge 64$ chars with Shannon Entropy $H \ge 4.5$ (or charset-normalized $H \ge 3.0$ for pure hex literals) (SPEC-GAP-2).
- `SC-OBF-002`: Single lines $> 1000$ characters without spaces.

### 6. Package Integrity (`SC-PKG-*`)

Detects decoy, placeholder, and stub packages.

- `SC-PKG-001`: Zero executable files in unpacked tarball.
- `SC-PKG-002`: Tarball unavailable from registry.

### 7. Metadata & SemVer (`SC-META-*`)

Detects registry poisoning and dependency confusion.

- `SC-META-001`: Release timestamps earlier than parent versions.
- `SC-META-002`: Major version increments exceeding policy threshold (e.g. 20+).
- `SC-META-003`: Divergence between unpacked `package.json` and registry packument.

### 8. Governance (`SC-GOV-*`)

Detects account takeovers and protestware.

- `SC-GOV-001`: New maintainer publishes immediately with added lifecycle scripts or high capabilities.
- `SC-GOV-002`: Publisher missing verified credentials.
- `SC-GOV-003`: Geo-IP or timezone based destructive logic.
