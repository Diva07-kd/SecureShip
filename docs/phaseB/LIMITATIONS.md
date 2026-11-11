# SecureShip Phase B: Function-Level Reachability — Blunt Limitations & Non-Goals

**Document:** Engineering Limitations, Non-Goals, & Soundness Constraints  
**Status:** PRODUCTION STANDARD  
**Author:** Principal Security Engineer & Verification Lead  
**Governing Standard:** Anti-Cheat Rules AC1–AC9 & Sound Pruning Principles F1–F10

---

## 1. Blunt Disclosure & Purpose

Security tools frequently overstate their capabilities with misleading claims such as "zero false positives" or "100% reachability accuracy." SecureShip explicitly rejects this practice (**Anti-Cheat Rule AC9**).

This document provides a blunt, unvarnished disclosure of what SecureShip Phase B **does not do**, where its static analysis boundaries lie, and why specific design decisions intentionally favor **false-positive preservation over unsound false negatives (Principle F1)**.

---

## 2. Core Operational Limitations

### 2.1. First-Party Code Analysis Only (Zero Dependency AST Analysis)

- **Limitation:** SecureShip analyzes only first-party application source code located inside the scanned workspace. It **does not parse or analyze the internal source code of third-party dependencies** (`node_modules/`, Python virtual environments, or vendor directories).
- **Security Implication:** If your code imports package $A$, and package $A$ internally calls the vulnerable function in package $B$, first-party static analysis cannot observe that internal call.
- **Enforced Defense (Precondition P5):** To remain sound, SecureShip **strictly limits function-level pruning to direct leaf dependencies**—packages upon which no other installed package in the dependency tree depends. If any other dependency depends on the target package, pruning is immediately blocked under `NOT_LEAF_PACKAGE`.

### 2.2. Transitive Dependencies Retain Package-Level Reachability (Rule R6)

- **Limitation:** Vulnerabilities in transitive dependencies (dependencies of dependencies) **cannot be pruned at the function level**.
- **Behavior:** All transitive dependency findings retain Phase 3 package-level reachability verdicts (`REACHABLE_IMPORT` or `UNREACHABLE` based purely on whether any production-reachable file imports a top-level package that transitively depends on them).
- **Rationale:** Because third-party library call paths are not constructed, claiming a transitive function is unreached would be an unsound guess.

### 2.3. Dependents in Lockfile Block Pruning (Precondition P5)

- **Limitation:** If `express` and `lodash` are both installed as direct dependencies, but `express` also transitively depends on `lodash`, `lodash` is **not a leaf dependency**.
- **Behavior:** Even if your first-party code only invokes `lodash.isEqual`, SecureShip will **not** prune `lodash.template` (`CVE-2021-23337`) to `UNREACHABLE`. The finding is retained as `REACHABLE_IMPORT` with `blockedBy: NOT_LEAF_PACKAGE`.

### 2.4. Dynamic Binding & Reflection Cause Immediate Fail-Closed (Rule R4)

- **Limitation:** SecureShip does not perform abstract interpretation or dynamic taint tracking across reflection boundaries.
- **Fail-Closed Triggers:** Any of the following dynamic patterns will immediately abort pruning and classify the package under `NAMESPACE_ESCAPES`:
  - Passing the imported object or module as an argument (`doSomething(_)`)
  - Returning the imported module from a function (`return _`)
  - Re-exporting the module (`export default _` or `module.exports = require('x')`)
  - Storing the module inside an object or array (`{ lib: _ }` or `[_]`)
  - Spreading the module (`{ ..._ }`)
  - Enumerating module properties (`Object.keys(_)`, `Object.assign`, `Object.entries`)
  - Non-literal computed property access (`_[dynKey]()`)
  - Python dynamic reflection (`getattr(requests, dyn_var)`)
  - Python wildcard imports (`from requests import *`)
  - Dynamic loader markers (`createRequire`, `module.require`)

### 2.5. Heuristic Candidate Tier Is Permanently Capped at LOW Confidence

- **Limitation:** If a vulnerability is not present in the curated dataset (`CURATED_DB`) or structured advisory metadata (`STRUCTURED_ADVISORY`), SecureShip falls back to Tier 3 (`HEURISTIC_TEXT`) regex extraction from advisory text.
- **Behavior:** Any candidate symbol derived via heuristic text regex is **permanently locked to `confidence: LOW`**.
- **Suppression Protection:** Under Gate 2 policy, findings with `confidence: LOW` **can never be suppressed**. They are displayed for informational purposes only.

### 2.6. Ecosystem Scope: npm and PyPI Only

- **Limitation:** Phase B function-level AST extraction is implemented exclusively for JavaScript/TypeScript (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`) and Python (`.py`).
- **Other Ecosystems:** Go (`go.mod`), Java (`pom.xml`, `build.gradle`), Rust (`Cargo.toml`), and C# (`.csproj`) retain standard Phase 3 package-level reachability verdicts.

### 2.7. Python SCA Confidence Ceiling (Precondition P9)

- **Limitation:** Due to Python's highly dynamic object model, runtime monkey-patching, and duck typing, Python direct dependencies can **never achieve `confidence: HIGH` pruning**.
- **Behavior:** Uninvoked Python findings are capped at `confidence: MEDIUM` (`UNREACHABLE` / `UNINVOKED_SYMBOL`). Under default Gate 2 suppression rules (which require `HIGH` confidence), Python findings are never suppressed automatically.

---

## 3. Explicit Non-Goals (Out of Scope by Design)

SecureShip will **never** implement the following mechanisms within Phase B:

1. **Dependency Source Code Analysis:** Walking or indexing the full AST of thousands of third-party packages in `node_modules`.
2. **Whole-Program Inter-Procedural Call Graphs:** Constructing exponential whole-program call graphs across library boundaries.
3. **Runtime Execution / Sandboxed Dynamic Testing:** Executing untrusted target code during static analysis.
4. **AI-Generated Reachability Guesses:** Using LLMs to hallucinate whether a function is reachable.
5. **Scan-Time Network Lookups:** Making HTTP requests to remote advisory databases during a scan.
6. **Weakening Gate 2 Suppression Safeguards:** Allowing medium or low confidence findings to be suppressed.
