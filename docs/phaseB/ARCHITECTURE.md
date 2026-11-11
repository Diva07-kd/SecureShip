# SecureShip Phase B: Function-Level Reachability — Architecture Specification

**Status:** PRODUCTION STANDARD  
**Version:** 1.0.0 (Phase B)  
**Author:** Principal Security Engineer & Verification Lead  
**Governing Standard:** Anti-Cheat Rules AC1–AC9 & Sound Pruning Principles F1–F10

---

## 1. Architectural Overview & Core Mission

SecureShip Gate 2 previously operated at **package-level reachability**: any direct dependency imported anywhere in a production file was labeled `REACHABLE_IMPORT` (`PACKAGE_IMPORTED`). This caused severe alert fatigue for large utility libraries like `lodash`—an application using only `_.isEqual` or `_.map` was burdened with critical security alerts for uninvoked vulnerabilities such as `lodash.template` command injection (`CVE-2021-23337`).

**Phase B** implements **sound, positive-evidence-based function-level (symbol-level) reachability refinement** for direct dependencies in npm and PyPI ecosystems. Under Phase B:

- Vulnerability findings are pruned from `REACHABLE_IMPORT` to `UNREACHABLE` (`UNINVOKED_SYMBOL`) **only when positive evidence confirms that no vulnerable entry point is referenced or escaped anywhere in production code**.
- Any uncertainty (dynamic imports, non-literal computed property accesses, object escapes, parse ambiguities, transitive dependents, or bin exposure) triggers **fail-closed** behavior, retaining `REACHABLE_IMPORT` or `UNKNOWN`.
- First-party code analysis only: dependency internals (`node_modules`) are not analyzed. If any other installed package depends on the package, function-level pruning is prohibited (precondition P5).
- Zero package-specific heuristics or branches in production code; all curated advisory knowledge is loaded generically and attested with SHA-256 cryptographic manifests.

---

## 2. End-to-End Analysis Pipeline

The following Mermaid diagram illustrates the execution flow through the SecureShip Phase B engine:

```mermaid
flowchart TD
    subgraph Inputs["1. Scan Inputs & Raw Findings"]
        Scanners["Raw SCA Findings\n(Trivy, OSV-Scanner)"]
        SourceCode["Source Code ASTs\n(JS/TS/TSX/Python)"]
        Lockfile["Lockfile Dependency Tree\n(package-lock, pnpm, Pipfile)"]
        Configs["Non-Code Files\n(Dockerfile, CI, Configs)"]
    end

    subgraph SymbolDataset["2. Curated Symbol Database & Integrity"]
        DatasetJson["vulnerable-symbols.json\n(18 Verified Advisories)"]
        ManifestJson["vulnerable-symbols.manifest.json\n(SHA-256 Digest)"]
        DatasetLoader["DatasetLoader\n(Offline SHA-256 Verification)"]
        DatasetJson --> DatasetLoader
        ManifestJson --> DatasetLoader
    end

    subgraph AstExtraction["3. AST Binding & Usage Extraction"]
        TreeSitter["TreeSitterLoader\n(Bundled WASM Parsers)"]
        JsExtractor["JsSymbolUsageExtractor\n(Iterative Bounded Traversal)"]
        PyExtractor["PythonSymbolUsageExtractor\n(Iterative Bounded Traversal)"]
        ExtCache["ExternalExtractionCache\n(HMAC-SHA256, Analyzer v2.0.0)"]
        SourceCode --> TreeSitter
        TreeSitter --> JsExtractor
        TreeSitter --> PyExtractor
        JsExtractor <--> ExtCache
        PyExtractor <--> ExtCache
    end

    subgraph Prover["4. Call Graph & Call-Path Prover"]
        CallGraphExt["CallGraphExtractor\n(Iterative Map Traversal)"]
        CallProver["CallPathProver\n(Conservative Shortest Path, Max 10 Hops)"]
        JsExtractor --> CallGraphExt
        CallGraphExt --> CallProver
    end

    subgraph Decision["5. SCA Decision Procedure (R1-R6 & P1-P10)"]
        CandExtract["CandidateExtractor\n(STRUCTURED > CURATED > HEURISTIC)"]
        RefScanner["ReferenceScanner\n(Additive Filter Mode)"]
        LeafCheck["LockfileTreeParser\n(Direct Leaf Dependency Guard)"]
        DecProc["ScaReachabilityAnalyzer\n(Rule R1 to R6 Evaluation)"]

        Scanners --> CandExtract
        DatasetLoader --> CandExtract
        CandExtract --> DecProc
        JsExtractor & PyExtractor --> DecProc
        CallProver --> DecProc
        RefScanner --> DecProc
        LeafCheck --> DecProc
    end

    subgraph Outputs["6. Normalized Output & Accounting"]
        VerdictReachable["REACHABLE_CALL_PATH / REACHABLE_IMPORT\n[CALL PATH PROVEN] / [SYMBOL REFERENCED]"]
        VerdictEscape["REACHABLE_IMPORT\n[IMPORTED] (NAMESPACE_ESCAPES)"]
        VerdictUnreachable["UNREACHABLE\n[SYMBOL NOT REFERENCED] (UNINVOKED_SYMBOL)"]
        Ledger["Suppression Ledger\n(Invariant P1 Accounting)"]

        DecProc --> VerdictReachable
        DecProc --> VerdictEscape
        DecProc --> VerdictUnreachable
        VerdictUnreachable --> Ledger
    end
```

---

## 3. Subsystem Architecture

### 3.1. Symbol Data & Candidate Extraction (`CandidateExtractor`)

Candidate symbols are extracted from raw SCA findings through a strictly prioritized three-tier hierarchy:

```mermaid
flowchart LR
    Finding["Raw SCA Finding"] --> T1{"Tier 1:\nStructured Advisory?"}
    T1 -- Yes --> Cand1["Source: STRUCTURED_ADVISORY\n(Confidence: HIGH)"]
    T1 -- No --> T2{"Tier 2:\nCurated Dataset Match?"}
    T2 -- Yes --> Cand2["Source: CURATED_DB\n(Confidence: HIGH / MEDIUM)"]
    T2 -- No --> T3{"Tier 3:\nHardened Heuristic Regex?"}
    T3 -- Match Found --> Cand3["Source: HEURISTIC_TEXT\n(Confidence: LOW Forever)"]
    T3 -- No Match --> NoCand["SYMBOL_DATA_UNAVAILABLE\n(Preserve Import Verdict)"]
```

1. **Tier 1 (`STRUCTURED_ADVISORY`):** Parsed directly from `finding.evidence[].metadata.affected_functions`. (Note: Empirical audit confirmed neither Trivy nor OSV-Scanner currently populates this in the wild; engine is ready when scanners add support).
2. **Tier 2 (`CURATED_DB`):** Matched by ecosystem (`npm` or `pypi`), normalized package name, and advisory identifier/alias intersection (`cveId`, `ghsaId`, `aliases`).
3. **Tier 3 (`HEURISTIC_TEXT`):** Hardened multi-pattern regex matching on advisory titles and descriptions. Implements:
   - English stoplist rejection (`of`, `to`, `in`, `the`, `when`, `node`, `js`, etc.).
   - Identifier length boundary enforcement ($2 \le \text{length} \le 64$).
   - Package name prefix congruence requirement (`<pkg>.<symbol>(` or normalized import alias).
   - Permanent ceiling at `confidence: LOW` (never eligible for Gate 2 suppression).

### 3.2. AST Binding & Usage Extraction (`symbol-usage/`)

Both JavaScript/TypeScript and Python extractors perform **iterative bounded AST traversals** to capture two categories of facts per source file:

```mermaid
classDiagram
    class FileSymbolUsage {
        +PackageSymbolUsage[] packages
        +boolean usageIncomplete
        +string[] unresolvedImports
        +boolean hasDynamicImports
        +boolean hasEvalMarkers
        +boolean hasGlobalRequireEscape
    }
    class PackageSymbolUsage {
        +string packageName
        +SymbolBinding[] bindings
        +SymbolUsageSite[] usages
        +SymbolEscape[] escapes
        +boolean hasUnknownSubpath
    }
    class SymbolBinding {
        +string localName
        +string importedName
        +string packageRoot
        +string subpath
        +string kind
    }
    class SymbolUsageSite {
        +string symbol
        +string file
        +number line
        +string form
    }
    class SymbolEscape {
        +string form
        +string file
        +number line
        +string detail
    }
    FileSymbolUsage *-- PackageSymbolUsage
    PackageSymbolUsage *-- SymbolBinding
    PackageSymbolUsage *-- SymbolUsageSite
    PackageSymbolUsage *-- SymbolEscape
```

#### Binding Forms Handled:

- **JavaScript/TypeScript:** ESM default imports, named imports, renamed imports (`as`), namespace imports (`* as`), CommonJS `require()`, destructuring assignments, CommonJS renamed destructuring, TypeScript `import = require()`, dynamic `import().then()`, and `await import()`.
- **Python:** Standard imports (`import requests`), aliased imports (`import requests as req`), from-imports (`from requests import get`), and aliased from-imports.

#### Escape Forms Handled (Soundness Invariant F1):

Any escape prevents claiming the symbol is unreferenced:

1. Passed as an argument to any function or method (`doSomething(_)`)
2. Returned from a function (`return _`)
3. Exported as default or CommonJS (`export default _`, `module.exports = require('x')`)
4. Stored in object or array literals (`{ lib: _ }`, `[_]`)
5. Object spread expressions (`{ ..._ }`)
6. Object reflection/enumeration (`Object.keys(_)`, `Object.assign`, `Object.entries`)
7. Non-literal computed property access (`_[dynamicKey]`)
8. Reassigned bindings (`let _ = require('x'); _ = alt;`)
9. Python dynamic reflection (`getattr(requests, dyn_var)`)
10. Python wildcard imports (`from requests import *`)
11. Dynamic loader markers (`createRequire`, `module.require`)

### 3.3. Call Graph Hardening & Call-Path Prover (`CallPathProver`)

The call-path subsystem bridges static symbol usage to production entry points:

- **`CallGraphExtractor`:** Hardened from quadratic recursion to an $O(N)$ iterative AST traversal keyed by node ID map. Callee resolution resolves full member access chains (`a.b.c()`), optional chains (`a?.b()`), constructor instantiations (`new A()`), and Python method calls.
- **`CallPathProver`:** Constructs a conservative directed call graph from discovered production entry points. Nodes are resolvable named functions, arrow-function variables, and methods. Edges represent definite resolved call sites.
- **Shortest-Path Traversal:** BFS search finds the shortest chain from an entry point to the vulnerable symbol invocation site (maximum 10 hops, deterministic sorted tie-break).
- **Soundness Invariant F4:** The call graph is **strictly monotonic**—it may only UPGRADE a verdict from `REACHABLE_IMPORT` to `REACHABLE_CALL_PATH`. It is **never** used to downgrade or prune findings, because dynamic dispatch, callbacks, and exports make negative call graph proofs unsound.

### 3.4. Decision Procedure & Precondition Matrix (`ScaReachabilityAnalyzer`)

The core decision procedure evaluates rules **R1 through R6** in strict sequence:

1. **R1 (Candidate Resolution):** Extract candidates. If none found $\to$ preserve import verdict with `SYMBOL_DATA_UNAVAILABLE`.
2. **R2 (Usage Completeness):** Check if any non-test source file failed to parse or hit resource caps $\to$ preserve import verdict with `blockedBy: USAGE_INCOMPLETE`.
3. **R3 (Symbol Referenced / Proved):** If any candidate or its `via` method chain was invoked:
   - Proved call path $\to$ `REACHABLE_CALL_PATH` with `evidenceKind: SYMBOL_CALL_PATH`.
   - Referenced without proven path $\to$ `REACHABLE_IMPORT` with `evidenceKind: SYMBOL_REFERENCED`.
4. **R4 (Namespace Escapes):** If an escape, non-literal computed access, or dynamic require marker is present $\to$ `REACHABLE_IMPORT` with `evidenceKind: NAMESPACE_ESCAPES`.
5. **R5 (Precondition Gate P1–P10):** To prune to `UNREACHABLE` (`UNINVOKED_SYMBOL`), **ALL** ten preconditions must hold:
   - **P1:** Entry points found and resolved.
   - **P2:** Zero parse errors across all non-test source files.
   - **P3:** Zero unresolved local imports, variable dynamic imports, or eval markers.
   - **P4:** Reference scanner clean across config, script, Dockerfile, and unparsed files.
   - **P5:** Lockfile dependency tree present and package is a direct leaf (no installed dependents).
   - **P6:** Package binary exposure safe (no executable CLI wrappers exposed).
   - **P7:** Dataset integrity manifest verified (cryptographic SHA-256 match).
   - **P8:** Dataset entry triggered on `CALL` and `entryPointsComplete: true`.
   - **P9:** Ecosystem rule: npm allowed for `HIGH`; PyPI capped at `MEDIUM`.
   - **P10:** Package not referenced under an alias specifier (`npm:lodash`).
     _If all pass:_ Verdict becomes `UNREACHABLE` (`UNINVOKED_SYMBOL`).
6. **R6 (Transitive & Out-of-Scope Preservation):** Transitive dependencies and unsupported ecosystems retain the exact Phase 3 package-level reachability behavior.

---

## 4. Trust Model & Security Guardrails (F6 & AC1–AC9)

1. **Repo-Resident Trust Guard (Principle F6):**
   Repository-resident configuration files (`secureship.config.json`, `.secureship/config.json`) and repository-resident files (`.secureship/symbols.json`) are **strictly prohibited** from:
   - Supplying custom symbol datasets.
   - Disabling or reconfiguring function-level reachability.
   - Overriding integrity manifests.
     If a repository attempts to supply reachability dataset settings, `ConfigLoader` discards the setting and issues a prominent security warning.
2. **Cryptographic Manifest Attestation:**
   The bundled `vulnerable-symbols.json` is protected by `vulnerable-symbols.manifest.json`. Tampering with any byte causes `DatasetLoader` to fail-closed, disabling function-level pruning and preserving package-level verdicts.
3. **External Authentication Cache:**
   All AST fact extraction is cached in `~/.secureship/cache` (or Windows `%LOCALAPPDATA%`), keyed by HMAC-SHA256 with a machine-local key, entirely outside the target repository. Cache entries carry `ANALYZER_VERSION = '2.0.0'`; any version mismatch triggers full recomputation.
4. **Zero-Network Invariant (Principle F8):**
   SecureShip executes 100% locally. Zero network calls, zero package manager executions, zero telemetry.
