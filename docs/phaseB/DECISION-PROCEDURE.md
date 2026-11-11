# SecureShip Phase B: Decision Procedure Specification (R1–R6 & P1–P10)

**Document:** Formal Decision Procedure Specification & Worked Example Matrix  
**Status:** PRODUCTION STANDARD  
**Author:** Principal Security Engineer & Verification Lead  
**Governing Standard:** Anti-Cheat Rules AC1–AC9 & Sound Pruning Principles F1–F10

---

## 1. Overview & Soundness Principles

The Phase B function-level decision procedure refines direct dependency SCA findings in JavaScript/TypeScript (npm) and Python (PyPI). It is executed within [`ScaReachabilityAnalyzer.analyzeFunctionLevelDirectImport`](file:///c:/dev/SecureShip-IDE/packages/reachability/src/sca/sca-reachability-analyzer.ts) exclusively when:

1. The finding originates from a direct dependency.
2. The dependency is directly imported in production-reachable code (i.e. would have received `REACHABLE_IMPORT` in Phase 3).
3. The ecosystem is `npm` or `pypi`.
4. Function-level analysis is enabled in configuration and allowed by tier capabilities (`allowCallPathReachability: true`).

In all other circumstances (e.g. transitive dependencies, unimported packages, non-npm/pypi ecosystems, or disabled tier), the procedure terminates immediately and preserves the Phase 3 package-level verdict.

### Non-Negotiable Invariants:

- **Principle F1 (Positive Evidence Required):** Findings are pruned to `UNREACHABLE` (`UNINVOKED_SYMBOL`) **only** when positive evidence demonstrates that no public API path to the vulnerability is referenced or leaked.
- **Principle F4 (Monotonic Call Graph):** The call graph may only upgrade a finding to `REACHABLE_CALL_PATH`. It is never used to downgrade or prune findings.
- **Principle F5 (Leaf Direct Dependencies Only):** Pruning is prohibited if any other package installed in the workspace depends on the target package.

---

## 2. Decision Rules Specification (R1 through R6)

The decision procedure evaluates rules in strict sequential order. The first matching rule determines the outcome:

|  Rule  | Rule Name                              | Condition & Logic                                                                                                                                                                                                                        |                    Resulting Verdict                    |                        Evidence Kind                        |                              Confidence                               |
| :----: | :------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-----------------------------------------------------: | :---------------------------------------------------------: | :-------------------------------------------------------------------: |
| **R1** | **Candidate Extraction Gate**          | Extract candidate symbols via `extractVulnerableSymbols(finding)`. If candidate list is empty, terminate.                                                                                                                                |                   `REACHABLE_IMPORT`                    |                  `SYMBOL_DATA_UNAVAILABLE`                  |                           `HIGH` / `MEDIUM`                           |
| **R2** | **Usage Extraction Completeness**      | If any non-test source file has `usageIncomplete: true` (parse failure, AST depth timeout, node count cap hit), terminate.                                                                                                               |                   `REACHABLE_IMPORT`                    |                     `USAGE_INCOMPLETE`                      |                          Previous Confidence                          |
| **R3** | **Symbol Invocation / Call-Path**      | Any candidate symbol (or dataset entry point matching via-chain) is referenced in any non-test source file. If a chain from an entry point is proven by `CallPathProver`, emit `REACHABLE_CALL_PATH`; otherwise emit `REACHABLE_IMPORT`. |       `REACHABLE_CALL_PATH` or `REACHABLE_IMPORT`       |          `SYMBOL_CALL_PATH` or `SYMBOL_REFERENCED`          |                 Tier 1/2: `HIGH`<br>Tier 3: `MEDIUM`                  |
| **R4** | **Namespace Escape & Dynamic Binding** | Package binding escapes (passed as argument, returned, re-exported, stored in object/array, spread, enumerated, non-literal computed access, reassigned, Python `getattr`, wildcard `import *`, or `createRequire` present in file).     |                   `REACHABLE_IMPORT`                    |                     `NAMESPACE_ESCAPES`                     |                               `MEDIUM`                                |
| **R5** | **Precondition Verification Gate**     | Candidate is unreferenced and no escapes occur. Evaluate all 10 preconditions ($P1 \dots P10$). If **ALL** pass, prune to `UNREACHABLE`. If any precondition fails, retain `REACHABLE_IMPORT` with `blockedBy = <PreconditionCode>`.     | All Pass: `UNREACHABLE`<br>Any Fail: `REACHABLE_IMPORT` | All Pass: `UNINVOKED_SYMBOL`<br>Any Fail: Previous Evidence | All Pass:<br>Tier 1/2 + P9: `HIGH`<br>PyPI: `MEDIUM`<br>Tier 3: `LOW` |
| **R6** | **Transitive & Non-Target Scope**      | Transitive dependencies, non-package findings, and unsupported ecosystems bypass function-level logic completely.                                                                                                                        |                Preserved Phase 3 Verdict                |                 Preserved Phase 3 Evidence                  |                         Preserved Confidence                          |

---

## 3. Precondition Specification Matrix (P1 through P10)

Before any finding can be pruned to `UNREACHABLE` (`UNINVOKED_SYMBOL`) under Rule **R5**, every single one of the following 10 preconditions must be affirmatively satisfied:

| Precondition | Name & Code                                                                 | Verification Requirement & Logic                                                                                                                                                      | Hardening Rationale                                                                                           |
| :----------: | :-------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------ |
|    **P1**    | **Entrypoints Resolved**<br>`NO_ENTRYPOINT`                                 | Entrypoint detector must identify and resolve at least one production entry point (`main`, `module`, `bin`, `index.js`, `app.py`).                                                    | Without entry points, production reachability cannot be bounded.                                              |
|    **P2**    | **Zero Parse Errors**<br>`PARSE_ERROR`                                      | All non-test source files in the project must parse successfully without syntax errors or parser crashes.                                                                             | A file with syntax errors could contain unanalyzed symbol references.                                         |
|    **P3**    | **Clean Dynamic Scope**<br>`UNRESOLVED_IMPORT`<br>`DYNAMIC_IMPORT`          | Zero unresolved local file imports; zero variable dynamic `import(variable)` calls; zero `eval()` markers outside test directories.                                                   | Dynamic module loading can load unanalyzed code or bypass static graphs.                                      |
|    **P4**    | **Clean Reference Scan**<br>`CONFIG_REFERENCE`                              | Additive reference scan over Dockerfiles, CI workflows, build scripts, YAML/JSON configs, and unparsed text files must contain zero occurrences of the package name or its bin names. | Packages can be invoked via CLI scripts or reflection in non-code files.                                      |
|    **P5**    | **Direct Leaf Package**<br>`NOT_LEAF_PACKAGE`<br>`NO_LOCKFILE_TREE`         | Lockfile dependency tree must be present, and no other installed package in the workspace may depend on the target package.                                                           | If package $A$ also depends on `lodash`, calls inside `node_modules/A` are invisible to first-party analysis. |
|    **P6**    | **Safe Binary Exposure**<br>`BIN_EXPOSURE`                                  | If package defines executable CLI binaries in `bin` (or lockfile cannot verify absence of binaries), confidence is capped at `MEDIUM`.                                                | A package with CLI binaries might be invoked via shell scripts or child processes.                            |
|    **P7**    | **Dataset Integrity Verified**<br>`INTEGRITY_FAILED`                        | Vulnerable symbol database must match its cryptographic SHA-256 manifest exactly.                                                                                                     | Protects against tampered or corrupt vulnerability datasets.                                                  |
|    **P8**    | **Dataset Entry Quality**<br>`TRIGGER_NOT_CALL`<br>`ENTRYPOINTS_INCOMPLETE` | For `HIGH` confidence pruning: dataset entry must have `triggeredOn: 'CALL'` and `entryPointsComplete: true`.                                                                         | If vulnerability triggers on import or entry points are incomplete, pruning is unsound.                       |
|    **P9**    | **Ecosystem Confidence Rule**<br>Ecosystem Cap                              | npm packages may achieve `HIGH` confidence; PyPI packages are capped at `MEDIUM` confidence.                                                                                          | Python dynamic introspection and duck typing warrant conservative confidence ceilings.                        |
|   **P10**    | **Clean Package Specifier**<br>`ALIASED_PACKAGE`                            | Package must not be imported via package manager aliases (`npm:lodash@...`) or non-standard specifiers.                                                                               | Aliased packages can masquerade under alternate local names.                                                  |

---

## 4. Worked Example Matrix (Corpus Cases 01 to 62)

The following matrix documents the exact evaluation trace, inputs, applied rule, and final verdict for all 62 hand-labeled benchmark corpus fixtures in `packages/benchmark/corpus/function-level/`:

### Group A: Binding Forms (Cases 01–10)

| Case ID | Fixture Description       | Source Code Pattern                                      | Applied Rule | Outcome Verdict & Evidence                 |
| :-----: | :------------------------ | :------------------------------------------------------- | :----------: | :----------------------------------------- |
| **01**  | ESM Default Import Used   | `import _ from 'lodash'; _.template('hi')`               |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |
| **02**  | ESM Named Import Used     | `import { template } from 'lodash'; template('hi')`      |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |
| **03**  | ESM Renamed Import Used   | `import { template as t } from 'lodash'; t('hi')`        |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |
| **04**  | ESM Namespace Import Used | `import * as _ from 'lodash'; _.template('hi')`          |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |
| **05**  | CJS Require Whole Module  | `const _ = require('lodash'); _.template('hi')`          |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |
| **06**  | CJS Require Destructuring | `const { template } = require('lodash'); template('hi')` |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |
| **07**  | CJS Require Renamed       | `const { template: t } = require('lodash'); t('hi')`     |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |
| **08**  | TS Import Equals          | `import _ = require('lodash'); _.template('hi')`         |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |
| **09**  | Dynamic Import Promise    | `import('lodash').then(m => m.template('hi'))`           |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |
| **10**  | Dynamic Import Await      | `const _ = await import('lodash'); _.template('hi')`     |    **R3**    | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`) |

### Group B: Namespace Escape Forms (Cases 11–23)

| Case ID | Fixture Description         | Source Code Pattern                                    | Applied Rule | Outcome Verdict & Evidence               |
| :-----: | :-------------------------- | :----------------------------------------------------- | :----------: | :--------------------------------------- |
| **11**  | Passed as Argument          | `const _ = require('lodash'); doSomething(_)`          |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **12**  | Returned from Function      | `function getLib() { return require('lodash'); }`      |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **13**  | Exported as Default         | `import _ from 'lodash'; export default _;`            |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **14**  | Exported as CommonJS        | `module.exports = require('lodash');`                  |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **15**  | Stored in Object Literal    | `const _ = require('lodash'); const obj = { lib: _ };` |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **16**  | Stored in Array Literal     | `const _ = require('lodash'); const arr = [_];`        |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **17**  | Object Spread               | `const _ = require('lodash'); const copy = { ..._ };`  |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **18**  | Enumeration (`Object.keys`) | `const _ = require('lodash'); Object.keys(_);`         |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **19**  | Non-Literal Computed Access | `const _ = require('lodash'); _[dynKey]();`            |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **20**  | Reassigned Binding (`let`)  | `let _ = require('lodash'); _ = alt;`                  |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **21**  | Python `getattr` Reflection | `import requests; getattr(requests, dyn_var)()`        |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **22**  | Python Wildcard Import      | `from requests import *; get(...)`                     |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |
| **23**  | Dynamic Loader Marker       | `const req = createRequire(import.meta.url);`          |    **R4**    | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`) |

### Group C: Precondition Violations (Cases 24–35)

| Case ID | Fixture Description              | Source Code / Project State                  | Triggered Precondition | Outcome Verdict & Blocked Reason                    |
| :-----: | :------------------------------- | :------------------------------------------- | :--------------------: | :-------------------------------------------------- |
| **24**  | Missing Entrypoint               | Project lacks `main`, `index.js`, or `bin`   |         **P1**         | `REACHABLE_IMPORT` (`blockedBy: NO_ENTRYPOINT`)     |
| **25**  | Syntax Parse Error               | `src/broken.js` contains invalid JavaScript  |         **P2**         | `REACHABLE_IMPORT` (`blockedBy: PARSE_ERROR`)       |
| **26**  | Unresolved Local Import          | `import './non-existent-file.js'`            |         **P3**         | `REACHABLE_IMPORT` (`blockedBy: UNRESOLVED_IMPORT`) |
| **27**  | Variable Dynamic Import          | `import(variablePath)`                       |         **P3**         | `REACHABLE_IMPORT` (`blockedBy: DYNAMIC_IMPORT`)    |
| **28**  | Eval Invocation                  | `eval('console.log(1)')`                     |         **P3**         | `REACHABLE_IMPORT` (`blockedBy: DYNAMIC_IMPORT`)    |
| **29**  | Dockerfile Package Reference     | Dockerfile runs `npm i lodash`               |         **P4**         | `REACHABLE_IMPORT` (`blockedBy: CONFIG_REFERENCE`)  |
| **30**  | Unparsed File Reference          | `docs/notes.txt` references `lodash`         |         **P4**         | `REACHABLE_IMPORT` (`blockedBy: CONFIG_REFERENCE`)  |
| **31**  | Transitive Dependent Present     | `express` depends on `lodash` in lockfile    |         **P5**         | `REACHABLE_IMPORT` (`blockedBy: NOT_LEAF_PACKAGE`)  |
| **32**  | Missing Lockfile Dependency Tree | Workspace has no lockfile                    |         **P5**         | `REACHABLE_IMPORT` (`blockedBy: NO_LOCKFILE_TREE`)  |
| **33**  | Binary Exposure Present          | Package exports CLI executable in `bin`      |         **P6**         | `UNREACHABLE` (Capped at `confidence: MEDIUM`)      |
| **34**  | Tampered Dataset Manifest        | `vulnerable-symbols.json` SHA mismatch       |         **P7**         | `REACHABLE_IMPORT` (`blockedBy: INTEGRITY_FAILED`)  |
| **35**  | Aliased Package Specifier        | `dependencies: { "mylodash": "npm:lodash" }` |        **P10**         | `REACHABLE_IMPORT` (`blockedBy: ALIASED_PACKAGE`)   |

### Group D: Heuristic Candidate Hardening Traps (Cases 36–41)

| Case ID | Fixture Description              | Advisory Text Tested                     | Expected Hardening Behavior                          | Outcome Verdict                                |
| :-----: | :------------------------------- | :--------------------------------------- | :--------------------------------------------------- | :--------------------------------------------- |
| **36**  | Stoplist Word Trap               | `"method of"` / `"function in"`          | Rejected by stoplist filter; no candidate extracted. | `REACHABLE_IMPORT` (`SYMBOL_DATA_UNAVAILABLE`) |
| **37**  | Version Number Trap              | `"fixed in 1.2.3"`                       | Rejected by identifier syntax filter.                | `REACHABLE_IMPORT` (`SYMBOL_DATA_UNAVAILABLE`) |
| **38**  | Prefix Mismatch Trap             | `"axios.get"` finding on `lodash`        | Rejected because prefix does not match package root. | `REACHABLE_IMPORT` (`SYMBOL_DATA_UNAVAILABLE`) |
| **39**  | Valid Heuristic Candidate        | `"vulnerable to lodash.template()"`      | Heuristic match admitted; permanently capped at LOW. | `UNREACHABLE` (`confidence: LOW`)              |
| **40**  | Identifier Too Short (< 2 chars) | `"vulnerable in a()"`                    | Length boundary violation (< 2 chars).               | `REACHABLE_IMPORT` (`SYMBOL_DATA_UNAVAILABLE`) |
| **41**  | Identifier Too Long (> 64 chars) | `"vulnerable in aVery...LongSymbolName"` | Length boundary violation (> 64 chars).              | `REACHABLE_IMPORT` (`SYMBOL_DATA_UNAVAILABLE`) |

### Group E: Dataset API Complexities & Invocation Forms (Cases 42–53)

| Case ID | Fixture Description                    | Source Code Pattern                                |  Applied Rule   | Outcome Verdict & Evidence                               |
| :-----: | :------------------------------------- | :------------------------------------------------- | :-------------: | :------------------------------------------------------- |
| **42**  | Method via Chain Used                  | `_.chain().template().value()`                     |     **R3**      | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`)               |
| **43**  | Method without via Match               | `const x = customlib.makeObj();` (Unmatched `via`) | **R5** / **P8** | `REACHABLE_IMPORT` (`blockedBy: ENTRYPOINTS_INCOMPLETE`) |
| **44**  | Triggered on Import-Time               | Advisory `triggeredOn: 'IMPORT_TIME'`              | **R5** / **P8** | `REACHABLE_IMPORT` (`blockedBy: TRIGGER_NOT_CALL`)       |
| **45**  | Incomplete Entry Points                | Advisory `entryPointsComplete: false`              | **R5** / **P8** | `REACHABLE_IMPORT` (`blockedBy: ENTRYPOINTS_INCOMPLETE`) |
| **46**  | Deep Subpath with Mapping Used         | `const t = require('lodash/template'); t('hi')`    |     **R3**      | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`)               |
| **47**  | Deep Subpath with Known Mapping Unused | `const m = require('lodash/map'); m([1], x => x)`  |     **R5**      | `UNREACHABLE` (`UNINVOKED_SYMBOL`, `HIGH`)               |
| **48**  | Deep Subpath Unknown Mapping           | `const fp = require('lodash/fp');`                 |     **R4**      | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES`)                 |
| **49**  | Literal Computed Access Used           | `_['template']('hi')`                              |     **R3**      | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`)               |
| **50**  | Single Assignment Member Alias         | `const t = _.template; t('hi')`                    |     **R3**      | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`)               |
| **51**  | Optional Chaining Invocation           | `_.template?.('hi')`                               |     **R3**      | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`)               |
| **52**  | Tagged Template Invocation             | `` _.template`<div>${x}</div>` ``                  |     **R3**      | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`)               |
| **53**  | Callback Reference Used                | `[1, 2].map(_.template)`                           |     **R3**      | `REACHABLE_IMPORT` (`SYMBOL_REFERENCED`)                 |

### Group F: Python, Frameworks, and Scoping (Cases 54–62)

| Case ID | Fixture Description              | Source Code / Project Context                            |  Applied Rule   | Outcome Verdict & Evidence                                    |
| :-----: | :------------------------------- | :------------------------------------------------------- | :-------------: | :------------------------------------------------------------ |
| **54**  | Python Direct Uninvoked          | `import requests; requests.__version__`                  | **R5** / **P9** | `UNREACHABLE` (`confidence: MEDIUM`)                          |
| **55**  | Python Aliased Import Used       | `import requests as req; req.get(...)`                   |     **R3**      | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`)                    |
| **56**  | Python From-Import Used          | `from requests import get; get(...)`                     |     **R3**      | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`)                    |
| **57**  | Python From-Import Uninvoked     | `from requests import post; post(...)`                   | **R5** / **P9** | `UNREACHABLE` (`confidence: MEDIUM`)                          |
| **58**  | Framework File Mention (.vue)    | `<template><div>{{ lodash.template }}</div></template>`  |     **R4**      | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES` / `CONFIG_REFERENCE`) |
| **59**  | Framework File Mention (.svelte) | `<div>{lodash.template}</div>`                           |     **R4**      | `REACHABLE_IMPORT` (`NAMESPACE_ESCAPES` / `CONFIG_REFERENCE`) |
| **60**  | Test-Only Usage                  | `test/app.test.js` invokes `_.template()`; prod does not |     **R5**      | `UNREACHABLE` (`UNINVOKED_SYMBOL`, `HIGH`)                    |
| **61**  | Dead-File Usage (Soundness F1)   | Unreachable file `dead.js` invokes `_.template()`        |     **R3**      | `REACHABLE_IMPORT` (`SYMBOL_REFERENCED`)                      |
| **62**  | Call-Path Proved Chain           | `main()` $\to$ `helper()` $\to$ `_.template()`           |     **R3**      | `REACHABLE_CALL_PATH` (`SYMBOL_CALL_PATH`)                    |
