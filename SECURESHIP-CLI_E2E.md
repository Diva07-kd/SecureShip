# SecureShip — Project Guide in Simple English

## Purpose of this document

This document explains the SecureShip project in straightforward English. It is based on the supplied project master document. The goal is to make the material easier to explain and understand while keeping the same architecture, security gates, rules, and workflow.

The source document contains implementation claims and test figures. This rewrite preserves those claims as claims from the source; it does not independently verify them. In particular, the source gives different totals for tests in different sections. Those figures are shown in the note in Section 10 instead of being silently reconciled.

## 1. What SecureShip does

SecureShip is a local-first security tool for software projects. It brings several existing security scanners together and adds its own analysis around their results. It can scan a project, organize findings, check whether some findings are relevant to production code, help review findings with an AI provider supplied by the user, and verify proposed fixes in an isolated copy of the project.

The external tools described in the project are:

- **Opengrep or Semgrep** for static application security testing (SAST).
- **Gitleaks** for finding possible secrets such as tokens and credentials.
- **Trivy** for software dependencies, containers, and related vulnerabilities.
- **OSV-Scanner** for checking direct and transitive dependencies against advisories.
- **Checkov** for infrastructure-as-code configuration problems.

SecureShip treats the output of these scanners as candidate findings. It then applies its own scope, reachability, and review steps. This is intended to reduce irrelevant alerts while keeping uncertain findings visible for human review.

### The six security principles

The project describes six principles that guide its design:

1. **Keep an accounting record for every finding.** The project defines the rule `totalRaw = totalReported + totalSuppressed + totalOutOfScope`. A finding should not disappear without being counted.
2. **Show unavailable or degraded tools honestly.** If a scanner is missing, times out, or has an incomplete database, the report should say so.
3. **Keep scanner processes separate.** A crash or hang in one scanner should not corrupt the work of another scanner.
4. **Work locally and avoid telemetry.** The project is designed to work offline and says it does not upload source code or make unauthorized network calls.
5. **Redact secrets twice.** Secrets are scrubbed at the subprocess output boundary and again when results are normalized.
6. **Run subprocesses safely.** The design uses argument-based process execution with `shell: false`, private temporary directories, and process-tree handling.

The project says its custom reachability analysis, supply-chain checks, and cited AI review can greatly reduce false positives. Any numerical performance claim should be understood as a result reported by the project and should be supported by the project's benchmark evidence when presented externally.

## 2. The problem SecureShip addresses

Security scanners can report a large number of issues. Some are real risks, while others may not affect the way a project actually runs. Examples described in the source include:

- A vulnerable function exists in a dependency, but the project never calls that function.
- A credential-like string is only a fake example in a test fixture.
- A flagged input is validated or sanitized before it reaches a risky operation.
- A package appears in a manifest but is not used by production code.

When developers repeatedly see alerts that do not apply, they may begin ignoring reports or disabling checks. This creates alert fatigue and can make real issues easier to miss.

SecureShip's approach is to use external scanners to find possible issues, then examine those issues in context. Its gates ask questions such as:

- Is the finding in a test, mock, fixture, documentation, or example path?
- Is the affected package used by production code?
- Is the specific vulnerable function used?
- Can a static call path be traced from an entry point to that function?
- Can an AI review support its conclusion with exact code quotations?
- Can a proposed fix pass checks in a separate workspace?

The system is designed to be conservative. If the analysis cannot safely show that a finding is irrelevant, it should keep the finding or send it for human review instead of suppressing it.

## 3. How the project was built

The source describes SecureShip as a set of phases that added capabilities over time:

### Foundation

The first phase added shared data contracts and validation schemas, a safe process runner, project detection, secret redaction, and the `doctor` command. These pieces provide common rules and basic system checks for the rest of the project.

### Scanner pipeline and normalization

The next phase connected the five scanner tools, normalized their output into SARIF 2.1.0, added path scoping, introduced the accounting ledger, and added Git diff modes such as `--diff` and `--staged`.

### Import-level reachability

The project added WebAssembly Tree-sitter parsers for JavaScript, TypeScript, and Python. It uses them to build an import graph and examine dependency lockfiles. It also scans non-code references such as scripts and configuration so that a package is not declared unused simply because it was not found in a normal source import.

### AI review

The AI stage added a code context slicer, two-pass secret redaction, a skeptical review engine, exact citation checks, defenses against prompt injection, a loopback HTTP client, an HMAC-SHA256 cache, and a consent manager. The design supports BYOK, meaning the user provides their own AI provider key.

### Remediation, sandboxing, and licenses

The project added a ten-stage fix verification process, an AST-aware patch applier, 23 patch safety rules, isolated workspaces, dependency pinning, license handling, and AI usage accounting.

### Function-level reachability

A later phase added a curated dataset of vulnerable symbols, symbol extraction from ASTs, a call-path prover, and conservative rules for deciding when a vulnerable function is or is not used.

### Air-gap and container hardening

The project added a single source of truth for pinned tools, safe archive extraction, checks against malicious binaries inside a target repository, a hardened multi-stage Docker image, deterministic archives, and signed offline bundles.

### Fleet hardening

The fleet service received token handling and crash-safe persistence work. The source describes private file permissions, atomic writes, backups, recovery, quarantine for damaged databases, and retry handling for temporary Windows file locks.

### Shell-safe browser opening and IDE support

The project replaced a shell-based Windows browser opener with argument-based execution and URL validation. It also added static checks against regressions and a VS Code extension.

## 4. The 13 packages in the monorepo

The project uses a `pnpm` workspace with 13 packages. Each package has a focused responsibility.

### 4.1 `@secureship/cli`

This is the main command-line application. It provides commands such as scan, fix, doctor, init, SBOM generation, tool installation, and offline bundle operations. It validates command-line options, provides interactive prompts, and supports distribution for Windows, Linux, and macOS.

### 4.2 `@secureship/contracts`

This package defines shared data structures, enums, and Zod validation schemas. Other packages use these contracts so that they agree on report formats, configuration, remediation data, and SARIF types. It also validates scanner output at the boundary because scanner output is untrusted input.

### 4.3 `@secureship/scanner-adapters`

This package starts the five scanner tools and converts their results into a consistent form. It runs tools without a shell, checks their SHA-256 hashes against `tools.lock.json`, and uses safeguards against a malicious binary planted inside the repository being scanned. It also contains safe archive handling and SARIF parsing.

### 4.4 `@secureship/reachability`

This package uses WebAssembly Tree-sitter parsers to analyze JavaScript, TypeScript, TSX, and Python. It builds import graphs, identifies entry points, examines vulnerable symbol use, and attempts to prove call paths. The source says the WebAssembly approach avoids requiring users to install native C++ build tools.

### 4.5 `@secureship/context-slicer`

This package extracts a small, relevant piece of source code around a finding for AI review. It applies token limits, blocks credential files such as `.env`, `.pem`, and `.aws`, checks real paths to prevent symlink escapes, and redacts secrets in two passes.

### 4.6 `@secureship/ai`

This package implements BYOK AI triage. It checks for prompt injection, sends a structured prompt, validates the response, and asks for exact source-code quotations when the model says a finding is likely a false positive. A citation that does not match the source exactly cannot support suppression. The package also provides consent handling, a cache, and provider HTTP support.

### 4.7 `@secureship/core-engine`

This is the central scan pipeline. It coordinates scanners and analysis, correlates findings, applies scope rules, maintains the accounting ledger, runs the supply-chain threat checks, creates SBOMs, and manages offline bundles.

### 4.8 `@secureship/patch-engine`

This package parses and applies unified diffs with exact context matching. It evaluates a proposed patch against 23 safety rules and can pin transitive dependency versions in lockfiles. Its purpose is to prevent unclear or unsafe edits from being applied automatically.

### 4.9 `@secureship/sandbox`

This package creates a separate copy of the workspace, applies a proposed patch there, and runs checks in that copy. It supports container-based and host-based backends. The source describes running baseline tests and patched tests to see whether the change introduces regressions.

### 4.10 `@secureship/fleet`

This package provides a control plane for coordinating scans across multiple workers. It uses bearer-token authentication, keeps token values out of ordinary server state through a `WeakMap`, and writes stored data using an atomic temp-file-and-rename process. It also describes backup recovery and quarantining damaged files.

### 4.11 `@secureship/license-server`

This package contains a Cloudflare Worker and D1 database for license issuance, seat activation, and Stripe webhook processing. The source says licenses can be validated cryptographically offline, without requiring the client to contact the server every time.

### 4.12 `@secureship/benchmark`

This package runs the project against vulnerability examples with known expected outcomes. It calculates precision, recall, F1, and suppression-recall metrics. The source lists target metric thresholds; these should be presented together with the actual benchmark results and the corpus used.

### 4.13 `@secureship/vscode-extension`

This package connects SecureShip to VS Code. It can show diagnostics and hover details, display findings in a panel, run the CLI, and offer quick fixes that use the verification ladder.

## 5. The four security gates

SecureShip describes four gates that run in sequence. A finding can be filtered or reviewed at one stage, but high-severity findings have additional protection against suppression.

### Gate 1: File and context scoping

Gate 1 checks where a finding occurs. It looks for path segments such as `test`, `__tests__`, `mocks`, `fixtures`, `docs`, and `examples`. It uses segment boundaries so that ordinary names such as `contest.ts` or `latest.ts` are not mistaken for test paths.

A finding in a test-like path may be treated as out of production scope. However, the Provider Secret Guard checks for real provider-specific secrets, including AWS, GitHub, Stripe, Slack, and private keys. The source says likely placeholder values such as `dummy`, `fake`, `xxxx`, `changeme`, and `secret_token_here` can be treated differently from real-looking credentials. The intent is to avoid ignoring a genuine credential merely because it appears under a test directory.

### Gate 2: Package-level reachability

The import graph uses AST parsing to find imports and determine which files can be reached from production entry points. It also examines dependency lockfiles to understand transitive dependencies.

The project includes a reference check for Dockerfiles, CI workflows, package scripts, configuration files, and other non-code uses. This prevents a package from being marked unused based only on source imports.

The source also describes type-only TypeScript imports as development-only because they are removed at runtime. Such a package can be treated as unreachable for runtime vulnerability analysis under the stated rules.

### Gate 2, Phase B: Vulnerable symbol reachability

A package can be used by production code even when the vulnerable part of that package is not used. Phase B therefore checks the specific vulnerable function or symbol.

The source describes this sequence:

1. Load advisory information from a curated dataset or a structured advisory.
2. Extract candidate vulnerable symbols using three tiers: structured advisory data, the curated database, and a heuristic fallback.
3. Walk the AST to find direct calls, member expressions, destructuring, property access, and other symbol references.
4. Try to prove a call path from an entry point to the vulnerable symbol, with a limit of ten hops.
5. Assign a clear result, such as `[CALL PATH PROVEN]`, `[SYMBOL REFERENCED]`, `[SYMBOL NOT REFERENCED]`, or `[IMPORTED]`.

If the analysis sees dynamic behavior or a namespace escape that makes the result uncertain, it should fail closed. In practice, that means keeping the finding as reachable or requiring review rather than claiming it is safe.

### Gate 3: AI triage and the Skeptic Oracle

The AI stage uses a limited source-code slice after secret redaction. It checks for prompt injection, adds a 24-character hexadecimal nonce to help separate instructions from code, and requests a structured answer. The response is checked against a schema.

If the AI says a finding is likely a false positive, it must provide an exact quotation from the source slice showing the relevant sanitization or other evidence. The verifier compares the quotation character by character. If the quotation is absent or does not match, the result becomes `NEEDS_HUMAN_REVIEW`.

The source also describes a second prompt variant for suppress mode. If the two results disagree, the finding is sent for human review. The safety floor says CRITICAL and HIGH findings cannot be suppressed by this AI gate. The AI is meant to assist analysis, not make those high-impact decisions alone.

### Gate 4: The ten-stage fix verification ladder

Proposed fixes are checked in a shadow workspace. The listed stages are:

1. **APPLY:** Apply a diff with exact matching and no fuzz.
2. **POLICY:** Check the patch against the 23 safety rules.
3. **SYNTAX:** Parse changed files and check for syntax errors.
4. **RESCAN:** Run the original scanner again to see whether the issue is gone. If the scanner is unavailable, the result is inconclusive rather than a pass.
5. **NEW_FINDINGS:** Run available scanners to check for new security findings.
6. **IMPORTS:** Check whether the patch introduced unapproved imports.
7. **INSTALL:** If package manifests changed, install dependencies in the isolated environment.
8. **TYPECHECK:** Run the applicable type checker, such as `tsc --noEmit`, `mypy`, or `pyright`.
9. **BUILD:** Run the project build command, such as `npm run build`.
10. **TEST:** Run tests on baseline and patched copies and compare results to detect regressions.

The purpose is to check both that the original issue was addressed and that the change did not break the project.

## 6. Fail-closed rules for symbol analysis

The project sets out six rules, R1 through R6, and ten preconditions, P1 through P10. These rules limit when SecureShip may label a finding unreachable.

### Rules R1–R6

- **R1 — Candidate extraction:** If no vulnerable-symbol candidate can be extracted, keep the finding as `REACHABLE_IMPORT` and note that symbol data is unavailable.
- **R2 — Incomplete usage analysis:** If symbol extraction was incomplete in any production file, keep the finding as `REACHABLE_IMPORT` and identify `USAGE_INCOMPLETE` as the reason.
- **R3 — Symbol reference and call path:** If the symbol is referenced, try to prove the call path. A proven path is `REACHABLE_CALL_PATH`; failure to prove a path does not by itself mean safe, so keep it as `REACHABLE_IMPORT`.
- **R4 — Namespace escape:** If a package namespace is passed, returned, spread, accessed dynamically, re-exported, or otherwise escapes analysis, keep it as `REACHABLE_IMPORT` with a namespace-escape reason.
- **R5 — Preconditions:** All ten preconditions must pass before a finding can be called `UNREACHABLE` because a vulnerable symbol was not referenced.
- **R6 — Transitive dependencies:** Do not prune transitive dependencies at function level because the project does not index internal call sites inside `node_modules`. Preserve them as reachable through lockfile tracing.

### Preconditions P1–P10

1. **P1:** At least one entry point was found and resolved.
2. **P2:** There are no syntax parse errors in production source files.
3. **P3:** There are no unresolved local imports or production path aliases.
4. **P4:** There are no dynamic imports, `eval`, `new Function`, or dynamic `require` uses in non-test files.
5. **P5:** Test-only imports are not hiding production use.
6. **P6:** The reference check across scripts, configuration, and string literals is clean.
7. **P7:** The advisory candidate source is high quality: a curated database entry or verified structured advisory.
8. **P8:** A curated dataset entry must say the trigger is a function call and must have a complete entry-point list. If the trigger is importing the package, importing it may be enough to activate the issue.
9. **P9:** The package must not expose command-line binaries through a `bin` field that scripts or CI could invoke.
10. **P10:** The package must be a direct dependency with no other installed packages depending on it.

Together, these safeguards make the system conservative when evidence is incomplete.

## 7. The 23 patch safety rules

A proposed patch is checked for the following problems:

1. **MALFORMED_DIFF:** The unified diff or its hunk alignment is invalid.
2. **CONTEXT_MISMATCH:** The surrounding source does not match the diff context.
3. **OUTSIDE_ROOT:** A path would escape the workspace, for example through `..`.
4. **PROTECTED_PATH:** A protected CI, build, or configuration file is changed.
5. **TEST_FILE:** A test is changed in a way that could bypass security checks.
6. **SENSITIVE_FILE:** A credential file such as `.env`, `.pem`, `.aws`, or `id_rsa` is touched.
7. **BINARY_PATCH:** The patch tries to change a binary file.
8. **SYMLINK:** The patch creates or changes a symbolic link.
9. **MODE_CHANGE:** The patch changes executable permissions or file mode.
10. **NEW_FILE:** An unexpected new file is created.
11. **DELETE_FILE:** A whole file is deleted.
12. **RENAME:** An existing file is renamed.
13. **TOO_MANY_FILES:** The patch changes more files than the configured limit, which defaults to one.
14. **TOO_MANY_LINES:** The patch exceeds the configured line-change limit, which defaults to 60.
15. **OUTSIDE_SCOPE:** The change reaches outside the finding's enclosing AST scope.
16. **SUPPRESSION_MARKER:** The patch adds an ignore marker such as `nosemgrep`, `noqa`, or `@ts-ignore`.
17. **NEW_DEPENDENCY:** The patch adds an external dependency to a manifest.
18. **NEW_DANGEROUS_API:** The patch adds a risky API such as `eval`, `child_process`, `pickle`, or `socket`.
19. **SECRET_IN_PATCH:** The patch contains a credential or API key.
20. **HIDDEN_UNICODE:** The patch contains bidi overrides or zero-width characters that could hide code.
21. **REMOVAL_ONLY:** The patch only deletes code without replacing the required behavior.
22. **EXCESSIVE_DELETION:** The patch deletes more lines than the allowed threshold.
23. **EOL_INCONSISTENT:** The patch mixes CRLF and LF line endings.

## 8. Other in-house features

### Supply-chain threat checks

The source describes an in-house engine with eight detector groups and 35 rules. These checks are intended to identify suspicious packages even when there is no published CVE.

1. **Typosquatting:** Compare package names to popular npm and PyPI names using Damerau-Levenshtein distance. This distance also catches adjacent letters that were swapped.
2. **Install scripts:** Look for `preinstall`, `install`, and `postinstall` scripts that perform suspicious actions such as downloading and piping content to a shell or decoding base64.
3. **Binary confusion:** Look for path traversal in binary declarations and packages that try to replace system commands such as `git`, `ssh`, `node`, `curl`, or `bash`.
4. **Unicode attacks:** Find bidi control characters, zero-width spaces, and look-alike characters that can disguise source code.
5. **High entropy:** Measure strings for unusually high entropy and look for encoded or obfuscated payloads.
6. **Metadata anomalies:** Check for unusual version jumps, dates, repository state, or mismatches between package descriptions and contents.
7. **Governance risks:** Look for concerns such as geographic targeting, abandoned maintenance, or missing maintainer MFA.
8. **Empty packages:** Detect missing or nearly empty package archives that may be related to dependency confusion.

The source also describes AST capability analysis. It examines capabilities such as shell execution, network sockets, environment-variable access, sensitive-file reads, `eval` or VM use, dynamic `require`, debugging internals, and install scripts. Combinations of capabilities can create additional alerts.

### SBOM generation

The project can generate software bills of materials in CycloneDX 1.5 and SPDX 2.3 formats. It creates package URLs, computes deterministic SHA-256 hashes for package directories, adds vulnerability information, and extracts license details from manifests and license files.

### Offline bundles and cryptographic signing

The offline bundle system uses deterministic JSON formatting based on RFC 8785 and Ed25519 signatures. The archive writer normalizes file modes, times, and ownership fields so the result can be reproduced. The archive reader streams data, limits memory use, rejects path traversal and symlinks, and checks Windows reserved names. The system also supports versioned database generations and an anti-rollback check.

### Fleet storage and token handling

The fleet service stores token files with restrictive permissions and keeps token values out of normal server serialization and logs. Its storage process writes to a temporary file, flushes it, and renames it into place. It can recover from a backup and preserve damaged files in a quarantine location. The source also describes retry delays to handle Windows antivirus software temporarily locking a file.

### Safe browser opening

The Windows browser opener avoids `cmd.exe /c start`, which interprets shell characters. Instead it uses `rundll32.exe` with `shell: false`; macOS and POSIX systems use their platform opener paths. Before opening a URL, the project checks that it is an acceptable HTTP or HTTPS URL and rejects whitespace, control characters, non-ASCII input, backslashes, user credentials, and unsafe schemes or characters.

### Licensing

The license service uses a Cloudflare Worker and D1 database. The source describes RS256 or Ed25519 token validation that can work offline, activation codes using Crockford Base32, machine-seat limits, and Stripe webhook checks using HMAC-SHA256 and timestamp tolerance. Webhook processing is designed to be idempotent.

## 9. Finding accounting rule

The project calls its central ledger rule **Invariant P1**:

`totalRaw = totalReported + totalSuppressed + totalOutOfScope`

The ledger is meant to account for every raw scanner result. It tracks results that were reported, suppressed, or placed out of scope. If the totals do not match, the ledger throws an error rather than silently accepting missing findings.

The source lists five reasons that a finding might be suppressed:

- `GATE1_TEST_OR_MOCK`: It is a benign test fixture or example.
- `GATE2_UNREACHABLE`: The package or vulnerable symbol was shown to be unused under the reachability rules.
- `GATE3_LIKELY_FALSE_POSITIVE`: AI review supported the decision with exact source citations.
- `USER_IGNORE_RULE`: The repository configuration explicitly ignores the finding.
- `BASELINE_KNOWN`: The finding is recorded as existing technical debt in `.secureship/baseline.json`.

These categories are part of the audit trail. They are not meant to erase the original raw finding from accounting.

## 10. Testing and verification described by the source

The source describes unit and integration tests, adversarial tests, generated repositories, mutation tests, and a check intended to detect fake tests.

### Test totals

There is a mismatch in the supplied master document:

- Its title, status summary, and test section heading refer to **2,346 test cases across 264 test files**.
- The table in Section 9.1 totals **2,478 test cases across 265 files**, including one release packaging test.

This rewrite preserves both source figures here rather than choosing one. The repository should be checked before using either number in an interview or company report.

### Hostile-input checks

The source lists tests for 50 MB single-line JavaScript files, invalid UTF-8 data, deeply nested functions, cyclic symlinks, directory traversal attempts, prototype-pollution inputs, and repositories containing 20,000 files. It reports a target of keeping memory within a 512 MB heap for the large-repository scenario.

### Generated project tests

A fuzz generator creates more than 500 synthesized repository layouts. These combine imports, re-exports, dynamic evaluation, aliases, and lockfile patterns. The source reports zero false-unreachable results in this generated set.

### Metamorphic mutation tests

Mutation tests deliberately alter behavior to check whether the test suite detects the change. The source lists 107 mutations:

- 17 mutations for import graphs and entry points.
- 21 mutations for AI prompts, citations, injection checks, and HTTP redirect behavior.
- 13 mutations for the verification ladder, patch rules, and shadow isolation.
- 26 mutations for symbol extraction, namespace escapes, call paths, and R1–R6/P1–P10.
- 9 mutations for offline bundles, signatures, rollback checks, and pointer swapping.
- 21 mutations for supply-chain checks.

The source reports that all 107 were caught.

### Test-integrity checks

The source describes an automated audit that flags tests with no assertions, tautologies such as `expect(true).toBe(true)`, empty catch blocks that hide errors, and prohibited mocks of core algorithms. It reports zero violations in the run shown in the master document.

### Benchmark targets

The benchmark package is described as using more than 100 vulnerability cases. The master document lists target values of at least 85% precision, 80% recall, 80% F1, and 90% suppression-recall. These are stated thresholds; a presentation should distinguish thresholds from measured results.

## 11. Production audit gates

The source says 16 audit gates were addressed in three waves.

### Wave 0: Blockers

1. **F-SEC-001:** Remove the JWT signing oracle and use RS256 SPKI handling in the license server.
2. **F-SEC-002:** Validate Stripe webhook HMAC signatures and timestamps.
3. **F-DIS-001:** Remove unpublished internal dependencies from the CLI package manifest.
4. **F-REL-001:** Package standalone binaries with the required WebAssembly grammars.
5. **F-LIC-001:** Synchronize the background license renewal protocol between client and server.
6. **F-FLT-003:** Restrict Fleet Server CORS origins instead of allowing `*`.
7. **F-LIC-002:** Enforce active machine-seat limits during activation.
8. **F-PKG-001:** Include curated vulnerable symbols and SAST rules in the CLI distribution.

### Wave 1: Critical issues

9. **F-ENG-001:** Remove `FakeSandboxBackend` from production code.
10. **F-GIT-001:** Find the repository root correctly when Git diff scanning starts from a subdirectory.
11. **F-FLT-001:** Require bearer tokens on fleet endpoints and keep token values private.
12. **F-SAN-001:** Translate Windows Docker mount paths correctly.
13. **F-FLT-004:** Use atomic fleet storage writes, `fsyncSync`, and backups.

### Wave 2: High-priority issues

14. **F-SEC-003:** Replace shell-based browser opening with a safe opener.
15. **F-TST-001:** Ensure the test-integrity script exits successfully when there are no violations.
16. **F-LEG-001:** Include LGPL-2.1 and Apache-2.0 notices in `THIRD_PARTY_NOTICES.md`.

## 12. Roadmap from the source

The source lists four future ideas:

1. **Automated pull-request agent:** Create pull requests on GitHub, GitLab, or Bitbucket with verified patches and test evidence.
2. **More language grammars:** Add Go, Java, Rust, and C# Tree-sitter WebAssembly grammars.
3. **Runtime trace correlation:** Compare static call paths with Linux eBPF runtime events in staging.
4. **Distributed worker fleet:** Run scan workers across Kubernetes clusters for large collections of repositories.

These are roadmap items in the supplied document, not current capabilities described as complete.

## 13. A simple way to explain SecureShip

### Short explanation

“SecureShip combines existing security scanners with its own checks to decide whether findings are relevant to production code. It checks file scope, package use, and vulnerable function use. When AI review is enabled, the model must support a false-positive decision with exact code quotations. Proposed fixes are tested in a separate workspace before they are accepted.”

### Explaining the four gates

1. **Context gate:** Check whether a finding is in tests, examples, or documentation, while still looking for real credentials in those locations.
2. **Reachability gate:** Check whether production code uses the affected package and, where supported, whether it calls the specific vulnerable function.
3. **AI review gate:** Use a user-provided AI provider to review a limited, redacted code slice. Require exact quotations before treating a finding as a likely false positive. Keep high-severity findings from being suppressed by AI.
4. **Fix verification gate:** Apply the change in a shadow copy and check its policy, syntax, scan results, imports, installation, types, build, and tests.

### Explaining what is built in-house

SecureShip adds supply-chain checks for suspicious package behavior, an auditable finding ledger, offline signed bundles, and a patch verification workflow. These features complement the external scanners; they do not replace the need to validate claims against project code and benchmark evidence.

### Explaining testing

“The project describes adversarial tests, generated repository layouts, mutation testing, and checks that look for weak or fake tests. The master document contains conflicting test totals, so I would verify the current repository count before quoting a number.”

## Conclusion

SecureShip is presented as a security analysis and remediation system that combines external scanners with local scope analysis, dependency reachability checks, optional AI review, supply-chain checks, and isolated fix verification. Its central design idea is to keep findings auditable and to make suppression conservative when evidence is incomplete.
