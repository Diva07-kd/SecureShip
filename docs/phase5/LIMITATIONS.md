# SecureShip Phase 5: Verified Remediation Limitations & Disclaimers

## 1. Explicit Scope & Capability Boundaries

SecureShip Phase 5 ("Gate 4 Verified Remediation") is engineered to provide conservative, honest, and high-assurance automated remediation. To prevent false security claims or over-reliance, the following boundaries and limitations are explicitly disclosed:

### 1.1 Single-Finding Remediation Only

- Gate 4 processes **exactly one finding at a time**.
- Complex, multi-file refactorings, system architecture migrations, or interdependent vulnerability cascades across multiple repositories are outside the scope of single-finding remediation.

### 1.2 Category Eligibility Constraints

- Automated patch generation is restricted strictly to **SAST** (code analysis) and **IAC** (infrastructure configuration) findings.
- **SECRET** findings (leaked keys, hardcoded credentials) are **ineligible**: automated tools cannot rotate credentials, revoke leaked tokens with third-party providers, or determine new secret values.
- **SCA** findings (vulnerable dependencies) are **ineligible**: upgrading package versions requires package manager lockfile resolution, compatibility audits, and migration testing.
- Findings matching credential or secret CWEs (e.g., CWE-259, CWE-798) are strictly rejected.

### 1.3 Test Suite Dependency

- Dynamic verification stages (`TEST`, `BUILD`, `TYPECHECK`) depend entirely on the presence and rigor of the repository's automated test suites.
- If a repository has no test suite, or if existing unit tests do not assert correctness on the modified code paths, tests will report `PASS` or `SKIPPED`, but semantic behavioral preservation cannot be guaranteed beyond what the tests cover.
- In repositories lacking test suites, verification tops out at `VERIFIED_STATIC`.

### 1.4 Container Sandbox Prerequisite

- Container execution requires Docker Desktop or Podman installed on the developer machine or CI runner.
- If container runtimes are unavailable, dynamic verification stages cannot execute unless the operator explicitly trusts the repository for host execution with `secureship sandbox trust-host`.

### 1.5 Probabilistic Patch Generation vs Deterministic Verification

- While verification ladder evaluation is **100% deterministic and reproducible**, patch generation using third-party LLM providers (BYOK) is probabilistic.
- Different models or API versions may propose distinct patches for the same finding.
- The verification ladder exists precisely to filter, validate, and verify these probabilistic outputs.

### 1.6 Conservative Claims Disclaimer

- SecureShip **never** claims that code is "secure", "fixed", or that a patch is "flawless".
- Verification statuses (`VERIFIED_STATIC` and `VERIFIED_RUNTIME`) certify strictly that the specific tests, scanners, Tree-sitter parsers, and policy rules executed without reporting failures or regressions.
- Developers remain responsible for reviewing and authorizing all changes before deployment.
