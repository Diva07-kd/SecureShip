# SecureShip Phase B: Privacy & Network Isolation Specification

**Document:** Privacy Guarantee, Data Flow, & Zero-Network Standard  
**Status:** PRODUCTION STANDARD  
**Author:** Principal Security Engineer & Verification Lead  
**Governing Standard:** Anti-Cheat Rules AC1–AC9 & Core Principle P4

---

## 1. Zero-Network Invariant (Principle P4 & F8)

SecureShip operates under a strict, non-negotiable architectural invariant:

> **Zero Outbound Network Requests:** SecureShip does not make outbound network connections during scan execution, reachability analysis, or report generation. It operates entirely offline and is fully air-gap certified.

Phase B function-level reachability strictly adheres to this standard:

- **No Advisory Lookups:** Vulnerability symbol data is bundled statically in [`packages/reachability/data/vulnerable-symbols.json`](file:///c:/dev/SecureShip-IDE/packages/reachability/data/vulnerable-symbols.json). The engine does not query the internet (GHSA, OSV, NVD, or proprietary servers) at scan time.
- **No Package Manager Invocations:** SecureShip never executes `npm`, `yarn`, `pnpm`, `pip`, or `poetry` to resolve or download dependencies. All dependency structures are parsed statically from existing lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `Pipfile.lock`).
- **No Telemetry or Phone-Home:** Zero usage telemetry, crash reporting, finding statistics, or license pings are transmitted.
- **No Remote AI Calls in Phase B:** Function-level reachability is 100% deterministic static analysis; it never invokes LLM APIs.

---

## 2. Cryptographic Offline Integrity

To ensure that offline vulnerability data cannot be tampered with or corrupted:

1. **Bundled SHA-256 Manifest:** The database is attested by [`vulnerable-symbols.manifest.json`](file:///c:/dev/SecureShip-IDE/packages/reachability/data/vulnerable-symbols.manifest.json), containing the cryptographic SHA-256 digest of `vulnerable-symbols.json`.
2. **Offline Attestation Script:** `pnpm verify:symbols` validates the dataset schema, entry completeness, and SHA-256 checksum without opening any network sockets.
3. **Fail-Closed Tamper Detection:** If the SHA-256 checksum fails at runtime, `DatasetLoader` discards the dataset, issues a security warning, and falls back to package-level reachability without crashing or leaking data.

---

## 3. Safe Local Storage & Cache Security

SecureShip avoids cache poisoning and repository contamination through strict isolation boundaries:

- **Outside-the-Repo Cache:** The external AST extraction cache is located exclusively in the user's home directory (`~/.secureship/cache` on Linux/macOS, `%LOCALAPPDATA%\secureship\cache` on Windows). It is never written into the target repository.
- **Machine-Local HMAC-SHA256 Key:** Cache entries are signed using a local machine secret stored with restricted POSIX permissions (`0600`).
- **Cache Poisoning Immunity:** A malicious repository containing pre-computed cache files or `.secureship/` directories cannot poison the engine, as repository-resident cache or dataset files are ignored.
- **Version Isolation:** All cache entries are tagged with `ANALYZER_VERSION = '2.0.0'`. Any schema change or analyzer upgrade invalidates older entries automatically.
