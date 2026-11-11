# SecureScan Academic References & Security Standards

This document establishes the authoritative academic, industrial, and standard citations governing the design, vulnerability categorization, archive validation, and reporting models of the **SecureScan** security platform.

---

## 1. Security Standards & Classification Frameworks

### 1.1 MITRE Common Weakness Enumeration (CWE)
- **Standard:** MITRE CWE Version 4.14 / CWE List Version 4.15
- **Publisher:** The MITRE Corporation / Cybersecurity and Infrastructure Security Agency (CISA)
- **URL:** [https://cwe.mitre.org/](https://cwe.mitre.org/)
- **Direct Application in SecureScan:**
  - SecureScan normalizes all SAST, SCA, and IaC vulnerability findings into canonical numeric CWE identifiers (`CWE-89`, `CWE-78`, `CWE-798`, `CWE-22`, `CWE-502`).
  - Implemented in `backend/app/models/report.py` via `normalize_cwe_id()`, `extract_cwe_ids()`, and `CWE_TO_OWASP_INT`.

### 1.2 OWASP Top 10:2021
- **Standard:** OWASP Top 10 Web Application Security Risks (2021 Standard)
- **Publisher:** Open Web Application Security Project (OWASP Foundation)
- **URL:** [https://owasp.org/Top10/](https://owasp.org/Top10/)
- **Categories Enforced in SecureScan:**
  - `A01:2021-Broken Access Control` (CWE-22, CWE-59, CWE-200, CWE-284, CWE-862)
  - `A02:2021-Cryptographic Failures` (CWE-261, CWE-310, CWE-327, CWE-328, CWE-330)
  - `A03:2021-Injection` (CWE-78, CWE-79, CWE-89, CWE-94, CWE-95, CWE-917)
  - `A04:2021-Insecure Design` (CWE-209, CWE-256, CWE-501)
  - `A05:2021-Security Misconfiguration` (CWE-16, CWE-260, CWE-732, Checkov IaC findings)
  - `A06:2021-Vulnerable and Outdated Components` (CWE-937, CWE-1035, Trivy/OSV SCA findings)
  - `A07:2021-Identification and Authentication Failures` (CWE-287, CWE-384, CWE-798, Gitleaks hardcoded credentials)
  - `A08:2021-Software and Data Integrity Failures` (CWE-502, CWE-829, CWE-494)
  - `A09:2021-Security Logging and Monitoring Failures` (CWE-117, CWE-778)
  - `A10:2021-Server-Side Request Forgery (SSRF)` (CWE-918)
- **Direct Application:** Implemented in `map_cwe_to_owasp()` providing automated multi-scanner alignment with OWASP Top 10 compliance audits.

### 1.3 OASIS SARIF 2.1.0 (Static Analysis Results Interchange Format)
- **Standard:** OASIS Standard: Static Analysis Results Interchange Format (SARIF) Version 2.1.0
- **Committee:** OASIS Static Analysis Results Interchange Format (SARIF) Technical Committee
- **Date:** 27 March 2020
- **URL:** [https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
- **Schema URI:** `https://json.schemastore.org/sarif-2.1.0.json`
- **Direct Application in SecureScan:**
  - Implemented in `backend/app/exporters/sarif_exporter.py`.
  - Serializes scanner results into standard SARIF runs, tool driver metadata, precision indicators, rule properties (CWE & OWASP tags), and physical URI location spans for GitHub Security and IDE consumption.

---

## 2. Defensive Archive Security & System Research

### 2.1 Snyk Zip Slip Research & Path Traversal Vulnerabilities
- **Citation:** Snyk Security Research Team. "Zip Slip Vulnerability: Arbitrary File Overwrite Through Archive Extraction." *Snyk Research Whitepaper*, June 2018.
- **Reference:** [https://snyk.io/research/zip-slip-vulnerability/](https://snyk.io/research/zip-slip-vulnerability/)
- **Summary:** Investigates how unvalidated directory traversals in archive extraction routines allow malicious zip files to escape destination target folders and overwrite arbitrary files across host operating systems.
- **Implementation in SecureScan:**
  - Implemented in `backend/app/core/safe_extract.py`.
  - Rejects any archive member with names containing `..`, absolute paths, or paths that resolve outside `target_dir.resolve()` using Python `is_relative_to()`.

### 2.2 Zip-Bomb Analysis & Defenses
- **Citation:** Fifield, David. "A non-recursive zip bomb." *USENIX Security Symposium / David Fifield Technical Reports*, July 2019.
- **URL:** [https://www.bamsoftware.com/hacks/zipbomb/](https://www.bamsoftware.com/hacks/zipbomb/)
- **Summary:** Analyzes modern overlapping-entry compression bombs capable of expanding a 42 KB archive into hundreds of gigabytes or petabytes of data, causing immediate disk and memory exhaustion.
- **Implementation in SecureScan:**
  - Enforces a strict compression ratio floor: any entry with `uncompressed_size / compressed_size > 100.0` is immediately rejected.
  - Implements streaming byte chunk counters that abort extraction if real-time cumulative output exceeds 50 MB total or 10 MB for a single file.

### 2.3 Symbolic Link Dereferencing Attacks (POSIX S_IFLNK)
- **Citation:** Wheeler, David A. "Secure Programming HOWTO: Creating Agile and Secure Code." *Free Software Foundation*, Section 7.3 ("File Operations & Symlinks"), 2003.
- **Implementation in SecureScan:**
  - Archives containing entries with external attributes flagged as symbolic links (`mode & 0o170000 == 0o120000` or explicit attribute `0xA1ED`) are rejected before disk writes, preventing attackers from linking target destinations to `/etc/passwd` or `/root/.ssh/id_rsa`.

---

## 3. Secret Detection & Algorithmic Analysis

### 3.1 Shannon Entropy in Information Theory
- **Citation:** Shannon, Claude E. "A Mathematical Theory of Communication." *Bell System Technical Journal*, Vol. 27, No. 3, pp. 379–423, July 1948.
- **DOI:** [10.1002/j.1538-7305.1948.tb01338.x](https://doi.org/10.1002/j.1538-7305.1948.tb01338.x)
- **Application in SecureScan & Gitleaks:**
  - High-entropy character sequence calculation ($H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$) distinguishes pseudo-random base64/hex cryptographic tokens and API keys (AWS, GitHub, Stripe, SSH) from ordinary source code text and identifiers.

---

## 4. Software Supply Chain Security

### 4.1 Academic Surveys on Software Supply Chain Integrity
- **Citation:** Ladisa, Piergiorgio; Plate, Henrik; Martinez, Matias; Monperrus, Martin. "SoK: Taxonomy of Attacks on Open-Source Software Supply Chains." *IEEE Symposium on Security and Privacy (S&P)*, pp. 1509–1526, 2023.
- **DOI:** [10.1109/SP46215.2023.10179304](https://doi.org/10.1109/SP46215.2023.10179304)
- **Citation:** Ohm, Marc; Sykosch, Arnold; Meier, Michael. "Towards Automated Security Analysis of Open Source Software Packages." *Proceedings of the 15th International Conference on Availability, Reliability and Security (ARES)*, Article 63, pp. 1–10, 2020.
- **Application in SecureScan:**
  - Guides the multi-engine software composition analysis (SCA) pipeline incorporating Trivy and OSV-Scanner to identify known CVEs in upstream open-source dependencies (npm, PyPI, Go modules) before deployment.
