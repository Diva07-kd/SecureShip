# SecureScan Third-Party Attributions & Software Bill of Materials (SBOM)

This document provides complete attributions, intellectual property declarations, licensing disclosures, and cryptographic hash verification references for all software components integrated into **SecureScan**.

---

## 1. Project Authorship & SecureShip Intellectual Property Declaration

> **Explicit Assessment Declaration:**
> **SecureShip** (`@secureship/*`, monorepo packages, core analysis engine, reachability graph algorithms, and CLI) is the author's **own original project and primary submission codebase**.
>
> SecureScan builds upon and wraps SecureShip as an enterprise web interface and API delivery platform for the **Heyram Infrastructure placement assessment**. SecureShip is authored by the candidate under the **Apache-2.0 License** and is incorporated as first-party foundational infrastructure.

---

## 2. Integrated Security Scanning Engines

All third-party scanning engines bundled within SecureScan are pre-baked during container image construction. No binaries are downloaded at runtime. Every binary is verified against authoritative upstream cryptographic SHA-256 hashes defined in `tools.lock.json`.

| Tool Name | Version | Primary Function | Upstream License | Distribution URL | SHA-256 (Linux x64) |
|---|---|---|---|---|---|
| **Opengrep** | `1.31.0` | AST-based Static Application Security Testing (SAST) | LGPL-2.1 | [opengrep/opengrep](https://github.com/opengrep/opengrep) | `dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147` |
| **Gitleaks** | `8.24.0` | High-entropy secret and credential detection | MIT | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | `cb49b7de5ee986510fe8666ca0273a6cc15eb82571f2f14832c9e8920751f3a4` |
| **Trivy** | `0.76.0` | Comprehensive vulnerability and container scanner (SCA) | Apache-2.0 | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | `e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7` |
| **OSV-Scanner** | `1.9.2` | Open Source Vulnerability Database dependency scanner | Apache-2.0 | [google/osv-scanner](https://github.com/google/osv-scanner) | `d6af4b67fa5de658598bd2d445efb99e90d1734b3146962418719c4350ecb74b` |
| **Checkov** | `3.3.29` | Infrastructure-as-Code (IaC) security and compliance | Apache-2.0 | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | PyPI Wheel Hash Verification |

---

## 3. Backend Python Ecosystem Dependencies

The FastAPI backend relies on the following open-source libraries:

| Library | Version / Constraint | License | Role in SecureScan |
|---|---|---|---|
| **FastAPI** | `>=0.115.0` | MIT | High-performance asynchronous web framework |
| **Uvicorn** | `>=0.30.0` | BSD-3-Clause | Lightning-fast ASGI web server implementation |
| **Pydantic** | `>=2.8.0` | MIT | Data validation and schema enforcement (Pydantic v2) |
| **Pydantic-Settings** | `>=2.4.0` | MIT | Environment variable parsing and type coercion |
| **Python-Multipart** | `>=0.0.9` | Apache-2.0 | Streaming multi-part form data parser for archive uploads |
| **SlowAPI** | `>=0.1.10` | MIT | IP-based rate limiting protection |
| **ReportLab** | `>=4.2.0` | BSD-like (Open Source) | High-fidelity binary PDF document generation fallback |
| **WeasyPrint** | `>=62.0` | BSD-3-Clause | Standards-compliant HTML/CSS to PDF document renderer |
| **Pytest & Pytest-Asyncio** | `>=8.3.0` | MIT | Automated unit, integration, and E2E testing suites |

---

## 4. Frontend Web Dashboard Dependencies

The user interface is built using modern React and web standards:

| Library | Version | License | Functionality |
|---|---|---|---|
| **React & React-DOM** | `^18.3.1` | MIT | Declarative component UI framework |
| **TypeScript** | `^5.6.3` | Apache-2.0 | Static typing and compile-time correctness |
| **Vite** | `^6.0.3` | MIT | ESM-based lightning fast frontend build tool |
| **Tailwind CSS** | `^3.4.16` | MIT | Utility-first responsive dark theme design system |
| **Recharts** | `^2.13.3` | MIT | Composable data visualization (Donut and Bar charts) |
| **Lucide-React** | `^0.468.0` | ISC | Accessible, pixel-perfect icon set |

---

## 5. Infrastructure, Reverse Proxy & Network Ingress

| Tool | Version | License | Function |
|---|---|---|---|
| **Nginx** | `Alpine 1.27+` | 2-clause BSD-like | Static SPA web server & reverse proxy with 50MB buffer |
| **Cloudflared** | `latest` | Apache-2.0 | Zero-configuration Cloudflare Quick Tunnel provider |
| **Docker & Compose** | `v2+` | Apache-2.0 | Container isolation and resource ceiling enforcement |
