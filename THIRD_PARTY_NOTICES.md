# SecureShip Third-Party Notices & WASM Supply Chain Attestation

SecureShip Phase 3 bundles pre-compiled WebAssembly (`.wasm`) grammars and the Tree-sitter WebAssembly core runtime to deliver fast, secure, native-compilation-free static syntax parsing across Node.js environments.

All bundled WebAssembly binaries are permissively licensed (MIT / Unlicense). They are executed strictly in an offline, memory-bounded, zero-system-call WebAssembly sandbox without any native host code execution.

---

## 1. Bundled WebAssembly Binaries & Cryptographic Manifest

| Binary Name                       | Upstream Repository                                                                         | Version  | License | SHA-256 Digest                                                     | Size (Bytes) |
| :-------------------------------- | :------------------------------------------------------------------------------------------ | :------- | :------ | :----------------------------------------------------------------- | :----------- |
| **`tree-sitter.wasm`**            | [tree-sitter/tree-sitter](https://github.com/tree-sitter/tree-sitter)                       | `0.22.6` | MIT     | `29208e71028ab0c11dfcc941255075aad75545394467aa22d817a6356714090f` | 188,635      |
| **`tree-sitter-javascript.wasm`** | [tree-sitter/tree-sitter-javascript](https://github.com/tree-sitter/tree-sitter-javascript) | `0.20.3` | MIT     | `63812b9e275d26851264734868d27a1656bd44a2ef6eb3e85e6b03728c595ab5` | 647,334      |
| **`tree-sitter-typescript.wasm`** | [tree-sitter/tree-sitter-typescript](https://github.com/tree-sitter/tree-sitter-typescript) | `0.20.5` | MIT     | `8515404dceed38e1ed86aa34b09fcf3379fff1b4ff9dd3967bcd6d1eb5ac3d8f` | 2,342,690    |
| **`tree-sitter-tsx.wasm`**        | [tree-sitter/tree-sitter-typescript](https://github.com/tree-sitter/tree-sitter-typescript) | `0.20.5` | MIT     | `6aa3b2c70e76f5d48eafef1093e9c4de383e13f2fdde2f4e9b98a378f6a8f1b6` | 2,411,272    |
| **`tree-sitter-python.wasm`**     | [tree-sitter/tree-sitter-python](https://github.com/tree-sitter/tree-sitter-python)         | `0.21.0` | MIT     | `9056d0fb0c337810d019fae350e8167786119da98f0f282aceae7ab89ee8253b` | 476,105      |

---

## 2. Upstream License Declarations

### 2.1 `tree-sitter` (Core WASM Runtime)

- **Repository:** https://github.com/tree-sitter/tree-sitter
- **License:** MIT License

```text
Copyright (c) 2018 Max Brunsfeld

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### 2.2 `tree-sitter-javascript`

- **Repository:** https://github.com/tree-sitter/tree-sitter-javascript
- **License:** MIT License

```text
Copyright (c) 2014 Max Brunsfeld

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
...
```

### 2.3 `tree-sitter-typescript` (TypeScript & TSX Grammars)

- **Repository:** https://github.com/tree-sitter/tree-sitter-typescript
- **License:** MIT License

```text
Copyright (c) 2017 Max Brunsfeld

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
...
```

### 2.4 `tree-sitter-python`

- **Repository:** https://github.com/tree-sitter/tree-sitter-python
- **License:** MIT License

```text
Copyright (c) 2016 Max Brunsfeld

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
...
```

### 2.5 `tree-sitter-wasms` (Packaging & Build Infrastructure)

- **Repository:** https://github.com/samiconductor/tree-sitter-wasms
- **License:** The Unlicense (Public Domain Dedication)

---

## 3. Supply Chain Verification Command

To independently verify the integrity of all bundled WebAssembly binaries against the hardcoded cryptographic manifest, run:

```bash
pnpm verify:wasm
```

This command inspects all `.wasm` files inside `packages/reachability/wasm/`, recalculates their cryptographic SHA-256 hashes, and asserts zero divergence from the verified manifest. In case of any tampering or corruption, SecureShip fails closed, refusing to produce unverified reachability verdicts.

---

## 4. Vulnerability Advisory & Security Metadata Attribution (Curated Symbols Dataset)

SecureShip bundles a curated, cryptographically attested dataset of vulnerable function and symbol entry points (`packages/reachability/data/vulnerable-symbols.json`) to perform sound function-level reachability analysis for direct SCA dependencies.

This dataset incorporates advisory information, public commit links, and security analysis derived from:

1. **GitHub Advisory Database**

   - **Repository:** https://github.com/github/advisory-database
   - **License:** Creative Commons Attribution 4.0 International (CC-BY 4.0)
   - **Attribution:** Security advisory descriptions, CVE/GHSA aliases, and vulnerability entry-point classifications are derived in part from the GitHub Advisory Database.

2. **National Vulnerability Database (NVD) — NIST**

   - **Source:** https://nvd.nist.gov
   - **License:** Public Domain / U.S. Government Work (17 U.S.C. § 105)
   - **Attribution:** Vulnerability identifiers, references, and descriptions cross-referenced with NIST NVD records.

3. **Open Source Vulnerabilities (OSV) Schema**
   - **Source:** https://osv.dev
   - **License:** Creative Commons Attribution 4.0 International (CC-BY 4.0)

To verify the integrity and schema validity of the curated vulnerable symbols dataset:

```bash
pnpm verify:symbols
```

---

## 5. Bundled External Security Scanner Engines

SecureShip container distributions pre-package vetted external security scanning engines into `/opt/secureship/bin` to allow completely self-contained, air-gapped security analysis with zero run-time network downloads.

| Engine Component  | Upstream Repository                                             | Bundled Version | License    | License File                    | Copyleft Status         |
| :---------------- | :-------------------------------------------------------------- | :-------------- | :--------- | :------------------------------ | :---------------------- |
| **`opengrep`**    | [opengrep/opengrep](https://github.com/opengrep/opengrep)       | `v1.31.0`       | LGPL-2.1   | `/licenses/opengrep/LICENSE`    | **Copyleft** (LGPL-2.1) |
| **`gitleaks`**    | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)       | `v8.24.0`       | MIT        | `/licenses/gitleaks/LICENSE`    | Permissive              |
| **`trivy`**       | [aquasecurity/trivy](https://github.com/aquasecurity/trivy)     | `v0.76.0`       | Apache-2.0 | `/licenses/trivy/LICENSE`       | Permissive              |
| **`osv-scanner`** | [google/osv-scanner](https://github.com/google/osv-scanner)     | `v1.9.2`        | Apache-2.0 | `/licenses/osv-scanner/LICENSE` | Permissive              |
| **`checkov`**     | [bridgecrewio/checkov](https://github.com/bridgecrewio/checkov) | `v3.3.29`       | Apache-2.0 | `/licenses/checkov/LICENSE`     | Permissive              |

### 5.1 GNU Lesser General Public License (LGPL-2.1) Notice — Opengrep

Opengrep is distributed under the GNU Lesser General Public License version 2.1 (LGPL-2.1). In compliance with Section 6 of the LGPL-2.1:

- SecureShip interacts with `opengrep` strictly as an independent executable program spawned via standard operating system process boundaries (`execve` / `SafeProcessRunner`) without static or dynamic linking against LGPL-licensed libraries.
- The complete upstream source code of Opengrep is publicly available at: https://github.com/opengrep/opengrep
- Users are free to modify or substitute their own build of Opengrep by placing it in `~/.secureship/bin/opengrep` or specifying `SECURESHIP_BIN_DIR`.

To verify cryptographic checksums of all pinned scanner engine distributions:

```bash
pnpm verify:tool-pins
```
