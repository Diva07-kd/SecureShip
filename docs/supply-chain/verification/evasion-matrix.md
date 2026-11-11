# SECURESHIP SUPPLY-CHAIN THREAT ENGINE

# EVASION & ADVERSARIAL RED-TEAM MATRIX (Phase T6)

This matrix systematically evaluates evasion techniques across capability hiding, install-script traps, Unicode obfuscation, scale attacks, and typosquats. For each technique, the status is verified through executed test evidence in `packages/core-engine/test/supply-chain/evasion-redteam.verify.test.ts`.

---

## 1. Evasion Matrix Summary

| Category                     | Total Techniques | Detected | Known Limitations | Detection Rate |
| :--------------------------- | :--------------- | :------- | :---------------- | :------------- |
| **Capability Hiding**        | 6                | 4        | 2                 | 66.7%          |
| **Install-Time Obfuscation** | 3                | 3        | 0                 | 100.0%         |
| **Unicode Obfuscation**      | 4                | 4        | 0                 | 100.0%         |
| **Archive & Scale Guards**   | 3                | 3        | 0                 | 100.0%         |
| **Typosquat Tactics**        | 3                | 2        | 1                 | 66.7%          |
| **TOTAL**                    | **19**           | **16**   | **3**             | **84.2%**      |

---

## 2. Detailed Technique Breakdown

### Category A: Capability Hiding & Dynamic Reflection

| Technique ID | Attack Vector / Payload                                                            | Status               | Handling Rule / Defense                                  | Verifying Test Name                                                                   |
| :----------- | :--------------------------------------------------------------------------------- | :------------------- | :------------------------------------------------------- | :------------------------------------------------------------------------------------ |
| `EV-CAP-001` | Dynamic `eval` on concatenated strings (`eval("pro" + "cess")`)                    | **DETECTED**         | `SC-CAP-005`                                             | `detects dynamic eval on concatenated string literals: eval("pro" + "cess")`          |
| `EV-CAP-002` | `Function` constructor dynamic code generator (`new Function("return process")()`) | **DETECTED**         | `SC-CAP-005`                                             | `detects Function constructor code dropper: Function("return process")()`             |
| `EV-CAP-003` | Indirection via `module.require` and `process.mainModule.require`                  | **DETECTED**         | `SC-CAP-001`                                             | `detects dynamic module loading via module.require and process.mainModule.require`    |
| `EV-CAP-004` | Dynamic `import()` with computed specifier expression                              | **DETECTED**         | `SC-CAP-006`                                             | `detects computed dynamic import specifiers as dynamicRequire capability`             |
| `EV-CAP-005` | String-assembled global scope lookup: `globalThis['pro' + 'cess'].env`             | **KNOWN LIMITATION** | Static AST limitation; dynamic runtime analysis required | `records indirect globalThis proxy/getter capability hiding as documented limitation` |
| `EV-CAP-006` | Prototype constructor lookup: `[].constructor.constructor('return process')()`     | **KNOWN LIMITATION** | Static AST limitation; prototype tracking required       | `records prototype chain Function evasion as documented limitation`                   |

### Category B: Install-Time Obfuscation & Shell Traps

| Technique ID | Attack Vector / Payload                                                     | Status       | Handling Rule / Defense               | Verifying Test Name                                                           |
| :----------- | :-------------------------------------------------------------------------- | :----------- | :------------------------------------ | :---------------------------------------------------------------------------- |
| `EV-INS-001` | Base64 decode execution in shell: `eval $(echo ... \| base64 -d)`           | **DETECTED** | `SC-INSTALL-003` (CRITICAL, blocking) | `detects eval of base64 decoded shell payload: eval $(echo ... \| base64 -d)` |
| `EV-INS-002` | PowerShell encoded string decode: `[Convert]::FromBase64String(...) \| iex` | **DETECTED** | `SC-INSTALL-003` (CRITICAL, blocking) | `detects PowerShell FromBase64String encoded command execution`               |
| `EV-INS-003` | Remote payload fetch piped to shell: `curl -sSL https://... \| sh`          | **DETECTED** | `SC-INSTALL-003` (CRITICAL, blocking) | `detects remote curl piping directly to shell`                                |

### Category C: Unicode Obfuscation & Trojan Source

| Technique ID | Attack Vector / Payload                        | Status       | Handling Rule / Defense           | Verifying Test Name                                                   |
| :----------- | :--------------------------------------------- | :----------- | :-------------------------------- | :-------------------------------------------------------------------- |
| `EV-UNI-001` | Bidi control override inside regex literal     | **DETECTED** | `SC-UNI-001` (CRITICAL, blocking) | `detects Bidi control characters inside regex literals`               |
| `EV-UNI-002` | Bidi control override inside template literal  | **DETECTED** | `SC-UNI-001` (CRITICAL, blocking) | `detects Bidi control characters inside template literals`            |
| `EV-UNI-003` | Bidi control override inside JSON keys         | **DETECTED** | `SC-UNI-001` (CRITICAL, blocking) | `detects Bidi control characters inside JSON keys or string literals` |
| `EV-UNI-004` | Zero-width space hidden inside identifier name | **DETECTED** | `SC-UNI-002` (HIGH)               | `detects zero-width space hidden inside identifier name`              |

### Category D: Scale & Archive Evasion Guards

| Technique ID | Attack Vector / Payload                                      | Status       | Handling Rule / Defense                                                 | Verifying Test Name                                                                           |
| :----------- | :----------------------------------------------------------- | :----------- | :---------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------- |
| `EV-ARC-001` | Tarball path traversal / zip-slip (`../../../../etc/shadow`) | **DETECTED** | `SafeTarExtractor` traversal guard rejects entry                        | `rejects archive containing path traversal entry (zip-slip)`                                  |
| `EV-ARC-002` | Single oversized file bomb (> 2 MiB file limit)              | **DETECTED** | `SafeTarExtractor` aborts with `File size limit exceeded`               | `halts and aborts extraction when a single file exceeds maxFileSize limit (e.g. 2 MiB)`       |
| `EV-ARC-003` | Total uncompressed archive explosion (> 100 MiB limit)       | **DETECTED** | `SafeTarExtractor` aborts with `Total uncompressed size limit exceeded` | `halts and aborts extraction when total archive uncompressed size exceeds maxTotalSize limit` |

### Category E: Typosquat Tactics

| Technique ID | Attack Vector / Payload                                              | Status               | Handling Rule / Defense                                               | Verifying Test Name                                                                         |
| :----------- | :------------------------------------------------------------------- | :------------------- | :-------------------------------------------------------------------- | :------------------------------------------------------------------------------------------ |
| `EV-TYP-001` | Deceptive prefix/suffix inflation (`node-lodash`, `lodash-js`)       | **DETECTED**         | `SC-TYPO-002` (MEDIUM)                                                | `detects separator collapse trick: lodash-js or node-lodash`                                |
| `EV-TYP-002` | Boundary character doubling (`llodash`)                              | **DETECTED**         | `SC-TYPO-001` (HIGH)                                                  | `detects character doubling / typo near boundary: llodash`                                  |
| `EV-TYP-003` | High-distance visual/phonetic distortion ($D > 2$, e.g. `lodashexx`) | **KNOWN LIMITATION** | Standard edit distance guard ($D \le 2$); flagged as known limitation | `records phonetically similar or visual-confusable squat as documented limitation if D > 2` |

---

## 3. Residual Risk & Known Limitations Analysis

1. **`EV-CAP-005` (Global Object Computed Properties)**:
   - _Impact_: Low to Moderate. An attacker splitting `"process"` into `"pro" + "cess"` and indexing `globalThis` avoids static identifier detection for process.env.
   - _Mitigation_: Fallback token scan or taint tracking in Phase 2 AST engine.
2. **`EV-CAP-006` (Constructor Chain Invocation)**:
   - _Impact_: Low. Evaluating dynamic code through `[].constructor.constructor` is captured by runtime sandboxing and `--ignore-scripts` during installation.
   - _Mitigation_: Add prototype chain pattern detection for `.constructor.constructor(` to AST analyzer.
3. **`EV-TYP-003` (Edit Distance > 2 Squats)**:
   - _Impact_: Low. Packages with edit distance > 2 diverge significantly in spelling; expanding search radius beyond 2 drastically increases false positive rates.
