# Supply-Chain Policy Configuration Guide

The Supply-Chain Threat Engine is configured under the `supplyChain` key in `secureship.config.json` or through programmatically supplied `SupplyChainPolicy` options.

---

## Schema & Default Configuration

```json
{
  "$schema": "https://secureship.dev/schema/config.json",
  "supplyChain": {
    "enabled": true,
    "provider": "null",
    "concurrency": 8,
    "packageTimeoutMs": 30000,
    "maxFileSizeBytes": 2097152,
    "maxTotalBytes": 104857600,
    "maxFileCount": 20000,
    "failOnSeverity": "HIGH",
    "typosquat": {
      "minScore": 0.82,
      "candidateMaxDownloads": 1000,
      "popularMinDownloads": 1000000
    },
    "entropy": {
      "minLength": 64,
      "threshold": 4.5
    },
    "obfuscation": {
      "longLine": 1000
    },
    "hallucination": {
      "minAgeDays": 30
    },
    "semver": {
      "majorJump": 20
    },
    "chrono": {
      "allowBackportSameMajor": true
    },
    "governance": {
      "dormancyDays": 365
    },
    "preInstall": {
      "forbidInstallScripts": true
    },
    "privateScopes": ["@internal", "@company"],
    "ruleOverrides": {
      "SC-INSTALL-001": {
        "enabled": true,
        "severity": "LOW"
      }
    },
    "allowlist": [
      {
        "packageName": "esbuild",
        "versionRange": ">=0.19.0",
        "ruleId": "SC-INSTALL-001",
        "scriptHash": "3b2c1a...",
        "reason": "Known platform binary bootstrap script",
        "expires": "2027-01-01T00:00:00Z"
      }
    ]
  }
}
```

---

## Policy Keys Reference

### `provider`

- `'null'`: (Default) Offline execution. No remote calls are made. Registry-dependent rules report `metadataUnavailable: true`.
- `'snapshot'`: Offline testing against cached JSON packuments in `snapshotDir`.
- `'registry'`: Opt-in live querying of the npm registry.

### `ruleOverrides`

Overrides can disable a rule or adjust its severity or blocking state:

- `enabled`: `boolean`
- `severity`: `'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'`
- `blocking`: `boolean` (fails scan immediately if triggered)

### `allowlist`

Explicit rule suppressions with mandatory audit trails:

- `packageName`: Target dependency name or glob pattern.
- `versionRange`: Valid semver range.
- `ruleId`: (Optional) Specific rule to allowlist.
- `scriptHash`: (Optional) Specific SHA-256 of the allowed script content.
- `reason`: Explanation (minimum 10 characters).
- `expires`: ISO 8601 expiration date. Allowlisted findings are suppressed with code `SUPPLY_CHAIN_ALLOWLISTED`.
