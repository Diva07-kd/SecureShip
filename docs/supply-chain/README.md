# SecureShip Supply-Chain Threat Engine

The SecureShip Supply-Chain Threat Engine is a deterministic, offline-capable analysis pipeline that inspects third-party npm and PyPI dependencies for zero-day malware, install script abuses, Unicode trojans, obfuscated payloads, typosquats, and governance anomalies.

---

## Architecture Overview

```mermaid
graph TD
    A[ScanOrchestrator] --> B[SupplyChainAnalyzer]
    B --> C[Package Discovery in node_modules]
    C --> D[Detector Pipeline]

    subgraph Detectors
        D --> D1[InstallScriptDetector: SC-INSTALL-*]
        D --> D2[BinConfusionDetector: SC-BIN-*]
        D --> D3[TyposquatDetector: SC-TYPO-*, SC-HALL-*]
        D --> D4[UnicodeDetector: SC-UNI-*]
        D --> D5[EntropyDetector: SC-OBF-*]
        D --> D6[PkgEmptyDetector: SC-PKG-*]
        D --> D7[MetadataDetector: SC-META-*]
        D --> D8[GovernanceDetector: SC-GOV-*]
    end

    D1 & D2 & D3 & D4 & D5 & D6 & D7 & D8 --> E[RuleHit Collection]
    E --> F[Fingerprint & Deduplication]
    F --> G[NormalizedFinding Conversion category=SUPPLY_CHAIN]
    G --> H[SuppressionLedger & Invariant P1 Verification]
    H --> I[ScanReport findings]
```

---

## Phased Implementation Roadmap

- **Phase 1 (WP0–WP3)**:
  - WP0: Reconnaissance & documentation skeleton
  - WP1: Core schemas, policies, and contracts
  - WP2: Pure, offline detectors (scripts, bins, typosquats, unicode, entropy, empty packages, metadata, governance)
  - WP3: Supply-chain analyzer orchestration, metadata providers (`NullProvider`, `SnapshotProvider`)
- **Phase 2 (WP4–WP9)**:
  - WP4: AST capability queries via Tree-sitter (`SC-CAP-*`)
  - WP5: Full first-class normalized finding schema extension
  - WP6: Gate 3 AI supply-chain triage slicer
  - WP7: Gate 4 pre-install gate & sandbox isolation
  - WP8: CLI commands, policy controls, SARIF export extensions
  - WP9: Hardening, fuzzing, and comprehensive benchmark corpora

---

## Running Supply-Chain Analysis

Supply-chain scanning is configured via `secureship.config.json` or programmatically via `ScanOrchestrator`:

```json
{
  "supplyChain": {
    "enabled": true,
    "provider": "null",
    "concurrency": 8,
    "failOnSeverity": "HIGH"
  }
}
```
