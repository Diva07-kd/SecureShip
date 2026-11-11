import type { FindingCategory, ScannerName } from './finding.schema.js';

export interface EngineBrandMetadata {
  id: string;
  legacyName: ScannerName;
  brandName: string;
  category: FindingCategory;
  shortLabel: string;
  actionMessage: string;
  rulePrefix: string;
}

export const SECURESHIP_ENGINES: Record<string, EngineBrandMetadata> = {
  opengrep: {
    id: 'secureship-ast',
    legacyName: 'opengrep',
    brandName: 'SecureShip Deep AST Engine',
    category: 'SAST',
    shortLabel: 'SecureShip SAST',
    actionMessage: 'Auditing source code syntax & patterns...',
    rulePrefix: 'SS-SAST',
  },
  semgrep: {
    id: 'secureship-ast',
    legacyName: 'semgrep',
    brandName: 'SecureShip Deep AST Engine',
    category: 'SAST',
    shortLabel: 'SecureShip SAST',
    actionMessage: 'Auditing source code syntax & patterns...',
    rulePrefix: 'SS-SAST',
  },
  gitleaks: {
    id: 'secureship-secret',
    legacyName: 'gitleaks',
    brandName: 'SecureShip Credential Sentinel',
    category: 'SECRET',
    shortLabel: 'SecureShip Secret',
    actionMessage: 'Inspecting tokens & entropy leaks...',
    rulePrefix: 'SS-SEC',
  },
  trivy: {
    id: 'secureship-sca',
    legacyName: 'trivy',
    brandName: 'SecureShip Component Auditor',
    category: 'SCA',
    shortLabel: 'SecureShip SCA',
    actionMessage: 'Auditing dependency supply chain...',
    rulePrefix: 'SS-SCA',
  },
  'osv-scanner': {
    id: 'secureship-intel',
    legacyName: 'osv-scanner',
    brandName: 'SecureShip Threat Intelligence',
    category: 'SCA',
    shortLabel: 'SecureShip Intel',
    actionMessage: 'Querying cryptographic vulnerability graph...',
    rulePrefix: 'SS-VULN',
  },
  checkov: {
    id: 'secureship-iac',
    legacyName: 'checkov',
    brandName: 'SecureShip Infrastructure Guard',
    category: 'IAC',
    shortLabel: 'SecureShip IaC',
    actionMessage: 'Verifying cloud & container manifests...',
    rulePrefix: 'SS-IAC',
  },
  generic: {
    id: 'secureship-generic',
    legacyName: 'generic',
    brandName: 'SecureShip Policy Engine',
    category: 'SAST',
    shortLabel: 'SecureShip Policy',
    actionMessage: 'Evaluating policy conformance...',
    rulePrefix: 'SS-CORE',
  },
};

export function getEngineBrand(scannerName: string): EngineBrandMetadata {
  const norm = scannerName.toLowerCase();
  return (
    SECURESHIP_ENGINES[norm] ?? {
      id: `secureship-${norm}`,
      legacyName: norm as ScannerName,
      brandName: `SecureShip ${scannerName.toUpperCase()} Engine`,
      category: 'SAST',
      shortLabel: `SecureShip ${scannerName.toUpperCase()}`,
      actionMessage: `Analyzing project with SecureShip ${scannerName}...`,
      rulePrefix: 'SS-CORE',
    }
  );
}

export function whiteLabelRuleId(ruleId: string, category: FindingCategory): string {
  if (!ruleId) return 'SS-CORE-UNKNOWN';
  if (ruleId.startsWith('SS-') || ruleId.startsWith('SC-')) {
    return ruleId;
  }
  if (/^(?:CVE|GHSA)-\d+/i.test(ruleId)) {
    return ruleId.toUpperCase();
  }
  const prefixMap: Record<FindingCategory, string> = {
    SAST: 'SS-SAST',
    SECRET: 'SS-SEC',
    SCA: 'SS-SCA',
    IAC: 'SS-IAC',
    SUPPLY_CHAIN: 'SS-SC',
  };
  const prefix = prefixMap[category] ?? 'SS-CORE';
  const cleanId = ruleId
    .replace(/^rules\./i, '')
    .replace(/^secureship-/i, '')
    .replace(/[^a-zA-Z0-9_-]/g, '-');
  return `${prefix}-${cleanId}`;
}
