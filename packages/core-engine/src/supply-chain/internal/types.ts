import type {
  Confidence,
  ScReachability,
  Severity,
  SupplyChainCapabilities,
  SupplyChainEvidenceItem,
  SupplyChainRuleId,
} from '@secureship/contracts';

export interface DetectorContext {
  packageName: string;
  version: string;
  ecosystem: 'npm' | 'pypi';
  packageDir: string;
  now: () => Date;
  signal?: AbortSignal;
}

export interface RuleHit {
  ruleId: SupplyChainRuleId;
  packageName: string;
  version: string;
  ecosystem: 'npm' | 'pypi';
  purl: string;
  severity: Severity;
  confidence: Confidence;
  evidence: SupplyChainEvidenceItem[];
  metadataUnavailable: boolean;
  blocking: boolean;
  title?: string;
  description?: string;
  reachabilityGated?: boolean;
  remediationText?: string;
  capabilities?: Partial<SupplyChainCapabilities>;
  scReachability?: ScReachability;
}
