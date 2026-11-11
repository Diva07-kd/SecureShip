import type { SupplyChainCapabilities } from '@secureship/contracts';

export type CapabilityType =
  | 'env'
  | 'network'
  | 'fsSensitive'
  | 'shell'
  | 'eval'
  | 'dynamicRequire'
  | 'debugInternals';

export interface CapabilitySite {
  capability: CapabilityType;
  file: string;
  startLine: number;
  startCol: number;
  endLine: number;
  endCol: number;
  snippet: string;
  resolved: boolean;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  enclosingFunction?: string;
  details?: string;
}

export interface FileCapabilityAnalysis {
  capabilities: SupplyChainCapabilities;
  sites: CapabilitySite[];
  hasSyntaxError?: boolean;
}

export interface PackageCapabilitySummary {
  packageName: string;
  version?: string;
  capabilities: SupplyChainCapabilities;
  sites: CapabilitySite[];
}
