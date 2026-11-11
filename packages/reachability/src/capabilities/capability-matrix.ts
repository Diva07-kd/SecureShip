import type {
  Severity,
  SupplyChainCapabilities,
  SupplyChainRuleId,
  SupplyChainThreatType,
} from '@secureship/contracts';
import type { CapabilitySite, CapabilityType } from './types.js';

export interface CapabilityMatrixHit {
  ruleId: SupplyChainRuleId;
  severity: Severity;
  threatType: SupplyChainThreatType;
  title: string;
  description: string;
  remediation: string;
  evidenceSites: CapabilitySite[];
  participatingCapabilities: CapabilityType[];
  blocking: boolean;
  reachabilityGated: boolean;
}

export interface CapabilityMatrixContext {
  packageName: string;
  version?: string;
  hasInstallScript?: boolean;
  hasHighEntropyOrObfuscation?: boolean;
  installScriptEvidence?: CapabilitySite[];
  obfuscationEvidence?: CapabilitySite[];
}

export class CapabilityMatrix {
  /**
   * Evaluates dangerous capability combinations according to Phase 2 matrix.
   */
  public static evaluateCombinations(
    capabilities: SupplyChainCapabilities,
    sites: CapabilitySite[],
    ctx: CapabilityMatrixContext
  ): CapabilityMatrixHit[] {
    const hits: CapabilityMatrixHit[] = [];

    const getSites = (types: CapabilityType[]): CapabilitySite[] =>
      sites.filter((s) => types.includes(s.capability));

    // 1. Network + Sensitive Filesystem Exfiltration (CRITICAL) -> SC-CAP-101
    if (capabilities.hasNetwork && capabilities.hasFsSensitive) {
      hits.push({
        ruleId: 'SC-CAP-101',
        severity: 'CRITICAL',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Network and Sensitive Filesystem Access Combination',
        description:
          'Package combines outbound network connectivity with reading sensitive configuration and credential files.',
        remediation:
          'Quarantine and block this package immediately. The combination strongly correlates with credential exfiltration.',
        evidenceSites: getSites(['network', 'fsSensitive']),
        participatingCapabilities: ['network', 'fsSensitive'],
        blocking: true,
        reachabilityGated: true,
      });
    }

    // 2. Network + Environment Harvesting (HIGH) -> SC-CAP-100
    if (capabilities.hasNetwork && capabilities.hasEnvAccess) {
      hits.push({
        ruleId: 'SC-CAP-100',
        severity: 'HIGH',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Network and Environment Exfiltration Combination',
        description:
          'Package combines outbound network connectivity with ambient process environment variable extraction.',
        remediation:
          'Audit environment variable reads and network destinations to ensure secrets are not being exfiltrated.',
        evidenceSites: getSites(['network', 'env']),
        participatingCapabilities: ['network', 'env'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    // 3. Shell + Network Remote Execution (HIGH) -> SC-CAP-102
    if (capabilities.hasShell && capabilities.hasNetwork) {
      hits.push({
        ruleId: 'SC-CAP-102',
        severity: 'HIGH',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Shell Execution and Network Sockets Combination',
        description:
          'Package combines arbitrary child process execution with outbound network communication.',
        remediation:
          'Review code paths connecting network input to process execution. Ensure untrusted data cannot spawn shells.',
        evidenceSites: getSites(['shell', 'network']),
        participatingCapabilities: ['shell', 'network'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    // 4. Shell + Dynamic Eval Dropper (HIGH) -> SC-CAP-103
    if (capabilities.hasShell && capabilities.hasEval) {
      hits.push({
        ruleId: 'SC-CAP-103',
        severity: 'HIGH',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Shell Execution and Dynamic Code Evaluation',
        description:
          'Package combines child process execution with dynamic string evaluation (eval / new Function).',
        remediation: 'Inspect dynamic evaluation routines for indirect shell payload generation.',
        evidenceSites: getSites(['shell', 'eval']),
        participatingCapabilities: ['shell', 'eval'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    // 5. Dynamic Execution + Obfuscation/High-Entropy (CRITICAL) -> SC-CAP-104
    if (
      (capabilities.hasEval || capabilities.hasDynamicRequire) &&
      ctx.hasHighEntropyOrObfuscation
    ) {
      const evalSites = getSites(['eval', 'dynamicRequire']);
      const obfSites = ctx.obfuscationEvidence ?? [];
      hits.push({
        ruleId: 'SC-CAP-104',
        severity: 'CRITICAL',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Dynamic Code Execution and Obfuscated / High-Entropy Payload',
        description:
          'Package evaluates dynamic code in the presence of obfuscated or high-entropy string payloads.',
        remediation:
          'Do not run or install this package. This pattern is characteristic of packed malware loaders.',
        evidenceSites: [...evalSites, ...obfSites],
        participatingCapabilities: ['eval', 'dynamicRequire'],
        blocking: true,
        reachabilityGated: true,
      });
    }

    // 6. Install Script + Sensitive Filesystem Exfiltration (CRITICAL) -> SC-CAP-106
    if (ctx.hasInstallScript && capabilities.hasFsSensitive) {
      const fsSites = getSites(['fsSensitive']);
      const installSites = ctx.installScriptEvidence ?? [];
      hits.push({
        ruleId: 'SC-CAP-106',
        severity: 'CRITICAL',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Install Script and Sensitive Filesystem Access',
        description:
          'Package executes install lifecycle scripts that access sensitive files (~/.ssh, ~/.aws, etc.).',
        remediation:
          'Quarantine immediately. Installation-phase filesystem probing poses severe host compromise risk.',
        evidenceSites: [...installSites, ...fsSites],
        participatingCapabilities: ['fsSensitive'],
        blocking: true,
        reachabilityGated: false, // Install-script findings are NOT reachability-gated!
      });
    }

    // 7. Install Script + Environment Access (HIGH) -> SC-CAP-105
    if (ctx.hasInstallScript && capabilities.hasEnvAccess) {
      const envSites = getSites(['env']);
      const installSites = ctx.installScriptEvidence ?? [];
      hits.push({
        ruleId: 'SC-CAP-105',
        severity: 'HIGH',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Install Script and Environment Variable Harvesting',
        description:
          'Package executes install lifecycle scripts while accessing ambient environment variables.',
        remediation:
          'Audit install script for environment variable harvesting or secret transmission.',
        evidenceSites: [...installSites, ...envSites],
        participatingCapabilities: ['env'],
        blocking: false,
        reachabilityGated: false, // Install-script findings are NOT reachability-gated!
      });
    }

    return hits;
  }

  /**
   * Evaluates individual lone capabilities (SC-CAP-001..007).
   * Lone capabilities are INFO-level diagnostic findings unless escalated by combinations.
   */
  public static evaluateSingleCapabilities(
    capabilities: SupplyChainCapabilities,
    sites: CapabilitySite[]
  ): CapabilityMatrixHit[] {
    const hits: CapabilityMatrixHit[] = [];

    const getSites = (type: CapabilityType): CapabilitySite[] =>
      sites.filter((s) => s.capability === type);

    if (capabilities.hasShell) {
      hits.push({
        ruleId: 'SC-CAP-001',
        severity: 'INFO',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Child Process Execution Capability Present',
        description: 'Package contains capability to spawn child processes or external commands.',
        remediation: 'Audit child process usage sites to verify legitimate usage.',
        evidenceSites: getSites('shell'),
        participatingCapabilities: ['shell'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    if (capabilities.hasNetwork) {
      hits.push({
        ruleId: 'SC-CAP-002',
        severity: 'INFO',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Outbound Network Socket Capability Present',
        description:
          'Package contains capability to initiate outbound network socket or HTTP requests.',
        remediation: 'Ensure package documentation declares network connectivity requirements.',
        evidenceSites: getSites('network'),
        participatingCapabilities: ['network'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    if (capabilities.hasEnvAccess) {
      hits.push({
        ruleId: 'SC-CAP-003',
        severity: 'INFO',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Environment Variable Access Capability Present',
        description: 'Package accesses ambient process.env variables.',
        remediation: 'Verify that required environment variables are documented and safe.',
        evidenceSites: getSites('env'),
        participatingCapabilities: ['env'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    if (capabilities.hasFsSensitive) {
      hits.push({
        ruleId: 'SC-CAP-004',
        severity: 'INFO',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Sensitive Filesystem Access Capability Present',
        description:
          'Package accesses filesystem paths matching sensitive system configuration targets.',
        remediation: 'Verify whether access to sensitive files or home directories is expected.',
        evidenceSites: getSites('fsSensitive'),
        participatingCapabilities: ['fsSensitive'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    if (capabilities.hasEval) {
      hits.push({
        ruleId: 'SC-CAP-005',
        severity: 'INFO',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Dynamic Eval / Function Execution Capability Present',
        description: 'Package uses eval() or new Function() to evaluate dynamic code.',
        remediation: 'Avoid dynamic string evaluation in production dependencies.',
        evidenceSites: getSites('eval'),
        participatingCapabilities: ['eval'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    if (capabilities.hasDynamicRequire) {
      hits.push({
        ruleId: 'SC-CAP-006',
        severity: 'INFO',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Dynamic Require / Reflection Loading Capability Present',
        description: 'Package invokes require() or import() with dynamic expressions.',
        remediation: 'Use static import specifiers where possible.',
        evidenceSites: getSites('dynamicRequire'),
        participatingCapabilities: ['dynamicRequire'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    if (capabilities.hasDebugInternals) {
      hits.push({
        ruleId: 'SC-CAP-007',
        severity: 'INFO',
        threatType: 'CAPABILITY_VIOLATION',
        title: 'Debug Internals / Anti-Analysis Capability Present',
        description: 'Package accesses internal runtime hooks or debugger introspection.',
        remediation: 'Verify why the package accesses internal Node.js runtime bindings.',
        evidenceSites: getSites('debugInternals'),
        participatingCapabilities: ['debugInternals'],
        blocking: false,
        reachabilityGated: true,
      });
    }

    return hits;
  }
}
