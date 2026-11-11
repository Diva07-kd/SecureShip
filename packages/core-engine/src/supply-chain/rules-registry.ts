import type { Severity, SupplyChainRuleId, SupplyChainThreatType } from '@secureship/contracts';

export interface RuleRegistryEntry {
  ruleId: SupplyChainRuleId;
  title: string;
  defaultSeverity: Severity;
  threatType: SupplyChainThreatType;
  description: string;
  remediationText: string;
  reachabilityGated: boolean;
}

export const RULES_REGISTRY: Record<SupplyChainRuleId, RuleRegistryEntry> = {
  'SC-INSTALL-001': {
    ruleId: 'SC-INSTALL-001',
    title: 'Install Script Lifecycle Hook Present',
    defaultSeverity: 'MEDIUM',
    threatType: 'INSTALL_SCRIPT',
    description:
      'Package defines preinstall, install, or postinstall lifecycle scripts that execute arbitrary commands during installation.',
    remediationText:
      'Review the lifecycle script in package.json. If legitimate, add an audit entry with the exact script hash to the allowlist.',
    reachabilityGated: false,
  },
  'SC-INSTALL-002': {
    ruleId: 'SC-INSTALL-002',
    title: 'Implicit Native Build (binding.gyp) Without Script',
    defaultSeverity: 'MEDIUM',
    threatType: 'INSTALL_SCRIPT',
    description:
      'Package contains a binding.gyp file which triggers native node-gyp compilation on install without declaring an install script.',
    remediationText:
      'Verify whether native compilation is expected for this package and ensure your build environment is isolated.',
    reachabilityGated: false,
  },
  'SC-INSTALL-003': {
    ruleId: 'SC-INSTALL-003',
    title: 'Dangerous Remote Execution or Exfiltration in Install Script',
    defaultSeverity: 'CRITICAL',
    threatType: 'INSTALL_SCRIPT',
    description:
      'Install script contains patterns for fetching remote code (curl/wget piped to shell), decoding base64, or reading sensitive files.',
    remediationText:
      'Do not install this package version. Quarantine the package immediately and inspect network/environment exposure.',
    reachabilityGated: false,
  },
  'SC-BIN-001': {
    ruleId: 'SC-BIN-001',
    title: 'Path Traversal in Binary Specification',
    defaultSeverity: 'HIGH',
    threatType: 'BIN_CONFUSION',
    description:
      'Package bin entry targets a path escaping the package directory via directory traversal or absolute root paths.',
    remediationText:
      'Remove or constrain the package. Ensure package.json bin field points strictly inside the package root.',
    reachabilityGated: false,
  },
  'SC-BIN-002': {
    ruleId: 'SC-BIN-002',
    title: 'System Command Shadowing Collision',
    defaultSeverity: 'HIGH',
    threatType: 'BIN_CONFUSION',
    description:
      'Package exposes a binary name that collides with standard system utilities (e.g. git, ssh, node, curl, bash).',
    remediationText:
      'Check whether this package binary will overwrite system utilities in node_modules/.bin or PATH.',
    reachabilityGated: false,
  },
  'SC-CAP-001': {
    ruleId: 'SC-CAP-001',
    title: 'Unauthorized Process Execution / Shell Spawn',
    defaultSeverity: 'HIGH',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package code invokes child_process functions (exec, spawn, execSync) to spawn external processes.',
    remediationText:
      'Audit call sites for child process spawning and verify if external shell execution is intended.',
    reachabilityGated: true,
  },
  'SC-CAP-002': {
    ruleId: 'SC-CAP-002',
    title: 'Outbound Network Socket Activity',
    defaultSeverity: 'HIGH',
    threatType: 'CAPABILITY_VIOLATION',
    description: 'Package code makes network socket connections or outbound HTTP/HTTPS requests.',
    remediationText:
      'Verify if outbound network connectivity is required for this package functionality.',
    reachabilityGated: true,
  },
  'SC-CAP-003': {
    ruleId: 'SC-CAP-003',
    title: 'Sensitive Environment Variable Harvesting',
    defaultSeverity: 'MEDIUM',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package accesses ambient environment variables or dumps process.env without filtering.',
    remediationText:
      'Ensure ambient secrets and tokens are not accessible in the runtime environment where this dependency executes.',
    reachabilityGated: true,
  },
  'SC-CAP-004': {
    ruleId: 'SC-CAP-004',
    title: 'Sensitive Filesystem Access',
    defaultSeverity: 'HIGH',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package attempts reading files outside the application root (e.g. ~/.ssh, ~/.aws, /etc/passwd, ~/.npmrc).',
    remediationText: 'Isolate the application using file access controls or container namespaces.',
    reachabilityGated: true,
  },
  'SC-CAP-005': {
    ruleId: 'SC-CAP-005',
    title: 'Dynamic Code Execution via eval / Function',
    defaultSeverity: 'HIGH',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package executes dynamically generated strings via eval(), new Function(), or vm modules.',
    remediationText: 'Refactor or replace dependencies that rely on runtime string evaluation.',
    reachabilityGated: true,
  },
  'SC-CAP-006': {
    ruleId: 'SC-CAP-006',
    title: 'Dynamic Require / Reflection Loading',
    defaultSeverity: 'MEDIUM',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package imports or requires dynamic computed module identifiers, hindering static reachability analysis.',
    remediationText:
      'Review dynamic import targets to ensure only legitimate optional dependencies are loaded.',
    reachabilityGated: true,
  },
  'SC-CAP-007': {
    ruleId: 'SC-CAP-007',
    title: 'Anti-Analysis / Debugger Internals Detection',
    defaultSeverity: 'MEDIUM',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package detects debugging environments, inspection protocols, or sandboxes to alter execution behaviour.',
    remediationText:
      'Inspect anti-analysis logic to determine why the package modifies behavior in analysis environments.',
    reachabilityGated: true,
  },
  'SC-CAP-100': {
    ruleId: 'SC-CAP-100',
    title: 'Network and Environment Exfiltration Combination',
    defaultSeverity: 'HIGH',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package combines outbound network connectivity with reading ambient process environment variables.',
    remediationText:
      'Audit environment variable reads and network destinations to ensure secrets are not being exfiltrated.',
    reachabilityGated: true,
  },
  'SC-CAP-101': {
    ruleId: 'SC-CAP-101',
    title: 'Network and Sensitive Filesystem Access Combination',
    defaultSeverity: 'CRITICAL',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package combines outbound network connectivity with access to sensitive credential and config files.',
    remediationText:
      'Quarantine and block this package immediately. The combination strongly correlates with credential exfiltration.',
    reachabilityGated: true,
  },
  'SC-CAP-102': {
    ruleId: 'SC-CAP-102',
    title: 'Shell Execution and Network Sockets Combination',
    defaultSeverity: 'HIGH',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package combines arbitrary child process execution with outbound network communication.',
    remediationText:
      'Review code paths connecting network input to process execution. Ensure untrusted data cannot spawn shells.',
    reachabilityGated: true,
  },
  'SC-CAP-103': {
    ruleId: 'SC-CAP-103',
    title: 'Shell Execution and Dynamic Code Evaluation',
    defaultSeverity: 'HIGH',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package combines child process execution with dynamic string evaluation (eval / new Function).',
    remediationText: 'Inspect dynamic evaluation routines for indirect shell payload generation.',
    reachabilityGated: true,
  },
  'SC-CAP-104': {
    ruleId: 'SC-CAP-104',
    title: 'Dynamic Code Execution and Obfuscated / High-Entropy Payload',
    defaultSeverity: 'CRITICAL',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package evaluates dynamic code in the presence of obfuscated or high-entropy string payloads.',
    remediationText:
      'Do not run or install this package. This pattern is characteristic of packed malware loaders.',
    reachabilityGated: true,
  },
  'SC-CAP-105': {
    ruleId: 'SC-CAP-105',
    title: 'Install Script and Environment Variable Harvesting',
    defaultSeverity: 'HIGH',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package executes install lifecycle scripts while accessing ambient environment variables.',
    remediationText:
      'Audit install script for environment variable harvesting or secret transmission.',
    reachabilityGated: false,
  },
  'SC-CAP-106': {
    ruleId: 'SC-CAP-106',
    title: 'Install Script and Sensitive Filesystem Access',
    defaultSeverity: 'CRITICAL',
    threatType: 'CAPABILITY_VIOLATION',
    description:
      'Package executes install lifecycle scripts that access sensitive files (~/.ssh, ~/.aws, etc.).',
    remediationText:
      'Quarantine immediately. Installation-phase filesystem probing poses severe host compromise risk.',
    reachabilityGated: false,
  },
  'SC-TYPO-001': {
    ruleId: 'SC-TYPO-001',
    title: 'Levenshtein Distance Typosquat Match',
    defaultSeverity: 'HIGH',
    threatType: 'TYPOSQUAT',
    description:
      'Package name is within edit distance 2 and high similarity score of a verified popular package.',
    remediationText:
      'Confirm the package name spelling against official project documentation to avoid typosquats.',
    reachabilityGated: false,
  },
  'SC-TYPO-002': {
    ruleId: 'SC-TYPO-002',
    title: 'Combosquatting / Suffix Inflation Confusion',
    defaultSeverity: 'MEDIUM',
    threatType: 'TYPOSQUAT',
    description:
      'Package name appends deceptive suffixes (-js, -node, -lib, -helper) to a popular package name.',
    remediationText:
      'Check whether the package is an official standalone component or an unauthorized clone.',
    reachabilityGated: false,
  },
  'SC-TYPO-003': {
    ruleId: 'SC-TYPO-003',
    title: 'Separator-Collapse Name Squatting',
    defaultSeverity: 'MEDIUM',
    threatType: 'TYPOSQUAT',
    description:
      'Package name matches a known package with hyphens, underscores, or periods collapsed or transposed.',
    remediationText:
      'Verify the precise separator conventions in your project lockfile against the upstream repository.',
    reachabilityGated: false,
  },
  'SC-HALL-001': {
    ruleId: 'SC-HALL-001',
    title: 'AI Hallucination Target Vulnerability',
    defaultSeverity: 'HIGH',
    threatType: 'AI_HALLUCINATION',
    description:
      'Package exhibits characteristics of an AI hallucination target (recently registered, low version count, zero downloads).',
    remediationText:
      'Verify whether this dependency was suggested by an AI assistant and confirm that it is an established package.',
    reachabilityGated: false,
  },
  'SC-PKG-001': {
    ruleId: 'SC-PKG-001',
    title: 'Package Contains No Executable Code Artifacts',
    defaultSeverity: 'MEDIUM',
    threatType: 'EMPTY_OR_MISSING_TARBALL',
    description:
      'Package contains only documentation or license files without any executable source code files.',
    remediationText:
      'Check if the package is a placeholder, empty placeholder, or incomplete publication.',
    reachabilityGated: false,
  },
  'SC-PKG-002': {
    ruleId: 'SC-PKG-002',
    title: 'Package Missing Upstream Registry Tarball',
    defaultSeverity: 'HIGH',
    threatType: 'EMPTY_OR_MISSING_TARBALL',
    description:
      'Registry packument does not provide a downloadable tarball URL or the tarball is 404.',
    remediationText:
      'Check if the package was unpublished or removed by the upstream registry for security violations.',
    reachabilityGated: false,
  },
  'SC-UNI-001': {
    ruleId: 'SC-UNI-001',
    title: 'Bidirectional Unicode Control Override (Bidi Trojan)',
    defaultSeverity: 'CRITICAL',
    threatType: 'BIDI_TROJAN',
    description:
      'Source code contains unbalanced or deceptive bidirectional Unicode control characters (CVE-2021-42574 Trojan Source).',
    remediationText:
      'Remove hidden bidi control characters. Re-encode the file using strictly ASCII/UTF-8 without bidirectional overrides.',
    reachabilityGated: false,
  },
  'SC-UNI-002': {
    ruleId: 'SC-UNI-002',
    title: 'Zero-Width or Invisible Code Characters',
    defaultSeverity: 'HIGH',
    threatType: 'OBFUSCATION',
    description:
      'Source code contains zero-width spaces, joiners, or invisible characters within executable tokens.',
    remediationText:
      'Strip invisible Unicode characters from the source code and verify identifier definitions.',
    reachabilityGated: false,
  },
  'SC-UNI-003': {
    ruleId: 'SC-UNI-003',
    title: 'Mixed-Script Identifiers and Confusable Homoglyphs',
    defaultSeverity: 'HIGH',
    threatType: 'OBFUSCATION',
    description:
      'Identifiers combine characters from different Unicode scripts (e.g. Cyrillic and Latin) to spoof variable names.',
    remediationText: 'Normalize identifier scripts and eliminate confusable homoglyphs.',
    reachabilityGated: false,
  },
  'SC-OBF-001': {
    ruleId: 'SC-OBF-001',
    title: 'High Shannon Entropy Packed or Encrypted String Literal',
    defaultSeverity: 'HIGH',
    threatType: 'HIGH_ENTROPY',
    description:
      'File contains long string literals with high Shannon entropy (H >= 4.5) matching base64 or hex payload structures.',
    remediationText: 'De-obfuscate the string literal and verify its origin and intended function.',
    reachabilityGated: false,
  },
  'SC-OBF-002': {
    ruleId: 'SC-OBF-002',
    title: 'Massive Unbroken Minified / Obfuscated Line',
    defaultSeverity: 'MEDIUM',
    threatType: 'OBFUSCATION',
    description:
      'File contains exceptionally long single lines (> 1000 characters) without whitespace.',
    remediationText: 'Format and un-minify the source file to review packed logic.',
    reachabilityGated: false,
  },
  'SC-META-001': {
    ruleId: 'SC-META-001',
    title: 'Chronological Version Release Anomaly',
    defaultSeverity: 'MEDIUM',
    threatType: 'CHRONO_ANOMALY',
    description:
      'A newer version was published with an older timestamp or out-of-order sequence compared to existing releases.',
    remediationText:
      'Review release changelogs to confirm legitimate backports or out-of-order publishing.',
    reachabilityGated: false,
  },
  'SC-META-002': {
    ruleId: 'SC-META-002',
    title: 'Major SemVer Jump Indicating Dependency Confusion',
    defaultSeverity: 'HIGH',
    threatType: 'SEMVER_ANOMALY',
    description:
      'Package release jumps multiple major versions (e.g. >= 20) or matches private scope namespace confusion.',
    remediationText:
      'Verify whether the package belongs to an internal scope that was inadvertently pulled from a public registry.',
    reachabilityGated: false,
  },
  'SC-META-003': {
    ruleId: 'SC-META-003',
    title: 'Manifest / Registry Metadata Desynchronization',
    defaultSeverity: 'HIGH',
    threatType: 'MANIFEST_CONFUSION',
    description:
      'Local package.json fields (dependencies, scripts, bin) diverge from the published registry packument metadata.',
    remediationText:
      'Re-install the dependency and verify whether the downloaded tarball matches the registry manifest.',
    reachabilityGated: false,
  },
  'SC-GOV-001': {
    ruleId: 'SC-GOV-001',
    title: 'Sudden Maintainer Ownership Change With Privilege Escalation',
    defaultSeverity: 'HIGH',
    threatType: 'GOVERNANCE_RISK',
    description:
      'Package was transferred to a new maintainer and immediately published with added lifecycle scripts or high capabilities.',
    remediationText:
      'Examine repository commit history and issue tracker for evidence of account compromise or ownership transfer.',
    reachabilityGated: false,
  },
  'SC-GOV-002': {
    ruleId: 'SC-GOV-002',
    title: 'Abandoned or Unclaimed Publisher Account',
    defaultSeverity: 'MEDIUM',
    threatType: 'GOVERNANCE_RISK',
    description:
      'Package publisher account has no other packages, no verified domain, or was dormant for > 1 year prior to release.',
    remediationText: 'Audit the publisher profile on the public registry.',
    reachabilityGated: false,
  },
  'SC-GOV-003': {
    ruleId: 'SC-GOV-003',
    title: 'Protestware & Destructive Geo-Targeting',
    defaultSeverity: 'CRITICAL',
    threatType: 'PROTESTWARE',
    description:
      'Package contains conditional execution checking system locale, timezone, or geo-IP to trigger destructive operations.',
    remediationText: 'Remove this package immediately. Pin to a previous unaffected version.',
    reachabilityGated: false,
  },
};

export function getRuleRegistryEntry(ruleId: SupplyChainRuleId): RuleRegistryEntry {
  const entry = RULES_REGISTRY[ruleId];
  if (!entry) {
    throw new Error(`Unknown supply chain rule ID: ${ruleId}`);
  }
  return entry;
}
