import fs from 'node:fs';
import path from 'node:path';
import type {
  PreInstallGateResult,
  PreInstallViolation,
  ScaPatchProposal,
  SupplyChainPolicy,
  TargetVersionFacts,
} from '@secureship/contracts';
import { SupplyChainPolicySchema } from '@secureship/contracts';
import { analyzeSupplyChain } from '../supply-chain/supply-chain-analyzer.js';
import type { MetadataProvider } from '../supply-chain/providers/provider.interface.js';
import { NullProvider } from '../supply-chain/providers/null.provider.js';

const PACKAGE_NAME_REGEX = /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/i;
const VERSION_REGEX = /^[0-9a-zA-Z._+-]+$/;

export interface PreInstallGateOptions {
  proposal: ScaPatchProposal;
  rootDir: string;
  targetDir: string;
  policy?: SupplyChainPolicy;
  candidateVersions?: string[];
  provider?: MetadataProvider;
  signal?: AbortSignal;
}

export class PreInstallGate {
  /**
   * Evaluates the pre-install security gate before any dependency upgrade or installation.
   */
  public static async evaluate(options: PreInstallGateOptions): Promise<PreInstallGateResult> {
    const { proposal, targetDir, candidateVersions = [], signal } = options;
    const policy = options.policy ?? SupplyChainPolicySchema.parse({});
    const provider = options.provider ?? new NullProvider();

    // 1. Strict Regex Validation of package name and version
    if (!PACKAGE_NAME_REGEX.test(proposal.targetPackage)) {
      return {
        passed: false,
        violations: [
          {
            ruleId: 'SC-PKG-MALFORMED',
            message: `Malformed package name rejected by safety gate: '${proposal.targetPackage}'`,
            severity: 'CRITICAL',
            blocking: true,
          },
        ],
        targetVersionFacts: {
          hasInstallScripts: false,
          chronoAnomaly: false,
          semverAnomaly: false,
          manifestConfusion: false,
          hasBidiOrInvisibleUnicode: false,
          hasTyposquatOrHallucination: false,
          blockingFindingsCount: 1,
        },
      };
    }

    if (!VERSION_REGEX.test(proposal.targetVersion)) {
      return {
        passed: false,
        violations: [
          {
            ruleId: 'SC-VER-MALFORMED',
            message: `Malformed target version rejected by safety gate: '${proposal.targetVersion}'`,
            severity: 'CRITICAL',
            blocking: true,
          },
        ],
        targetVersionFacts: {
          hasInstallScripts: false,
          chronoAnomaly: false,
          semverAnomaly: false,
          manifestConfusion: false,
          hasBidiOrInvisibleUnicode: false,
          hasTyposquatOrHallucination: false,
          blockingFindingsCount: 1,
        },
      };
    }

    // 2. Evaluate target version (check targetDir or rootDir if shadow excluded node_modules)
    const evalDir = fs.existsSync(path.join(targetDir, 'node_modules', proposal.targetPackage))
      ? targetDir
      : fs.existsSync(path.join(options.rootDir, 'node_modules', proposal.targetPackage))
        ? options.rootDir
        : targetDir;

    const targetEval = await PreInstallGate.scanTargetVersion(
      proposal.targetPackage,
      proposal.targetVersion,
      evalDir,
      policy,
      provider,
      signal
    );

    if (targetEval.violations.length === 0) {
      return {
        passed: true,
        violations: [],
        targetVersionFacts: targetEval.facts,
      };
    }

    // 3. Fallback to candidate safe versions if available (bounded to 5 candidates)
    let safeCandidateVersion: string | undefined;
    for (const candidate of candidateVersions.slice(0, 5)) {
      if (candidate === proposal.targetVersion) continue;
      if (!VERSION_REGEX.test(candidate)) continue;

      const candidateEval = await PreInstallGate.scanTargetVersion(
        proposal.targetPackage,
        candidate,
        targetDir,
        policy,
        provider,
        signal
      );

      if (candidateEval.violations.length === 0) {
        safeCandidateVersion = candidate;
        break;
      }
    }

    return {
      passed: false,
      violations: targetEval.violations,
      targetVersionFacts: targetEval.facts,
      safeCandidateVersion,
    };
  }

  /**
   * Internal scanner evaluating safety signals on a specific version.
   */
  private static async scanTargetVersion(
    packageName: string,
    version: string,
    targetDir: string,
    policy: SupplyChainPolicy,
    provider: MetadataProvider,
    signal?: AbortSignal
  ): Promise<{ violations: PreInstallViolation[]; facts: TargetVersionFacts }> {
    const violations: PreInstallViolation[] = [];

    // Analyze target directory with supply chain engine
    const scanResult = await analyzeSupplyChain({
      rootDir: targetDir,
      policy: {
        ...policy,
        enabled: true,
      },
      provider,
      signal,
    });

    // Check findings associated with target package and specific version
    const relevantFindings = scanResult.findings.filter((f) => {
      const matchPkg =
        f.package?.name?.toLowerCase() === packageName.toLowerCase() ||
        f.location.filePath.toLowerCase().includes(packageName.toLowerCase());
      if (!matchPkg) return false;
      if (f.package?.version && f.package.version !== version) {
        return false;
      }
      return true;
    });

    let hasInstallScripts = false;
    let chronoAnomaly = false;
    let semverAnomaly = false;
    let manifestConfusion = false;
    let hasBidiOrInvisibleUnicode = false;
    let hasTyposquatOrHallucination = false;
    let blockingCount = 0;

    for (const finding of relevantFindings) {
      const meta = finding.evidence?.[0]?.metadata ?? {};
      const isBlocking = Boolean(meta['blocking']) || finding.severity === 'CRITICAL';
      if (isBlocking) blockingCount++;

      // Install Script check
      if (finding.ruleId.startsWith('SC-INSTALL-')) {
        hasInstallScripts = true;
        const isAllowlisted = policy.allowlist?.some(
          (a) => a.packageName.toLowerCase() === packageName.toLowerCase()
        );
        if (policy.preInstall?.forbidInstallScripts && !isAllowlisted) {
          violations.push({
            ruleId: finding.ruleId,
            threatType: 'INSTALL_SCRIPT',
            message: `Target version introduces un-allowlisted install script hook (${finding.ruleId})`,
            severity: finding.severity,
            blocking: true,
          });
        }
      }

      // Chrono Anomaly
      if (finding.ruleId === 'SC-META-001') {
        chronoAnomaly = true;
        violations.push({
          ruleId: 'SC-META-001',
          threatType: 'CHRONO_ANOMALY',
          message: 'Target version exhibits anomalous publication chronology',
          severity: finding.severity,
          blocking: isBlocking,
        });
      }

      // Semver Anomaly / Manifest Confusion
      if (finding.ruleId === 'SC-META-002') {
        semverAnomaly = true;
        violations.push({
          ruleId: 'SC-META-002',
          threatType: 'SEMVER_ANOMALY',
          message: 'Target version major version jump exceeds configured threshold',
          severity: finding.severity,
          blocking: isBlocking,
        });
      }

      if (finding.ruleId === 'SC-META-003') {
        manifestConfusion = true;
        violations.push({
          ruleId: 'SC-META-003',
          threatType: 'MANIFEST_CONFUSION',
          message: 'Target version exhibits registry-to-tarball manifest confusion',
          severity: 'HIGH',
          blocking: true,
        });
      }

      // Unicode attacks
      if (finding.ruleId.startsWith('SC-UNI-')) {
        hasBidiOrInvisibleUnicode = true;
        violations.push({
          ruleId: finding.ruleId,
          threatType: 'BIDI_TROJAN',
          message: `Target version contains hidden/bidi directional unicode in code (${finding.ruleId})`,
          severity: finding.severity,
          blocking: true,
        });
      }

      // Typosquat or AI Hallucination
      if (finding.ruleId.startsWith('SC-TYPO-') || finding.ruleId === 'SC-HALL-001') {
        if (finding.confidence === 'HIGH') {
          hasTyposquatOrHallucination = true;
          violations.push({
            ruleId: finding.ruleId,
            threatType: finding.ruleId === 'SC-HALL-001' ? 'AI_HALLUCINATION' : 'TYPOSQUAT',
            message: `Target package matches high-confidence typosquat or hallucination pattern (${finding.ruleId})`,
            severity: finding.severity,
            blocking: true,
          });
        }
      }

      // Dangerous capability combinations
      if (finding.ruleId.startsWith('SC-CAP-10') && isBlocking) {
        violations.push({
          ruleId: finding.ruleId,
          threatType: 'CAPABILITY_VIOLATION',
          message: `Target package contains critical multi-capability combination (${finding.ruleId})`,
          severity: 'CRITICAL',
          blocking: true,
        });
      }
    }

    const facts: TargetVersionFacts = {
      hasInstallScripts,
      chronoAnomaly,
      semverAnomaly,
      manifestConfusion,
      hasBidiOrInvisibleUnicode,
      hasTyposquatOrHallucination,
      blockingFindingsCount: blockingCount,
    };

    return { violations, facts };
  }
}
