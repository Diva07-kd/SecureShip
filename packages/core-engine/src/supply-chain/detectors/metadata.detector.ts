import crypto from 'node:crypto';
import type { SupplyChainEvidenceItem, SupplyChainPolicy } from '@secureship/contracts';
import type { DetectorContext, RuleHit } from '../internal/types.js';
import type { MetadataProvider } from '../providers/provider.interface.js';
import { RULES_REGISTRY } from '../rules-registry.js';

function computeHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function parseMajorVersion(ver: string): number | null {
  const clean = ver.replace(/^[v^~]/, '').trim();
  const parts = clean.split('.');
  const first = parts[0];
  if (!first) return null;
  const num = parseInt(first, 10);
  return isNaN(num) ? null : num;
}

export async function detectMetadataAnomalies(
  packageName: string,
  version: string,
  packageJson: Record<string, unknown>,
  provider: MetadataProvider,
  policy: SupplyChainPolicy,
  ctx: DetectorContext
): Promise<RuleHit[]> {
  const hits: RuleHit[] = [];
  const purl = `pkg:${ctx.ecosystem}/${packageName}@${version}`;

  // Check private scope dependency confusion first (works offline)
  const privateScopes = policy.privateScopes ?? [];
  const matchesPrivateScope = privateScopes.some((scope) => packageName.startsWith(scope));

  const packumentRes = await provider.getPackument(ctx.ecosystem, packageName, ctx);

  if (!packumentRes.ok) {
    // Graceful degradation when metadata provider is unavailable
    if (packumentRes.error.code === 'UNAVAILABLE') {
      // If package is under private scope and metadata source is unavailable, we don't alarm needlessly
      return hits;
    }
    return hits;
  }

  const packument = packumentRes.value;

  // 1. SC-META-002: Private scope confusion / Massive SemVer jump
  if (matchesPrivateScope) {
    const reg = RULES_REGISTRY['SC-META-002'];
    const snippetText = `Package '${packageName}' belongs to private scope but exists on public metadata registry`;
    const evidenceItem: SupplyChainEvidenceItem = {
      file: 'package.json',
      startLine: 1,
      startCol: 1,
      endLine: 1,
      endCol: Math.min(200, snippetText.length + 1),
      snippetSha256: computeHash(snippetText),
      redactedSnippet: snippetText.slice(0, 200),
      note: 'Dependency confusion target: private scope package published on public registry',
    };

    hits.push({
      ruleId: 'SC-META-002',
      packageName,
      version,
      ecosystem: ctx.ecosystem,
      purl,
      severity: reg.defaultSeverity,
      confidence: 'HIGH',
      evidence: [evidenceItem],
      metadataUnavailable: false,
      blocking: true,
      title: reg.title,
      description: `${reg.description} (${snippetText})`,
      reachabilityGated: false,
      remediationText: reg.remediationText,
      scReachability: 'REACHABLE',
    });
  }

  const currentMajor = parseMajorVersion(version);
  const majorJumpThreshold = policy.semver?.majorJump ?? 20;

  if (currentMajor !== null && currentMajor >= majorJumpThreshold) {
    // Check if there are versions below majorJumpThreshold
    const allVersions = Object.keys(packument.versions ?? {});
    const smallerMajors = allVersions
      .map(parseMajorVersion)
      .filter((m): m is number => m !== null && m < 10);

    if (smallerMajors.length > 0) {
      const reg = RULES_REGISTRY['SC-META-002'];
      const snippetText = `Version jump from major ${Math.max(...smallerMajors)} to ${currentMajor} exceeds threshold ${majorJumpThreshold}`;
      const evidenceItem: SupplyChainEvidenceItem = {
        file: 'package.json',
        startLine: 1,
        startCol: 1,
        endLine: 1,
        endCol: Math.min(200, snippetText.length + 1),
        snippetSha256: computeHash(snippetText),
        redactedSnippet: snippetText.slice(0, 200),
        note: 'Abnormal major version jump indicates potential dependency confusion hijacking',
      };

      hits.push({
        ruleId: 'SC-META-002',
        packageName,
        version,
        ecosystem: ctx.ecosystem,
        purl,
        severity: reg.defaultSeverity,
        confidence: 'HIGH',
        evidence: [evidenceItem],
        metadataUnavailable: false,
        blocking: true,
        title: reg.title,
        description: `${reg.description} (${snippetText})`,
        reachabilityGated: false,
        remediationText: reg.remediationText,
        scReachability: 'REACHABLE',
      });
    }
  }

  // 2. SC-META-001: Chrono anomaly
  const timeMap = packument.time ?? {};
  const currentPublishTimeStr = timeMap[version];
  if (currentPublishTimeStr) {
    const currentPublishDate = new Date(currentPublishTimeStr);
    const now = ctx.now();

    // Future publish date
    if (currentPublishDate.getTime() > now.getTime() + 86400000) {
      const reg = RULES_REGISTRY['SC-META-001'];
      const snippetText = `Version publish date (${currentPublishTimeStr}) is in the future`;
      const evidenceItem: SupplyChainEvidenceItem = {
        file: 'package.json',
        startLine: 1,
        startCol: 1,
        endLine: 1,
        endCol: Math.min(200, snippetText.length + 1),
        snippetSha256: computeHash(snippetText),
        redactedSnippet: snippetText.slice(0, 200),
        note: 'Chronological anomaly: publish timestamp is in the future',
      };

      hits.push({
        ruleId: 'SC-META-001',
        packageName,
        version,
        ecosystem: ctx.ecosystem,
        purl,
        severity: reg.defaultSeverity,
        confidence: 'MEDIUM',
        evidence: [evidenceItem],
        metadataUnavailable: false,
        blocking: false,
        title: reg.title,
        description: `${reg.description} (${snippetText})`,
        reachabilityGated: false,
        remediationText: reg.remediationText,
        scReachability: 'REACHABLE',
      });
    }
  }

  // 3. SC-META-003: Manifest / Registry Metadata Desynchronization
  const regVersion = packument.versions?.[version];
  if (regVersion) {
    const localScripts = (
      packageJson.scripts && typeof packageJson.scripts === 'object' ? packageJson.scripts : {}
    ) as Record<string, unknown>;
    const remoteScripts = (
      regVersion.scripts && typeof regVersion.scripts === 'object' ? regVersion.scripts : {}
    ) as Record<string, string>;

    const hasNewInstallScriptLocally =
      (Boolean(localScripts.install) && !remoteScripts.install) ||
      (Boolean(localScripts.preinstall) && !remoteScripts.preinstall) ||
      (Boolean(localScripts.postinstall) && !remoteScripts.postinstall);

    if (hasNewInstallScriptLocally) {
      const reg = RULES_REGISTRY['SC-META-003'];
      const snippetText = `Local package.json defines install scripts not present in registry packument metadata for ${version}`;
      const evidenceItem: SupplyChainEvidenceItem = {
        file: 'package.json',
        startLine: 1,
        startCol: 1,
        endLine: 1,
        endCol: Math.min(200, snippetText.length + 1),
        snippetSha256: computeHash(snippetText),
        redactedSnippet: snippetText.slice(0, 200),
        note: 'Manifest desynchronization: hidden lifecycle script injected into local package',
      };

      hits.push({
        ruleId: 'SC-META-003',
        packageName,
        version,
        ecosystem: ctx.ecosystem,
        purl,
        severity: reg.defaultSeverity,
        confidence: 'HIGH',
        evidence: [evidenceItem],
        metadataUnavailable: false,
        blocking: true,
        title: reg.title,
        description: `${reg.description} (${snippetText})`,
        reachabilityGated: false,
        remediationText: reg.remediationText,
        scReachability: 'REACHABLE',
      });
    }
  }

  return hits;
}
