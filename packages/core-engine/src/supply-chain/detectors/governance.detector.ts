import crypto from 'node:crypto';
import type { SupplyChainEvidenceItem, SupplyChainPolicy } from '@secureship/contracts';
import type { DetectorContext, RuleHit } from '../internal/types.js';
import type { MetadataProvider } from '../providers/provider.interface.js';
import { RULES_REGISTRY } from '../rules-registry.js';

function computeHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

const PROTESTWARE_GEO_PATTERNS = [
  /resolvedoptions\(\)\.timezone/i,
  /process\.env\.(?:LANG|LC_ALL|TZ)/i,
  /(?:ip-api\.com|freegeoip|ipinfo\.io|extreme-ip-lookup)/i,
];

const PROTESTWARE_DESTRUCTIVE_PATTERNS = [
  /(?:rmdir|unlinkSync|rimraf|rm\s+-rf)/i,
  /(?:writeFileSync|appendFileSync)\s*\([^,]+,\s*['"](?:WITH_LOVE_FROM|PEACE|STOP_WAR|PROTEST)/i,
];

export async function detectGovernanceRisk(
  packageName: string,
  version: string,
  packageJson: Record<string, unknown>,
  provider: MetadataProvider,
  _policy: SupplyChainPolicy,
  ctx: DetectorContext
): Promise<RuleHit[]> {
  const hits: RuleHit[] = [];
  const purl = `pkg:${ctx.ecosystem}/${packageName}@${version}`;

  // 1. SC-GOV-003: Protestware heuristics (checked from package manifest scripts or files)
  const scripts = (
    packageJson.scripts && typeof packageJson.scripts === 'object' ? packageJson.scripts : {}
  ) as Record<string, unknown>;

  for (const [hook, cmd] of Object.entries(scripts)) {
    if (typeof cmd !== 'string') continue;

    const hasGeo = PROTESTWARE_GEO_PATTERNS.some((pat) => pat.test(cmd));
    const hasDestructive = PROTESTWARE_DESTRUCTIVE_PATTERNS.some((pat) => pat.test(cmd));

    if (hasGeo && hasDestructive) {
      const reg = RULES_REGISTRY['SC-GOV-003'];
      const snippetText = `Script '${hook}' contains geo-targeting conditions combined with destructive filesystem operations`;
      const evidenceItem: SupplyChainEvidenceItem = {
        file: 'package.json',
        startLine: 1,
        startCol: 1,
        endLine: 1,
        endCol: Math.min(200, cmd.length + 1),
        snippetSha256: computeHash(cmd),
        redactedSnippet: cmd.slice(0, 200),
        note: 'Protestware heuristic: conditional destructive payload based on locale or geo-IP',
      };

      hits.push({
        ruleId: 'SC-GOV-003',
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
      break;
    }
  }

  // 2. Metadata-dependent checks
  const publisherRes = await provider.getPublisher(ctx.ecosystem, packageName, version, ctx);
  if (publisherRes.ok) {
    const publisher = publisherRes.value;
    if (!publisher) {
      const reg = RULES_REGISTRY['SC-GOV-002'];
      const snippetText = `Publisher metadata is missing or unverified for package '${packageName}'`;
      const evidenceItem: SupplyChainEvidenceItem = {
        file: 'package.json',
        startLine: 1,
        startCol: 1,
        endLine: 1,
        endCol: Math.min(200, snippetText.length + 1),
        snippetSha256: computeHash(snippetText),
        redactedSnippet: snippetText.slice(0, 200),
        note: 'Unverified or missing publisher account',
      };

      hits.push({
        ruleId: 'SC-GOV-002',
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
        description: reg.description,
        reachabilityGated: false,
        remediationText: reg.remediationText,
        scReachability: 'REACHABLE',
      });
    }
  }

  // 3. SC-GOV-001: Maintainer change with escalation
  const packumentRes = await provider.getPackument(ctx.ecosystem, packageName, ctx);
  if (packumentRes.ok) {
    const packument = packumentRes.value;
    const versions = Object.keys(packument.versions ?? {});
    if (versions.length > 1) {
      const prevVersionKey = versions[versions.length - 2];
      if (prevVersionKey) {
        const prevVer = packument.versions?.[prevVersionKey];
        const currVer = packument.versions?.[version];

        if (prevVer && currVer) {
          const hadScript = Boolean(prevVer.scripts?.install || prevVer.scripts?.postinstall);
          const hasScript = Boolean(currVer.scripts?.install || currVer.scripts?.postinstall);

          if (!hadScript && hasScript) {
            const reg = RULES_REGISTRY['SC-GOV-001'];
            const snippetText = `Package added install scripts in version ${version} (not present in previous release ${prevVersionKey})`;
            const evidenceItem: SupplyChainEvidenceItem = {
              file: 'package.json',
              startLine: 1,
              startCol: 1,
              endLine: 1,
              endCol: Math.min(200, snippetText.length + 1),
              snippetSha256: computeHash(snippetText),
              redactedSnippet: snippetText.slice(0, 200),
              note: 'Privilege escalation: newly introduced lifecycle scripts',
            };

            hits.push({
              ruleId: 'SC-GOV-001',
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
      }
    }
  }

  return hits;
}
