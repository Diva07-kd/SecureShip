import crypto from 'node:crypto';
import path from 'node:path';
import type { SupplyChainEvidenceItem, SupplyChainPolicy } from '@secureship/contracts';
import type { DetectorContext, RuleHit } from '../internal/types.js';
import { RULES_REGISTRY } from '../rules-registry.js';
import systemCommands from '../data/system-commands.json' with { type: 'json' };

const SYSTEM_COMMANDS_SET = new Set<string>(
  (systemCommands as string[]).map((cmd) => cmd.toLowerCase())
);

function computeHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function isPathTraversal(targetPath: string): boolean {
  if (path.isAbsolute(targetPath) || targetPath.startsWith('/') || targetPath.startsWith('\\')) {
    return true;
  }
  const normalized = path.normalize(targetPath);
  return normalized.startsWith('..') || targetPath.includes('../') || targetPath.includes('..\\');
}

export function detectBinConfusion(
  packageJson: Record<string, unknown>,
  _policy: SupplyChainPolicy,
  ctx: DetectorContext
): RuleHit[] {
  const hits: RuleHit[] = [];
  const purl = `pkg:${ctx.ecosystem}/${ctx.packageName}@${ctx.version}`;
  const binField = packageJson.bin;

  if (!binField) {
    return hits;
  }

  const binMap: Record<string, string> = {};

  if (typeof binField === 'string') {
    const parts = ctx.packageName.split('/');
    const shortName = (parts.length > 1 ? parts[1] : parts[0]) || ctx.packageName;
    binMap[shortName] = binField;
  } else if (typeof binField === 'object' && binField !== null) {
    for (const [name, target] of Object.entries(binField)) {
      if (typeof target === 'string') {
        binMap[name] = target;
      }
    }
  }

  for (const [binName, binTarget] of Object.entries(binMap)) {
    const rawEntry = `"${binName}": "${binTarget}"`;
    const snippetHash = computeHash(rawEntry);

    // SC-BIN-001: Path traversal check
    if (isPathTraversal(binTarget)) {
      const reg = RULES_REGISTRY['SC-BIN-001'];
      const evidenceItem: SupplyChainEvidenceItem = {
        file: 'package.json',
        startLine: 1,
        startCol: 1,
        endLine: 1,
        endCol: Math.min(200, rawEntry.length + 1),
        snippetSha256: snippetHash,
        redactedSnippet: rawEntry.slice(0, 200),
        note: `Path traversal detected in binary entry: ${binTarget}`,
      };

      hits.push({
        ruleId: 'SC-BIN-001',
        packageName: ctx.packageName,
        version: ctx.version,
        ecosystem: ctx.ecosystem,
        purl,
        severity: reg.defaultSeverity,
        confidence: 'HIGH',
        evidence: [evidenceItem],
        metadataUnavailable: false,
        blocking: true,
        title: reg.title,
        description: `Package bin '${binName}' defines a path escaping the package directory: "${binTarget}"`,
        reachabilityGated: false,
        remediationText: reg.remediationText,
        scReachability: 'REACHABLE',
      });
    }

    // SC-BIN-002: System command shadowing
    const lowerBinName = binName.trim().toLowerCase();
    if (SYSTEM_COMMANDS_SET.has(lowerBinName)) {
      const reg = RULES_REGISTRY['SC-BIN-002'];
      const evidenceItem: SupplyChainEvidenceItem = {
        file: 'package.json',
        startLine: 1,
        startCol: 1,
        endLine: 1,
        endCol: Math.min(200, rawEntry.length + 1),
        snippetSha256: snippetHash,
        redactedSnippet: rawEntry.slice(0, 200),
        note: `Binary entry shadows system utility '${lowerBinName}'`,
      };

      hits.push({
        ruleId: 'SC-BIN-002',
        packageName: ctx.packageName,
        version: ctx.version,
        ecosystem: ctx.ecosystem,
        purl,
        severity: reg.defaultSeverity,
        confidence: 'HIGH',
        evidence: [evidenceItem],
        metadataUnavailable: false,
        blocking: false,
        title: reg.title,
        description: `Package defines binary '${binName}' which shadows standard system utility '${lowerBinName}'`,
        reachabilityGated: false,
        remediationText: reg.remediationText,
        scReachability: 'REACHABLE',
      });
    }
  }

  return hits;
}
