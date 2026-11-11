import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { SupplyChainEvidenceItem } from '@secureship/contracts';
import type { DetectorContext, RuleHit } from '../internal/types.js';
import { RULES_REGISTRY } from '../rules-registry.js';

function computeHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

const NON_CODE_FILES = new Set([
  'package.json',
  'readme.md',
  'readme',
  'license',
  'license.md',
  'license.txt',
  'changelog.md',
  'changelog',
  'authors',
  '.npmignore',
  '.gitignore',
  'notice',
  'notice.txt',
  'notice.md',
]);

const NON_CODE_EXTS = new Set(['.md', '.txt', '.markdown', '.rst']);

function countCodeFiles(dir: string, depth = 0): number {
  if (depth > 5) return 0;
  if (!fs.existsSync(dir)) return 0;

  let count = 0;
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const ent of entries) {
      const nameLower = ent.name.toLowerCase();
      if (ent.isDirectory()) {
        if (nameLower !== 'node_modules' && !nameLower.startsWith('.')) {
          count += countCodeFiles(path.join(dir, ent.name), depth + 1);
        }
      } else if (ent.isFile()) {
        if (!NON_CODE_FILES.has(nameLower)) {
          const ext = path.extname(nameLower);
          if (!NON_CODE_EXTS.has(ext)) {
            count++;
          }
        }
      }
    }
  } catch {
    // Ignore read errors
  }

  return count;
}

export function detectEmptyPackage(
  packageDir: string,
  _packageJson: Record<string, unknown>,
  ctx: DetectorContext
): RuleHit[] {
  const hits: RuleHit[] = [];
  const purl = `pkg:${ctx.ecosystem}/${ctx.packageName}@${ctx.version}`;

  const codeFilesCount = countCodeFiles(packageDir);

  if (codeFilesCount === 0) {
    const reg = RULES_REGISTRY['SC-PKG-001'];
    const snippetText = `Package directory '${ctx.packageName}' contains 0 executable code files (only metadata, README, or license files)`;
    const evidenceItem: SupplyChainEvidenceItem = {
      file: 'package.json',
      startLine: 1,
      startCol: 1,
      endLine: 1,
      endCol: Math.min(200, snippetText.length + 1),
      snippetSha256: computeHash(snippetText),
      redactedSnippet: snippetText.slice(0, 200),
      note: 'Zero executable source files found in package directory',
    };

    hits.push({
      ruleId: 'SC-PKG-001',
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
      description: reg.description,
      reachabilityGated: false,
      remediationText: reg.remediationText,
      scReachability: 'REACHABLE',
    });
  }

  return hits;
}
