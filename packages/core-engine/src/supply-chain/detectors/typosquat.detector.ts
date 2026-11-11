import crypto from 'node:crypto';
import type { SupplyChainEvidenceItem, SupplyChainPolicy } from '@secureship/contracts';
import type { DetectorContext, RuleHit } from '../internal/types.js';
import type { MetadataProvider } from '../providers/provider.interface.js';
import { RULES_REGISTRY } from '../rules-registry.js';

function computeHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

const D_BUFFER = new Int32Array(2048);
const DA_TABLE = new Int32Array(65536);

/**
 * Unrestricted Damerau-Levenshtein distance with optional early-exit maxDist.
 * Supports insertions, deletions, substitutions, and transpositions.
 */
export function damerauLevenshtein(a: string, b: string, maxDist?: number): number {
  if (a === b) return 0;
  const aLen = a.length;
  const bLen = b.length;

  if (aLen === 0) return bLen;
  if (bLen === 0) return aLen;

  // If length difference alone exceeds maxDist, exit early
  if (maxDist !== undefined && Math.abs(aLen - bLen) > maxDist) {
    return maxDist + 1;
  }

  const INF = aLen + bLen;
  const stride = bLen + 2;
  const totalSize = (aLen + 2) * stride;
  const d = totalSize <= 2048 ? D_BUFFER : new Int32Array(totalSize);

  d[0] = INF;
  for (let i = 0; i <= aLen; i++) {
    d[(i + 1) * stride + 0] = INF;
    d[(i + 1) * stride + 1] = i;
  }
  for (let j = 0; j <= bLen; j++) {
    d[0 * stride + (j + 1)] = INF;
    d[1 * stride + (j + 1)] = j;
  }

  const touchedChars: number[] = [];
  let daFallback: Map<number, number> | undefined;

  try {
    for (let i = 1; i <= aLen; i++) {
      let db = 0;
      let rowMin = Infinity;
      const charA = a.charCodeAt(i - 1);

      for (let j = 1; j <= bLen; j++) {
        const charB = b.charCodeAt(j - 1);
        const k = charB < 65536 ? DA_TABLE[charB]! : (daFallback?.get(charB) ?? 0);
        const l = db;

        let cost = 1;
        if (charA === charB) {
          cost = 0;
          db = j;
        }

        const delCost = (d[i * stride + (j + 1)] ?? 0) + 1;
        const insCost = (d[(i + 1) * stride + j] ?? 0) + 1;
        const subCost = (d[i * stride + j] ?? 0) + cost;
        const transCost = (d[k * stride + l] ?? 0) + (i - k - 1) + 1 + (j - l - 1);

        const val = Math.min(delCost, insCost, subCost, transCost);
        d[(i + 1) * stride + (j + 1)] = val;
        if (val < rowMin) rowMin = val;
      }

      if (charA < 65536) {
        if (DA_TABLE[charA] === 0) {
          touchedChars.push(charA);
        }
        DA_TABLE[charA] = i;
      } else {
        if (!daFallback) daFallback = new Map();
        daFallback.set(charA, i);
      }

      if (maxDist !== undefined && rowMin > maxDist) {
        return maxDist + 1;
      }
    }

    return d[(aLen + 1) * stride + (bLen + 1)] ?? 0;
  } finally {
    for (let t = 0; t < touchedChars.length; t++) {
      const c = touchedChars[t];
      if (c !== undefined) DA_TABLE[c] = 0;
    }
  }
}

export class PopularListIndex {
  private readonly byLength = new Map<number, string[]>();
  private readonly exactSet = new Set<string>();

  constructor(entries: { name: string }[]) {
    for (const entry of entries) {
      const name = entry.name.toLowerCase();
      this.exactSet.add(name);
      const len = name.length;
      const bucket = this.byLength.get(len) ?? [];
      bucket.push(name);
      this.byLength.set(len, bucket);
    }
  }

  public has(name: string): boolean {
    return this.exactSet.has(name.toLowerCase());
  }

  public getCandidates(name: string): string[] {
    const len = name.length;
    const candidates: string[] = [];
    for (let offset = -2; offset <= 2; offset++) {
      const bucket = this.byLength.get(len + offset);
      if (bucket) {
        candidates.push(...bucket);
      }
    }
    return candidates;
  }
}

const COMMON_SUFFIXES = [
  '-js',
  '-node',
  '-lib',
  '-utils',
  '-helper',
  '-helpers',
  '-cli',
  '-core',
  '-client',
  '-server',
  '-api',
  '_js',
  '_node',
  '.js',
  '-py',
  '_py',
  '.py',
  '-python',
  '_python',
];

const COMMON_PREFIXES = ['node-', 'js-', 'lib-', 'client-', 'py-', 'python-'];

function collapseSeparators(name: string): string {
  return name.toLowerCase().replace(/[-_.]/g, '');
}

export async function detectTyposquats(
  candidate: string,
  ecosystem: 'npm' | 'pypi',
  index: PopularListIndex,
  policy: SupplyChainPolicy,
  provider?: MetadataProvider,
  ctx?: DetectorContext
): Promise<RuleHit[]> {
  const hits: RuleHit[] = [];
  const version = ctx?.version ?? '0.0.0';
  const purl = `pkg:${ecosystem}/${candidate}@${version}`;
  const candidateLower = candidate.toLowerCase();

  // If candidate is an exact known popular package, it is legitimate
  if (index.has(candidateLower)) {
    return hits;
  }

  const minScore = policy.typosquat?.minScore ?? 0.82;
  const isScoped = candidate.startsWith('@');
  const unscopedName = isScoped ? (candidate.split('/')[1] ?? candidate) : candidate;
  const unscopedLower = unscopedName.toLowerCase();

  // 1. SC-TYPO-001: Edit Distance Squat
  if (unscopedLower.length >= 4) {
    const candidateList = index.getCandidates(unscopedLower);
    for (const popName of candidateList) {
      // Don't flag if it matches identically (e.g. scoped clone handled in SC-TYPO-002)
      if (popName === unscopedLower) continue;

      const dist = damerauLevenshtein(unscopedLower, popName, 2);
      if (dist <= 2) {
        const maxLen = Math.max(unscopedLower.length, popName.length);
        const score = 1 - dist / maxLen;
        const isSingleEditShortSquat = dist === 1 && maxLen >= 5;

        if (score >= minScore || isSingleEditShortSquat) {
          const reg = RULES_REGISTRY['SC-TYPO-001'];
          const severity = score >= minScore ? reg.defaultSeverity : 'MEDIUM';
          const snippetText = `package: "${candidate}" resembles popular package "${popName}" (edit distance ${dist}, similarity ${score.toFixed(3)})`;
          const evidenceItem: SupplyChainEvidenceItem = {
            file: 'package.json',
            startLine: 1,
            startCol: 1,
            endLine: 1,
            endCol: Math.min(200, snippetText.length + 1),
            snippetSha256: computeHash(snippetText),
            redactedSnippet: snippetText.slice(0, 200),
            note: `Typosquat target: ${popName}`,
          };

          hits.push({
            ruleId: 'SC-TYPO-001',
            packageName: candidate,
            version,
            ecosystem,
            purl,
            severity,
            confidence: isSingleEditShortSquat && score < minScore ? 'MEDIUM' : 'HIGH',
            evidence: [evidenceItem],
            metadataUnavailable: false,
            blocking: false,
            title: reg.title,
            description: `${reg.description} (${snippetText})`,
            reachabilityGated: false,
            remediationText: reg.remediationText,
            scReachability: 'REACHABLE',
          });
          // One SC-TYPO-001 hit per candidate is sufficient
          break;
        }
      }
    }
  }

  // 2. SC-TYPO-002: Combosquatting / Suffix Inflation / Scope Confusion
  let combosquatTarget: string | null = null;
  let combosquatType = '';

  if (isScoped && index.has(unscopedLower)) {
    combosquatTarget = unscopedLower;
    combosquatType = `Scope confusion: scoped clone '${candidate}' shadows popular unscoped package '${unscopedLower}'`;
  } else {
    for (const sfx of COMMON_SUFFIXES) {
      if (unscopedLower.endsWith(sfx)) {
        const base = unscopedLower.slice(0, -sfx.length);
        if (index.has(base)) {
          combosquatTarget = base;
          combosquatType = `Suffix inflation: '${unscopedLower}' appends suffix '${sfx}' to popular package '${base}'`;
          break;
        }
      }
    }

    if (!combosquatTarget) {
      for (const pfx of COMMON_PREFIXES) {
        if (unscopedLower.startsWith(pfx)) {
          const base = unscopedLower.slice(pfx.length);
          if (index.has(base)) {
            combosquatTarget = base;
            combosquatType = `Prefix inflation: '${unscopedLower}' appends prefix '${pfx}' to popular package '${base}'`;
            break;
          }
        }
      }
    }
  }

  if (combosquatTarget) {
    const reg = RULES_REGISTRY['SC-TYPO-002'];
    const snippetText = `combosquat detected: ${combosquatType}`;
    const evidenceItem: SupplyChainEvidenceItem = {
      file: 'package.json',
      startLine: 1,
      startCol: 1,
      endLine: 1,
      endCol: Math.min(200, snippetText.length + 1),
      snippetSha256: computeHash(snippetText),
      redactedSnippet: snippetText.slice(0, 200),
      note: `Combosquat target: ${combosquatTarget}`,
    };

    hits.push({
      ruleId: 'SC-TYPO-002',
      packageName: candidate,
      version,
      ecosystem,
      purl,
      severity: reg.defaultSeverity,
      confidence: 'MEDIUM',
      evidence: [evidenceItem],
      metadataUnavailable: false,
      blocking: false,
      title: reg.title,
      description: `${reg.description} (${combosquatType})`,
      reachabilityGated: false,
      remediationText: reg.remediationText,
      scReachability: 'REACHABLE',
    });
  }

  // 3. SC-TYPO-003: Separator Collapse Squatting
  const collapsed = collapseSeparators(unscopedLower);
  const candidatesForCollapse = index.getCandidates(unscopedLower);
  for (const popName of candidatesForCollapse) {
    if (popName === unscopedLower) continue;
    if (collapseSeparators(popName) === collapsed) {
      const reg = RULES_REGISTRY['SC-TYPO-003'];
      const snippetText = `Separator collapse match: "${unscopedLower}" vs popular package "${popName}"`;
      const evidenceItem: SupplyChainEvidenceItem = {
        file: 'package.json',
        startLine: 1,
        startCol: 1,
        endLine: 1,
        endCol: Math.min(200, snippetText.length + 1),
        snippetSha256: computeHash(snippetText),
        redactedSnippet: snippetText.slice(0, 200),
        note: `Separator collapse target: ${popName}`,
      };

      hits.push({
        ruleId: 'SC-TYPO-003',
        packageName: candidate,
        version,
        ecosystem,
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
      break;
    }
  }

  // 4. SC-HALL-001: AI Hallucination Target Risk
  if (provider && ctx) {
    const packumentRes = await provider.getPackument(ecosystem, candidate, ctx);
    if (packumentRes.ok) {
      const packument = packumentRes.value;
      const versions = Object.keys(packument.versions ?? {});
      const createdTime = packument.time?.created ? new Date(packument.time.created) : null;
      const now = ctx.now();
      const minAgeDays = policy.hallucination?.minAgeDays ?? 30;

      let isVeryYoung = false;
      if (createdTime && !isNaN(createdTime.getTime())) {
        const ageDays = (now.getTime() - createdTime.getTime()) / (1000 * 60 * 60 * 24);
        isVeryYoung = ageDays < minAgeDays;
      }

      const downloadsRes = await provider.getWeeklyDownloads(ecosystem, candidate, ctx);
      const downloads = downloadsRes.ok ? downloadsRes.value : 0;

      if (isVeryYoung && versions.length <= 2 && downloads < 50) {
        const reg = RULES_REGISTRY['SC-HALL-001'];
        const snippetText = `Package "${candidate}" created recently (< ${minAgeDays} days), ${versions.length} versions, ${downloads} weekly downloads`;
        const evidenceItem: SupplyChainEvidenceItem = {
          file: 'package.json',
          startLine: 1,
          startCol: 1,
          endLine: 1,
          endCol: Math.min(200, snippetText.length + 1),
          snippetSha256: computeHash(snippetText),
          redactedSnippet: snippetText.slice(0, 200),
          note: 'AI hallucination risk characteristics verified against registry packument',
        };

        hits.push({
          ruleId: 'SC-HALL-001',
          packageName: candidate,
          version,
          ecosystem,
          purl,
          severity: reg.defaultSeverity,
          confidence: 'HIGH',
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

  return hits;
}
