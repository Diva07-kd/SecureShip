import crypto from 'node:crypto';
import type { SupplyChainEvidenceItem, SupplyChainPolicy } from '@secureship/contracts';
import type { DetectorContext, RuleHit } from '../internal/types.js';
import { RULES_REGISTRY } from '../rules-registry.js';

function computeHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function shannonEntropy(s: string): number {
  if (!s || s.length === 0) return 0;
  const frequencies = new Map<string, number>();
  let totalSymbols = 0;

  for (const c of s) {
    frequencies.set(c, (frequencies.get(c) ?? 0) + 1);
    totalSymbols++;
  }

  if (totalSymbols === 0) return 0;

  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / totalSymbols;
    entropy -= p * Math.log2(p);
  }

  return Math.abs(entropy) < 1e-12 ? 0 : entropy;
}

const BASE64_OR_HEX_REGEX = /^[A-Za-z0-9+/=_-]+$/;

function isExcludedLiteral(lit: string): boolean {
  // Subresource Integrity
  if (/^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(lit)) return true;
  // Data URIs
  if (/^data:[a-zA-Z0-9/+-]+;base64,/.test(lit)) return true;
  // Source maps
  if (lit.includes('sourceMappingURL=') || lit.includes('sourceURL=')) return true;
  // Standard UUID
  if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(lit))
    return true;
  // License comments or standard headers
  if (lit.includes('Apache-2.0') || lit.includes('MIT License') || lit.includes('Copyright (c)'))
    return true;
  return false;
}

export function detectHighEntropy(
  fileContent: string,
  filePath: string,
  policy: SupplyChainPolicy,
  ctx?: DetectorContext
): RuleHit[] {
  const hits: RuleHit[] = [];
  const packageName = ctx?.packageName ?? 'unknown';
  const version = ctx?.version ?? '0.0.0';
  const ecosystem = ctx?.ecosystem ?? 'npm';
  const purl = `pkg:${ecosystem}/${packageName}@${version}`;

  const minLength = policy.entropy?.minLength ?? 64;
  const threshold = policy.entropy?.threshold ?? 4.5;
  const longLineThreshold = policy.obfuscation?.longLine ?? 1000;

  const lines = fileContent.split('\n');

  const highEntropyEvidence: SupplyChainEvidenceItem[] = [];
  const longLineEvidence: SupplyChainEvidenceItem[] = [];

  // Match string literals safely (single quote, double quote, backtick)
  const STRING_LITERAL_REGEX = /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line === undefined) continue;
    const lineNum = i + 1;

    // Check SC-OBF-002: Massive single line
    if (line.length > longLineThreshold) {
      // Check if line lacks whitespace or is minified packed
      const spaceCount = (line.match(/\s/g) ?? []).length;
      const spaceRatio = spaceCount / line.length;

      if (spaceRatio < 0.05) {
        if (longLineEvidence.length < 5) {
          longLineEvidence.push({
            file: filePath,
            startLine: lineNum,
            startCol: 1,
            endLine: lineNum,
            endCol: Math.min(200, line.length),
            snippetSha256: computeHash(line),
            redactedSnippet: line.slice(0, 180) + '...',
            note: `Massive unbroken line (${line.length} characters, ${(spaceRatio * 100).toFixed(1)}% spaces)`,
          });
        }
      }
    }

    // Check SC-OBF-001: High Shannon entropy literals
    let match: RegExpExecArray | null;
    STRING_LITERAL_REGEX.lastIndex = 0;

    while ((match = STRING_LITERAL_REGEX.exec(line)) !== null) {
      const raw = match[0];
      const startCol = match.index + 1;
      const endCol = startCol + raw.length;

      // Extract inner content without surrounding quotes
      const inner = raw.slice(1, -1);

      if (inner.length >= minLength && !isExcludedLiteral(inner)) {
        if (BASE64_OR_HEX_REGEX.test(inner)) {
          const h = shannonEntropy(inner);
          // Charset-aware threshold: 16-symbol hex has theoretical max entropy 4.0.
          // Normalized against 64-symbol base64 (max 6.0): threshold * (4.0 / 6.0)
          const isPureHex = /^[0-9a-fA-F]+$/.test(inner);
          const effectiveThreshold = isPureHex ? (threshold / 6.0) * 4.0 : threshold;

          if (h >= effectiveThreshold) {
            if (highEntropyEvidence.length < 5) {
              highEntropyEvidence.push({
                file: filePath,
                startLine: lineNum,
                startCol,
                endLine: lineNum,
                endCol: Math.min(endCol, startCol + 200),
                snippetSha256: computeHash(raw),
                redactedSnippet: raw.slice(0, 180) + '...',
                note: `High entropy literal: length ${inner.length}, H = ${h.toFixed(2)} >= ${effectiveThreshold.toFixed(2)} (${isPureHex ? 'hex' : 'base64'} normalized)`,
              });
            }
          }
        }
      }
    }
  }

  if (highEntropyEvidence.length > 0) {
    const reg = RULES_REGISTRY['SC-OBF-001'];
    hits.push({
      ruleId: 'SC-OBF-001',
      packageName,
      version,
      ecosystem,
      purl,
      severity: reg.defaultSeverity,
      confidence: 'HIGH',
      evidence: highEntropyEvidence,
      metadataUnavailable: false,
      blocking: false,
      title: reg.title,
      description: reg.description,
      reachabilityGated: false,
      remediationText: reg.remediationText,
      scReachability: 'REACHABLE',
    });
  }

  if (longLineEvidence.length > 0) {
    const reg = RULES_REGISTRY['SC-OBF-002'];
    hits.push({
      ruleId: 'SC-OBF-002',
      packageName,
      version,
      ecosystem,
      purl,
      severity: reg.defaultSeverity,
      confidence: 'MEDIUM',
      evidence: longLineEvidence,
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
