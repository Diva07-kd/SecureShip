import crypto from 'node:crypto';
import type { SupplyChainEvidenceItem, SupplyChainPolicy } from '@secureship/contracts';
import type { DetectorContext, RuleHit } from '../internal/types.js';
import { RULES_REGISTRY } from '../rules-registry.js';
import confusablesData from '../data/confusables.json' with { type: 'json' };

const CONFUSABLES_MAP: Record<string, string> = confusablesData as Record<string, string>;

// Bidi control characters
const BIDI_OVERRIDES = new Set([
  '\u202A', // LRE
  '\u202B', // RLE
  '\u202C', // PDF
  '\u202D', // LRO
  '\u202E', // RLO
  '\u2066', // LRI
  '\u2067', // RLI
  '\u2068', // FSI
  '\u2069', // PDI
]);

// Zero-width & invisible characters
const ZERO_WIDTH_CHARS = new Set([
  '\u200B', // ZWSP
  '\u200C', // ZWNJ
  '\u200D', // ZWJ
  '\u2060', // Word joiner
  '\u2062', // Invisible times
  '\u2063', // Invisible separator
  '\u2064', // Invisible plus
]);

function computeHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function escapeUnicode(str: string): string {
  return [...str]
    .map((c) => {
      const code = c.codePointAt(0);
      if (code !== undefined && (code < 32 || code > 126)) {
        return `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;
      }
      return c;
    })
    .join('');
}

export function detectUnicodeAttacks(
  fileContent: string,
  filePath: string,
  _policy: SupplyChainPolicy,
  ctx?: DetectorContext
): RuleHit[] {
  const hits: RuleHit[] = [];
  const packageName = ctx?.packageName ?? 'unknown';
  const version = ctx?.version ?? '0.0.0';
  const ecosystem = ctx?.ecosystem ?? 'npm';
  const purl = `pkg:${ecosystem}/${packageName}@${version}`;

  const lines = fileContent.split('\n');

  let bidiFound = false;
  let zeroWidthFound = false;
  let homoglyphFound = false;

  const bidiEvidence: SupplyChainEvidenceItem[] = [];
  const zeroWidthEvidence: SupplyChainEvidenceItem[] = [];
  const homoglyphEvidence: SupplyChainEvidenceItem[] = [];

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];
    if (line === undefined) continue;
    const lineNum = lineIdx + 1;
    const codepoints = [...line];

    for (let colIdx = 0; colIdx < codepoints.length; colIdx++) {
      const char = codepoints[colIdx];
      if (char === undefined) continue;
      const colNum = colIdx + 1;

      // 1. SC-UNI-001 Bidi Trojan Source
      if (BIDI_OVERRIDES.has(char)) {
        bidiFound = true;
        if (bidiEvidence.length < 5) {
          const escaped = escapeUnicode(line.slice(Math.max(0, colIdx - 10), colIdx + 15));
          bidiEvidence.push({
            file: filePath,
            startLine: lineNum,
            startCol: colNum,
            endLine: lineNum,
            endCol: colNum + 1,
            snippetSha256: computeHash(line),
            redactedSnippet: escaped.slice(0, 200),
            note: `Bidirectional override control: ${escapeUnicode(char)}`,
          });
        }
      }

      // 2. SC-UNI-002 Zero-width or invisible character
      // Ignore BOM at position 0 on line 1
      const isBomAtStart = lineNum === 1 && colIdx === 0 && char === '\uFEFF';

      // Ignore ZWJ (\u200D) when part of standard Emoji ZWJ sequences (e.g. 👨‍👩‍👧‍👦 or 🏳️‍🌈)
      let isEmojiZwj = false;
      if (char === '\u200D') {
        const prev1 = colIdx > 0 ? (codepoints[colIdx - 1] ?? '') : '';
        const prev2 = colIdx > 1 ? (codepoints[colIdx - 2] ?? '') : '';
        const next1 = colIdx < codepoints.length - 1 ? (codepoints[colIdx + 1] ?? '') : '';
        const isPrevEmoji =
          /\p{Extended_Pictographic}/u.test(prev1) ||
          (prev1 === '\uFE0F' && /\p{Extended_Pictographic}/u.test(prev2));
        const isNextEmoji = /\p{Extended_Pictographic}/u.test(next1);
        isEmojiZwj = isPrevEmoji || isNextEmoji;
      }

      if (!isBomAtStart && !isEmojiZwj && (ZERO_WIDTH_CHARS.has(char) || char === '\uFEFF')) {
        zeroWidthFound = true;
        if (zeroWidthEvidence.length < 5) {
          const escaped = escapeUnicode(line.slice(Math.max(0, colIdx - 10), colIdx + 15));
          zeroWidthEvidence.push({
            file: filePath,
            startLine: lineNum,
            startCol: colNum,
            endLine: lineNum,
            endCol: colNum + 1,
            snippetSha256: computeHash(line),
            redactedSnippet: escaped.slice(0, 200),
            note: `Zero-width or invisible character: ${escapeUnicode(char)}`,
          });
        }
      }

      // 3. SC-UNI-003 Confusable homoglyph check
      if (CONFUSABLES_MAP[char]) {
        // Check if character is part of a word / identifier
        const prevChar = colIdx > 0 ? codepoints[colIdx - 1] : undefined;
        const nextChar = colIdx < codepoints.length - 1 ? codepoints[colIdx + 1] : undefined;
        const isSurroundedByAscii =
          (prevChar !== undefined && /[a-zA-Z0-9_]/.test(prevChar)) ||
          (nextChar !== undefined && /[a-zA-Z0-9_]/.test(nextChar));

        if (isSurroundedByAscii) {
          homoglyphFound = true;
          if (homoglyphEvidence.length < 5) {
            const escaped = escapeUnicode(line.slice(Math.max(0, colIdx - 10), colIdx + 15));
            const targetAscii = CONFUSABLES_MAP[char];
            homoglyphEvidence.push({
              file: filePath,
              startLine: lineNum,
              startCol: colNum,
              endLine: lineNum,
              endCol: colNum + 1,
              snippetSha256: computeHash(line),
              redactedSnippet: escaped.slice(0, 200),
              note: `Mixed-script homoglyph: ${escapeUnicode(char)} confuses with Latin '${targetAscii}'`,
            });
          }
        }
      }
    }
  }

  if (bidiFound) {
    const reg = RULES_REGISTRY['SC-UNI-001'];
    hits.push({
      ruleId: 'SC-UNI-001',
      packageName,
      version,
      ecosystem,
      purl,
      severity: reg.defaultSeverity,
      confidence: 'HIGH',
      evidence: bidiEvidence,
      metadataUnavailable: false,
      blocking: true,
      title: reg.title,
      description: reg.description,
      reachabilityGated: false,
      remediationText: reg.remediationText,
      scReachability: 'REACHABLE',
    });
  }

  if (zeroWidthFound) {
    const reg = RULES_REGISTRY['SC-UNI-002'];
    hits.push({
      ruleId: 'SC-UNI-002',
      packageName,
      version,
      ecosystem,
      purl,
      severity: reg.defaultSeverity,
      confidence: 'HIGH',
      evidence: zeroWidthEvidence,
      metadataUnavailable: false,
      blocking: false,
      title: reg.title,
      description: reg.description,
      reachabilityGated: false,
      remediationText: reg.remediationText,
      scReachability: 'REACHABLE',
    });
  }

  if (homoglyphFound) {
    const reg = RULES_REGISTRY['SC-UNI-003'];
    hits.push({
      ruleId: 'SC-UNI-003',
      packageName,
      version,
      ecosystem,
      purl,
      severity: reg.defaultSeverity,
      confidence: 'HIGH',
      evidence: homoglyphEvidence,
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
