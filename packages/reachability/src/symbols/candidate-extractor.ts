import type { NormalizedFinding } from '@secureship/contracts';
import {
  isEligibleForHighPruning,
  type VulnerableSymbolDataset,
  type VulnerableSymbolEntry,
} from './vulnerable-symbol.schema.js';
import { SymbolDatasetLoader } from './dataset-loader.js';

export interface VulnerableSymbolCandidate {
  symbol: string;
  source: 'STRUCTURED_ADVISORY' | 'CURATED_DB' | 'HEURISTIC_TEXT';
  entry?: VulnerableSymbolEntry;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  kind?: 'FUNCTION' | 'CLASS' | 'METHOD' | 'PROPERTY';
  via?: string[];
}

/**
 * Documented stoplist of ordinary English prose, conjunctions, pronouns, tech abbreviations,
 * and language keywords that frequently get falsely captured by heuristic prose regexes.
 * Anti-Cheat Rule AC1 & Deliverable 2 mandatory hardening.
 */
export const HEURISTIC_STOPLIST = new Set<string>([
  'is',
  'of',
  'to',
  'in',
  'the',
  'an',
  'and',
  'or',
  'via',
  'when',
  'that',
  'this',
  'js',
  'ts',
  'io',
  'net',
  'com',
  'e',
  'g',
  'for',
  'with',
  'from',
  'as',
  'by',
  'at',
  'on',
  'if',
  'it',
  'not',
  'be',
  'are',
  'was',
  'were',
  'has',
  'have',
  'had',
  'do',
  'does',
  'did',
  'but',
  'so',
  'no',
  'up',
  'out',
  'all',
  'any',
  'can',
  'may',
  'will',
  'function',
  'method',
  'property',
  'symbol',
  'class',
  'module',
  'package',
  'node',
  'nodejs',
  'version',
  'versions',
  'vulnerability',
  'advisory',
  'cve',
  'ghsa',
  'true',
  'false',
  'null',
  'undefined',
  'object',
  'string',
  'number',
  'boolean',
  'array',
  'new',
  'return',
  'void',
  'typeof',
  'instanceof',
  'export',
  'import',
  'default',
  'const',
  'let',
  'var',
  'async',
  'await',
  'then',
  'catch',
  'throw',
  'try',
  'finally',
  'error',
  'exception',
  'issue',
  'bug',
  'patch',
  'fix',
]);

const IDENTIFIER_REGEX = /^[a-zA-Z_$][a-zA-Z0-9_$]*$/;

/**
 * Checks whether an extracted candidate symbol is a valid JS/Python identifier,
 * satisfies length bounds 2..64, and is not in the documented stoplist.
 */
export function isValidHeuristicSymbol(candidate: string): boolean {
  if (!candidate || candidate.length < 2 || candidate.length > 64) {
    return false;
  }
  if (!IDENTIFIER_REGEX.test(candidate)) {
    return false;
  }
  if (HEURISTIC_STOPLIST.has(candidate.toLowerCase())) {
    return false;
  }
  return true;
}

/**
 * Normalizes package name variations for call-form prefix matching.
 */
function getAllowedPrefixes(packageName?: string): Set<string> {
  const prefixes = new Set<string>();
  if (!packageName) {
    return prefixes;
  }

  const raw = packageName.toLowerCase().trim();
  prefixes.add(raw);

  // If scoped package: @scope/name -> name
  if (raw.startsWith('@') && raw.includes('/')) {
    const afterSlash = raw.split('/')[1];
    if (afterSlash) {
      prefixes.add(afterSlash);
    }
  }

  // Handle hyphen to camelCase or snake_case
  const camel = raw.replace(/-([a-z])/g, (_, g) => g.toUpperCase());
  prefixes.add(camel.toLowerCase());
  prefixes.add(raw.replace(/-/g, '_'));

  return prefixes;
}

/**
 * Extracts vulnerable symbol candidates for an SCA finding following strict precedence:
 * 1. STRUCTURED_ADVISORY: finding.evidence[].metadata.affected_functions (all evidence items)
 * 2. CURATED_DB: Matched by package/ecosystem and alias intersection
 * 3. HEURISTIC_TEXT: Hardened regex extraction from title and description (LOW forever)
 */
export function extractVulnerableSymbols(
  finding: NormalizedFinding,
  dataset?: VulnerableSymbolDataset | null
): VulnerableSymbolCandidate[] {
  // 1. Tier 1: STRUCTURED_ADVISORY
  const structuredCandidates = extractStructuredAdvisorySymbols(finding);
  if (structuredCandidates.length > 0) {
    return structuredCandidates;
  }

  // 2. Tier 2: CURATED_DB
  const effectiveDataset =
    dataset !== undefined ? dataset : SymbolDatasetLoader.loadBundledDataset().dataset;
  if (effectiveDataset) {
    const curatedCandidates = extractCuratedDbSymbols(finding, effectiveDataset);
    if (curatedCandidates.length > 0) {
      return curatedCandidates;
    }
  }

  // 3. Tier 3: HEURISTIC_TEXT
  return extractHeuristicTextSymbols(finding);
}

/**
 * Thin wrapper returning the first candidate name (or null).
 * Spec note: The SCA decision logic must NOT use this wrapper; it is provided for legacy / simple callers.
 */
export function extractVulnerableSymbol(
  finding: NormalizedFinding,
  dataset?: VulnerableSymbolDataset | null
): string | null {
  const candidates = extractVulnerableSymbols(finding, dataset);
  return candidates.length > 0 && candidates[0]?.symbol ? candidates[0].symbol : null;
}

/**
 * Extracts symbols from finding evidence metadata (affected_functions).
 */
function extractStructuredAdvisorySymbols(finding: NormalizedFinding): VulnerableSymbolCandidate[] {
  const candidates: VulnerableSymbolCandidate[] = [];
  const seen = new Set<string>();

  if (!Array.isArray(finding.evidence)) {
    return candidates;
  }

  for (const ev of finding.evidence) {
    if (!ev || !ev.metadata || typeof ev.metadata !== 'object') {
      continue;
    }

    const affected = (ev.metadata as Record<string, unknown>).affected_functions;
    if (!affected) {
      continue;
    }

    const rawList: string[] = [];
    if (Array.isArray(affected)) {
      for (const item of affected) {
        if (typeof item === 'string') {
          rawList.push(item);
        } else if (
          item &&
          typeof item === 'object' &&
          'name' in item &&
          typeof (item as { name: unknown }).name === 'string'
        ) {
          rawList.push((item as { name: string }).name);
        }
      }
    } else if (typeof affected === 'string') {
      rawList.push(affected);
    }

    for (const name of rawList) {
      const trimmed = name.trim();
      if (trimmed.length > 0 && !seen.has(trimmed)) {
        seen.add(trimmed);
        candidates.push({
          symbol: trimmed,
          source: 'STRUCTURED_ADVISORY',
          confidence: 'HIGH',
        });
      }
    }
  }

  return candidates.sort((a, b) => a.symbol.localeCompare(b.symbol));
}

/**
 * Extracts symbols from the curated vulnerable symbols database.
 */
function extractCuratedDbSymbols(
  finding: NormalizedFinding,
  dataset: VulnerableSymbolDataset
): VulnerableSymbolCandidate[] {
  const candidates: VulnerableSymbolCandidate[] = [];
  const packageName = finding.package?.name?.toLowerCase().trim();
  const rawEcosystem = finding.package?.ecosystem?.toLowerCase().trim();
  const ecosystem = rawEcosystem === 'pip' ? 'pypi' : rawEcosystem;

  // Collect all known aliases and IDs for this finding
  const findingIds = new Set<string>();
  if (finding.id) findingIds.add(finding.id.trim().toUpperCase());
  if (finding.ruleId) findingIds.add(finding.ruleId.trim().toUpperCase());
  if (Array.isArray(finding.aliases)) {
    for (const a of finding.aliases) {
      if (a) findingIds.add(a.trim().toUpperCase());
    }
  }
  const idAliases = (finding as { identifiers?: { aliases?: string[] } }).identifiers?.aliases;
  if (Array.isArray(idAliases)) {
    for (const a of idAliases) {
      if (a) findingIds.add(a.trim().toUpperCase());
    }
  }

  if (Array.isArray(finding.evidence)) {
    for (const ev of finding.evidence) {
      if (ev?.scannerRuleId) findingIds.add(ev.scannerRuleId.trim().toUpperCase());
      if (ev?.metadata && typeof ev.metadata === 'object') {
        const meta = ev.metadata as Record<string, unknown>;
        if (typeof meta.cve === 'string') findingIds.add(meta.cve.trim().toUpperCase());
        if (typeof meta.ghsa === 'string') findingIds.add(meta.ghsa.trim().toUpperCase());
      }
    }
  }

  // Find matching entries in dataset
  const matchedEntries: VulnerableSymbolEntry[] = [];
  for (const entry of dataset.entries) {
    // 1. Package match
    const entryPkg = entry.package.toLowerCase().trim();
    if (packageName && entryPkg !== packageName) {
      continue;
    }

    // 2. Ecosystem match (if finding specifies it)
    if (ecosystem && entry.ecosystem.toLowerCase() !== ecosystem) {
      continue;
    }

    // 3. ID / Alias intersection
    const entryIds = new Set<string>([
      entry.id.trim().toUpperCase(),
      ...entry.aliases.map((a: string) => a.trim().toUpperCase()),
    ]);

    let intersects = false;
    for (const id of findingIds) {
      if (entryIds.has(id)) {
        intersects = true;
        break;
      }
    }

    if (intersects) {
      matchedEntries.push(entry);
    }
  }

  const seen = new Set<string>();
  for (const entry of matchedEntries) {
    const isHigh = isEligibleForHighPruning(entry);
    const confidence = isHigh ? 'HIGH' : 'MEDIUM';

    for (const ep of entry.entryPoints) {
      const sym = ep.export;
      if (!seen.has(sym)) {
        seen.add(sym);
        candidates.push({
          symbol: sym,
          source: 'CURATED_DB',
          entry,
          confidence,
          kind: ep.kind,
          via: ep.via,
        });
      }
    }
  }

  return candidates.sort((a, b) => a.symbol.localeCompare(b.symbol));
}

/**
 * Extracts candidates from title and description using hardened regex patterns.
 * Confidence is LOW forever.
 */
function extractHeuristicTextSymbols(finding: NormalizedFinding): VulnerableSymbolCandidate[] {
  const text = `${finding.title || ''} ${finding.description || ''}`;
  if (!text.trim()) {
    return [];
  }

  const matches = new Set<string>();
  const allowedPrefixes = getAllowedPrefixes(finding.package?.name);

  // Pattern (a): /\b(?:function|method|property|symbol)\s+['`"]?([a-zA-Z0-9_$]+)['`"]?/gi
  const patternA = /\b(?:function|method|property|symbol)\s+['`"]?([a-zA-Z0-9_$]+)['`"]?/gi;
  let matchA: RegExpExecArray | null;
  while ((matchA = patternA.exec(text)) !== null) {
    const candidate = matchA[1];
    if (candidate && isValidHeuristicSymbol(candidate)) {
      matches.add(candidate);
    }
  }

  // Pattern (b): /\b([a-zA-Z0-9_$-]+)\.([a-zA-Z0-9_$]+)\s*\(/gi
  // Prefix must match package name or import alias!
  const patternB = /\b([a-zA-Z0-9_$-]+)\.([a-zA-Z0-9_$]+)\s*\(/gi;
  let matchB: RegExpExecArray | null;
  while ((matchB = patternB.exec(text)) !== null) {
    const prefix = matchB[1]?.toLowerCase().trim();
    const candidate = matchB[2];
    if (prefix && allowedPrefixes.size > 0 && !allowedPrefixes.has(prefix)) {
      // Prefix does not match the package or its conventional aliases => reject trap (e.g. Node.js ()
      continue;
    }
    if (candidate && isValidHeuristicSymbol(candidate)) {
      matches.add(candidate);
    }
  }

  // Pattern (c): /`([a-zA-Z0-9_$]+)\(\)`/g
  const patternC = /`([a-zA-Z0-9_$]+)\(\)`/g;
  let matchC: RegExpExecArray | null;
  while ((matchC = patternC.exec(text)) !== null) {
    const candidate = matchC[1];
    if (candidate && isValidHeuristicSymbol(candidate)) {
      matches.add(candidate);
    }
  }

  const sorted = Array.from(matches).sort((a, b) => a.localeCompare(b));
  return sorted.map((symbol) => ({
    symbol,
    source: 'HEURISTIC_TEXT',
    confidence: 'LOW' as const,
  }));
}
