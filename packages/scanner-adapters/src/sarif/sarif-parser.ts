import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import {
  type Confidence,
  type FindingCategory,
  type FindingLocation,
  type NormalizedFinding,
  type ScannerName,
  type Severity,
  SarifLogSchema,
  type SarifLog,
  type SarifResult,
  type SarifRule,
  type SarifRun,
} from '@secureship/contracts';
import { FindingCorrelator, SecretRedactor } from '@secureship/core-engine';

export interface SarifParserOptions {
  scannerName: ScannerName;
  category: FindingCategory;
  targetDir: string;
  defaultConfidence?: Confidence;
  defaultSeverity?: Severity;
  maxFileSizeMB?: number;
}

export interface SarifParseResult {
  findings: NormalizedFinding[];
  warnings: string[];
  rawFindingCount: number;
}

const DEFAULT_MAX_SARIF_SIZE_MB = 100;

export class SarifParser {
  /**
   * Normalizes a file path to POSIX relative path from target root.
   */
  public static resolveArtifactPath(
    uri: string,
    targetDir: string,
    uriBaseId?: string,
    originalUriBaseIds?: Record<string, { uri?: string }>
  ): string | null {
    if (!uri || typeof uri !== 'string') {
      return null;
    }

    let decoded = uri;
    try {
      decoded = decodeURIComponent(uri);
    } catch {
      // Keep original if decoding fails
    }

    const stripFileUri = (u: string): string => {
      let s = u;
      if (s.startsWith('file:///')) {
        s = s.slice(8);
        if (!/^[a-zA-Z]:/.test(s)) s = '/' + s;
      } else if (s.startsWith('file://')) {
        s = s.slice(7);
        if (!/^[a-zA-Z]:/.test(s)) s = '/' + s;
      } else if (s.startsWith('file:/')) {
        s = s.slice(6);
        if (!/^[a-zA-Z]:/.test(s)) s = '/' + s;
      }
      return s;
    };

    decoded = stripFileUri(decoded);

    // Handle uriBaseId resolution if applicable
    if (uriBaseId && originalUriBaseIds && originalUriBaseIds[uriBaseId]?.uri) {
      let baseUri = originalUriBaseIds[uriBaseId]!.uri!;
      try {
        baseUri = decodeURIComponent(baseUri);
      } catch {
        // Keep original
      }
      baseUri = stripFileUri(baseUri);
      decoded = path.join(baseUri, decoded);
    }

    // Resolve against targetDir
    const absoluteTarget = path.resolve(targetDir);
    const resolvedPath = path.isAbsolute(decoded)
      ? path.resolve(decoded)
      : path.resolve(absoluteTarget, decoded);

    // Security check: Check if path escapes targetDir
    const relativeToTarget = path.relative(absoluteTarget, resolvedPath);
    if (relativeToTarget.startsWith('..') || path.isAbsolute(relativeToTarget)) {
      return null; // Escaped targetDir boundary
    }

    return FindingCorrelator.toPosix(relativeToTarget);
  }

  /**
   * Maps SARIF security-severity CVSS score or level to SecureShip Severity.
   */
  public static mapSeverity(securitySeverity?: unknown, level?: string): Severity {
    // 1. Prefer security-severity CVSS score if available
    if (securitySeverity !== undefined && securitySeverity !== null) {
      const score =
        typeof securitySeverity === 'number'
          ? securitySeverity
          : parseFloat(String(securitySeverity));
      if (!isNaN(score)) {
        if (score >= 9.0) return 'CRITICAL';
        if (score >= 7.0) return 'HIGH';
        if (score >= 4.0) return 'MEDIUM';
        if (score > 0.0) return 'LOW';
        return 'INFO';
      }
    }

    // 2. Fall back to SARIF result level
    const normalizedLevel = (level ?? '').toLowerCase();
    switch (normalizedLevel) {
      case 'error':
        return 'HIGH';
      case 'warning':
        return 'MEDIUM';
      case 'note':
        return 'LOW';
      case 'none':
        return 'INFO';
      default:
        return 'MEDIUM';
    }
  }

  /**
   * Derives confidence from rule properties, tags, or adapter defaults.
   */
  public static mapConfidence(
    rule?: SarifRule,
    defaultConfidence: Confidence = 'MEDIUM'
  ): Confidence {
    if (!rule?.properties) {
      return defaultConfidence;
    }

    const precision = String(
      rule.properties['precision'] ?? rule.properties['confidence'] ?? ''
    ).toLowerCase();

    if (precision === 'very-high' || precision === 'high') {
      return 'HIGH';
    }
    if (precision === 'medium') {
      return 'MEDIUM';
    }
    if (precision === 'low') {
      return 'LOW';
    }

    return defaultConfidence;
  }

  /**
   * Extracts CWE IDs from rule tags and properties.
   */
  public static extractCweIds(rule?: SarifRule): string[] {
    const cweSet = new Set<string>();
    if (!rule) return [];

    const tags = Array.isArray(rule.properties?.['tags'])
      ? (rule.properties!['tags'] as unknown[])
      : [];

    for (const tag of tags) {
      if (typeof tag === 'string') {
        const match = tag.match(/(?:cwe[/-]|cwe:)(\d+)/i);
        if (match && match[1]) {
          cweSet.add(`CWE-${match[1]}`);
        }
      }
    }

    if (Array.isArray(rule.properties?.['cwe'])) {
      for (const item of rule.properties!['cwe'] as unknown[]) {
        if (typeof item === 'string') {
          const match = item.match(/CWE-(\d+)/i) ?? item.match(/^(\d+)$/);
          if (match && match[1]) {
            cweSet.add(`CWE-${match[1]}`);
          }
        }
      }
    }

    return Array.from(cweSet);
  }

  /**
   * Parses a SARIF JSON file from disk safely.
   */
  public static parseFile(filePath: string, options: SarifParserOptions): SarifParseResult {
    if (!existsSync(filePath)) {
      throw new Error(`SARIF file does not exist: ${filePath}`);
    }

    const maxBytes = (options.maxFileSizeMB ?? DEFAULT_MAX_SARIF_SIZE_MB) * 1024 * 1024;
    const stat = statSync(filePath);
    if (stat.size > maxBytes) {
      throw new Error(
        `SARIF file size (${(stat.size / (1024 * 1024)).toFixed(2)} MB) exceeds allowed limit of ${options.maxFileSizeMB ?? DEFAULT_MAX_SARIF_SIZE_MB} MB`
      );
    }

    const rawContent = readFileSync(filePath, 'utf-8');
    return SarifParser.parseJson(rawContent, options);
  }

  /**
   * Parses raw SARIF JSON text into NormalizedFindings.
   */
  public static parseJson(rawJson: string, options: SarifParserOptions): SarifParseResult {
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawJson);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Invalid SARIF JSON payload: ${msg}`);
    }

    const parseResult = SarifLogSchema.safeParse(parsed);
    if (!parseResult.success) {
      throw new Error(`Malformed SARIF document schema: ${parseResult.error.message}`);
    }

    const log: SarifLog = parseResult.data;
    const findings: NormalizedFinding[] = [];
    const warnings: string[] = [];
    let rawFindingCount = 0;

    const runs = log.runs ?? [];
    for (const run of runs) {
      const rulesMap = new Map<string, SarifRule>();
      const rulesList = run.tool.driver.rules ?? [];
      for (let i = 0; i < rulesList.length; i++) {
        const r = rulesList[i]!;
        rulesMap.set(r.id, r);
        const normalized = FindingCorrelator.normalizeRuleId(r.id);
        if (normalized !== r.id) {
          rulesMap.set(normalized, r);
        }
        // Also map by index
        rulesMap.set(String(i), r);
      }

      const results = run.results ?? [];
      for (const res of results) {
        rawFindingCount++;
        const finding = SarifParser.convertResult(res, run, rulesMap, options, warnings);
        if (finding) {
          findings.push(finding);
        }
      }
    }

    return {
      findings,
      warnings,
      rawFindingCount,
    };
  }

  /**
   * Converts a single SARIF result object into a NormalizedFinding.
   */
  private static convertResult(
    result: SarifResult,
    run: SarifRun,
    rulesMap: Map<string, SarifRule>,
    options: SarifParserOptions,
    warnings: string[]
  ): NormalizedFinding | null {
    // 1. Resolve rule metadata
    const rawRuleId =
      result.ruleId ??
      (result.ruleIndex !== undefined ? rulesMap.get(String(result.ruleIndex))?.id : undefined) ??
      'unknown-rule';

    const rule =
      rulesMap.get(rawRuleId) ??
      (result.ruleIndex !== undefined ? rulesMap.get(String(result.ruleIndex)) : undefined) ??
      rulesMap.get(FindingCorrelator.normalizeRuleId(rawRuleId));

    const ruleId =
      options.scannerName === 'opengrep' || options.scannerName === 'semgrep'
        ? FindingCorrelator.normalizeRuleId(rawRuleId)
        : rawRuleId;

    // 2. Resolve location
    const firstLocation = result.locations?.[0];
    const physical = firstLocation?.physicalLocation;
    const rawUri = physical?.artifactLocation?.uri;
    const uriBaseId = physical?.artifactLocation?.uriBaseId;

    if (!rawUri) {
      warnings.push(`Result for rule '${ruleId}' dropped: missing artifactLocation URI.`);
      return null;
    }

    const relativePath = SarifParser.resolveArtifactPath(
      rawUri,
      options.targetDir,
      uriBaseId,
      run.originalUriBaseIds
    );

    if (!relativePath) {
      warnings.push(
        `Result for rule '${ruleId}' dropped: URI '${rawUri}' escapes the scan target boundary.`
      );
      return null;
    }

    // 3. Region & snippet
    const region = physical?.region;
    const startLine = region?.startLine ?? 1;
    const endLine = region?.endLine ?? startLine;
    const startColumn = region?.startColumn;
    const endColumn = region?.endColumn;

    const rawSnippet =
      region?.snippet?.text ??
      (typeof result.properties?.['snippet'] === 'string'
        ? (result.properties['snippet'] as string)
        : '');

    // Max 500 chars snippet and redact secrets
    const truncatedSnippet = rawSnippet.slice(0, 500);
    const redactedSnippet = SecretRedactor.redactText(truncatedSnippet);

    const location: FindingLocation = {
      filePath: relativePath,
      startLine,
      endLine,
      startColumn,
      endColumn,
      redactedSnippet: redactedSnippet || undefined,
    };

    // 4. Severity & Confidence
    const secSeverity =
      result.properties?.['security-severity'] ?? rule?.properties?.['security-severity'];
    let severity: Severity;
    if (options.scannerName === 'checkov') {
      if (secSeverity !== undefined && secSeverity !== null) {
        severity = SarifParser.mapSeverity(secSeverity, result.level);
      } else {
        severity = options.defaultSeverity ?? 'MEDIUM';
      }
    } else {
      severity = SarifParser.mapSeverity(secSeverity, result.level);
    }
    const confidence = SarifParser.mapConfidence(rule, options.defaultConfidence ?? 'MEDIUM');

    // Category mapping (e.g. Trivy misconfiguration vs vulnerability)
    let category: FindingCategory = options.category;
    if (options.scannerName === 'trivy') {
      const isMisconfig =
        /^(?:KSV|DS|AWS|AVD|AZU|GCP|CIB)-/i.test(rawRuleId) ||
        /^(?:KSV|DS|AWS|AVD|AZU|GCP|CIB)-/i.test(ruleId) ||
        rule?.name?.toLowerCase() === 'misconfiguration' ||
        (Array.isArray(rule?.properties?.['tags']) &&
          (rule!.properties!['tags'] as unknown[]).some(
            (t) => typeof t === 'string' && t.toLowerCase() === 'misconfiguration'
          ));
      category = isMisconfig ? 'IAC' : 'SCA';
    }

    // 5. Message & Descriptions
    const rawMessage =
      result.message?.text ??
      result.message?.markdown ??
      rule?.shortDescription?.text ??
      rule?.fullDescription?.text ??
      ruleId;
    const redactedMessage = SecretRedactor.redactText(rawMessage);

    let title: string;
    if (options.scannerName === 'opengrep' || options.scannerName === 'semgrep') {
      title = redactedMessage.split('\n')[0] ?? ruleId;
    } else {
      title =
        rule?.shortDescription?.text ?? rule?.name ?? redactedMessage.split('\n')[0] ?? ruleId;
      if (title.startsWith('Opengrep Finding:') || title.startsWith('Semgrep Finding:')) {
        title = redactedMessage.split('\n')[0] ?? ruleId;
      }
    }
    const description =
      rule?.fullDescription?.text ?? rule?.fullDescription?.markdown ?? redactedMessage;

    // 6. CWE IDs
    const cweIds = SarifParser.extractCweIds(rule);

    // 7. Optional SCA Aliases & Package Metadata
    const aliases: string[] = [];
    if (Array.isArray(result.properties?.['aliases'])) {
      for (const a of result.properties!['aliases'] as unknown[]) {
        if (typeof a === 'string') aliases.push(a);
      }
    }
    // Also extract CVE/GHSA/OSV from ruleId if it matches
    const idAliasMatch = ruleId.match(/\b(CVE-\d{4}-\d+|GHSA-[a-z0-9-]+|OSV-[a-z0-9-]+)\b/i);
    if (idAliasMatch && idAliasMatch[1] && !aliases.includes(idAliasMatch[1])) {
      aliases.push(idAliasMatch[1]);
    }

    let pkgInfo:
      | { ecosystem: string; name: string; version: string; fixedVersion?: string }
      | undefined;

    if (result.properties?.['package'] && typeof result.properties['package'] === 'object') {
      const p = result.properties['package'] as Record<string, unknown>;
      if (typeof p['name'] === 'string' && typeof p['version'] === 'string') {
        pkgInfo = {
          ecosystem: typeof p['ecosystem'] === 'string' ? p['ecosystem'] : 'generic',
          name: p['name'],
          version: p['version'],
          fixedVersion: typeof p['fixedVersion'] === 'string' ? p['fixedVersion'] : undefined,
        };
      }
    } else if (result.properties?.['pkgName'] || result.properties?.['packageName']) {
      const pName = (result.properties['pkgName'] ?? result.properties['packageName']) as string;
      const pVer = (result.properties['installedVersion'] ??
        result.properties['version'] ??
        'unknown') as string;
      pkgInfo = {
        ecosystem:
          typeof result.properties['ecosystem'] === 'string'
            ? (result.properties['ecosystem'] as string)
            : 'npm',
        name: pName,
        version: pVer,
      };
    } else if (!pkgInfo && typeof rawMessage === 'string') {
      // OSV-Scanner format: Package 'name@version' is vulnerable to 'CVE-...'
      const osvMatch = rawMessage.match(/Package\s+'(@?[^'@\s]+)@([^'@\s]+)'\s+is\s+vulnerable/i);
      if (osvMatch) {
        pkgInfo = {
          ecosystem:
            relativePath.endsWith('.py') ||
            relativePath.includes('requirements') ||
            relativePath.includes('poetry') ||
            relativePath.includes('Pipfile')
              ? 'pypi'
              : 'npm',
          name: osvMatch[1]!.trim(),
          version: osvMatch[2]!.trim(),
        };
      } else {
        const nameMatch = rawMessage.match(/Package:\s*([^\r\n]+)/i);
        const verMatch = rawMessage.match(/Installed Version:\s*([^\r\n]+)/i);
        const fixMatch = rawMessage.match(/Fixed Version:\s*([^\r\n]+)/i);
        if (nameMatch && verMatch) {
          pkgInfo = {
            ecosystem: 'npm',
            name: nameMatch[1]!.trim(),
            version: verMatch[1]!.trim(),
            fixedVersion: fixMatch ? fixMatch[1]!.trim() : undefined,
          };
        }
      }
    }

    const lockfilePath =
      typeof result.properties?.['lockfilePath'] === 'string'
        ? (result.properties['lockfilePath'] as string)
        : undefined;

    // 8. Deterministic Fingerprint
    const fingerprint = FindingCorrelator.generateFingerprint(
      relativePath,
      ruleId,
      redactedSnippet
    );

    const findingId = `finding-${fingerprint.slice(0, 16)}`;

    return {
      id: findingId,
      fingerprint,
      ruleId,
      scannerName: options.scannerName,
      category,
      severity,
      confidence,
      reachability: 'UNKNOWN',
      location,
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: SecretRedactor.redactText(title),
      description: SecretRedactor.redactText(description),
      cweIds,
      aliases: aliases.length > 0 ? aliases : undefined,
      package: pkgInfo,
      lockfilePath,
      evidence: [
        {
          scannerName: options.scannerName,
          scannerRuleId: rawRuleId,
          message: redactedMessage,
          metadata: result.properties ? SecretRedactor.redactObject(result.properties) : undefined,
        },
      ],
      createdAt: new Date().toISOString(),
    };
  }
}
