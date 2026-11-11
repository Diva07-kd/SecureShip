import { createHash } from 'node:crypto';
import type {
  NormalizedFinding,
  ProjectProfile,
  Severity,
  Confidence,
} from '@secureship/contracts';

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 50,
  HIGH: 40,
  MEDIUM: 30,
  LOW: 20,
  INFO: 10,
};

const CONFIDENCE_RANK: Record<Confidence, number> = {
  HIGH: 30,
  MEDIUM: 20,
  LOW: 10,
};

const TEST_PATH_REGEX =
  /(?:^|[\\/])(?:test|tests|__tests__|mocks|__mocks__|fixtures|fixture|spec|specs|e2e|testdata)(?:$|[\\/])/i;

export class FindingCorrelator {
  /**
   * Normalizes a file path to POSIX style.
   */
  public static toPosix(p: string): string {
    return p.replace(/\\/g, '/').replace(/^\.\//, '');
  }

  /**
   * Generates a deterministic SHA-256 fingerprint for a finding.
   */
  public static generateFingerprint(
    filePath: string,
    ruleId: string,
    snippetOrSink?: string
  ): string {
    const posixPath = FindingCorrelator.toPosix(filePath);
    const normalizedRule = ruleId.trim().toLowerCase();
    const normalizedSink = (snippetOrSink ?? '').replace(/\s+/g, ' ').trim();

    return createHash('sha256')
      .update(`${posixPath}:${normalizedRule}:${normalizedSink}`)
      .digest('hex');
  }

  /**
   * Normalizes a scanner rule ID by stripping path-derived prefixes (e.g., from Semgrep / Opengrep config paths).
   */
  public static normalizeRuleId(rawRuleId: string): string {
    if (!rawRuleId) return rawRuleId;
    const trimmed = rawRuleId.trim();

    // 1. Matches secureship rule IDs (e.g. rules.secureship-sast.secureship-js-eval or C.Users...secureship-js-eval)
    const secureshipMatch = trimmed.match(/(secureship-[a-zA-Z0-9_-]+)$/);
    if (secureshipMatch && secureshipMatch[1]) {
      return secureshipMatch[1];
    }

    // 2. Path-derived prefix stripping: if the ID has a config-path prefix ending with a rule name
    // e.g., rules.<pack>.<rulename> or /path/to/<pack>.<rulename> or C.Users...<rulename>
    const dotIndex = trimmed.lastIndexOf('.');
    if (dotIndex !== -1) {
      const candidate = trimmed.slice(dotIndex + 1);
      if (
        /^[a-zA-Z0-9_-]+$/.test(candidate) &&
        (trimmed.includes('/') ||
          trimmed.includes('\\') ||
          /^(?:[a-zA-Z]:|[a-z0-9_-]+\.[a-z0-9_-]+)/i.test(trimmed))
      ) {
        if (/^(?:.*[\\/]|rules\.|.*sast\.|[a-zA-Z]:|.*AppData)/i.test(trimmed)) {
          return candidate;
        }
      }
    }

    return trimmed;
  }

  /**
   * Checks whether a given file path is located inside a test or mock directory.
   */
  public static isTestPath(filePath: string, profile?: ProjectProfile): boolean {
    const posixPath = FindingCorrelator.toPosix(filePath);

    if (TEST_PATH_REGEX.test(posixPath)) {
      return true;
    }

    if (profile?.testDirectories) {
      for (const testDir of profile.testDirectories) {
        const posixTestDir = FindingCorrelator.toPosix(testDir);
        if (posixPath.startsWith(posixTestDir + '/') || posixPath === posixTestDir) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Finds an existing SCA finding that represents the same underlying package vulnerability.
   */
  private static findMatchingScaFinding(
    map: Map<string, NormalizedFinding>,
    candidate: NormalizedFinding
  ): NormalizedFinding | undefined {
    if (candidate.category !== 'SCA' || !candidate.package) {
      return undefined;
    }

    const candidateLockfile = candidate.lockfilePath ?? candidate.location.filePath;
    const candidateAliases = new Set([...(candidate.aliases ?? []), candidate.ruleId]);

    for (const existing of map.values()) {
      if (existing.category === 'SCA' && existing.package) {
        const existingLockfile = existing.lockfilePath ?? existing.location.filePath;

        const sameLockfile =
          FindingCorrelator.toPosix(existingLockfile) ===
          FindingCorrelator.toPosix(candidateLockfile);
        const sameEcosystem =
          existing.package.ecosystem.toLowerCase() === candidate.package.ecosystem.toLowerCase() ||
          existing.package.ecosystem.toLowerCase() === 'generic' ||
          candidate.package.ecosystem.toLowerCase() === 'generic';
        const sameName =
          existing.package.name.toLowerCase() === candidate.package.name.toLowerCase();
        const sameVersion = existing.package.version === candidate.package.version;

        if (sameLockfile && sameEcosystem && sameName && sameVersion) {
          const existingAliases = new Set([...(existing.aliases ?? []), existing.ruleId]);

          // Check if any CVE/GHSA/OSV or rule ID overlaps
          const sharesAlias = [...candidateAliases].some((a) => existingAliases.has(a));
          if (sharesAlias) {
            return existing;
          }
        }
      }
    }

    return undefined;
  }

  /**
   * Correlates, deduplicates, and applies Gate 1 scope filtering to findings.
   */
  public static correlate(
    findings: NormalizedFinding[],
    profile?: ProjectProfile
  ): NormalizedFinding[] {
    const map = new Map<string, NormalizedFinding>();

    for (const rawFinding of findings) {
      // Ensure file path is posix normalized
      const posixPath = FindingCorrelator.toPosix(rawFinding.location.filePath);
      const fingerprint =
        rawFinding.fingerprint ||
        FindingCorrelator.generateFingerprint(
          posixPath,
          rawFinding.ruleId,
          rawFinding.location.redactedSnippet
        );

      const normalizedFinding: NormalizedFinding = {
        ...rawFinding,
        fingerprint,
        location: {
          ...rawFinding.location,
          filePath: posixPath,
        },
      };

      // Gate 1 Scope Filter Check
      if (FindingCorrelator.isTestPath(posixPath, profile)) {
        normalizedFinding.confidence = 'LOW';
        normalizedFinding.reachability = 'UNREACHABLE';
        normalizedFinding.scopeTag = 'TEST_OR_MOCK';
      }

      // Check 1: Deduplication by identical SHA-256 fingerprint
      let existing = map.get(fingerprint);

      // Check 2: Deduplication by SCA vulnerability correlation (lockfile+pkg+version+aliases)
      if (!existing && normalizedFinding.category === 'SCA') {
        existing = FindingCorrelator.findMatchingScaFinding(map, normalizedFinding);
      }

      if (!existing) {
        map.set(fingerprint, normalizedFinding);
      } else {
        // Merge evidence and choose higher severity & confidence
        const mergedEvidence = [...existing.evidence];
        for (const ev of normalizedFinding.evidence) {
          const alreadyExists = mergedEvidence.some(
            (e) => e.scannerName === ev.scannerName && e.scannerRuleId === ev.scannerRuleId
          );
          if (!alreadyExists) {
            mergedEvidence.push(ev);
          }
        }

        const highestSeverity =
          SEVERITY_RANK[normalizedFinding.severity] > SEVERITY_RANK[existing.severity]
            ? normalizedFinding.severity
            : existing.severity;

        const highestConfidence =
          normalizedFinding.scopeTag === 'TEST_OR_MOCK' || existing.scopeTag === 'TEST_OR_MOCK'
            ? 'LOW' // Gate 1 override keeps test code low confidence
            : CONFIDENCE_RANK[normalizedFinding.confidence] > CONFIDENCE_RANK[existing.confidence]
              ? normalizedFinding.confidence
              : existing.confidence;

        const mergedCwe = Array.from(new Set([...existing.cweIds, ...normalizedFinding.cweIds]));

        const mergedAliases = Array.from(
          new Set([...(existing.aliases ?? []), ...(normalizedFinding.aliases ?? [])])
        );

        const updatedFinding: NormalizedFinding = {
          ...existing,
          severity: highestSeverity,
          confidence: highestConfidence,
          evidence: mergedEvidence,
          cweIds: mergedCwe,
          aliases: mergedAliases.length > 0 ? mergedAliases : undefined,
          package: existing.package ?? normalizedFinding.package,
          lockfilePath: existing.lockfilePath ?? normalizedFinding.lockfilePath,
          fixRecommendation: existing.fixRecommendation ?? normalizedFinding.fixRecommendation,
        };

        // Update the key in map
        map.set(existing.fingerprint, updatedFinding);
      }
    }

    // Sort findings deterministically: Severity desc, then file path asc, then start line asc
    return Array.from(map.values()).sort((a, b) => {
      const diff = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      if (diff !== 0) return diff;
      const fileCompare = a.location.filePath.localeCompare(b.location.filePath);
      if (fileCompare !== 0) return fileCompare;
      return a.location.startLine - b.location.startLine;
    });
  }
}
