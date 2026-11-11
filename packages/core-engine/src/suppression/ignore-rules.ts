import type { IgnoreRule, NormalizedFinding } from '@secureship/contracts';
import { FindingCorrelator } from '../normalizer/finding-correlator.js';

export interface IgnoreEvaluationResult {
  isIgnored: boolean;
  matchedRule?: IgnoreRule;
  detail?: string;
}

export class IgnoreRulesEvaluator {
  private readonly rules: IgnoreRule[];
  private readonly ruleMatchCounts: number[];

  constructor(rules: IgnoreRule[] = []) {
    this.rules = rules;
    this.ruleMatchCounts = new Array(rules.length).fill(0);
  }

  /**
   * Simple glob matcher supporting * and ** for path globs.
   */
  public static matchesGlob(filePath: string, pattern: string): boolean {
    const posixPath = FindingCorrelator.toPosix(filePath);
    const posixPattern = FindingCorrelator.toPosix(pattern);

    // Escape regex special chars except * and ?
    let regexStr = posixPattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '___DOUBLE_STAR___')
      .replace(/\*/g, '[^/]*')
      .replace(/___DOUBLE_STAR___/g, '.*')
      .replace(/\?/g, '[^/]');

    // If pattern doesn't start with / or .*, match anywhere or prefix
    if (!regexStr.startsWith('.*') && !regexStr.startsWith('^')) {
      regexStr = '(?:^|.*/)' + regexStr;
    }

    const regex = new RegExp(`^${regexStr}$`);
    return regex.test(posixPath);
  }

  /**
   * Tests if an ignore rule is expired.
   */
  public static isExpired(rule: IgnoreRule): boolean {
    const exp = new Date(rule.expires);
    if (isNaN(exp.getTime())) return false;
    return exp.getTime() < Date.now();
  }

  /**
   * Evaluates a finding against configured ignore rules.
   */
  public evaluate(finding: NormalizedFinding): IgnoreEvaluationResult {
    for (let i = 0; i < this.rules.length; i++) {
      const rule = this.rules[i]!;

      // Check expiration
      if (IgnoreRulesEvaluator.isExpired(rule)) {
        continue; // Expired rules are skipped
      }

      let matches = true;

      if (rule.ruleId) {
        const normRule = FindingCorrelator.normalizeRuleId(rule.ruleId).toLowerCase();
        const normFindingRule = FindingCorrelator.normalizeRuleId(finding.ruleId).toLowerCase();
        const scannerRuleId = (finding.evidence?.[0]?.scannerRuleId ?? '').toLowerCase();
        const ruleIdLower = rule.ruleId.toLowerCase();
        if (
          ruleIdLower !== finding.ruleId.toLowerCase() &&
          normRule !== normFindingRule &&
          ruleIdLower !== scannerRuleId
        ) {
          matches = false;
        }
      }

      if (rule.fingerprint && rule.fingerprint !== finding.fingerprint) {
        // Also check legacy fingerprint if available
        const scannerRuleId = finding.evidence?.[0]?.scannerRuleId;
        let legacyFp: string | undefined;
        if (scannerRuleId && scannerRuleId !== finding.ruleId) {
          legacyFp = FindingCorrelator.generateFingerprint(
            finding.location.filePath,
            scannerRuleId,
            finding.location.redactedSnippet
          );
        }
        if (rule.fingerprint !== legacyFp) {
          matches = false;
        }
      }

      if (
        rule.pathGlob &&
        !IgnoreRulesEvaluator.matchesGlob(finding.location.filePath, rule.pathGlob)
      ) {
        matches = false;
      }

      if (matches) {
        this.ruleMatchCounts[i] = (this.ruleMatchCounts[i] ?? 0) + 1;
        return {
          isIgnored: true,
          matchedRule: rule,
          detail: `User ignore rule matched: "${rule.reason}" (expires: ${rule.expires})`,
        };
      }
    }

    return { isIgnored: false };
  }

  /**
   * Collects warnings for expired rules and unused rules.
   */
  public collectWarnings(): string[] {
    const warnings: string[] = [];

    for (let i = 0; i < this.rules.length; i++) {
      const rule = this.rules[i]!;
      const identifier = rule.ruleId ?? rule.fingerprint ?? rule.pathGlob ?? 'rule';

      if (IgnoreRulesEvaluator.isExpired(rule)) {
        warnings.push(
          `Ignore rule for '${identifier}' expired on ${rule.expires} and was not applied.`
        );
      } else if ((this.ruleMatchCounts[i] ?? 0) === 0) {
        warnings.push(`Ignore rule for '${identifier}' did not match any findings in this scan.`);
      }
    }

    return warnings;
  }
}
