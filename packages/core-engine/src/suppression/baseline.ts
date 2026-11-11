import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import type { NormalizedFinding } from '@secureship/contracts';
import { FindingCorrelator } from '../normalizer/finding-correlator.js';
import { checkDirWritable } from '../paths/index.js';

export interface BaselineEntry {
  fingerprint: string;
  ruleId: string;
  filePath: string;
  firstSeen: string;
}

export interface BaselineDocument {
  schemaVersion: '1.0';
  updatedAt: string;
  findings: BaselineEntry[];
}

export class BaselineEvaluator {
  private readonly baselineMap = new Map<string, BaselineEntry>();

  constructor(baselineFilePath?: string) {
    if (baselineFilePath && existsSync(baselineFilePath)) {
      try {
        const raw = readFileSync(baselineFilePath, 'utf-8');
        const doc = JSON.parse(raw) as BaselineDocument;
        if (Array.isArray(doc.findings)) {
          for (const entry of doc.findings) {
            if (entry.fingerprint) {
              this.baselineMap.set(entry.fingerprint, entry);
            }
          }
        }
      } catch {
        // Corrupted baseline treated as empty with warning
      }
    }
  }

  /**
   * Checks whether a finding fingerprint is present in baseline.
   */
  public isKnownInBaseline(finding: NormalizedFinding): boolean {
    return this.getBaselineEntry(finding) !== undefined;
  }

  public getBaselineEntry(finding: NormalizedFinding): BaselineEntry | undefined {
    // 1. Direct match on normalized fingerprint
    const direct = this.baselineMap.get(finding.fingerprint);
    if (direct) return direct;

    // 2. Check legacy fingerprint if scannerRuleId differs from normalized ruleId
    const scannerRuleId = finding.evidence?.[0]?.scannerRuleId;
    if (scannerRuleId && scannerRuleId !== finding.ruleId) {
      const legacyFp = FindingCorrelator.generateFingerprint(
        finding.location.filePath,
        scannerRuleId,
        finding.location.redactedSnippet
      );
      const legacyMatch = this.baselineMap.get(legacyFp);
      if (legacyMatch) return legacyMatch;
    }

    // 3. Check known default prefix: rules.secureship-sast.<ruleId>
    if (!finding.ruleId.startsWith('rules.')) {
      const prefixedFp = FindingCorrelator.generateFingerprint(
        finding.location.filePath,
        `rules.secureship-sast.${finding.ruleId}`,
        finding.location.redactedSnippet
      );
      const prefixedMatch = this.baselineMap.get(prefixedFp);
      if (prefixedMatch) return prefixedMatch;
    }

    // 4. Secondary fallback: check if any baseline entry matches same file and normalized ruleId
    const posixTarget = FindingCorrelator.toPosix(finding.location.filePath);
    const normTargetRule = FindingCorrelator.normalizeRuleId(finding.ruleId).toLowerCase();
    for (const entry of this.baselineMap.values()) {
      if (
        FindingCorrelator.toPosix(entry.filePath) === posixTarget &&
        FindingCorrelator.normalizeRuleId(entry.ruleId).toLowerCase() === normTargetRule
      ) {
        return entry;
      }
    }

    return undefined;
  }

  /**
   * Writes findings to a baseline document file deterministically.
   */
  public static writeBaseline(targetFilePath: string, findings: NormalizedFinding[]): void {
    const parentDir = path.dirname(targetFilePath);
    const writability = checkDirWritable(parentDir);
    if (!writability.writable) {
      throw new Error(`Cannot write baseline file to '${targetFilePath}': ${writability.error}`);
    }

    // Preserve existing firstSeen timestamps if baseline already exists
    const existingMap = new Map<string, string>();
    if (existsSync(targetFilePath)) {
      try {
        const raw = readFileSync(targetFilePath, 'utf-8');
        const existingDoc = JSON.parse(raw) as BaselineDocument;
        if (Array.isArray(existingDoc.findings)) {
          for (const item of existingDoc.findings) {
            if (item.fingerprint && item.firstSeen) {
              existingMap.set(item.fingerprint, item.firstSeen);
            }
          }
        }
      } catch {
        // Ignore read errors on corrupt file
      }
    }

    const now = new Date().toISOString();
    const sortedFindings = [...findings].sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));

    const entries: BaselineEntry[] = sortedFindings.map((f) => ({
      fingerprint: f.fingerprint,
      ruleId: f.ruleId,
      filePath: f.location.filePath,
      firstSeen: existingMap.get(f.fingerprint) ?? f.createdAt ?? now,
    }));

    const doc: BaselineDocument = {
      schemaVersion: '1.0',
      updatedAt: now,
      findings: entries,
    };

    writeFileSync(targetFilePath, JSON.stringify(doc, null, 2), 'utf-8');
  }
}
