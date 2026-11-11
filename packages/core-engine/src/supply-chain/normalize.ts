import crypto from 'node:crypto';
import type { NormalizedFinding } from '@secureship/contracts';
import type { RuleHit } from './internal/types.js';

function computeFingerprint(hit: RuleHit): string {
  const primaryEvidence = hit.evidence[0];
  const file = primaryEvidence?.file ?? 'package.json';
  const startLine = primaryEvidence?.startLine ?? 1;
  const hash = primaryEvidence?.snippetSha256 ?? '0'.repeat(64);

  const raw = `${hit.ruleId}:${hit.purl}:${file}:${startLine}:${hash}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export function normalizeRuleHit(hit: RuleHit, nowIso?: string): NormalizedFinding {
  const fingerprint = computeFingerprint(hit);
  const primaryEvidence = hit.evidence[0];
  const file = primaryEvidence?.file ?? 'package.json';
  const startLine = primaryEvidence?.startLine ?? 1;
  const endLine = primaryEvidence?.endLine ?? startLine;
  const startColumn = primaryEvidence?.startCol ?? 1;
  const endColumn = primaryEvidence?.endCol ?? 1;

  const finding: NormalizedFinding = {
    id: `sc-${hit.ruleId.toLowerCase()}-${fingerprint.slice(0, 16)}`,
    fingerprint,
    ruleId: hit.ruleId,
    scannerName: 'generic',
    category: 'SUPPLY_CHAIN',
    severity: hit.severity,
    confidence: hit.confidence,
    reachability: 'UNKNOWN',
    reachabilityDetail: {
      verdict: 'UNKNOWN',
      analysisConfidence: hit.confidence,
      evidence: {
        kind: 'NOT_APPLICABLE',
        notes: hit.description ?? hit.title,
      },
      limitations: [
        'Supply chain findings use package-level analysis; call-graph reachability is deferred to Phase 2.',
      ],
    },
    location: {
      filePath: file,
      startLine,
      endLine,
      startColumn,
      endColumn,
      redactedSnippet: primaryEvidence?.redactedSnippet,
    },
    upstreamValidationStatus: 'UNKNOWN',
    verificationStatus: 'UNVERIFIED',
    scopeTag: 'PRODUCTION',
    title: hit.title ?? hit.ruleId,
    description: hit.description ?? hit.title ?? hit.ruleId,
    cweIds: [],
    package: {
      ecosystem: hit.ecosystem,
      name: hit.packageName,
      version: hit.version,
    },
    evidence: [
      {
        scannerName: 'generic',
        scannerRuleId: hit.ruleId,
        message: hit.description ?? hit.title ?? '',
        metadata: {
          purl: hit.purl,
          blocking: hit.blocking,
          metadataUnavailable: hit.metadataUnavailable,
          capabilities: hit.capabilities ?? {},
          scReachability: hit.scReachability ?? 'UNKNOWN',
          items: hit.evidence,
        },
      },
    ],
    fixRecommendation: hit.remediationText
      ? {
          explanation: hit.remediationText,
        }
      : undefined,
    createdAt: nowIso ?? new Date().toISOString(),
  };

  return finding;
}
