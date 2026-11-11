import fs from 'node:fs';
import type {
  NormalizedFinding,
  ProjectProfile,
  ScopeTag,
  SuppressionReasonCode,
} from '@secureship/contracts';
import { FindingCorrelator } from '../normalizer/finding-correlator.js';

export interface Gate1EvaluationResult {
  scopeTag: ScopeTag;
  shouldSuppress: boolean;
  suppressionReason?: SuppressionReasonCode;
  suppressionDetail?: string;
}

export interface Gate1Options {
  enabled?: boolean;
  keepProviderSecrets?: boolean;
  includeNonProduction?: boolean;
  customTestDirs?: string[];
}

const TEST_SEGMENT_REGEX =
  /(?:^|[\\/])(test|tests|__tests__|mocks|__mocks__|fixtures|fixture|corpus|spec|specs|e2e|testdata)(?:$|[\\/])/i;

const EXAMPLE_SEGMENT_REGEX = /(?:^|[\\/])(example|examples|sample|samples)(?:$|[\\/])/i;

const DOCS_SEGMENT_REGEX = /(?:^|[\\/])(doc|docs|documentation)(?:$|[\\/])/i;

const PLACEHOLDER_LIST = [
  'example',
  'dummy',
  'changeme',
  'change_me',
  'xxxx',
  'test',
  'mock',
  'fake',
  'sample',
  '000000',
  '123456',
  'placeholder',
  'secret_token_here',
  'verysecret',
  'supersecret',
  'abcdefgh',
];

const PROVIDER_SPECIFIC_RULE_REGEX =
  /(?:aws|amazon|github|slack|stripe|private[_-]?key|google[_-]?api|twilio|sendgrid|datadog)/i;

export class Gate1Scope {
  /**
   * Classifies a file path into its scope tag (PRODUCTION, TEST_OR_MOCK, EXAMPLE, DOCUMENTATION).
   * Uses strict path-segment boundaries so lookalikes (contest, latest, attestation) are never tagged.
   */
  public static classifyPath(
    filePath: string,
    profile?: ProjectProfile,
    customTestDirs?: string[]
  ): ScopeTag {
    const posixPath = FindingCorrelator.toPosix(filePath);

    // 1. Check custom test directories
    if (customTestDirs) {
      for (const dir of customTestDirs) {
        const posixDir = FindingCorrelator.toPosix(dir);
        if (posixPath.startsWith(posixDir + '/') || posixPath === posixDir) {
          return 'TEST_OR_MOCK';
        }
      }
    }

    // 2. Check profile test directories
    if (profile?.testDirectories) {
      for (const dir of profile.testDirectories) {
        const posixDir = FindingCorrelator.toPosix(dir);
        if (posixPath.startsWith(posixDir + '/') || posixPath === posixDir) {
          return 'TEST_OR_MOCK';
        }
      }
    }

    // 3. Check regex segment patterns
    if (TEST_SEGMENT_REGEX.test(posixPath)) {
      return 'TEST_OR_MOCK';
    }

    if (EXAMPLE_SEGMENT_REGEX.test(posixPath)) {
      return 'EXAMPLE';
    }

    if (DOCS_SEGMENT_REGEX.test(posixPath)) {
      return 'DOCUMENTATION';
    }

    return 'PRODUCTION';
  }

  /**
   * Detects whether a snippet or secret sink contains obvious dummy placeholder values.
   */
  public static isPlaceholder(snippetOrSink?: string): boolean {
    if (!snippetOrSink) return false;
    const lower = snippetOrSink.toLowerCase();
    for (const ph of PLACEHOLDER_LIST) {
      if (lower.includes(ph)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks whether a finding in test/mock scope is located inside an assertion,
   * mock expectation, or test definition (e.g. expect(...), it('...fake secrets...')).
   */
  public static isTestAssertionContext(filePath: string, startLine?: number): boolean {
    if (!filePath || !fs.existsSync(filePath)) return false;
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split(/\r?\n/);
      const targetIdx = (startLine ?? 1) - 1;

      // Look at lines within a 4-line window around target line
      const minLine = Math.max(0, targetIdx - 3);
      const maxLine = Math.min(lines.length - 1, targetIdx + 3);
      const windowText = lines
        .slice(minLine, maxLine + 1)
        .join('\n')
        .toLowerCase();

      // Check for placeholder patterns in the raw disk source line
      const targetLineText = (lines[targetIdx] ?? '').toLowerCase();
      if (Gate1Scope.isPlaceholder(targetLineText)) {
        return true;
      }

      // Check for assertion / mock testing contexts
      const testContextPatterns = [
        'expect(',
        'assert(',
        'assert.',
        'should.',
        'it(',
        'test(',
        'describe(',
        'mock(',
        'mockresolvedvalue',
        'tobe(',
        'toequal(',
        'tocontain(',
        'tothrow(',
        'secretredactor',
        'redacttext',
        'fake secret',
        'secret_in_patch',
        'policyengine',
        '[redacted]',
      ];

      return testContextPatterns.some((pattern) => windowText.includes(pattern));
    } catch {
      return false;
    }
  }

  /**
   * Checks whether a ruleId or category corresponds to a provider-specific secret.
   */
  public static isProviderSpecificSecret(finding: NormalizedFinding): boolean {
    if (finding.category !== 'SECRET') return false;
    const textToCheck = `${finding.ruleId} ${finding.title}`;
    return PROVIDER_SPECIFIC_RULE_REGEX.test(textToCheck);
  }

  /**
   * Evaluates a finding against Gate 1 Scope & Policy.
   */
  public static evaluate(
    finding: NormalizedFinding,
    options: Gate1Options = {},
    profile?: ProjectProfile
  ): Gate1EvaluationResult {
    const scopeTag = Gate1Scope.classifyPath(
      finding.location.filePath,
      profile,
      options.customTestDirs
    );

    // If production, no Gate 1 suppression applies
    if (scopeTag === 'PRODUCTION') {
      return { scopeTag: 'PRODUCTION', shouldSuppress: false };
    }

    // If user passed --include-nonproduction, do not suppress
    if (options.includeNonProduction) {
      return { scopeTag, shouldSuppress: false };
    }

    const keepProviderSecrets = options.keepProviderSecrets ?? true;

    // Gate 1 Secret Policy:
    // Provider-specific secrets without placeholder values or test assertion context stay reported at confidence: MEDIUM
    if (keepProviderSecrets && Gate1Scope.isProviderSpecificSecret(finding)) {
      const isDummySnippet = Gate1Scope.isPlaceholder(finding.location.redactedSnippet);
      const isTestContext =
        scopeTag === 'TEST_OR_MOCK' &&
        Gate1Scope.isTestAssertionContext(finding.location.filePath, finding.location.startLine);

      if (!isDummySnippet && !isTestContext) {
        finding.confidence = 'MEDIUM';
        return {
          scopeTag,
          shouldSuppress: false, // Keep reported!
        };
      }
    }

    // Determine suppression reason code based on scope tag
    let reasonCode: SuppressionReasonCode = 'GATE1_TEST_OR_MOCK';
    let detail = `Finding located in test or mock code (${finding.location.filePath})`;

    if (scopeTag === 'EXAMPLE') {
      reasonCode = 'GATE1_EXAMPLE';
      detail = `Finding located in example or sample directory (${finding.location.filePath})`;
    } else if (scopeTag === 'DOCUMENTATION') {
      reasonCode = 'GATE1_DOCUMENTATION';
      detail = `Finding located in documentation directory (${finding.location.filePath})`;
    }

    return {
      scopeTag,
      shouldSuppress: true,
      suppressionReason: reasonCode,
      suppressionDetail: detail,
    };
  }
}
