import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { SarifParser } from '../src/sarif/sarif-parser.js';

describe('SarifParser Unit & Hostile Input Suite', () => {
  const targetDir = 'C:/dev/SecureShip-IDE';

  it('parses valid multi-run SARIF log and resolves rules and locations', () => {
    const sarif = JSON.stringify({
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'opengrep',
              rules: [
                {
                  id: 'rule-eval',
                  name: 'EvalInjection',
                  shortDescription: { text: 'Eval with dynamic input' },
                  fullDescription: { text: 'Dynamic eval injection vulnerability' },
                  properties: {
                    'security-severity': '9.5',
                    tags: ['external/cwe/cwe-95'],
                    precision: 'high',
                  },
                },
              ],
            },
          },
          results: [
            {
              ruleId: 'rule-eval',
              level: 'error',
              message: { text: 'Unsafe eval detected' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'src/api/handler.ts' },
                    region: {
                      startLine: 42,
                      endLine: 42,
                      snippet: { text: 'eval(userInput)' },
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const res = SarifParser.parseJson(sarif, {
      scannerName: 'opengrep',
      category: 'SAST',
      targetDir,
    });

    expect(res.rawFindingCount).toBe(1);
    expect(res.findings).toHaveLength(1);

    const f = res.findings[0]!;
    expect(f.ruleId).toBe('rule-eval');
    expect(f.severity).toBe('CRITICAL'); // CVSS 9.5 -> CRITICAL
    expect(f.confidence).toBe('HIGH');
    expect(f.location.filePath).toBe('src/api/handler.ts');
    expect(f.location.startLine).toBe(42);
    expect(f.cweIds).toContain('CWE-95');
    expect(f.evidence).toHaveLength(1);
    expect(f.fingerprint).toHaveLength(64);
  });

  it('maps severity correctly from CVSS score and fallback SARIF level', () => {
    expect(SarifParser.mapSeverity(9.8, 'warning')).toBe('CRITICAL');
    expect(SarifParser.mapSeverity(7.5, 'error')).toBe('HIGH');
    expect(SarifParser.mapSeverity(5.0, 'error')).toBe('MEDIUM');
    expect(SarifParser.mapSeverity(2.5, 'none')).toBe('LOW');
    expect(SarifParser.mapSeverity(0.0, 'note')).toBe('INFO');

    // Without security-severity, fallback to level
    expect(SarifParser.mapSeverity(undefined, 'error')).toBe('HIGH');
    expect(SarifParser.mapSeverity(null, 'warning')).toBe('MEDIUM');
    expect(SarifParser.mapSeverity(undefined, 'note')).toBe('LOW');
    expect(SarifParser.mapSeverity(undefined, 'none')).toBe('INFO');
    expect(SarifParser.mapSeverity(undefined, 'unknown')).toBe('MEDIUM');
  });

  it('handles results without regions and missing rule metadata cleanly', () => {
    const sarif = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'checkov',
              rules: [], // Empty rules array
            },
          },
          results: [
            {
              ruleId: 'CKV_DOCKER_1',
              level: 'warning',
              message: { text: 'Ensure base image has tag' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'Dockerfile' },
                    // No region specified!
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const res = SarifParser.parseJson(sarif, {
      scannerName: 'checkov',
      category: 'IAC',
      targetDir,
    });

    expect(res.findings).toHaveLength(1);
    const f = res.findings[0]!;
    expect(f.location.startLine).toBe(1); // Defaulted to line 1
    expect(f.location.endLine).toBe(1);
    expect(f.severity).toBe('MEDIUM');
  });

  it('resolves URL-encoded and file:// URIs, and drops paths escaping target boundary', () => {
    // 1. Valid file:// URI
    const p1 = SarifParser.resolveArtifactPath(
      'file:///C:/dev/SecureShip-IDE/src/auth.ts',
      targetDir
    );
    expect(p1).toBe('src/auth.ts');

    // 2. URL-encoded path with spaces
    const p2 = SarifParser.resolveArtifactPath('src/my%20folder/file%201.ts', targetDir);
    expect(p2).toBe('src/my folder/file 1.ts');

    // 3. Path escaping targetDir boundary (traversal attack)
    const p3 = SarifParser.resolveArtifactPath('../../Windows/System32/cmd.exe', targetDir);
    expect(p3).toBeNull(); // Dropped!
  });

  it('drops out-of-boundary findings and logs a clear warning', () => {
    const sarif = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'gitleaks' } },
          results: [
            {
              ruleId: 'secret-leak',
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: '../../etc/passwd' },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const res = SarifParser.parseJson(sarif, {
      scannerName: 'gitleaks',
      category: 'SECRET',
      targetDir,
    });

    expect(res.findings).toHaveLength(0);
    expect(res.warnings).toHaveLength(1);
    expect(res.warnings[0]).toContain('escapes the scan target boundary');
  });

  it('extracts CWE IDs from tags and properties in multiple formats', () => {
    const rule1 = {
      id: 'r1',
      properties: {
        tags: ['security', 'external/cwe/cwe-89', 'cwe-78'],
        cwe: ['CWE-798', '502'],
      },
    };
    const cweIds = SarifParser.extractCweIds(rule1);
    expect(cweIds).toContain('CWE-89');
    expect(cweIds).toContain('CWE-78');
    expect(cweIds).toContain('CWE-798');
    expect(cweIds).toContain('CWE-502');
  });

  it('truncates snippets over 500 characters and redacts secrets', () => {
    const longSecretSnippet = `const token = "AKIA1234567890ABCDEF"; ${'a'.repeat(600)}`;
    const sarif = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'gitleaks' } },
          results: [
            {
              ruleId: 'aws-key',
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'src/config.ts' },
                    region: { startLine: 1, snippet: { text: longSecretSnippet } },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const res = SarifParser.parseJson(sarif, {
      scannerName: 'gitleaks',
      category: 'SECRET',
      targetDir,
    });

    expect(res.findings).toHaveLength(1);
    const snippet = res.findings[0]!.location.redactedSnippet!;
    expect(snippet.length).toBeLessThanOrEqual(500);
    expect(snippet).toMatch(/\[REDACTED/);
    expect(snippet).not.toContain('AKIA1234567890ABCDEF');
  });

  it('normalizes Opengrep rule IDs by stripping config path prefix and uses rule message for title (R2)', () => {
    const sarif = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Opengrep OSS',
              rules: [
                {
                  id: 'rules.secureship-sast.secureship-js-eval',
                  name: 'rules.secureship-sast.secureship-js-eval',
                  shortDescription: {
                    text: 'Opengrep Finding: rules.secureship-sast.secureship-js-eval',
                  },
                  fullDescription: {
                    text: 'Dynamic code execution via eval() or Function constructor with non-literal input can lead to Arbitrary Code Execution.',
                  },
                  properties: {
                    precision: 'very-high',
                    tags: ['CWE-95', 'security'],
                  },
                },
              ],
            },
          },
          results: [
            {
              ruleId: 'rules.secureship-sast.secureship-js-eval',
              message: {
                text: 'Dynamic code execution via eval() or Function constructor with non-literal input can lead to Arbitrary Code Execution.',
              },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'src/eval.js' },
                    region: { startLine: 3, endLine: 3, snippet: { text: 'eval(userInput)' } },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const res = SarifParser.parseJson(sarif, {
      scannerName: 'opengrep',
      category: 'SAST',
      targetDir,
    });

    expect(res.findings).toHaveLength(1);
    const finding = res.findings[0]!;
    expect(finding.ruleId).toBe('secureship-js-eval');
    expect(finding.evidence[0]!.scannerRuleId).toBe('rules.secureship-sast.secureship-js-eval');
    expect(finding.title).toBe(
      'Dynamic code execution via eval() or Function constructor with non-literal input can lead to Arbitrary Code Execution.'
    );
    expect(finding.title).not.toContain('Opengrep Finding:');
  });

  it('maps Trivy result classes: vulnerabilities to SCA and misconfigurations to IAC (R3)', () => {
    const sarif = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Trivy',
              rules: [
                {
                  id: 'DS-0001',
                  name: 'Misconfiguration',
                  shortDescription: { text: "':latest' tag used" },
                  properties: { tags: ['misconfiguration'] },
                },
                {
                  id: 'CVE-2023-1234',
                  name: 'Vulnerability',
                  shortDescription: { text: 'Package vulnerability' },
                  properties: { tags: ['vulnerability'] },
                },
              ],
            },
          },
          results: [
            {
              ruleId: 'DS-0001',
              message: { text: 'Dockerfile check failed' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'Dockerfile' },
                    region: { startLine: 1, endLine: 1 },
                  },
                },
              ],
            },
            {
              ruleId: 'CVE-2023-1234',
              message: { text: 'Vulnerable dependency' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'package-lock.json' },
                    region: { startLine: 10, endLine: 10 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const res = SarifParser.parseJson(sarif, {
      scannerName: 'trivy',
      category: 'SCA',
      targetDir,
    });

    expect(res.findings).toHaveLength(2);
    expect(res.findings[0]!.category).toBe('IAC');
    expect(res.findings[1]!.category).toBe('SCA');
  });

  it('defaults Checkov findings to MEDIUM unless security-severity is present (R4)', () => {
    const sarif = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Checkov',
              rules: [
                {
                  id: 'CKV_AWS_23',
                  name: 'Ensure every security group and rule has a description',
                  defaultConfiguration: { level: 'error' },
                },
                {
                  id: 'CKV_AWS_CRIT',
                  name: 'Critical CVSS check',
                  properties: { 'security-severity': '9.5' },
                },
              ],
            },
          },
          results: [
            {
              ruleId: 'CKV_AWS_23',
              level: 'error',
              message: { text: 'Ensure every security group and rule has a description' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'main.tf' },
                    region: { startLine: 1, endLine: 5 },
                  },
                },
              ],
            },
            {
              ruleId: 'CKV_AWS_CRIT',
              level: 'error',
              message: { text: 'Critical check failed' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'main.tf' },
                    region: { startLine: 10, endLine: 15 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });

    const res = SarifParser.parseJson(sarif, {
      scannerName: 'checkov',
      category: 'IAC',
      targetDir,
    });

    expect(res.findings).toHaveLength(2);
    expect(res.findings[0]!.severity).toBe('MEDIUM');
    expect(res.findings[1]!.severity).toBe('CRITICAL');
  });

  it('parses real trivy SARIF output and classifies all misconfigurations as IAC (R3)', () => {
    const fixturePath = path.resolve(__dirname, 'fixtures/real/trivy.sarif');
    const res = SarifParser.parseFile(fixturePath, {
      scannerName: 'trivy',
      category: 'SCA',
      targetDir: 'C:/Users/kdiva/AppData/Local/Temp/trivy-fixture',
    });

    expect(res.findings.length).toBeGreaterThan(0);
    for (const f of res.findings) {
      expect(f.category).toBe('IAC');
      expect(f.category).not.toBe('SCA');
    }
  });

  it('parses real checkov SARIF output and defaults severity to MEDIUM (R4)', () => {
    const fixturePath = path.resolve(__dirname, 'fixtures/real/checkov.sarif');
    const res = SarifParser.parseFile(fixturePath, {
      scannerName: 'checkov',
      category: 'IAC',
      targetDir: 'c:/dev/SecureShip-IDE',
    });

    expect(res.findings.length).toBeGreaterThan(0);
    for (const f of res.findings) {
      expect(f.severity).toBe('MEDIUM');
    }
  });
});
