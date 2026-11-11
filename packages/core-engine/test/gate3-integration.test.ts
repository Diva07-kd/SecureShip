import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, statSync } from 'node:fs';
import type {
  NormalizedFinding,
  IScannerAdapter,
  ScanExecutionResult,
} from '@secureship/contracts';
import { ConsentManager, type ILlmProvider } from '@secureship/ai';
import { ScanOrchestrator } from '../src/orchestrator/scan-orchestrator.js';
import { SuppressionLedger } from '../src/suppression/ledger.js';

function makeMockFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  const id = overrides.id ?? `finding-${Math.random().toString(36).slice(2, 8)}`;
  const fp = (overrides.fingerprint ?? id.padEnd(64, '0')).slice(0, 64);
  return {
    id,
    fingerprint: fp,
    ruleId: overrides.ruleId ?? 'rules.sqli.injection',
    scannerName: 'opengrep',
    category: overrides.category ?? 'SAST',
    severity: overrides.severity ?? 'MEDIUM',
    confidence: overrides.confidence ?? 'HIGH',
    reachability: overrides.reachability ?? 'UNKNOWN',
    location: overrides.location ?? {
      filePath: 'index.ts',
      startLine: 1,
      endLine: 2,
    },
    scopeTag: overrides.scopeTag ?? 'PRODUCTION',
    upstreamValidationStatus: overrides.upstreamValidationStatus ?? 'UNKNOWN',
    verificationStatus: overrides.verificationStatus ?? 'UNVERIFIED',
    cweIds: overrides.cweIds ?? [],
    title: overrides.title ?? 'Potential SQL injection',
    description: overrides.description ?? 'Potential SQL injection in database call',
    evidence: [
      {
        scannerName: 'opengrep',
        scannerRuleId: overrides.ruleId ?? 'rules.sqli.injection',
        message: 'Mock evidence message',
      },
    ],
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

describe('ScanOrchestrator Gate 3 Integration', () => {
  let tempWorkspace: string;
  let tempConsentPath: string;
  let tempConfigPath: string;

  beforeEach(() => {
    tempWorkspace = mkdtempSync(path.join(tmpdir(), 'gate3-test-'));
    tempConsentPath = path.join(tempWorkspace, 'consent.json');
    tempConfigPath = path.join(tempWorkspace, 'config.json');
    writeFileSync(
      path.join(tempWorkspace, 'package.json'),
      JSON.stringify({ name: 'test-app' }),
      'utf-8'
    );
    writeFileSync(
      path.join(tempWorkspace, 'index.ts'),
      'export const dbQuery = (q: string) => q;\n',
      'utf-8'
    );
  });

  afterEach(() => {
    try {
      rmSync(tempWorkspace, { recursive: true, force: true });
    } catch {}
  });

  function createAdapter(findings: NormalizedFinding[]): IScannerAdapter {
    return {
      name: 'opengrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => true,
      supportsProject: () => true,
      scan: async (): Promise<ScanExecutionResult> => ({
        scannerName: 'opengrep',
        status: 'SUCCESS',
        findings,
        durationMs: 10,
        exitCode: 0,
        timedOut: false,
      }),
    };
  }

  it('in dry-run mode: attaches dry-run triage without network transmission and respects skips', async () => {
    const findings = [
      makeMockFinding({
        id: 'sast-fp-medium',
        ruleId: 'rules.test.sql',
        severity: 'MEDIUM',
        category: 'SAST',
        fingerprint: 'fp-1'.padEnd(64, '0'),
        location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
      }),
      makeMockFinding({
        id: 'sast-cred',
        ruleId: 'secureship-js-hardcoded-jwt-secret',
        cweIds: ['CWE-798'],
        severity: 'HIGH',
        category: 'SAST',
        fingerprint: 'fp-cred'.padEnd(64, '0'),
        location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
      }),
      makeMockFinding({
        id: 'secret-key',
        ruleId: 'rules.secret.aws',
        severity: 'CRITICAL',
        category: 'SECRET',
        fingerprint: 'fp-secret'.padEnd(64, '0'),
        location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
      }),
      makeMockFinding({
        id: 'sast-high',
        ruleId: 'rules.rce',
        severity: 'HIGH',
        category: 'SAST',
        fingerprint: 'fp-high'.padEnd(64, '0'),
        location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
      }),
    ];

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter(findings)],
      ai: true,
      aiDryRun: true,
      gate3Mode: 'annotate',
    });

    expect(report.schemaVersion).toBe('1.3');
    expect(report.ai).toBeDefined();

    // Credential-class and SECRET findings skipped
    const credFinding = report.findings.find((f) => f.id === 'sast-cred');
    expect(credFinding?.aiTriage).toBeUndefined();

    const secretFinding = report.findings.find((f) => f.id === 'secret-key');
    expect(secretFinding?.aiTriage).toBeUndefined();

    // Standard SAST finding has dry-run triage attached
    const sastFinding = report.findings.find((f) => f.id === 'sast-fp-medium');
    expect(sastFinding?.aiTriage).toBeDefined();
    expect(sastFinding?.aiTriage?.verdict).toBe('NEEDS_HUMAN_REVIEW');
    expect(sastFinding?.aiTriage?.rationale).toContain('Dry-run inspection');

    // Invariant P1 accounting check
    const summary = report.summary;
    expect(summary.totalRaw).toBe(
      summary.totalReported + summary.totalSuppressed + summary.totalOutOfScope
    );
  });

  it('in suppress mode: never suppresses HIGH severity findings by default', async () => {
    ConsentManager.recordConsent(
      'http://127.0.0.1:8080/v1',
      'test-model',
      'openai',
      tempConsentPath
    );
    const fakePositiveProvider = {
      name: 'fake',
      sendTriageRequest: async () => ({
        rawText: JSON.stringify({
          verdict: 'LIKELY_FALSE_POSITIVE',
          confidence: 'HIGH',
          rationale: 'Safe function call with hardcoded data',
          citations: [
            { file: 'index.ts', line: 1, quote: 'export const dbQuery = (q: string) => q;' },
          ],
        }),
        tokensIn: 50,
        tokensOut: 50,
        deterministic: true,
      }),
    };

    const highFinding = makeMockFinding({
      id: 'high-fp',
      severity: 'HIGH',
      category: 'SAST',
      fingerprint: 'fp-h'.padEnd(64, '0'),
      location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
    });

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter([highFinding])],
      ai: true,
      aiDryRun: false,
      aiProvider: 'openai',
      aiBaseUrl: 'http://127.0.0.1:8080/v1',
      aiModel: 'test-model',
      aiConsentPath: tempConsentPath,
      aiConfigPath: tempConfigPath,
      noAiCache: true,
      customLlmProvider: fakePositiveProvider as unknown as ILlmProvider,
      gate3Mode: 'suppress',
    });

    // HIGH severity finding should NOT be suppressed
    expect(report.findings.some((f) => f.id === 'high-fp')).toBe(true);
    expect(report.suppressed.some((s) => s.finding.id === 'high-fp')).toBe(false);
  });

  it('preserves Invariant P1 across Gate 3 suppressions and accounting', () => {
    const ledger = new SuppressionLedger();
    ledger.recordRaw(5);

    const f1 = makeMockFinding({ id: 'f1', category: 'SAST' });
    const f2 = makeMockFinding({ id: 'f2', category: 'SAST' });
    const f3 = makeMockFinding({ id: 'f3', category: 'SAST' });

    ledger.addReported(f1);
    ledger.suppress(
      f2,
      'GATE3_LIKELY_FALSE_POSITIVE',
      'AI concluded benign dead test utility',
      'Gate 3 AI Triage'
    );
    ledger.suppress(f3, 'GATE2_UNREACHABLE', 'Package not imported', 'Gate 2 Reachability');
    ledger.recordOutOfScope(2);

    expect(ledger.getReportedFindings().length).toBe(1);
    expect(ledger.getSuppressedFindings().length).toBe(2);

    const summary = ledger.computeSummary();

    expect(summary.totalRaw).toBe(
      summary.totalReported + summary.totalSuppressed + summary.totalOutOfScope
    );
    expect(summary.suppressedByReason.GATE3_LIKELY_FALSE_POSITIVE).toBe(1);
    expect(summary.suppressedByReason.GATE2_UNREACHABLE).toBe(1);
  });

  it('in suppress mode: never suppresses IAC findings', async () => {
    ConsentManager.recordConsent(
      'http://127.0.0.1:8080/v1',
      'test-model',
      'openai',
      tempConsentPath
    );
    const fakePositiveProvider = {
      name: 'fake',
      sendTriageRequest: async () => ({
        rawText: JSON.stringify({
          verdict: 'LIKELY_FALSE_POSITIVE',
          confidence: 'HIGH',
          rationale: 'Safe function call with hardcoded data',
          citations: [
            { file: 'index.ts', line: 1, quote: 'export const dbQuery = (q: string) => q;' },
          ],
        }),
        tokensIn: 50,
        tokensOut: 50,
        deterministic: true,
      }),
    };

    const iacFinding = makeMockFinding({
      id: 'iac-tf-1',
      severity: 'MEDIUM',
      category: 'IAC',
      fingerprint: 'fp-iac'.padEnd(64, '0'),
      location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
    });

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter([iacFinding])],
      ai: true,
      aiDryRun: false,
      aiProvider: 'openai',
      aiBaseUrl: 'http://127.0.0.1:8080/v1',
      aiModel: 'test-model',
      aiConsentPath: tempConsentPath,
      aiConfigPath: tempConfigPath,
      noAiCache: true,
      customLlmProvider: fakePositiveProvider as unknown as ILlmProvider,
      gate3Mode: 'suppress',
    });

    // IAC findings are advisory and must not be suppressed
    expect(report.findings.some((f) => f.id === 'iac-tf-1')).toBe(true);
    expect(report.suppressed.some((s) => s.finding.id === 'iac-tf-1')).toBe(false);
  });

  it('does not run Gate 3 on already-suppressed findings', async () => {
    const finding = makeMockFinding({
      id: 'gate2-suppressed-finding',
      severity: 'MEDIUM',
      category: 'SAST',
      reachability: 'UNREACHABLE',
      fingerprint: 'fp-unreachable'.padEnd(64, '0'),
      location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
    });

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter([finding])],
      ai: true,
      aiDryRun: true,
      gate3Mode: 'annotate',
    });

    // Already suppressed findings in Gate 2 should not undergo Gate 3 triage
    const suppressedItem = report.suppressed.find(
      (s) => s.finding.id === 'gate2-suppressed-finding'
    );
    if (suppressedItem) {
      expect(suppressedItem.finding.aiTriage).toBeUndefined();
    }
  });

  it('records Gate 3 suppressed findings in the suppression ledger', async () => {
    ConsentManager.recordConsent(
      'http://127.0.0.1:8080/v1',
      'test-model',
      'openai',
      tempConsentPath
    );
    const fakePositiveProvider = {
      name: 'fake',
      sendTriageRequest: async () => ({
        rawText: JSON.stringify({
          verdict: 'LIKELY_FALSE_POSITIVE',
          confidence: 'HIGH',
          rationale: 'Safe function call with hardcoded data',
          citations: [
            { file: 'index.ts', line: 1, quote: 'export const dbQuery = (q: string) => q;' },
          ],
        }),
        tokensIn: 50,
        tokensOut: 50,
        deterministic: true,
      }),
    };

    const finding = makeMockFinding({
      id: 'sast-to-suppress',
      severity: 'LOW',
      category: 'SAST',
      fingerprint: 'fp-suppress'.padEnd(64, '0'),
      location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
    });

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter([finding])],
      ai: true,
      aiDryRun: false,
      aiProvider: 'openai',
      aiBaseUrl: 'http://127.0.0.1:8080/v1',
      aiModel: 'test-model',
      aiConsentPath: tempConsentPath,
      aiConfigPath: tempConfigPath,
      noAiCache: true,
      customLlmProvider: fakePositiveProvider as unknown as ILlmProvider,
      gate3Mode: 'suppress',
    });

    expect(report.suppressed.length).toBe(1);
    expect(report.suppressed[0]?.reasonCode).toBe('GATE3_LIKELY_FALSE_POSITIVE');
    expect(report.summary.totalSuppressed).toBe(1);
  });

  it('enforces consent check on non-dry-run scans', async () => {
    const finding = makeMockFinding({ id: 'sast-unconsented' });
    await expect(
      ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [createAdapter([finding])],
        ai: true,
        aiDryRun: false,
        aiProvider: 'openai',
        aiBaseUrl: 'http://127.0.0.1:54321/v1',
        aiModel: 'test-model',
        aiConsentPath: tempConsentPath,
        aiConfigPath: tempConfigPath,
      })
    ).rejects.toThrow(/consent/i);
  });

  it('provider failure falls back gracefully without failing the scan', async () => {
    const finding = makeMockFinding({ id: 'sast-provider-fail' });
    ConsentManager.recordConsent(
      'http://127.0.0.1:8080/v1',
      'test-model',
      'openai',
      tempConsentPath
    );

    const failingProvider = {
      name: 'failing',
      sendTriageRequest: async () => {
        throw new Error('ECONNREFUSED connection refused to provider');
      },
    };

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter([finding])],
      ai: true,
      aiDryRun: false,
      aiProvider: 'openai',
      aiBaseUrl: 'http://127.0.0.1:8080/v1',
      aiModel: 'test-model',
      aiConsentPath: tempConsentPath,
      aiConfigPath: tempConfigPath,
      customLlmProvider: failingProvider as unknown as ILlmProvider,
    });

    expect(report.findings.length).toBe(1);
    expect(report.ai?.warnings.length).toBeGreaterThan(0);
  });

  it('skips already-suppressed findings and never sends them to Gate 3', async () => {
    const testFinding = makeMockFinding({
      id: 'sast-in-test',
      location: { filePath: 'test/sample.test.ts', startLine: 1, endLine: 1 },
      severity: 'MEDIUM',
    });
    ConsentManager.recordConsent(
      'http://127.0.0.1:8080/v1',
      'test-model',
      'openai',
      tempConsentPath
    );

    let providerCalls = 0;
    const trackingProvider = {
      name: 'tracking',
      sendTriageRequest: async () => {
        providerCalls++;
        return {
          rawResponse: JSON.stringify({
            verdict: 'LIKELY_FALSE_POSITIVE',
            confidence: 'HIGH',
            rationale: 'Mock',
            citations: [],
          }),
          tokensIn: 10,
          tokensOut: 10,
          deterministic: true,
        };
      },
    };

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter([testFinding])],
      ai: true,
      aiDryRun: false,
      aiProvider: 'openai',
      aiBaseUrl: 'http://127.0.0.1:8080/v1',
      aiModel: 'test-model',
      aiConsentPath: tempConsentPath,
      aiConfigPath: tempConfigPath,
      customLlmProvider: trackingProvider as unknown as ILlmProvider,
    });

    expect(report.suppressed.length).toBe(1);
    expect(report.suppressed[0]?.reasonCode).toBe('GATE1_TEST_OR_MOCK');
    expect(report.ai?.findingsConsidered).toBe(0);
    expect(report.ai?.findingsSent).toBe(0);
    expect(providerCalls).toBe(0);
  });

  it('supports --ai-estimate mode without network calls', async () => {
    const finding = makeMockFinding({ id: 'sast-estimate' });
    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter([finding])],
      ai: true,
      aiEstimate: true,
    });
    expect(report.ai).toBeDefined();
    expect(report.findings[0]?.aiTriage).toBeDefined();
    expect(report.findings[0]?.aiTriage?.rationale).toContain('Dry-run inspection');
  });

  it('throws CONFIG_ERROR if model name is missing and not dry-run/estimate', async () => {
    const finding = makeMockFinding({ id: 'sast-nomodel' });
    await expect(
      ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [createAdapter([finding])],
        ai: true,
        aiDryRun: false,
        aiEstimate: false,
        aiModel: '',
      })
    ).rejects.toThrow(/Model name is required/i);
  });

  it('skips findings when maxFindings or token budget is exceeded', async () => {
    const findings = [
      makeMockFinding({ id: 'f1', fingerprint: 'fp1'.padEnd(64, '0') }),
      makeMockFinding({ id: 'f2', fingerprint: 'fp2'.padEnd(64, '0') }),
    ];
    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter(findings)],
      ai: true,
      aiDryRun: true,
      aiMaxFindings: 1,
    });
    expect(report.ai?.findingsSkipped.some((s) => s.reason === 'BUDGET_EXCEEDED')).toBe(true);
  });

  it('instantiates FakeLlmProvider when provider is fake and baseUrl is loopback', async () => {
    const finding = makeMockFinding({ id: 'sast-fake-provider' });
    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [createAdapter([finding])],
      ai: true,
      aiDryRun: false,
      aiProvider: 'fake',
      aiModel: 'fake-model',
      aiBaseUrl: 'http://127.0.0.1:8080/v1',
      noAiCache: true,
    });
    expect(report.ai).toBeDefined();
  });

  it('egress-accounting: report filesSent/bytes/tokens equal what recording local server actually received (R13)', async () => {
    let recordedBytes = 0;
    let recordedTokensIn = 0;
    const recordedFiles = new Set<string>();

    const recordingServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => {
        body += chunk;
      });
      req.on('end', () => {
        recordedBytes += Buffer.byteLength(body, 'utf-8');
        try {
          const parsed = JSON.parse(body);
          const messages = parsed.messages || [];
          for (const m of messages) {
            if (m.content) {
              const fileMatches = m.content.match(/(?:File|Location):\s*([a-zA-Z0-9_\-./]+)/gi);
              if (fileMatches) {
                for (const match of fileMatches) {
                  const f = match.replace(/^(?:File|Location):\s*/i, '').trim();
                  recordedFiles.add(f);
                }
              }
            }
          }
        } catch {}

        recordedTokensIn += Math.ceil(body.length / 4);

        const reply = {
          id: 'chatcmpl-test',
          choices: [
            {
              message: {
                content: JSON.stringify({
                  verdict: 'NEEDS_HUMAN_REVIEW',
                  confidence: 'HIGH',
                  rationale: 'Reviewing query for SQL injection parameters.',
                  citations: [{ file: 'index.ts', line: 1, quote: 'export const dbQuery' }],
                }),
              },
            },
          ],
          usage: { prompt_tokens: 150, completion_tokens: 30 },
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(reply));
      });
    });

    await new Promise<void>((resolve) => recordingServer.listen(0, '127.0.0.1', () => resolve()));
    const port = (recordingServer.address() as { port: number }).port;
    const serverUrl = `http://127.0.0.1:${port}/v1`;

    try {
      ConsentManager.recordConsent(serverUrl, 'test-model', 'openai', tempConsentPath);

      const finding = makeMockFinding({
        id: 'sast-egress-test',
        location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
      });

      const report = await ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [createAdapter([finding])],
        ai: true,
        aiDryRun: false,
        aiProvider: 'openai',
        aiBaseUrl: serverUrl,
        aiModel: 'test-model',
        aiConsentPath: tempConsentPath,
        aiConfigPath: tempConfigPath,
        noAiCache: true,
      });

      expect(report.ai).toBeDefined();
      expect(report.ai!.filesSent).toContain('index.ts');
      expect(report.ai!.filesSent.length).toBeGreaterThan(0);
      expect(report.ai!.tokensIn).toBe(150);
      expect(report.ai!.tokensOut).toBe(30);
      expect(recordedBytes).toBeGreaterThan(0);
      expect(recordedTokensIn).toBeGreaterThan(0);
    } finally {
      await new Promise<void>((resolve) => recordingServer.close(() => resolve()));
    }
  });

  it('forbids --ai-trace destination path inside the scan target repository', async () => {
    const insideTrace = path.join(tempWorkspace, 'ai-trace.json');
    const finding = makeMockFinding({
      id: 'trace-test-1',
      location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
    });

    await expect(
      ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [createAdapter([finding])],
        ai: true,
        aiDryRun: true,
        aiModel: 'test-model',
        aiTrace: insideTrace,
      })
    ).rejects.toThrow(/cannot be inside the scan target directory/);
  });

  it('writes redacted trace to explicit path outside targetDir with restricted permissions', async () => {
    const outsideDir = mkdtempSync(path.join(tmpdir(), 'secureship-trace-test-'));
    const outsideTrace = path.join(outsideDir, 'ai-trace.json');

    try {
      const finding = makeMockFinding({
        id: 'trace-test-2',
        location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
      });

      await ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [createAdapter([finding])],
        ai: true,
        aiDryRun: true,
        aiModel: 'test-model',
        aiTrace: outsideTrace,
      });

      expect(existsSync(outsideTrace)).toBe(true);
      const content = JSON.parse(readFileSync(outsideTrace, 'utf-8'));
      expect(content.targetDir).toBe(path.resolve(tempWorkspace));
      expect(content.findingsTraced).toBe(1);
      expect(content.traces[0].findingId).toBe('trace-test-2');
      expect(content.traces[0].request.systemPrompt).toBeDefined();

      if (process.platform !== 'win32') {
        const stats = statSync(outsideTrace);
        expect(stats.mode & 0o777).toBe(0o600);
      }
    } finally {
      rmSync(outsideDir, { recursive: true, force: true });
    }
  });
});
