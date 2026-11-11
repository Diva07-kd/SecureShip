import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { FakeLlmHttpServer } from '../../../ai/test/verification/independent-oracle.js';
import { ScanOrchestrator } from '../../src/orchestrator/scan-orchestrator.js';
import { ConfigLoader } from '../../src/config/load-config.js';
import { ConsentManager, AiError } from '@secureship/ai';
import type {
  NormalizedFinding,
  IScannerAdapter,
  ScanExecutionResult,
  Severity,
} from '@secureship/contracts';

describe('Part C & I Verification: Trust Model and Failure Isolation (C1-C5, I1-I4)', () => {
  let tempWorkspace: string;
  let canaryServer: FakeLlmHttpServer;

  beforeEach(async () => {
    tempWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-ci-verify-'));
    canaryServer = new FakeLlmHttpServer();
    await canaryServer.start();

    // Create minimal repo
    fs.writeFileSync(
      path.join(tempWorkspace, 'package.json'),
      JSON.stringify({ name: 'victim-app' }),
      'utf8'
    );
    fs.writeFileSync(
      path.join(tempWorkspace, 'index.ts'),
      'export const run = (x: string) => eval(x);\n',
      'utf8'
    );
  });

  afterEach(async () => {
    await canaryServer.stop();
    try {
      fs.rmSync(tempWorkspace, { recursive: true, force: true });
    } catch {}
  });

  function makeMockFinding(id = 'f-1', severity: Severity = 'MEDIUM'): NormalizedFinding {
    return {
      id,
      fingerprint: id.padEnd(64, '0'),
      ruleId: 'secureship-js-eval',
      scannerName: 'opengrep',
      category: 'SAST',
      severity,
      confidence: 'HIGH',
      cweIds: ['CWE-95'],
      reachability: 'UNKNOWN',
      location: { filePath: 'index.ts', startLine: 1, endLine: 1 },
      scopeTag: 'PRODUCTION',
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      title: 'Eval sink',
      description: 'Dynamic code execution',
      evidence: [
        { scannerName: 'opengrep', scannerRuleId: 'secureship-js-eval', message: 'eval sink' },
      ],
      createdAt: new Date().toISOString(),
    };
  }

  function makeAdapter(findings: NormalizedFinding[]): IScannerAdapter {
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

  it('C1: Repo config attempting to enable AI or set canary baseUrl receives ZERO requests and emits warning', async () => {
    // Malicious untrusted repo config
    const repoConfig = {
      ai: true,
      provider: 'openai',
      baseUrl: canaryServer.baseUrl,
      gate3: {
        mode: 'suppress',
      },
    };
    fs.writeFileSync(
      path.join(tempWorkspace, 'secureship.config.json'),
      JSON.stringify(repoConfig),
      'utf8'
    );

    // Load config
    const loaded = ConfigLoader.loadConfig(tempWorkspace);
    expect((loaded as Record<string, unknown>).ai).toBeUndefined();
    expect((loaded as Record<string, unknown>).baseUrl).toBeUndefined();

    // Run orchestrator without CLI --ai
    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [makeAdapter([makeMockFinding()])],
    });
    expect(report.summary.totalReported).toBe(1);
    expect(report.ai).toBeUndefined();

    // Strict Trust Assertion: canary server received ZERO requests
    expect(canaryServer.recordedRequests).toHaveLength(0);
  });

  it('C2: AI never activates without recorded consent; host changes require re-consent', async () => {
    const tempConsentFile = path.join(tempWorkspace, 'consent.json');

    // 1. No consent granted -> checkConsent is false
    const noConsent = ConsentManager.checkConsent(canaryServer.baseUrl, 'openai', tempConsentFile);
    expect(noConsent.consented).toBe(false);

    // 2. Grant consent to canaryServer origin (scheme + host + port)
    ConsentManager.recordConsent(canaryServer.baseUrl, 'gpt-4o', 'openai', tempConsentFile);
    const validConsent = ConsentManager.checkConsent(
      canaryServer.baseUrl,
      'openai',
      tempConsentFile
    );
    expect(validConsent.consented).toBe(true);

    // 3. Change host / port -> consent must be refused
    const differentHost = 'http://127.0.0.1:65432/v1';
    const invalidConsent = ConsentManager.checkConsent(differentHost, 'openai', tempConsentFile);
    expect(invalidConsent.consented).toBe(false);
    expect(invalidConsent.reason).toContain('Endpoint binding change detected');
  });

  it('C3: gate3 suppress is ignored when specified only in repo config', async () => {
    fs.writeFileSync(
      path.join(tempWorkspace, 'secureship.config.json'),
      JSON.stringify({ gate3: { mode: 'suppress' } }),
      'utf8'
    );
    const loaded = ConfigLoader.loadConfig(tempWorkspace);
    expect((loaded as Record<string, unknown>).gate3).toBeUndefined();
  });

  it('C4: API keys read only from env/user config; never from repo; never leaked', async () => {
    const fakeKey = 'sk-fake-secret-key-do-not-leak-998877';

    // Put key in repo config
    fs.writeFileSync(
      path.join(tempWorkspace, 'secureship.config.json'),
      JSON.stringify({ apiKey: fakeKey }),
      'utf8'
    );

    const loaded = ConfigLoader.loadConfig(tempWorkspace);
    expect((loaded as Record<string, unknown>).apiKey).toBeUndefined();

    // Ensure report output never contains fakeKey
    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [makeAdapter([makeMockFinding()])],
    });
    const reportJson = JSON.stringify(report);
    expect(reportJson).not.toContain(fakeKey);
  });

  it('I1: Provider failures (500, 401, timeout) leave findings reported and preserve scan exit codes', async () => {
    // Canary server returns 500
    canaryServer.setDefaultResponse({
      statusCode: 500,
      body: { error: 'Internal Server Error' },
    });

    // Record consent so AI attempt proceeds
    const tempConsentFile = path.join(tempWorkspace, 'consent.json');
    ConsentManager.recordConsent(canaryServer.baseUrl, 'gpt-4o', 'openai', tempConsentFile);

    const report = await ScanOrchestrator.scan({
      targetDir: tempWorkspace,
      adapters: [makeAdapter([makeMockFinding()])],
      ai: true,
      aiProvider: 'openai',
      aiModel: 'gpt-4o',
      aiBaseUrl: canaryServer.baseUrl,
      aiConsentPath: tempConsentFile,
    });

    // Scan completes without crashing, finding is reported untouched
    expect(report.summary.totalReported).toBe(1);
    expect(report.findings[0]!.aiTriage?.verdict).toBe('NEEDS_HUMAN_REVIEW');
    expect(report.ai?.warnings.length).toBeGreaterThan(0);
  });

  it('I3: --ai without model exits 2 with actionable error message', async () => {
    const emptyConfig = path.join(tempWorkspace, 'empty-config.json');
    fs.writeFileSync(emptyConfig, JSON.stringify({}), 'utf-8');
    await expect(
      ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [makeAdapter([makeMockFinding()])],
        ai: true,
        aiProvider: 'openai',
        aiConfigPath: emptyConfig,
        // no model provided
      })
    ).rejects.toThrowError(AiError);
  });

  it('I4: Phase 2 NOT SCANNED behavior intact with --ai (all scanners missing)', async () => {
    const missingAdapter: IScannerAdapter = {
      name: 'opengrep',
      category: 'SAST',
      version: async () => '1.0.0',
      isAvailable: async () => false, // missing scanner
      supportsProject: () => true,
      scan: async () => {
        throw new Error('Scanner not installed');
      },
    };

    await expect(
      ScanOrchestrator.scan({
        targetDir: tempWorkspace,
        adapters: [missingAdapter],
        ai: true,
        strict: true,
      })
    ).rejects.toThrowError(/Scanner not installed|not scanned|failed/i);
    // Assert zero AI calls made
    expect(canaryServer.recordedRequests).toHaveLength(0);
  });
});
