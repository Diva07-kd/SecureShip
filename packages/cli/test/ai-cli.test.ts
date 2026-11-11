import { describe, it, expect, afterEach } from 'vitest';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { SafeProcessRunner } from '@secureship/core-engine';

describe('CLI AI & Gate 3 E2E Suite', () => {
  const cliEntry = path.resolve('packages/cli/dist/index.js');
  const tmpDirs: string[] = [];

  function createFixture(files: Record<string, string>): string {
    const dir = mkdtempSync(path.join(tmpdir(), 'secureship-cli-ai-'));
    tmpDirs.push(dir);
    for (const [relPath, content] of Object.entries(files)) {
      const fullPath = path.join(dir, relPath);
      writeFileSync(fullPath, content, 'utf8');
    }
    return dir;
  }

  afterEach(() => {
    for (const d of tmpDirs) {
      try {
        rmSync(d, { recursive: true, force: true });
      } catch {
        // cleanup
      }
    }
    tmpDirs.length = 0;
  });

  it('status command displays Gate 3 local OpenAI-compatible endpoints included (A13)', async () => {
    const res = await SafeProcessRunner.run('node', [cliEntry, 'status'], { timeoutMs: 10_000 });
    expect(res.exitCode).toBe(0);
    const cleanOut = res.stdout.replace(/\u001b\[[0-9;]*m/g, '');
    expect(cleanOut).toContain('AI Triage & Skeptic (Gate 3)');
    expect(cleanOut).toContain('included for BYOK');
    expect(cleanOut).toContain('Ollama, LM Studio, vLLM');
    expect(cleanOut).toContain('Enterprise Support & Private Deployments: Enterprise tier');
  });

  it('doctor command displays Gate 3 AI Triage section', async () => {
    const res = await SafeProcessRunner.run('node', [cliEntry, 'doctor'], { timeoutMs: 15_000 });
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('Gate 3 AI Triage Configuration & Environment:');
    expect(res.stdout).toContain('AI Enablement:');
  });

  it('ai enable without --yes in non-interactive exits 2 (A3)', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'ai', 'enable', '--provider', 'openai', '--model', 'gpt-4o'],
      {
        timeoutMs: 5000,
      }
    );
    expect(res.exitCode).toBe(2);
    expect(res.stderr).toContain(
      'Non-interactive `ai enable` requires explicit --provider, --model, --base-url and --yes'
    );
  });

  it('ai enable with non-loopback http URL is rejected (A3)', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [
        cliEntry,
        'ai',
        'enable',
        '--provider',
        'openai',
        '--model',
        'gpt-4o',
        '--base-url',
        'http://api.openai.com/v1',
        '--yes',
      ],
      { timeoutMs: 5000 }
    );
    expect(res.exitCode).toBe(2);
    expect(res.stderr).toContain('HTTPS is strictly required for non-loopback hosts');
  });

  it('ai enable with loopback URL succeeds and binds consent (A3)', async () => {
    const res = await SafeProcessRunner.run(
      'node',
      [
        cliEntry,
        'ai',
        'enable',
        '--provider',
        'openai',
        '--model',
        'gpt-4o',
        '--base-url',
        'http://localhost:11434/v1',
        '--yes',
      ],
      { timeoutMs: 5000 }
    );
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('Gate 3 AI Triage successfully enabled!');
    expect(res.stdout).toContain('Bound to http://localhost:11434');

    const statusRes = await SafeProcessRunner.run('node', [cliEntry, 'ai', 'status'], {
      timeoutMs: 5000,
    });
    expect(statusRes.exitCode).toBe(0);
    const cleanStatus = statusRes.stdout.replace(/\u001b\[[0-9;]*m/g, '');
    expect(cleanStatus).toContain('AI Enabled     : Yes');
    expect(cleanStatus).toContain('Model          : gpt-4o');

    // Clean up
    await SafeProcessRunner.run('node', [cliEntry, 'ai', 'disable'], { timeoutMs: 5000 });
  });

  it('scan --ai without configured model exits 2 (A3, A9)', async () => {
    const dir = createFixture({ 'test.js': 'console.log("clean");' });
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'scan', dir, '--ai', '--ai-model', ''],
      {
        timeoutMs: 10_000,
      }
    );
    expect(res.exitCode).toBe(2);
    expect(res.stderr).toContain('Model name is required when --ai is enabled');
  });

  it('scan --ai --ai-dry-run runs without network or key requirement (A15)', async () => {
    const dir = createFixture({
      'index.js': 'const x = 1;\n',
      'package.json': JSON.stringify({ name: 'dry-app' }),
    });
    const res = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', dir, '--ai', '--ai-model', 'gpt-4o', '--ai-dry-run', '--json'],
      { timeoutMs: 45_000 }
    );
    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(res.stdout);
    expect(parsed.schemaVersion).toBe('1.3');
    expect(parsed.ai).toBeDefined();
    expect(parsed.ai.findingsConsidered).toBeGreaterThanOrEqual(0);
  }, 60_000);

  it('scan --gate3 suppress prints experimental banner (A9)', async () => {
    const dir = createFixture({
      'index.js': 'const x = 1;\n',
      'package.json': JSON.stringify({ name: 'app' }),
    });
    const res = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', dir, '--gate3', 'suppress'],
      { timeoutMs: 45_000 }
    );
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toContain('EXPERIMENTAL: Gate 3 AI suppression is active');
  }, 60_000);

  it('explain command rejects traversal outside root jail (A11)', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'secureship-cli-ai-'));
    tmpDirs.push(dir);
    const reportContent = {
      schemaVersion: '1.2',
      tool: { name: 'secureship', version: '0.1.0' },
      target: dir,
      mode: 'FULL',
      startedAt: new Date().toISOString(),
      durationMs: 50,
      scanners: [],
      findings: [
        {
          id: 'f-evil',
          fingerprint: 'e'.repeat(64),
          ruleId: 'test.rule',
          scannerName: 'opengrep',
          category: 'SAST',
          severity: 'HIGH',
          confidence: 'HIGH',
          reachability: 'UNKNOWN',
          location: {
            filePath: '../../etc/passwd',
            startLine: 1,
            endLine: 1,
          },
          scopeTag: 'PRODUCTION',
          upstreamValidationStatus: 'UNKNOWN',
          verificationStatus: 'UNVERIFIED',
          cweIds: [],
          title: 'Path Traversal Injection',
          description: 'Test',
          evidence: [
            {
              scannerName: 'opengrep',
              scannerRuleId: 'test.rule',
              message: 'Test finding',
            },
          ],
          createdAt: new Date().toISOString(),
        },
      ],
      suppressed: [],
      summary: {
        totalRaw: 1,
        totalReported: 1,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 1, SCA: 0, SECRET: 0, IAC: 0 },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 0,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
          GATE2_UNREACHABLE: 0,
          GATE3_LIKELY_FALSE_POSITIVE: 0,
        },
      },
    };
    writeFileSync(path.join(dir, 'report.json'), JSON.stringify(reportContent), 'utf-8');

    const reportPath = path.join(dir, 'report.json');
    const res = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'explain', reportPath, '--finding', 'f-evil', '--root', dir],
      { timeoutMs: 5000 }
    );
    expect(res.exitCode).toBe(2);
    expect(res.stderr).toContain('Security Error: Finding path traverses outside jail root');
  });

  it('explain command supports spec syntax: explain <fingerprint|index> --report <file> --root <dir>', async () => {
    const dir = createFixture({
      'index.js': 'eval("bad");\n',
      'package.json': JSON.stringify({ name: 'app' }),
    });

    const testFp = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const reportContent = {
      schemaVersion: '1.2',
      tool: { name: 'secureship', version: '0.1.0' },
      mode: 'FULL',
      target: dir,
      startedAt: new Date().toISOString(),
      durationMs: 100,
      scanners: [],
      findings: [
        {
          id: 'f-eval-1',
          fingerprint: testFp,
          ruleId: 'secureship-js-eval',
          scannerName: 'opengrep',
          title: 'Eval finding',
          description: 'Avoid eval',
          category: 'SAST',
          severity: 'HIGH',
          confidence: 'HIGH',
          location: { filePath: 'index.js', startLine: 1, endLine: 1 },
          evidence: [
            {
              scannerName: 'opengrep',
              scannerRuleId: 'secureship-js-eval',
              message: 'Avoid eval',
            },
          ],
          createdAt: new Date().toISOString(),
        },
      ],
      suppressed: [],
      summary: {
        totalRaw: 1,
        totalReported: 1,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
        byCategory: { SAST: 1, SECRET: 0, SCA: 0, IAC: 0 },
        suppressedByReason: {
          GATE1_TEST_OR_MOCK: 0,
          GATE1_EXAMPLE: 0,
          GATE1_DOCUMENTATION: 0,
          USER_IGNORE_RULE: 0,
          BASELINE_KNOWN: 0,
          GATE2_UNREACHABLE: 0,
          GATE3_LIKELY_FALSE_POSITIVE: 0,
        },
      },
    };
    const reportPath = path.join(dir, 'report.json');
    writeFileSync(reportPath, JSON.stringify(reportContent), 'utf-8');

    // 1. By index: 1
    const resIndex = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'explain', '1', '--report', reportPath, '--root', dir],
      { timeoutMs: 5000 }
    );
    expect(resIndex.exitCode).toBe(2);
    expect(resIndex.stderr).toMatch(/AI model is not configured|Missing API key/);

    // 2. By fingerprint
    const resFp = await SafeProcessRunner.run(
      'node',
      [cliEntry, 'explain', testFp, '--report', reportPath, '--root', dir],
      { timeoutMs: 5000 }
    );
    expect(resFp.exitCode).toBe(2);
    expect(resFp.stderr).toMatch(/AI model is not configured|Missing API key/);
  });

  it('never prints API key in verbose or report output (A2, A18)', async () => {
    const dir = createFixture({
      'index.js': 'const x = 1;\n',
      'package.json': JSON.stringify({ name: 'app' }),
    });

    const secretKey = 'sk-ant-very-secret-test-key-1234567890';
    const res = await SafeProcessRunner.run(
      process.execPath,
      [cliEntry, 'scan', dir, '--ai', '--ai-model', 'gpt-4o', '--ai-dry-run', '--verbose'],
      {
        timeoutMs: 30_000,
        env: {
          ...process.env,
          ANTHROPIC_API_KEY: secretKey,
          OPENAI_API_KEY: secretKey,
        },
      }
    );

    expect(res.exitCode).toBe(0);
    expect(res.stdout).not.toContain(secretKey);
    expect(res.stderr).not.toContain(secretKey);
  }, 45_000);
});
