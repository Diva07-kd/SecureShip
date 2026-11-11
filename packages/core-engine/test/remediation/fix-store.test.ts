import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { FixReport } from '@secureship/contracts';
import { FixStore } from '../../src/remediation/fix-store.js';
import { VerificationLadder } from '../../src/remediation/verification-ladder.js';

describe('FixStore', () => {
  let tempStoreDir: string;
  let tempRepo: string;

  beforeEach(() => {
    tempStoreDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-store-test-'));
    tempRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-repo-test-'));
    fs.mkdirSync(path.join(tempRepo, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tempRepo, 'src', 'vuln.ts'),
      'export function handle(input: string) {\n  const query = "SELECT * FROM users WHERE id = " + input;\n  return query;\n}\n'
    );
  });

  afterEach(() => {
    fs.rmSync(tempStoreDir, { recursive: true, force: true });
    fs.rmSync(tempRepo, { recursive: true, force: true });
  });

  const getSampleReport = (repoDir: string): { report: FixReport; diff: string } => {
    const filePath = 'src/vuln.ts';
    const fullPath = path.join(repoDir, filePath);
    const content = fs.readFileSync(fullPath);
    const sha256 = crypto.createHash('sha256').update(content).digest('hex');

    const diff =
      '--- a/src/vuln.ts\n+++ b/src/vuln.ts\n@@ -2,1 +2,1 @@\n-  const query = "SELECT * FROM users WHERE id = " + input;\n+  const query = "SELECT * FROM users WHERE id = $1";';
    const patchSha256 = crypto.createHash('sha256').update(diff).digest('hex');

    const unsignedReport: Omit<FixReport, 'signature'> = {
      schemaVersion: '1.0',
      tool: 'secureship',
      findingRef: {
        fingerprint: 'f'.repeat(64),
        ruleId: 'rules.sqli',
        category: 'SAST',
        severity: 'HIGH',
        file: filePath,
        line: 2,
      },
      patchSha256,
      proposalSummary: 'Use parameterized query',
      baseFiles: [{ path: filePath, sha256 }],
      status: 'VERIFIED_STATIC',
      requirement: 'VERIFIED_STATIC',
      requirementMet: true,
      stages: [
        { id: 'APPLY', outcome: 'PASS', detail: 'OK', durationMs: 1 },
        { id: 'POLICY', outcome: 'PASS', detail: 'OK', durationMs: 1 },
      ],
      sandbox: {
        backend: 'container',
        networkMode: 'none',
        limits: {},
        runtime: 'auto',
      },
      scanners: [{ name: 'semgrep', version: '1.0.0' }],
      attempts: 1,
      limitations: ['Test limitation'],
      disclaimer: 'Test disclaimer',
      createdAt: new Date().toISOString(),
    };

    const signature = VerificationLadder.signReport(unsignedReport);
    return {
      report: { ...unsignedReport, signature },
      diff,
    };
  };

  it('saves, retrieves, lists, and discards fix bundles', async () => {
    const store = new FixStore(tempStoreDir);
    const { report, diff } = getSampleReport(tempRepo);

    const fixId = await store.saveFix(tempRepo, report, diff);
    expect(fixId).toMatch(/^fix-[a-f0-9]{8}-[a-f0-9]{8}$/);

    const retrieved = await store.getFix(tempRepo, fixId);
    expect(retrieved).not.toBeNull();
    expect(retrieved?.validSig).toBe(true);
    expect((retrieved?.report as { patchSha256?: string })?.patchSha256).toBe(report.patchSha256);
    expect(retrieved?.diff).toBe(diff);

    const list = await store.listFixes(tempRepo);
    expect(list).toHaveLength(1);
    expect(list[0]?.findingRef.fingerprint).toBe(report.findingRef.fingerprint);

    const discarded = await store.discardFix(tempRepo, fixId);
    expect(discarded).toBe(true);

    const listAfter = await store.listFixes(tempRepo);
    expect(listAfter).toHaveLength(0);
  });

  it('detects tampered fix reports with HMAC mismatch (Mutation 22)', async () => {
    const store = new FixStore(tempStoreDir);
    const { report, diff } = getSampleReport(tempRepo);

    const fixId = await store.saveFix(tempRepo, report, diff);

    // Tamper with report file directly on disk
    const repoHash = FixStore.computeRepoHash(tempRepo);
    const reportPath = path.join(tempStoreDir, repoHash, fixId, 'report.json');
    const diskJson = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    diskJson.status = 'VERIFIED_RUNTIME'; // Tampered!
    fs.writeFileSync(reportPath, JSON.stringify(diskJson, null, 2));

    const retrieved = await store.getFix(tempRepo, fixId);
    expect(retrieved?.validSig).toBe(false);

    // Attempting to apply tampered fix must fail
    const applyRes = await store.applyFix(tempRepo, fixId, { allowNonGit: true });
    expect(applyRes.success).toBe(false);
    expect(applyRes.exitCode).toBe(2);
    expect(applyRes.error).toContain('HMAC signature verification failed');
  });

  it('rejects apply when base file hash does not match (Mutation 23)', async () => {
    const store = new FixStore(tempStoreDir);
    const { report, diff } = getSampleReport(tempRepo);
    const fixId = await store.saveFix(tempRepo, report, diff);

    // Modify base file on disk before applying
    fs.appendFileSync(
      path.join(tempRepo, 'src', 'vuln.ts'),
      '\n// User modified file concurrently'
    );

    const applyRes = await store.applyFix(tempRepo, fixId, { allowNonGit: true });
    expect(applyRes.success).toBe(false);
    expect(applyRes.exitCode).toBe(2);
    expect(applyRes.error).toContain('Base file hash mismatch');
  });

  it('rejects apply on non-git directory without --allow-non-git (Mutation 24)', async () => {
    const store = new FixStore(tempStoreDir);
    const { report, diff } = getSampleReport(tempRepo);
    const fixId = await store.saveFix(tempRepo, report, diff);

    const applyRes = await store.applyFix(tempRepo, fixId, { allowNonGit: false });
    expect(applyRes.success).toBe(false);
    expect(applyRes.exitCode).toBe(2);
    expect(applyRes.error).toContain('not a Git working tree');
  });

  it('applies fix cleanly and atomically with --allow-non-git (Mutation 25, 26, 27)', async () => {
    const store = new FixStore(tempStoreDir);
    const { report, diff } = getSampleReport(tempRepo);
    const fixId = await store.saveFix(tempRepo, report, diff);

    const applyRes = await store.applyFix(tempRepo, fixId, { allowNonGit: true });
    expect(applyRes.success).toBe(true);
    expect(applyRes.exitCode).toBe(0);
    expect(applyRes.appliedFiles).toEqual(['src/vuln.ts']);

    // Check patched content on disk
    const patchedContent = fs.readFileSync(path.join(tempRepo, 'src', 'vuln.ts'), 'utf8');
    expect(patchedContent).toContain('SELECT * FROM users WHERE id = $1');
    expect(patchedContent).not.toContain('id = " + input');
  });

  it('never auto-commits or auto-branches on apply (Mutation 25)', async () => {
    const { execFileSync } = await import('node:child_process');
    // Init git repo
    execFileSync('git', ['init'], { cwd: tempRepo });
    execFileSync('git', ['config', 'user.name', 'SecureShip Dev'], { cwd: tempRepo });
    execFileSync('git', ['config', 'user.email', 'dev@secureship.local'], { cwd: tempRepo });
    execFileSync('git', ['add', '.'], { cwd: tempRepo });
    execFileSync('git', ['commit', '-m', 'Initial commit'], { cwd: tempRepo });

    const store = new FixStore(tempStoreDir);
    const { report, diff } = getSampleReport(tempRepo);
    const fixId = await store.saveFix(tempRepo, report, diff);

    const applyRes = await store.applyFix(tempRepo, fixId);
    expect(applyRes.success).toBe(true);
    expect(applyRes.exitCode).toBe(0);

    // Verify git log has NOT changed (no auto-commit)
    const lastCommitMsg = execFileSync('git', ['log', '-1', '--pretty=%B'], {
      cwd: tempRepo,
      encoding: 'utf8',
    }).trim();
    expect(lastCommitMsg).toBe('Initial commit');

    // Verify changes are in working tree, unstaged
    const status = execFileSync('git', ['status', '--porcelain'], {
      cwd: tempRepo,
      encoding: 'utf8',
    }).trim();
    expect(status).toBe('M src/vuln.ts');
  });

  it('rejects apply for non-existent fix ID', async () => {
    const store = new FixStore(tempStoreDir);
    const res = await store.applyFix(tempRepo, 'fix-00000000-00000000', { allowNonGit: true });
    expect(res.success).toBe(false);
    expect(res.exitCode).toBe(2);
    expect(res.error).toContain('not found');
  });

  it('rejects apply when base file does not exist on disk', async () => {
    const store = new FixStore(tempStoreDir);
    const { report, diff } = getSampleReport(tempRepo);
    const fixId = await store.saveFix(tempRepo, report, diff);

    // Delete base file
    fs.rmSync(path.join(tempRepo, 'src', 'vuln.ts'));

    const res = await store.applyFix(tempRepo, fixId, { allowNonGit: true });
    expect(res.success).toBe(false);
    expect(res.exitCode).toBe(2);
    expect(res.error).toContain('does not exist on disk');
  });

  it('rejects apply on dirty Git working tree without --allow-dirty and accepts with it', async () => {
    const { execFileSync } = await import('node:child_process');
    execFileSync('git', ['init'], { cwd: tempRepo });
    execFileSync('git', ['config', 'user.name', 'SecureShip Dev'], { cwd: tempRepo });
    execFileSync('git', ['config', 'user.email', 'dev@secureship.local'], { cwd: tempRepo });
    execFileSync('git', ['add', '.'], { cwd: tempRepo });
    execFileSync('git', ['commit', '-m', 'Initial commit'], { cwd: tempRepo });

    const store = new FixStore(tempStoreDir);
    const { report, diff } = getSampleReport(tempRepo);
    const fixId = await store.saveFix(tempRepo, report, diff);

    // Create uncommitted dirty file
    fs.writeFileSync(path.join(tempRepo, 'dirty.txt'), 'uncommitted content');

    // Without --allow-dirty => 2
    const resNoDirty = await store.applyFix(tempRepo, fixId, { allowDirty: false });
    expect(resNoDirty.success).toBe(false);
    expect(resNoDirty.exitCode).toBe(2);
    expect(resNoDirty.error).toContain('uncommitted changes');

    // With --allow-dirty => 0
    const resAllowDirty = await store.applyFix(tempRepo, fixId, { allowDirty: true });
    expect(resAllowDirty.success).toBe(true);
    expect(resAllowDirty.exitCode).toBe(0);
  });

  it('returns exit code 2 on diff parse error during apply', async () => {
    const store = new FixStore(tempStoreDir);
    const { report } = getSampleReport(tempRepo);
    const badDiff = 'MALFORMED DIFF NOT A PATCH';
    const fixId = await store.saveFix(tempRepo, report, badDiff);

    const res = await store.applyFix(tempRepo, fixId, { allowNonGit: true });
    expect(res.success).toBe(false);
    expect(res.exitCode).toBe(2);
    expect(res.error).toContain('Diff parse error');
  });
});
