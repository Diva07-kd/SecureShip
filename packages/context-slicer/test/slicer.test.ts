import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import type { NormalizedFinding } from '@secureship/contracts';
import { ContextSlicer, SlicerDenylist, UsageFinder } from '../src/index.js';

describe('ContextSlicer Suite', () => {
  let tempRoot: string;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-slicer-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch {}
  });

  const makeFinding = (overrides: Partial<NormalizedFinding> = {}): NormalizedFinding => ({
    id: 'f-1',
    fingerprint: 'a'.repeat(64),
    ruleId: 'sql-injection',
    scannerName: 'opengrep',
    category: 'SAST',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    reachability: 'UNKNOWN',
    location: {
      filePath: 'src/app.ts',
      startLine: 5,
      endLine: 5,
      redactedSnippet: 'db.query(userQuery)',
    },
    upstreamValidationStatus: 'UNKNOWN',
    verificationStatus: 'UNVERIFIED',
    scopeTag: 'PRODUCTION',
    title: 'SQL Injection',
    description: 'User input concatenation in database query',
    cweIds: ['CWE-89'],
    evidence: [
      {
        scannerName: 'opengrep',
        scannerRuleId: 'sql-injection',
        message: 'Untrusted query',
      },
    ],
    createdAt: new Date().toISOString(),
    ...overrides,
  });

  it('rejects SECRET category findings immediately (A5, T2)', async () => {
    const finding = makeFinding({ category: 'SECRET' });
    const result = await ContextSlicer.sliceFinding(tempRoot, finding);

    expect(result.skipped).toBe(true);
    if (result.skipped) {
      expect(result.skipReason).toBe('SECRET');
    }
  });

  it('rejects credential-class SAST findings (CWE-798, CWE-259, CWE-321) (A5)', async () => {
    const finding1 = makeFinding({ cweIds: ['CWE-798'] });
    const result1 = await ContextSlicer.sliceFinding(tempRoot, finding1);
    expect(result1.skipped).toBe(true);
    if (result1.skipped) expect(result1.skipReason).toBe('CREDENTIAL_CLASS');

    const finding2 = makeFinding({ ruleId: 'secureship-js-hardcoded-jwt-secret' });
    const result2 = await ContextSlicer.sliceFinding(tempRoot, finding2);
    expect(result2.skipped).toBe(true);
    if (result2.skipped) expect(result2.skipReason).toBe('CREDENTIAL_CLASS');
  });

  it('rejects SCA category findings (Gate 3 is SAST and IAC only)', async () => {
    const finding = makeFinding({ category: 'SCA' });
    const result = await ContextSlicer.sliceFinding(tempRoot, finding);
    expect(result.skipped).toBe(true);
    if (result.skipped) expect(result.skipReason).toBe('SCA');
  });

  it('enforces sensitive file denylist (A4)', async () => {
    expect(SlicerDenylist.isDenylisted('.env')).toBe(true);
    expect(SlicerDenylist.isDenylisted('.env.production')).toBe(true);
    expect(SlicerDenylist.isDenylisted('certs/server.pem')).toBe(true);
    expect(SlicerDenylist.isDenylisted('.ssh/id_rsa')).toBe(true);
    expect(SlicerDenylist.isDenylisted('terraform.tfstate')).toBe(true);
    expect(SlicerDenylist.isDenylisted('.npmrc')).toBe(true);
    expect(SlicerDenylist.isDenylisted('src/app.ts')).toBe(false);

    const finding = makeFinding({
      location: { filePath: '.env.local', startLine: 1, endLine: 1 },
    });
    const result = await ContextSlicer.sliceFinding(tempRoot, finding);
    expect(result.skipped).toBe(true);
    if (result.skipped) expect(result.skipReason).toBe('DENYLIST_MATCH');
  });

  it('prevents symlink jailbreaks and path traversal outside root (A11)', async () => {
    const outsideFile = path.join(os.tmpdir(), 'outside-target.ts');
    fs.writeFileSync(outsideFile, 'export const secret = 1;');

    const symlinkPath = path.join(tempRoot, 'link-outside.ts');
    try {
      fs.symlinkSync(outsideFile, symlinkPath);
    } catch {
      // Symlink creation might require admin on Windows; fallback to traversal
    }

    const finding = makeFinding({
      location: { filePath: '../outside-escape.ts', startLine: 1, endLine: 1 },
    });
    const result = await ContextSlicer.sliceFinding(tempRoot, finding);
    expect(result.skipped).toBe(true);
    if (result.skipped) expect(result.skipReason).toBe('SYMLINK_JAIL_ESCAPE');

    try {
      fs.unlinkSync(outsideFile);
    } catch {}
  });

  it('slices JS/TS function and redacts embedded secrets with two passes (A4)', async () => {
    const srcDir = path.join(tempRoot, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    const dummyStripe = 'sk_' + 'live_1234567890abcdef1234567890';
    const code = `
import { db } from './db';

export function runQuery(userQuery: string) {
  const stripeKey = "${dummyStripe}";
  const googleKey = "AIzaSyD-1234567890abcdefghijklmnopqrstU";
  return db.query(userQuery);
}
`;
    const filePath = path.join(srcDir, 'app.ts');
    fs.writeFileSync(filePath, code, 'utf-8');

    const finding = makeFinding({
      location: { filePath: 'src/app.ts', startLine: 7, endLine: 7 },
    });

    const result = await ContextSlicer.sliceFinding(tempRoot, finding);
    expect(result.skipped).toBe(false);
    if (!result.skipped) {
      expect(result.filePath).toBe('src/app.ts');
      expect(result.filesSent).toContain('src/app.ts');
      expect(result.filesSent.length).toBeGreaterThanOrEqual(1);
      expect(result.primarySlice).toContain('function runQuery');
      // Verify secrets were redacted
      expect(result.primarySlice).not.toContain(dummyStripe);
      expect(result.primarySlice).toContain('sk_live...[REDACTED]');
      expect(result.primarySlice).not.toContain('AIzaSyD-1234567890abcdefghijklmnopqrstU');
      expect(result.primarySlice).toContain('AIza...[REDACTED]');
      expect(result.truncated).toBe(false);
    }
  });

  it('parses Terraform IaC resource blocks', async () => {
    const tfCode = `
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-bucket"
  acl    = "public-read"
}
`;
    const tfPath = path.join(tempRoot, 'main.tf');
    fs.writeFileSync(tfPath, tfCode, 'utf-8');

    const finding = makeFinding({
      category: 'IAC',
      location: { filePath: 'main.tf', startLine: 3, endLine: 3 },
    });

    const result = await ContextSlicer.sliceFinding(tempRoot, finding);
    expect(result.skipped).toBe(false);
    if (!result.skipped) {
      expect(result.filePath).toBe('main.tf');
      expect(result.enclosingScopeName).toContain('aws_s3_bucket');
      expect(result.primarySlice).toContain('acl    = "public-read"');
    }
  });

  it('discovers symbol usage sites bounded by limits', () => {
    const srcDir = path.join(tempRoot, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    fs.writeFileSync(
      path.join(srcDir, 'consumer1.ts'),
      'import { runQuery } from "./app";\nrunQuery("SELECT 1;");\n'
    );
    fs.writeFileSync(
      path.join(srcDir, 'consumer2.ts'),
      'import { runQuery } from "./app";\nrunQuery("SELECT 2;");\n'
    );

    const usage = UsageFinder.findUsageSites(tempRoot, 'runQuery', path.join(srcDir, 'app.ts'));
    expect(usage.length).toBeGreaterThanOrEqual(1);
    expect(usage[0]!.snippet).toContain('runQuery');
    expect(usage[0]!.filePath).toMatch(/consumer\d\.ts/);
  });

  it('enforces token budget and sets truncated flag when slice exceeds budget', async () => {
    const srcDir = path.join(tempRoot, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    // Generate large function (10,000 characters)
    const longCode = `
export function hugeFunction() {
  ${'const a = 1;\n'.repeat(500)}
}
`;
    fs.writeFileSync(path.join(srcDir, 'large.ts'), longCode);

    const finding = makeFinding({
      location: { filePath: 'src/large.ts', startLine: 200, endLine: 200 },
    });

    const result = await ContextSlicer.sliceFinding(tempRoot, finding, {
      sliceTokens: 200, // Very low budget
    });

    expect(result.skipped).toBe(false);
    if (!result.skipped) {
      expect(result.truncated).toBe(true);
      expect(result.primarySlice).toContain('[TRUNCATED]');
    }
  });

  it('skips finding when file does not exist', async () => {
    const finding = makeFinding({
      location: { filePath: 'src/missing-file.ts', startLine: 1, endLine: 1 },
    });
    const result = await ContextSlicer.sliceFinding(tempRoot, finding);
    expect(result.skipped).toBe(true);
    if (result.skipped) {
      expect(result.skipReason).toBe('FILE_NOT_FOUND');
    }
  });

  it('evaluates isCredentialClassFinding correctly across rules and CWEs', () => {
    expect(ContextSlicer.isCredentialClassFinding(makeFinding({ cweIds: ['CWE-259'] }))).toBe(true);
    expect(ContextSlicer.isCredentialClassFinding(makeFinding({ cweIds: ['CWE-321'] }))).toBe(true);
    expect(
      ContextSlicer.isCredentialClassFinding(makeFinding({ ruleId: 'rules.jwt_secret.detection' }))
    ).toBe(true);
    expect(
      ContextSlicer.isCredentialClassFinding(makeFinding({ ruleId: 'hardcoded_password_rule' }))
    ).toBe(true);
    expect(
      ContextSlicer.isCredentialClassFinding(
        makeFinding({ ruleId: 'rules.sqli', cweIds: ['CWE-89'] })
      )
    ).toBe(false);
  });

  it('skips finding when file exceeds MAX_FILE_SIZE (FILE_TOO_LARGE)', async () => {
    const srcDir = path.join(tempRoot, 'src');
    fs.mkdirSync(srcDir, { recursive: true });
    const hugeFilePath = path.join(srcDir, 'huge-file.ts');

    // Create a buffer larger than 1MB
    const bigBuf = Buffer.alloc(1_048_576 + 10, 65); // 'A's
    fs.writeFileSync(hugeFilePath, bigBuf);

    const finding = makeFinding({
      location: { filePath: 'src/huge-file.ts', startLine: 1, endLine: 1 },
    });

    const result = await ContextSlicer.sliceFinding(tempRoot, finding);
    expect(result.skipped).toBe(true);
    if (result.skipped) {
      expect(result.skipReason).toBe('FILE_TOO_LARGE');
    }
  });

  it('honors skipUsageSites option and handles fallback finding messages', async () => {
    const srcDir = path.join(tempRoot, 'src');
    fs.mkdirSync(srcDir, { recursive: true });
    const appFile = path.join(srcDir, 'app2.ts');
    fs.writeFileSync(appFile, 'export function isolatedFunc() { return 42; }\n');

    const findingNoEvidence = makeFinding({
      location: { filePath: 'src/app2.ts', startLine: 1, endLine: 1, redactedSnippet: undefined },
      evidence: [],
      description: 'Test description',
    });

    const result = await ContextSlicer.sliceFinding(tempRoot, findingNoEvidence, {
      skipUsageSites: true,
      gitleaksPath: null, // explicit null triggers gitleaks not installed branch
    });

    expect(result.skipped).toBe(false);
    if (!result.skipped) {
      expect(result.usageSites).toHaveLength(0);
      expect(result.scannerMessage).toBe('Test description');
      expect(result.scannerSnippet).toBeUndefined();
    }
  });

  it('supports gitleaks integration via explicit executable path', async () => {
    const srcDir = path.join(tempRoot, 'src');
    fs.mkdirSync(srcDir, { recursive: true });
    const appFile = path.join(srcDir, 'app3.ts');
    fs.writeFileSync(appFile, 'export function sample() { return 1; }\n');

    const finding = makeFinding({
      location: { filePath: 'src/app3.ts', startLine: 1, endLine: 1 },
    });

    // Mock gitleaks executable that exits 1 (detects secret)
    const mockGitleaksCmd = path.join(tempRoot, 'gitleaks.js');
    fs.writeFileSync(mockGitleaksCmd, 'process.exit(1);');

    const leakResult = await ContextSlicer.sliceFinding(tempRoot, finding, {
      gitleaksPath: mockGitleaksCmd,
    });
    expect(leakResult.skipped).toBe(true);
    if (leakResult.skipped) {
      expect(leakResult.skipReason).toBe('PAYLOAD_SECRET_DETECTED');
    }

    // Mock gitleaks executable that exits 0 (clean)
    fs.writeFileSync(mockGitleaksCmd, 'process.exit(0);');

    const cleanResult = await ContextSlicer.sliceFinding(tempRoot, finding, {
      gitleaksPath: mockGitleaksCmd,
    });
    expect(cleanResult.skipped).toBe(false);
  });
});
