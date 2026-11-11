import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import type { NormalizedFinding } from '@secureship/contracts';
import { ContextSlicer } from '../../src/slicer.js';
import { SlicerDenylist } from '../../src/denylist.js';
import { SecretRedactor } from '../../src/redactor.js';

function makeFinding(overrides: Partial<NormalizedFinding> = {}): NormalizedFinding {
  return {
    id: overrides.id ?? 'finding-1',
    fingerprint: overrides.fingerprint ?? 'f'.repeat(64),
    ruleId: overrides.ruleId ?? 'secureship-sast-test',
    scannerName: overrides.scannerName ?? 'opengrep',
    category: overrides.category ?? 'SAST',
    severity: overrides.severity ?? 'MEDIUM',
    confidence: overrides.confidence ?? 'HIGH',
    cweIds: overrides.cweIds ?? [],
    reachability: overrides.reachability ?? 'UNKNOWN',
    location: overrides.location ?? {
      filePath: 'src/index.ts',
      startLine: 1,
      endLine: 2,
    },
    scopeTag: overrides.scopeTag ?? 'PRODUCTION',
    upstreamValidationStatus: overrides.upstreamValidationStatus ?? 'UNKNOWN',
    verificationStatus: overrides.verificationStatus ?? 'UNVERIFIED',
    title: overrides.title ?? 'Test Finding',
    description: overrides.description ?? 'Test description',
    evidence: [
      {
        scannerName: 'opengrep',
        scannerRuleId: 'secureship-sast-test',
        message: 'Evidence message',
      },
    ],
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

describe('Part E Verification: Context Slicer (E1 - E6)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-slicer-verify-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('E1: AST enclosing scope, +/- lines, determinism, token estimate, truncation', async () => {
    const srcDir = path.join(tempDir, 'src');
    fs.mkdirSync(srcDir, { recursive: true });

    // JS/TS file with enclosing function and import block
    const tsCode = `import { helper } from './util';
import path from 'node:path';

export class UserService {
  public getUser(id: string) {
    const raw = helper(id);
    const sink = eval(raw);
    return sink;
  }
}
`;
    fs.writeFileSync(path.join(srcDir, 'user.ts'), tsCode, 'utf8');

    const finding = makeFinding({
      location: { filePath: 'src/user.ts', startLine: 7, endLine: 7 },
    });

    // 1. Run slice
    const slice1 = await ContextSlicer.sliceFinding(tempDir, finding, { sliceTokens: 2000 });
    expect(slice1.skipped).toBe(false);
    if (!slice1.skipped) {
      expect(slice1.primarySlice).toContain('getUser');
      expect(slice1.primarySlice).toContain('eval(raw)');
      expect(slice1.enclosingScopeName).toBeDefined();
      expect(slice1.contentHash).toBeDefined();
      expect(slice1.estimatedTokens).toBeGreaterThan(0);
      expect(slice1.truncated).toBe(false);

      // 2. Determinism check: running twice produces identical hash and slice
      const slice2 = await ContextSlicer.sliceFinding(tempDir, finding, { sliceTokens: 2000 });
      expect(slice2.skipped).toBe(false);
      if (!slice2.skipped) {
        expect(slice2.contentHash).toBe(slice1.contentHash);
        expect(slice2.primarySlice).toBe(slice1.primarySlice);
      }
    }

    // 3. Truncation when enclosing function does not fit token budget
    const tinySlice = await ContextSlicer.sliceFinding(tempDir, finding, { sliceTokens: 10 });
    expect(tinySlice.skipped).toBe(false);
    if (!tinySlice.skipped) {
      expect(tinySlice.truncated).toBe(true);
    }

    // 4. Python tree-sitter enclosing function
    const pyCode = `import os
import sys

def process_data(user_input):
    clean = user_input.strip()
    result = eval(clean)
    return result
`;
    fs.writeFileSync(path.join(srcDir, 'process.py'), pyCode, 'utf8');
    const pyFinding = makeFinding({
      location: { filePath: 'src/process.py', startLine: 6, endLine: 6 },
    });
    const pySlice = await ContextSlicer.sliceFinding(tempDir, pyFinding, { sliceTokens: 2000 });
    expect(pySlice.skipped).toBe(false);
    if (!pySlice.skipped) {
      expect(pySlice.primarySlice).toContain('def process_data');
      expect(pySlice.primarySlice).toContain('eval(clean)');
    }
  });

  it('E2: Denylist: sensitive files are NEVER read or sent', async () => {
    const denylistedFiles = [
      '.env',
      '.env.local',
      '.env.production',
      'cert.pem',
      'server.key',
      'id_rsa',
      'cert.p12',
      'cert.pfx',
      'credentials.json',
      'secrets.yaml',
      'vault.kdbx',
      '.npmrc',
      '.pypirc',
      '.netrc',
      'terraform.tfstate',
      'terraform.tfstate.backup',
      '.aws/credentials',
      '.ssh/id_ed25519',
    ];

    for (const relPath of denylistedFiles) {
      const fullPath = path.join(tempDir, relPath);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, 'TOP_SECRET_CONTENT_CANARY_12345', 'utf8');

      // Test denylist static validator
      expect(SlicerDenylist.isDenylisted(relPath)).toBe(true);

      // Test slicer skips finding pointing to denylisted file
      const finding = makeFinding({
        location: { filePath: relPath, startLine: 1, endLine: 1 },
      });
      const sliceRes = await ContextSlicer.sliceFinding(tempDir, finding);
      expect(sliceRes.skipped).toBe(true);
      if (sliceRes.skipped) {
        expect(sliceRes.skipReason).toBe('DENYLIST_MATCH');
      }
    }
  });

  it('E3: Path safety: symlinks outside root, ../ escapes, and canary files outside root never read', async () => {
    // 1. Create a canary file outside tempDir
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-outside-canary-'));
    const canaryFile = path.join(outsideDir, 'canary.txt');
    fs.writeFileSync(canaryFile, 'OUTSIDE_CANARY_SECRET_DATA_DO_NOT_READ', 'utf8');

    try {
      // 2. Traversal path ../
      const traversalFinding = makeFinding({
        location: { filePath: '../canary.txt', startLine: 1, endLine: 1 },
      });
      const travRes = await ContextSlicer.sliceFinding(tempDir, traversalFinding);
      expect(travRes.skipped).toBe(true);

      // 3. Absolute path outside root
      const absFinding = makeFinding({
        location: { filePath: canaryFile, startLine: 1, endLine: 1 },
      });
      const absRes = await ContextSlicer.sliceFinding(tempDir, absFinding);
      expect(absRes.skipped).toBe(true);

      // 4. Symlink pointing outside root
      const linkPath = path.join(tempDir, 'link_outside');
      let canSymlink = true;
      try {
        fs.symlinkSync(outsideDir, linkPath, 'junction');
      } catch {
        canSymlink = false; // Non-admin on Windows might disallow file symlinks
      }

      if (canSymlink) {
        const linkFinding = makeFinding({
          location: { filePath: 'link_outside/canary.txt', startLine: 1, endLine: 1 },
        });
        const linkRes = await ContextSlicer.sliceFinding(tempDir, linkFinding);
        expect(linkRes.skipped).toBe(true);
      }
    } finally {
      try {
        fs.rmSync(outsideDir, { recursive: true, force: true });
      } catch {}
    }
  });

  it('E4: Redaction of fake secrets (AWS, GitHub, JWT, Private Keys, passwords, Stripe, Slack)', () => {
    const dummyStripe = 'sk_' + 'live_51AbCdEfGhIjKlMnOpQrStUvWxYz1234567890';
    const dummySlack = 'xox' + 'b-123456789012-1234567890123-abcdefghijklmnopqrstuvwx';
    const rawCodeWithSecrets = `
      const awsKey = "AKIAIOSFODNN7EXAMPLE";
      const ghToken = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456";
      const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
      const privKey = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEAz...\\n-----END RSA PRIVATE KEY-----";
      const password = "SuperSecretPassword123!";
      const stripe = "${dummyStripe}";
      const slack = "${dummySlack}";
      const normalCode = "db.query('SELECT * FROM users');";
    `;

    const redacted = SecretRedactor.redactText(rawCodeWithSecrets);

    expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(redacted).not.toContain('ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456');
    expect(redacted).not.toContain('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9');
    expect(redacted).not.toContain('BEGIN RSA PRIVATE KEY');
    expect(redacted).not.toContain('SuperSecretPassword123!');
    expect(redacted).not.toContain(dummyStripe);
    expect(redacted).not.toContain('xox' + 'b-123456789012');

    expect(redacted).toContain('[REDACTED');
    expect(redacted).toContain("db.query('SELECT * FROM users');");
  });

  it('E5: SECRET-category and credential-class findings skipped; oversize/binary handled safely', async () => {
    // 1. Category SECRET finding
    const secretFinding = makeFinding({
      category: 'SECRET',
      ruleId: 'generic-secret',
    });
    const secretRes = await ContextSlicer.sliceFinding(tempDir, secretFinding);
    expect(secretRes.skipped).toBe(true);
    if (secretRes.skipped) {
      expect(secretRes.skipReason).toBe('SECRET');
    }

    // 2. Credential-class SAST findings (CWE-798, CWE-259, CWE-321, jwt-secret)
    const credCweFinding = makeFinding({
      category: 'SAST',
      cweIds: ['CWE-798'],
      ruleId: 'hardcoded-credentials',
    });
    expect(ContextSlicer.isCredentialClassFinding(credCweFinding)).toBe(true);
    const credRes = await ContextSlicer.sliceFinding(tempDir, credCweFinding);
    expect(credRes.skipped).toBe(true);
    if (credRes.skipped) {
      expect(credRes.skipReason).toBe('CREDENTIAL_CLASS');
    }

    // 3. Oversized file (> 1 MB)
    const bigFilePath = path.join(tempDir, 'huge.ts');
    fs.writeFileSync(bigFilePath, 'const x = 1;\n'.repeat(100_000), 'utf8'); // ~1.3 MB > 1 MB
    const bigFinding = makeFinding({
      location: { filePath: 'huge.ts', startLine: 1, endLine: 2 },
    });
    const bigRes = await ContextSlicer.sliceFinding(tempDir, bigFinding);
    expect(bigRes.skipped).toBe(true);
    if (bigRes.skipped) {
      expect(bigRes.skipReason).toBe('FILE_TOO_LARGE');
    }

    // 4. Missing / unreadable file
    const missingFinding = makeFinding({
      location: { filePath: 'non_existent.ts', startLine: 1, endLine: 2 },
    });
    const missRes = await ContextSlicer.sliceFinding(tempDir, missingFinding);
    expect(missRes.skipped).toBe(true);
    if (missRes.skipped) {
      expect(missRes.skipReason).toBe('FILE_NOT_FOUND');
    }
  });

  it('E6: Other languages (Go/Java): line window slicing works without AST crash', async () => {
    // Go file
    const goCode = `package main

import "fmt"

func main() {
    fmt.Println("Hello Go")
    query := "SELECT * FROM users WHERE id = " + userInput
    db.Exec(query)
}
`;
    fs.writeFileSync(path.join(tempDir, 'main.go'), goCode, 'utf8');
    const goFinding = makeFinding({
      location: { filePath: 'main.go', startLine: 7, endLine: 7 },
    });
    const goSlice = await ContextSlicer.sliceFinding(tempDir, goFinding);
    expect(goSlice.skipped).toBe(false);
    if (!goSlice.skipped) {
      expect(goSlice.primarySlice).toContain('db.Exec(query)');
      expect(goSlice.primarySlice).toContain('package main');
    }

    // Java file
    const javaCode = `package com.secureship;

public class SqlService {
    public void run(String input) {
        String query = "SELECT * FROM t WHERE id = " + input;
        stmt.execute(query);
    }
}
`;
    fs.writeFileSync(path.join(tempDir, 'SqlService.java'), javaCode, 'utf8');
    const javaFinding = makeFinding({
      location: { filePath: 'SqlService.java', startLine: 6, endLine: 6 },
    });
    const javaSlice = await ContextSlicer.sliceFinding(tempDir, javaFinding);
    expect(javaSlice.skipped).toBe(false);
    if (!javaSlice.skipped) {
      expect(javaSlice.primarySlice).toContain('stmt.execute(query)');
    }
  });
});
