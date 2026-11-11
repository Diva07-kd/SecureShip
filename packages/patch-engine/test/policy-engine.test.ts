import { describe, it, expect } from 'vitest';
import { DiffParser } from '../src/diff-parser.js';
import { PatchPolicyEngine, type PolicyEngineOptions } from '../src/policy-engine.js';
import { isPythonStdlibModule } from '../src/python-stdlib.js';

describe('PatchPolicyEngine Comprehensive Safety Suite', () => {
  const baseOptions: PolicyEngineOptions = {
    rootDir: '/project',
    category: 'SAST',
    findingLocation: {
      filePath: 'src/app.ts',
      startLine: 10,
      endLine: 15,
    },
    scopeWindow: {
      filePath: 'src/app.ts',
      startLine: 5,
      endLine: 25,
    },
    maxFiles: 1,
    maxChangedLines: 60,
  };

  it('passes a clean, safe patch modifying only the target scope', () => {
    const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,3 +10,3 @@
 function handle(input: string) {
-  const query = "SELECT * FROM users WHERE id = " + input;
+  const query = "SELECT * FROM users WHERE id = ?";
   return db.query(query, [input]);
`;
    const parsed = DiffParser.parse(diff);
    const result = PatchPolicyEngine.evaluate(parsed, baseOptions);
    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('rejects changes outside scope window with OUTSIDE_SCOPE', () => {
    const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -50,3 +50,3 @@
 function distantFunction() {
-  const x = 1;
+  const x = 2;
   return x;
`;
    const parsed = DiffParser.parse(diff);
    const result = PatchPolicyEngine.evaluate(parsed, baseOptions);
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.code === 'OUTSIDE_SCOPE')).toBe(true);
  });

  it('rejects sensitive files matching denylist with SENSITIVE_FILE', () => {
    const diff = `--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 PORT=3000
-DEBUG=true
+DEBUG=false
`;
    const parsed = DiffParser.parse(diff);
    const result = PatchPolicyEngine.evaluate(parsed, {
      ...baseOptions,
      findingLocation: { filePath: '.env', startLine: 1, endLine: 2 },
    });
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.code === 'SENSITIVE_FILE')).toBe(true);
  });

  it('rejects test and fixture files with TEST_FILE', () => {
    const diff = `--- a/tests/app.test.ts
+++ b/tests/app.test.ts
@@ -1,3 +1,3 @@
 test('runs', () => {
-  expect(1).toBe(2);
+  expect(1).toBe(1);
 });
`;
    const parsed = DiffParser.parse(diff);
    const result = PatchPolicyEngine.evaluate(parsed, {
      ...baseOptions,
      findingLocation: { filePath: 'tests/app.test.ts', startLine: 1, endLine: 2 },
    });
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.code === 'TEST_FILE')).toBe(true);
  });

  it('rejects protected files (package.json, lockfiles, CI) with PROTECTED_PATH', () => {
    const diff = `--- a/package.json
+++ b/package.json
@@ -1,3 +1,3 @@
 {
-  "version": "1.0.0"
+  "version": "1.0.1"
 }
`;
    const parsed = DiffParser.parse(diff);
    const result = PatchPolicyEngine.evaluate(parsed, {
      ...baseOptions,
      findingLocation: { filePath: 'package.json', startLine: 1, endLine: 2 },
    });
    expect(result.allowed).toBe(false);
    expect(result.violations.some((v) => v.code === 'PROTECTED_PATH')).toBe(true);
  });

  it('rejects Dockerfile/Terraform for SAST findings, allows for IAC', () => {
    const diff = `--- a/Dockerfile
+++ b/Dockerfile
@@ -1,1 +1,1 @@
-FROM node:18
+FROM node:20
`;
    const parsed = DiffParser.parse(diff);

    // For SAST: rejected
    const sastResult = PatchPolicyEngine.evaluate(parsed, {
      ...baseOptions,
      category: 'SAST',
      findingLocation: { filePath: 'Dockerfile', startLine: 1, endLine: 2 },
    });
    expect(sastResult.allowed).toBe(false);
    expect(sastResult.violations.some((v) => v.code === 'PROTECTED_PATH')).toBe(true);

    // For IAC: allowed
    const iacResult = PatchPolicyEngine.evaluate(parsed, {
      ...baseOptions,
      category: 'IAC',
      findingLocation: { filePath: 'Dockerfile', startLine: 1, endLine: 2 },
    });
    expect(iacResult.allowed).toBe(true);
  });

  it('detects all suppression markers with SUPPRESSION_MARKER', () => {
    const markers = [
      '// nosemgrep',
      '# nosec',
      '# noqa',
      '# pylint: disable=all',
      '/* eslint-disable */',
      '// @ts-ignore',
      '// @ts-nocheck',
      '# type: ignore',
      '// secureship-ignore',
      '# checkov:skip=CKV_123',
      '// trivy:ignore',
      '// gitleaks:allow',
    ];

    for (const marker of markers) {
      const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,4 +10,4 @@
 function handle() {
-  eval(x);
+  eval(x); ${marker}
   return true;
 }
`;
      const parsed = DiffParser.parse(diff);
      const res = PatchPolicyEngine.evaluate(parsed, baseOptions);
      expect(res.allowed).toBe(false);
      expect(res.violations.some((v) => v.code === 'SUPPRESSION_MARKER')).toBe(true);
    }
  });

  it('detects commented-out code replacing vulnerability as suppression', () => {
    const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,4 +10,4 @@
 function handle() {
-  dangerousCommand(input);
+  // dangerousCommand(input);
   return true;
 }
`;
    const parsed = DiffParser.parse(diff);
    const res = PatchPolicyEngine.evaluate(parsed, baseOptions);
    expect(res.allowed).toBe(false);
    expect(res.violations.some((v) => v.code === 'SUPPRESSION_MARKER')).toBe(true);
  });

  it('rejects deletion-only patch with REMOVAL_ONLY unless permitted', () => {
    const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,4 +10,1 @@
-const bad1 = 1;
-const bad2 = 2;
-const bad3 = 3;
 const keep = 4;
`;
    const parsed = DiffParser.parse(diff);
    const res = PatchPolicyEngine.evaluate(parsed, baseOptions);
    expect(res.allowed).toBe(false);
    expect(res.violations.some((v) => v.code === 'REMOVAL_ONLY')).toBe(true);

    // Allowed when allowRemovalOnly = true
    const allowedRes = PatchPolicyEngine.evaluate(parsed, {
      ...baseOptions,
      allowRemovalOnly: true,
    });
    expect(allowedRes.allowed).toBe(true);
  });

  it('rejects excessive deletion with EXCESSIVE_DELETION', () => {
    const deleted = Array.from({ length: 15 }, (_, i) => `-const del_${i} = ${i};`).join('\n');
    const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -1,16 +1,2 @@
-const keepOld = 0;
${deleted}
+const keepNew = 0;
+const singleAdded = 1;
`;
    const parsed = DiffParser.parse(diff);
    const res = PatchPolicyEngine.evaluate(parsed, baseOptions);
    expect(res.allowed).toBe(false);
    expect(res.violations.some((v) => v.code === 'EXCESSIVE_DELETION')).toBe(true);
  });

  it('rejects net-new dangerous APIs with NEW_DANGEROUS_API', () => {
    const dangerousSnippets = [
      'eval(userCommand)',
      'child_process.exec(cmd)',
      'subprocess.Popen(args)',
      'pickle.loads(data)',
      'yaml.load(payload)',
      'fetch("https://attacker.com")',
      'requests.get("http://evil.com")',
      'import("malicious-module")',
    ];

    for (const snippet of dangerousSnippets) {
      const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,4 +10,4 @@
 function handle() {
-  safeMethod();
+  ${snippet};
   return true;
 }
`;
      const parsed = DiffParser.parse(diff);
      const res = PatchPolicyEngine.evaluate(parsed, baseOptions);
      expect(res.allowed).toBe(false);
      expect(res.violations.some((v) => v.code === 'NEW_DANGEROUS_API')).toBe(true);
    }
  });

  it('allows replacing a dangerous API occurrence without increasing count', () => {
    const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,4 +10,4 @@
 function handle() {
-  eval(userCommand);
+  eval(sanitizedCommand);
   return true;
 }
`;
    const parsed = DiffParser.parse(diff);
    const res = PatchPolicyEngine.evaluate(parsed, baseOptions);
    expect(res.allowed).toBe(true);
  });

  it('rejects new unapproved dependencies with NEW_DEPENDENCY', () => {
    const jsDiff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -1,1 +1,2 @@
+import axios from 'axios';
 const x = 1;
`;
    const parsedJs = DiffParser.parse(jsDiff);
    const jsRes = PatchPolicyEngine.evaluate(parsedJs, baseOptions);
    expect(jsRes.allowed).toBe(false);
    expect(jsRes.violations.some((v) => v.code === 'NEW_DEPENDENCY')).toBe(true);

    const pyDiff = `--- a/src/app.py
+++ b/src/app.py
@@ -1,1 +1,2 @@
+import requests
 x = 1
`;
    const parsedPy = DiffParser.parse(pyDiff);
    const pyRes = PatchPolicyEngine.evaluate(parsedPy, {
      ...baseOptions,
      findingLocation: { filePath: 'src/app.py', startLine: 1, endLine: 2 },
    });
    expect(pyRes.allowed).toBe(false);
    expect(pyRes.violations.some((v) => v.code === 'NEW_DEPENDENCY')).toBe(true);
  });

  it('allows Node builtins and Python stdlib modules', () => {
    const jsDiff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -1,1 +1,3 @@
+import path from 'node:path';
+import crypto from 'crypto';
 const x = 1;
`;
    const parsedJs = DiffParser.parse(jsDiff);
    const jsRes = PatchPolicyEngine.evaluate(parsedJs, baseOptions);
    expect(jsRes.allowed).toBe(true);

    const pyDiff = `--- a/src/app.py
+++ b/src/app.py
@@ -1,1 +1,3 @@
+import hashlib
+from datetime import datetime
 x = 1
`;
    const parsedPy = DiffParser.parse(pyDiff);
    const pyRes = PatchPolicyEngine.evaluate(parsedPy, {
      ...baseOptions,
      findingLocation: { filePath: 'src/app.py', startLine: 1, endLine: 2 },
    });
    expect(pyRes.allowed).toBe(true);
  });

  it('rejects hardcoded secrets with SECRET_IN_PATCH', () => {
    const diff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,3 +10,3 @@
 function getAuth() {
-  return getToken();
+  return "ghp_VerySecretGitHubPersonalAccessToken123456";
 }
`;
    const parsed = DiffParser.parse(diff);
    const res = PatchPolicyEngine.evaluate(parsed, baseOptions);
    expect(res.allowed).toBe(false);
    expect(res.violations.some((v) => v.code === 'SECRET_IN_PATCH')).toBe(true);
  });

  it('rejects Trojan Source bidirectional characters and hidden Unicode with HIDDEN_UNICODE', () => {
    // 1. Bidi override character \u202E
    const bidiDiff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,3 +10,3 @@
 function check() {
-  return true;
+  return true; \u202E/* admin access */
 }
`;
    const parsedBidi = DiffParser.parse(bidiDiff);
    const bidiRes = PatchPolicyEngine.evaluate(parsedBidi, baseOptions);
    expect(bidiRes.allowed).toBe(false);
    expect(bidiRes.violations.some((v) => v.code === 'HIDDEN_UNICODE')).toBe(true);

    // 2. Zero-width character \u200B
    const zwDiff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,3 +10,3 @@
 function check() {
-  return true;
+  const x\u200By = 1;
 }
`;
    const parsedZw = DiffParser.parse(zwDiff);
    const zwRes = PatchPolicyEngine.evaluate(parsedZw, baseOptions);
    expect(zwRes.allowed).toBe(false);
    expect(zwRes.violations.some((v) => v.code === 'HIDDEN_UNICODE')).toBe(true);

    // 3. Mixed Cyrillic / Latin homoglyph
    // 'а' is Cyrillic small letter a (U+0430) mixed with Latin 'admin'
    const homoglyphDiff = `--- a/src/app.ts
+++ b/src/app.ts
@@ -10,3 +10,3 @@
 function check() {
-  return user.isAdmin;
+  return user.\u0430dmin;
 }
`;
    const parsedHg = DiffParser.parse(homoglyphDiff);
    const hgRes = PatchPolicyEngine.evaluate(parsedHg, baseOptions);
    expect(hgRes.allowed).toBe(false);
    expect(hgRes.violations.some((v) => v.code === 'HIDDEN_UNICODE')).toBe(true);
  });

  it('isPythonStdlibModule correctly identifies modules with and without submodules', () => {
    expect(isPythonStdlibModule('sys')).toBe(true);
    expect(isPythonStdlibModule('os.path')).toBe(true);
    expect(isPythonStdlibModule('unknown_package')).toBe(false);
    expect(isPythonStdlibModule('requests.auth')).toBe(false);
  });
});
