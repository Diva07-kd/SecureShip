import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { LockfileTreeParser } from '../src/lockfile/lockfile-tree-parser.js';

describe('LockfileTreeParser Suite (Amendments A1 & A9)', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(
      os.tmpdir(),
      `secureship-lockfile-test-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  it('parses npm package-lock.json v2/v3 with dev and optional flags', () => {
    const npmLock = {
      name: 'test-app',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'test-app',
          dependencies: {
            express: '^4.18.2',
          },
          devDependencies: {
            jest: '^29.5.0',
          },
        },
        'node_modules/express': {
          version: '4.18.2',
          dependencies: {
            debug: '2.6.9',
            depd: '2.0.0',
          },
        },
        'node_modules/debug': {
          version: '2.6.9',
          dependencies: {
            ms: '2.0.0',
          },
        },
        'node_modules/depd': {
          version: '2.0.0',
        },
        'node_modules/jest': {
          version: '29.5.0',
          dev: true,
          dependencies: {
            'jest-cli': '29.5.0',
          },
        },
        'node_modules/jest-cli': {
          version: '29.5.0',
          dev: true,
        },
      },
    };

    fs.writeFileSync(path.join(tmpDir, 'package-lock.json'), JSON.stringify(npmLock, null, 2));

    const res = LockfileTreeParser.parse(tmpDir);
    expect(res.success).toBe(true);
    if (!res.success) return;

    expect(res.graph.format).toBe('NPM_V2_V3');
    expect(res.graph.directProdDependencies.has('express')).toBe(true);
    expect(res.graph.directDevDependencies.has('jest')).toBe(true);

    // Test transitive tracing: ms is pulled via debug -> express
    const prodImported = new Set(['express']);
    const trace = LockfileTreeParser.traceTransitiveVia(res.graph, 'ms', prodImported);
    expect(trace.isTransitiveVia).toBe(true);
    expect(trace.viaChain).toContain('express');

    // Test leaf direct package
    expect(LockfileTreeParser.isLeafDirectPackage(res.graph, 'express')).toBe(true);
    // ms has a dependent (debug), so it is not a leaf direct
    expect(LockfileTreeParser.isLeafDirectPackage(res.graph, 'ms')).toBe(false);
  });

  it('parses pnpm-lock.yaml v6 and v9 formats', () => {
    const pnpmV6 = `
lockfileVersion: '6.0'
importers:
  .:
    dependencies:
      axios:
        specifier: ^1.6.0
        version: 1.6.0
    devDependencies:
      typescript:
        specifier: ^5.0.0
        version: 5.0.0
packages:
  /axios@1.6.0:
    resolution: {integrity: sha512-xxx}
    dependencies:
      follow-redirects: 1.15.4
  /follow-redirects@1.15.4:
    resolution: {integrity: sha512-yyy}
  /typescript@5.0.0:
    resolution: {integrity: sha512-zzz}
    dev: true
`;

    const pnpmDir = path.join(tmpDir, 'pnpm-app');
    fs.mkdirSync(pnpmDir, { recursive: true });
    fs.writeFileSync(path.join(pnpmDir, 'pnpm-lock.yaml'), pnpmV6);

    const res = LockfileTreeParser.parse(pnpmDir);
    expect(res.success).toBe(true);
    if (!res.success) return;

    expect(res.graph.format).toBe('PNPM_V6');
    expect(res.graph.directProdDependencies.has('axios')).toBe(true);

    // Transitive tracing: follow-redirects via axios
    const prodImported = new Set(['axios']);
    const trace = LockfileTreeParser.traceTransitiveVia(
      res.graph,
      'follow-redirects',
      prodImported
    );
    expect(trace.isTransitiveVia).toBe(true);
    expect(trace.viaChain).toEqual(['axios', 'follow-redirects']);
  });

  it('parses poetry.lock dependency trees and respects direct dependencies from pyproject.toml', () => {
    const poetryLock = `
[[package]]
name = "requests"
version = "2.31.0"
category = "main"

[package.dependencies]
urllib3 = ">=1.21.1,<3"
certifi = ">=2017.4.17"

[[package]]
name = "urllib3"
version = "2.0.7"
category = "main"

[[package]]
name = "certifi"
version = "2023.7.22"
category = "main"
`;
    const pyproject = `
[tool.poetry.dependencies]
python = "^3.10"
requests = "^2.31.0"
`;

    fs.writeFileSync(path.join(tmpDir, 'poetry.lock'), poetryLock);
    fs.writeFileSync(path.join(tmpDir, 'pyproject.toml'), pyproject);

    const res = LockfileTreeParser.parse(tmpDir);
    expect(res.success).toBe(true);
    if (!res.success) return;

    expect(res.graph.format).toBe('POETRY');
    expect(res.graph.nodes.has('requests')).toBe(true);
    expect(res.graph.nodes.has('urllib3')).toBe(true);

    const trace = LockfileTreeParser.traceTransitiveVia(
      res.graph,
      'urllib3',
      new Set(['requests'])
    );
    expect(trace.isTransitiveVia).toBe(true);
    expect(trace.viaChain).toEqual(['requests', 'urllib3']);
  });

  it('parses Pipfile.lock direct dependencies', () => {
    const pipfileLock = {
      _meta: { hash: { sha256: 'abc' } },
      default: {
        flask: { version: '==2.3.0' },
      },
      develop: {
        pytest: { version: '==7.4.0' },
      },
    };

    fs.writeFileSync(path.join(tmpDir, 'Pipfile.lock'), JSON.stringify(pipfileLock));

    const res = LockfileTreeParser.parse(tmpDir);
    expect(res.success).toBe(true);
    if (!res.success) return;

    expect(res.graph.format).toBe('PIPFILE');
    expect(res.graph.directProdDependencies.has('flask')).toBe(true);
    expect(res.graph.directDevDependencies.has('pytest')).toBe(true);
  });

  it('parses local .venv site-packages METADATA for Requires-Dist', () => {
    const distInfoDir = path.join(
      tmpDir,
      '.venv',
      'lib',
      'site-packages',
      'botocore-1.31.0.dist-info'
    );
    fs.mkdirSync(distInfoDir, { recursive: true });
    fs.writeFileSync(
      path.join(distInfoDir, 'METADATA'),
      `Name: botocore\nVersion: 1.31.0\nRequires-Dist: jmespath\nRequires-Dist: urllib3\n`
    );

    const res = LockfileTreeParser.parse(tmpDir);
    expect(res.success).toBe(true);
    if (!res.success) return;

    expect(res.graph.format).toBe('VENV_METADATA');
    expect(res.graph.nodes.has('botocore')).toBe(true);
    const node = res.graph.nodes.get('botocore')!;
    expect(node.dependencies).toContain('jmespath');
    expect(node.dependencies).toContain('urllib3');
  });

  it('rejects flat requirements.txt and yarn.lock with NO_LOCKFILE_TREE (Amendment A1 & A9)', () => {
    const flatDir = path.join(os.tmpdir(), `secureship-flat-test-${Date.now()}`);
    fs.mkdirSync(flatDir, { recursive: true });
    fs.writeFileSync(path.join(flatDir, 'requirements.txt'), 'flask==2.3.0\nrequests==2.31.0\n');

    const res = LockfileTreeParser.parse(flatDir);
    expect(res.success).toBe(false);
    if (!res.success) {
      expect(res.reason).toBe('NO_LOCKFILE_TREE');
    }
  });
});
