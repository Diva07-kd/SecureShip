import { describe, expect, it, vi } from 'vitest';
import type * as vscode from 'vscode';
import type { ExtNormalizedFinding } from '../src/types/extension-types.js';

vi.mock('vscode', () => ({
  MarkdownString: class {
    public value: string = '';
    public isTrusted: boolean = false;
    public supportHtml: boolean = false;
    constructor(val: string = '', isTrusted: boolean = false) {
      this.value = val;
      this.isTrusted = isTrusted;
    }
    appendMarkdown(str: string) {
      this.value += str;
      return this;
    }
  },
  Hover: class {
    constructor(public contents: { value: string; isTrusted: boolean }) {}
  },
  Position: class {
    constructor(
      public line: number,
      public character: number
    ) {}
  },
}));

import {
  extractPackageFromLine,
  normalizePackageName,
  SecureShipHoverProvider,
} from '../src/providers/hover-provider.js';

function createMockDoc(lineText: string): vscode.TextDocument {
  return {
    lineAt: (_line: number) => ({ text: lineText }),
  } as unknown as vscode.TextDocument;
}

function createFinding(overrides: Partial<ExtNormalizedFinding> = {}): ExtNormalizedFinding {
  return {
    id: 'f-1',
    fingerprint: 'b'.repeat(64),
    ruleId: 'SEC-DEP-01',
    scannerName: 'trivy',
    category: 'SUPPLY_CHAIN',
    severity: 'HIGH',
    title: 'Vulnerable Dependency',
    description: 'Known vulnerability in package.',
    location: {
      filePath: 'package.json',
      startLine: 1,
      endLine: 1,
    },
    ...overrides,
  };
}

function getHoverContent(hover: vscode.Hover | null): string {
  if (!hover) return '';
  const contents = hover.contents as unknown;
  if (typeof contents === 'object' && contents !== null && 'value' in contents) {
    return String((contents as { value: unknown }).value);
  }
  return '';
}

describe('SecureShipHoverProvider', () => {
  it("extracts simple package from: import X from 'lodash'", () => {
    const pkg = extractPackageFromLine("import X from 'lodash'");
    expect(pkg).toBe('lodash');
  });

  it("extracts scoped package from: import { A } from '@secureship/contracts'", () => {
    const pkg = extractPackageFromLine("import { A } from '@secureship/contracts'");
    expect(pkg).toBe('@secureship/contracts');
  });

  it("strips sub-path from: import fn from 'lodash/merge'", () => {
    const pkg = extractPackageFromLine("import fn from 'lodash/merge'");
    expect(pkg).toBe('lodash');
  });

  it("extracts from require(): const x = require('express')", () => {
    const pkg = extractPackageFromLine("const x = require('express')");
    expect(pkg).toBe('express');
  });

  it('returns null for lines with no import', () => {
    const pkg = extractPackageFromLine('const x = foo.bar()');
    expect(pkg).toBeNull();
  });

  it("ignores relative imports (starting with '.')", () => {
    const norm = normalizePackageName('./utils');
    expect(norm).toBeNull();
  });

  it('SUPPLY_CHAIN findings matching package name trigger hover', () => {
    const provider = new SecureShipHoverProvider();
    provider.updateFindings([
      createFinding({
        category: 'SUPPLY_CHAIN',
        package: { name: 'lodash', version: '4.17.20' },
        severity: 'CRITICAL',
      }),
    ]);

    const doc = createMockDoc("import x from 'lodash'");
    const hover = provider.provideHover(doc, { line: 0, character: 5 } as vscode.Position);

    expect(hover).not.toBeNull();
    const contents = getHoverContent(hover);
    expect(contents).toContain('SecureShip Supply-Chain Threat Alert');
    expect(contents).toContain('lodash');
  });

  it('SAST findings do NOT appear in hover (only SUPPLY_CHAIN)', () => {
    const provider = new SecureShipHoverProvider();
    provider.updateFindings([
      createFinding({
        category: 'SAST',
        package: { name: 'lodash', version: '4.17.20' },
        severity: 'CRITICAL',
      }),
    ]);

    const doc = createMockDoc("import x from 'lodash'");
    const hover = provider.provideHover(doc, { line: 0, character: 5 } as vscode.Position);

    expect(hover).toBeNull();
  });

  it('highest severity correctly selected from multiple findings on same package', () => {
    const provider = new SecureShipHoverProvider();
    provider.updateFindings([
      createFinding({
        id: '1',
        category: 'SUPPLY_CHAIN',
        package: { name: 'evil-pkg', version: '1.0.0' },
        severity: 'LOW',
      }),
      createFinding({
        id: '2',
        category: 'SUPPLY_CHAIN',
        package: { name: 'evil-pkg', version: '1.0.0' },
        severity: 'CRITICAL',
      }),
      createFinding({
        id: '3',
        category: 'SUPPLY_CHAIN',
        package: { name: 'evil-pkg', version: '1.0.0' },
        severity: 'HIGH',
      }),
    ]);

    const doc = createMockDoc("import { payload } from 'evil-pkg'");
    const hover = provider.provideHover(doc, { line: 0, character: 5 } as vscode.Position);

    expect(hover).not.toBeNull();
    const contents = getHoverContent(hover);
    expect(contents).toContain('**CRITICAL**');
  });

  it('fixedVersion shown when package has fixedVersion', () => {
    const provider = new SecureShipHoverProvider();
    provider.updateFindings([
      createFinding({
        category: 'SUPPLY_CHAIN',
        package: {
          name: 'vulnerable-dep',
          version: '1.0.0',
          fixedVersion: '1.2.3',
        },
        severity: 'HIGH',
      }),
    ]);

    const doc = createMockDoc("const v = require('vulnerable-dep')");
    const hover = provider.provideHover(doc, { line: 0, character: 5 } as vscode.Position);

    expect(hover).not.toBeNull();
    const contents = getHoverContent(hover);
    expect(contents).toContain('1.2.3');
  });
});
