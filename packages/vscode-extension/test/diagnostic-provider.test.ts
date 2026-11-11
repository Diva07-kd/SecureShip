import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ExtNormalizedFinding } from '../src/types/extension-types.js';

let mockCollection: {
  clear: ReturnType<typeof vi.fn>;
  set: ReturnType<typeof vi.fn>;
  dispose: ReturnType<typeof vi.fn>;
};

vi.mock('vscode', () => ({
  languages: {
    createDiagnosticCollection: vi.fn(() => {
      mockCollection = {
        clear: vi.fn(),
        set: vi.fn(),
        dispose: vi.fn(),
      };
      return mockCollection;
    }),
  },
  DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2, Hint: 3 },
  Range: class {
    constructor(
      public sl: number,
      public sc: number,
      public el: number,
      public ec: number
    ) {}
  },
  Diagnostic: class {
    public source?: string;
    public code?: unknown;
    constructor(
      public range: unknown,
      public message: string,
      public severity: number
    ) {}
  },
  Uri: {
    file: (p: string) => ({ fsPath: p }),
    parse: (s: string) => ({ href: s }),
  },
}));

import { SecureShipDiagnosticProvider } from '../src/providers/diagnostic-provider.js';

function createMockFinding(overrides: Partial<ExtNormalizedFinding> = {}): ExtNormalizedFinding {
  return {
    id: 'test-finding-id',
    fingerprint: 'a'.repeat(64),
    ruleId: 'SEC-001',
    scannerName: 'opengrep',
    category: 'SAST',
    severity: 'HIGH',
    title: 'SQL Injection',
    description: 'Untrusted user input passed into raw database query.',
    location: {
      filePath: 'src/index.ts',
      startLine: 1,
      endLine: 1,
    },
    ...overrides,
  };
}

describe('SecureShipDiagnosticProvider', () => {
  let provider: SecureShipDiagnosticProvider;

  beforeEach(() => {
    vi.clearAllMocks();
    provider = new SecureShipDiagnosticProvider();
  });

  it('CRITICAL severity maps to DiagnosticSeverity.Error (0)', () => {
    const finding = createMockFinding({
      severity: 'CRITICAL',
    });

    provider.publish([finding], '/workspace', 'INFO');

    expect(mockCollection.set).toHaveBeenCalledTimes(1);
    const diags = mockCollection.set.mock.calls[0]?.[1];
    expect(diags).toHaveLength(1);
    expect(diags[0].severity).toBe(0);
  });

  it('MEDIUM severity maps to DiagnosticSeverity.Warning (1)', () => {
    const finding = createMockFinding({
      severity: 'MEDIUM',
    });

    provider.publish([finding], '/workspace', 'INFO');

    expect(mockCollection.set).toHaveBeenCalledTimes(1);
    const diags = mockCollection.set.mock.calls[0]?.[1];
    expect(diags).toHaveLength(1);
    expect(diags[0].severity).toBe(1);
  });

  it('1-indexed startLine=10 converts to 0-indexed VSCode Range startLine=9', () => {
    const finding = createMockFinding({
      location: {
        filePath: 'src/app.ts',
        startLine: 10,
        endLine: 12,
      },
    });

    provider.publish([finding], '/workspace', 'INFO');

    expect(mockCollection.set).toHaveBeenCalledTimes(1);
    const diags = mockCollection.set.mock.calls[0]?.[1];
    const range = diags[0].range;
    expect(range.sl).toBe(9);
    expect(range.sc).toBe(0);
    expect(range.el).toBe(11);
    expect(range.ec).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('findings below minSeverity threshold are excluded', () => {
    const findings: ExtNormalizedFinding[] = [
      createMockFinding({ severity: 'LOW' }),
      createMockFinding({ severity: 'INFO' }),
      createMockFinding({ severity: 'MEDIUM' }),
    ];

    provider.publish(findings, '/workspace', 'HIGH');

    expect(mockCollection.set).not.toHaveBeenCalled();
  });

  it('multiple findings in same file are batched in single collection.set call', () => {
    const findings: ExtNormalizedFinding[] = [
      createMockFinding({
        id: '1',
        ruleId: 'R1',
        location: { filePath: 'src/index.ts', startLine: 1, endLine: 1 },
      }),
      createMockFinding({
        id: '2',
        ruleId: 'R2',
        location: { filePath: 'src/index.ts', startLine: 5, endLine: 5 },
      }),
      createMockFinding({
        id: '3',
        ruleId: 'R3',
        location: { filePath: 'src/index.ts', startLine: 10, endLine: 10 },
      }),
    ];

    provider.publish(findings, '/workspace', 'INFO');

    expect(mockCollection.set).toHaveBeenCalledTimes(1);
    const callArgs = mockCollection.set.mock.calls[0];
    expect(callArgs?.[0]?.fsPath).toContain('index.ts');
    expect(callArgs?.[1]).toHaveLength(3);
  });

  it('findings in different files each get their own collection.set call', () => {
    const findings: ExtNormalizedFinding[] = [
      createMockFinding({ id: '1', location: { filePath: 'src/a.ts', startLine: 1, endLine: 1 } }),
      createMockFinding({ id: '2', location: { filePath: 'src/b.ts', startLine: 2, endLine: 2 } }),
    ];

    provider.publish(findings, '/workspace', 'INFO');

    expect(mockCollection.set).toHaveBeenCalledTimes(2);
  });

  it('clear() calls collection.clear()', () => {
    provider.clear();
    expect(mockCollection.clear).toHaveBeenCalledTimes(1);
  });

  it("diagnostic.source format is 'SecureShip (<scannerName>)'", () => {
    const finding = createMockFinding({
      scannerName: 'opengrep',
    });

    provider.publish([finding], '/workspace', 'INFO');

    expect(mockCollection.set).toHaveBeenCalledTimes(1);
    const diag = mockCollection.set.mock.calls[0]?.[1]?.[0];
    expect(diag?.source).toBe('SecureShip (opengrep)');
  });
});
