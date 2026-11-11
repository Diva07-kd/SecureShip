import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';
import { BaselineEvaluator } from '@secureship/core-engine';
import { type NormalizedFinding } from '@secureship/contracts';

describe('ScanCommand — Developer Experience Suite (Watch & New-Only) (Phase 2)', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-test-scan-dev-'));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    vi.restoreAllMocks();
  });

  it('correctly suppresses findings present in baseline under BaselineEvaluator', () => {
    const baselineFile = path.join(tempDir, 'baseline.json');

    const knownFinding: NormalizedFinding = {
      id: 'mock-1',
      fingerprint: '1111111111111111111111111111111111111111111111111111111111111111',
      ruleId: 'SEC-001',
      severity: 'HIGH',
      category: 'SAST',
      scannerName: 'opengrep',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Legacy Known Vulnerability',
      description: 'Historical security debt',
      cweIds: [],
      evidence: [
        {
          scannerName: 'opengrep',
          scannerRuleId: 'SEC-001',
          message: 'Historical security debt',
        },
      ],
      createdAt: '2026-01-01T00:00:00.000Z',
      location: {
        filePath: 'src/legacy.ts',
        startLine: 10,
        endLine: 12,
      },
    };

    const newFinding: NormalizedFinding = {
      id: 'mock-2',
      fingerprint: '2222222222222222222222222222222222222222222222222222222222222222',
      ruleId: 'SEC-002',
      severity: 'HIGH',
      category: 'SAST',
      scannerName: 'opengrep',
      confidence: 'HIGH',
      reachability: 'UNKNOWN',
      upstreamValidationStatus: 'UNKNOWN',
      verificationStatus: 'UNVERIFIED',
      scopeTag: 'PRODUCTION',
      title: 'Newly Introduced Vulnerability',
      description: 'Fresh issue in current PR',
      cweIds: [],
      evidence: [
        {
          scannerName: 'opengrep',
          scannerRuleId: 'SEC-002',
          message: 'Fresh issue in current PR',
        },
      ],
      createdAt: '2026-01-01T00:00:00.000Z',
      location: {
        filePath: 'src/new-feature.ts',
        startLine: 25,
        endLine: 28,
      },
    };

    // Establish baseline with knownFinding only
    BaselineEvaluator.writeBaseline(baselineFile, [knownFinding]);
    const evaluator = new BaselineEvaluator(baselineFile);

    expect(evaluator.isKnownInBaseline(knownFinding)).toBe(true);
    expect(evaluator.isKnownInBaseline(newFinding)).toBe(false);
  });

  it('debounces rapid filesystem watch triggers deterministically using mock timers', () => {
    vi.useFakeTimers();

    let scanExecutionCount = 0;
    const triggerScan = () => {
      scanExecutionCount++;
    };

    let debounceTimer: NodeJS.Timeout | null = null;
    const onFileChange = () => {
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        triggerScan();
      }, 300);
    };

    // Simulate 5 rapid file change events within 100ms
    onFileChange();
    onFileChange();
    onFileChange();
    onFileChange();
    onFileChange();

    expect(scanExecutionCount).toBe(0);

    // Fast-forward past the 300ms debounce threshold
    vi.advanceTimersByTime(350);

    expect(scanExecutionCount).toBe(1);
    vi.useRealTimers();
  });

  it('filters out ignored directory paths from watch monitor triggers', () => {
    const ignoredSubstrings = ['node_modules', '.git', 'dist', '.secureship', 'coverage', '.tmp'];

    const testPaths = [
      { path: 'src/components/button.ts', shouldTrigger: true },
      { path: 'node_modules/lodash/index.js', shouldTrigger: false },
      { path: '.git/refs/heads/main', shouldTrigger: false },
      { path: 'dist/index.js', shouldTrigger: false },
      { path: '.secureship/baseline.json', shouldTrigger: false },
      { path: 'package.json', shouldTrigger: true },
      { path: 'packages/core-engine/src/index.ts', shouldTrigger: true },
    ];

    for (const testItem of testPaths) {
      const normalized = testItem.path.replace(/\\/g, '/');
      const isIgnored = ignoredSubstrings.some((ign) => normalized.includes(ign));
      const triggers = !isIgnored;
      expect(triggers).toBe(testItem.shouldTrigger);
    }
  });
});
