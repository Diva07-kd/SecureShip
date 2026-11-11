import { describe, it, expect } from 'vitest';
import { BudgetTracker } from '../src/budget/budget-tracker.js';

describe('BudgetTracker Unit Suite', () => {
  it('tracks findings considered, sent, skips, files, cache hits, and warnings', () => {
    const tracker = new BudgetTracker(2, 100);

    tracker.recordConsidered(5);
    tracker.recordSkip('SECRET', 2);
    tracker.recordSkip('CREDENTIAL_CLASS', 1);
    tracker.recordFiles(['src/a.ts', 'src/b.ts']);
    tracker.recordFiles(['src/a.ts']); // Duplicate file
    tracker.recordTruncatedSlice();
    tracker.recordCacheHit();
    tracker.addWarning('Warn 1');

    expect(tracker.canSendFinding()).toBe(true);
    tracker.recordFindingSent();
    tracker.recordTokens(30, 20);

    expect(tracker.canSendFinding()).toBe(true);
    tracker.recordFindingSent();
    tracker.recordTokens(30, 25);

    // Max findings reached (2)
    expect(tracker.canSendFinding()).toBe(false);

    const summary = tracker.toExecutionSummary(
      'anthropic',
      'claude-3-5-sonnet',
      'api.anthropic.com',
      true
    );

    expect(summary.provider).toBe('anthropic');
    expect(summary.model).toBe('claude-3-5-sonnet');
    expect(summary.host).toBe('api.anthropic.com');
    expect(summary.deterministic).toBe(true);
    expect(summary.findingsConsidered).toBe(5);
    expect(summary.findingsSent).toBe(2);
    expect(summary.tokensIn).toBe(60);
    expect(summary.tokensOut).toBe(45);
    expect(summary.truncatedSlices).toBe(1);
    expect(summary.cacheHits).toBe(1);
    expect(summary.filesSent).toEqual(['src/a.ts', 'src/b.ts']);
    expect(summary.warnings).toEqual(['Warn 1']);
    expect(summary.findingsSkipped).toEqual([
      { reason: 'SECRET', count: 2 },
      { reason: 'CREDENTIAL_CLASS', count: 1 },
    ]);
  });

  it('stops sending findings when token budget is exceeded', () => {
    const tracker = new BudgetTracker(10, 50);
    expect(tracker.canSendFinding()).toBe(true);
    tracker.recordTokens(25, 30); // 55 tokens >= 50
    expect(tracker.canSendFinding()).toBe(false);
  });
});
