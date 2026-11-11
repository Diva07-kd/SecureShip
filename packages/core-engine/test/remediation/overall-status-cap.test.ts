import { describe, it, expect, afterEach, vi } from 'vitest';
import type { StageId, StageOutcome, StageResult, VerificationStatus } from '@secureship/contracts';
import { VerificationLadder } from '../../src/remediation/verification-ladder.js';
import { ScaVerificationLadder } from '../../src/remediation/sca-verification-ladder.js';

/**
 * Independent oracle specified by requirements:
 * 1. Any FAIL -> FAILED
 * 2. Else any INCONCLUSIVE -> INCONCLUSIVE
 * 3. Else dynamicDisabled -> VERIFIED_STATIC
 * 4. Else any dynamic PASS -> VERIFIED_RUNTIME
 * 5. Else VERIFIED_STATIC
 */
function independentOracle(
  stageOutcomes: Array<{ id: StageId; outcome: StageOutcome }>,
  options?: { dynamicDisabled?: boolean },
  dynamicStageIds: StageId[] = ['TYPECHECK', 'BUILD', 'TEST']
): VerificationStatus {
  for (const s of stageOutcomes) {
    if (s.outcome === 'FAIL') return 'FAILED';
  }
  for (const s of stageOutcomes) {
    if (s.outcome === 'INCONCLUSIVE') return 'INCONCLUSIVE';
  }
  if (options?.dynamicDisabled === true) {
    return 'VERIFIED_STATIC';
  }
  const dynamicStages = stageOutcomes.filter((s) => dynamicStageIds.includes(s.id));
  const hasDynamicPass = dynamicStages.some((s) => s.outcome === 'PASS');
  if (hasDynamicPass) {
    return 'VERIFIED_RUNTIME';
  }
  return 'VERIFIED_STATIC';
}

describe('LAYER F: computeOverallStatus & Cap Invariants', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  const outcomes: StageOutcome[] = ['PASS', 'FAIL', 'SKIPPED', 'INCONCLUSIVE'];
  const optionCases: Array<{ dynamicDisabled?: boolean } | undefined> = [
    undefined,
    {},
    { dynamicDisabled: false },
    { dynamicDisabled: true },
  ];

  it('F1 (Code Ladder): exhaustive truth table across all 256 dynamic combinations matches independent oracle', () => {
    const codeDynamicStageIds: StageId[] = ['TYPECHECK', 'BUILD', 'TEST'];

    for (const opt of optionCases) {
      for (const tc of outcomes) {
        for (const b of outcomes) {
          for (const t of outcomes) {
            const stages: StageResult[] = [
              { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
              { id: 'POLICY', outcome: 'PASS', durationMs: 0, detail: '' },
              { id: 'SYNTAX', outcome: 'PASS', durationMs: 0, detail: '' },
              { id: 'RESCAN', outcome: 'PASS', durationMs: 0, detail: '' },
              { id: 'NEW_FINDINGS', outcome: 'PASS', durationMs: 0, detail: '' },
              { id: 'IMPORTS', outcome: 'PASS', durationMs: 0, detail: '' },
              { id: 'INSTALL', outcome: 'SKIPPED', durationMs: 0, detail: '' },
              { id: 'TYPECHECK', outcome: tc, durationMs: 0, detail: '' },
              { id: 'BUILD', outcome: b, durationMs: 0, detail: '' },
              { id: 'TEST', outcome: t, durationMs: 0, detail: '' },
            ];

            const expected = independentOracle(stages, opt, codeDynamicStageIds);
            const actual = VerificationLadder.computeOverallStatus(stages, opt);

            expect(actual).toBe(expected);
          }
        }
      }
    }
  });

  it('F1 (SCA Ladder): exhaustive truth table across all 1024 dynamic combinations matches independent oracle', () => {
    const scaDynamicStageIds: StageId[] = ['INSTALL', 'TYPECHECK', 'BUILD', 'TEST'];

    for (const opt of optionCases) {
      for (const inst of outcomes) {
        for (const tc of outcomes) {
          for (const b of outcomes) {
            for (const t of outcomes) {
              const stages: StageResult[] = [
                { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
                { id: 'POLICY', outcome: 'PASS', durationMs: 0, detail: '' },
                { id: 'SYNTAX', outcome: 'SKIPPED', durationMs: 0, detail: '' },
                { id: 'RESCAN', outcome: 'PASS', durationMs: 0, detail: '' },
                { id: 'NEW_FINDINGS', outcome: 'PASS', durationMs: 0, detail: '' },
                { id: 'IMPORTS', outcome: 'SKIPPED', durationMs: 0, detail: '' },
                { id: 'INSTALL', outcome: inst, durationMs: 0, detail: '' },
                { id: 'TYPECHECK', outcome: tc, durationMs: 0, detail: '' },
                { id: 'BUILD', outcome: b, durationMs: 0, detail: '' },
                { id: 'TEST', outcome: t, durationMs: 0, detail: '' },
              ];

              const expected = independentOracle(stages, opt, scaDynamicStageIds);
              const actual = ScaVerificationLadder.computeOverallStatus(stages, opt);

              expect(actual).toBe(expected);
            }
          }
        }
      }
    }
  });

  it('F2: a dynamic PASS combined with dynamicDisabled: true gives VERIFIED_STATIC', () => {
    const codeStages: StageResult[] = [
      { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'TEST', outcome: 'PASS', durationMs: 10, detail: 'all tests green' },
    ];
    expect(VerificationLadder.computeOverallStatus(codeStages, { dynamicDisabled: true })).toBe(
      'VERIFIED_STATIC'
    );

    const scaStages: StageResult[] = [
      { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'INSTALL', outcome: 'PASS', durationMs: 10, detail: 'installed cleanly' },
    ];
    expect(ScaVerificationLadder.computeOverallStatus(scaStages, { dynamicDisabled: true })).toBe(
      'VERIFIED_STATIC'
    );
  });

  it('F3: FAIL and INCONCLUSIVE keep absolute precedence over dynamicDisabled cap', () => {
    // FAIL precedence
    const failStages: StageResult[] = [
      { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'TYPECHECK', outcome: 'FAIL', durationMs: 5, detail: 'type error' },
      { id: 'TEST', outcome: 'PASS', durationMs: 5, detail: '' },
    ];
    expect(VerificationLadder.computeOverallStatus(failStages, { dynamicDisabled: true })).toBe(
      'FAILED'
    );
    expect(ScaVerificationLadder.computeOverallStatus(failStages, { dynamicDisabled: true })).toBe(
      'FAILED'
    );

    // INCONCLUSIVE precedence
    const incStages: StageResult[] = [
      { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'TYPECHECK', outcome: 'INCONCLUSIVE', durationMs: 5, detail: 'timeout' },
      { id: 'TEST', outcome: 'PASS', durationMs: 5, detail: '' },
    ];
    expect(VerificationLadder.computeOverallStatus(incStages, { dynamicDisabled: true })).toBe(
      'INCONCLUSIVE'
    );
    expect(ScaVerificationLadder.computeOverallStatus(incStages, { dynamicDisabled: true })).toBe(
      'INCONCLUSIVE'
    );

    // FAIL takes precedence over INCONCLUSIVE
    const bothStages: StageResult[] = [
      { id: 'APPLY', outcome: 'FAIL', durationMs: 0, detail: '' },
      { id: 'TYPECHECK', outcome: 'INCONCLUSIVE', durationMs: 0, detail: '' },
    ];
    expect(VerificationLadder.computeOverallStatus(bothStages, { dynamicDisabled: true })).toBe(
      'FAILED'
    );
    expect(ScaVerificationLadder.computeOverallStatus(bothStages, { dynamicDisabled: true })).toBe(
      'FAILED'
    );
  });

  it('F4: static-stage outcomes never influence the RUNTIME decision', () => {
    const allStaticPassNoDynamic: StageResult[] = [
      { id: 'APPLY', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'POLICY', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'SYNTAX', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'RESCAN', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'NEW_FINDINGS', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'IMPORTS', outcome: 'PASS', durationMs: 0, detail: '' },
      { id: 'INSTALL', outcome: 'SKIPPED', durationMs: 0, detail: '' },
      { id: 'TYPECHECK', outcome: 'SKIPPED', durationMs: 0, detail: '' },
      { id: 'BUILD', outcome: 'SKIPPED', durationMs: 0, detail: '' },
      { id: 'TEST', outcome: 'SKIPPED', durationMs: 0, detail: '' },
    ];

    // Without dynamicDisabled, dynamic stages are all SKIPPED -> must be VERIFIED_STATIC, never VERIFIED_RUNTIME
    expect(VerificationLadder.computeOverallStatus(allStaticPassNoDynamic)).toBe('VERIFIED_STATIC');
    expect(
      VerificationLadder.computeOverallStatus(allStaticPassNoDynamic, { dynamicDisabled: false })
    ).toBe('VERIFIED_STATIC');
    expect(
      VerificationLadder.computeOverallStatus(allStaticPassNoDynamic, { dynamicDisabled: true })
    ).toBe('VERIFIED_STATIC');

    expect(ScaVerificationLadder.computeOverallStatus(allStaticPassNoDynamic)).toBe(
      'VERIFIED_STATIC'
    );
    expect(
      ScaVerificationLadder.computeOverallStatus(allStaticPassNoDynamic, { dynamicDisabled: false })
    ).toBe('VERIFIED_STATIC');
    expect(
      ScaVerificationLadder.computeOverallStatus(allStaticPassNoDynamic, { dynamicDisabled: true })
    ).toBe('VERIFIED_STATIC');
  });
});
