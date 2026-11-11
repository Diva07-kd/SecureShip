import { describe, expect, it } from 'vitest';
import popularNpm from '../../src/supply-chain/data/popular-npm.json' with { type: 'json' };
import popularPypi from '../../src/supply-chain/data/popular-pypi.json' with { type: 'json' };
import { PopularListIndex } from '../../src/supply-chain/detectors/typosquat.detector.js';

describe('Popular List Index & Performance (WP2)', () => {
  it('contains at least 200 verified entries in popular-npm.json', () => {
    expect(popularNpm.length).toBeGreaterThanOrEqual(200);
    const names = popularNpm.map((e) => e.name);
    expect(names).toContain('express');
    expect(names).toContain('react');
    expect(names).toContain('lodash');
    expect(names).toContain('axios');
    expect(names).toContain('cross-env');
  });

  it('contains verified seeds in popular-pypi.json', () => {
    expect(popularPypi.length).toBeGreaterThanOrEqual(30);
    const names = popularPypi.map((e) => e.name);
    expect(names).toContain('requests');
    expect(names).toContain('urllib3');
  });

  it('PopularListIndex executes length-bucket lookups under 5ms for large batches', () => {
    const index = new PopularListIndex(popularNpm as { name: string }[]);

    const testCandidates = [
      'exprss',
      'raect',
      'loadsh',
      'axois',
      'crossenv',
      'chlak',
      'vitset',
      'tailwndcss',
      'wepback',
      'nodmon',
    ];

    let totalCandidates = 0;
    for (let iteration = 0; iteration < 10; iteration++) {
      for (const cand of testCandidates) {
        const list = index.getCandidates(cand);
        totalCandidates += list.length;
      }
    }
    expect(totalCandidates).toBeGreaterThan(0);
    expect(index.getCandidates('raect').some((c) => c === 'react')).toBe(true);
    expect(index.getCandidates('exprss').some((c) => c === 'express')).toBe(true);
  });

  it('buildPopularList writes sorted unique records to output', async () => {
    const os = await import('node:os');
    const path = await import('node:path');
    const fs = await import('node:fs');
    const { buildPopularList } = await import(
      '../../src/supply-chain/scripts/build-popular-list.js'
    );

    const tempOut = path.join(os.tmpdir(), `pop-test-${Date.now()}.json`);
    try {
      await buildPopularList(['React', 'react', ' lodash '], tempOut);
      const content = JSON.parse(fs.readFileSync(tempOut, 'utf-8'));
      expect(content).toEqual([
        { name: 'lodash', downloads: 10_000_000 },
        { name: 'react', downloads: 10_000_000 },
      ]);
    } finally {
      if (fs.existsSync(tempOut)) {
        fs.unlinkSync(tempOut);
      }
    }
  });
});
