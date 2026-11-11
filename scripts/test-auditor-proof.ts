import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { runIntegrityAudit } from './verify-test-integrity.ts';

console.log('=== PROVING AUDITOR INTEGRITY (T1) ===');
console.log('Planting >=10 deliberately fake tests in temporary isolated directory...\n');

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-fake-tests-'));

try {
  // Plant 1: zero-assertions
  fs.writeFileSync(
    path.join(tempDir, 'fake-zero-assertions.test.ts'),
    `import { describe, it } from 'vitest';
describe('Fake Suite', () => {
  it('fake test without assertions', () => {
    const x = 1 + 1;
    console.log(x);
  });
});`
  );

  // Plant 2: tautology
  fs.writeFileSync(
    path.join(tempDir, 'fake-tautology.test.ts'),
    `import { describe, it, expect } from 'vitest';
describe('Fake Suite', () => {
  it('tautological assertion', () => {
    expect(true).toBe(true);
  });
});`
  );

  // Plant 3: weak-only
  fs.writeFileSync(
    path.join(tempDir, 'fake-weak-only.test.ts'),
    `import { describe, it, expect } from 'vitest';
describe('Fake Suite', () => {
  it('weak only assertion', () => {
    const result = { status: 'ok' };
    expect(result).toBeDefined();
  });
});`
  );

  // Plant 4: skip-only-todo
  fs.writeFileSync(
    path.join(tempDir, 'fake-skip.test.ts'),
    `import { describe, it, expect } from 'vitest';
describe('Fake Suite', () => {
  it.skip('skipped test to hide failure', () => {
    expect(1).toBe(2);
  });
});`
  );

  // Plant 5: commented-assertion
  fs.writeFileSync(
    path.join(tempDir, 'fake-commented.test.ts'),
    `import { describe, it, expect } from 'vitest';
describe('Fake Suite', () => {
  it('test with commented assertion', () => {
    // expect(actualVal).toBe(100);
    expect(10).toBe(10 + 0);
  });
});`
  );

  // Plant 6: swallowed-catch
  fs.writeFileSync(
    path.join(tempDir, 'fake-swallowed-catch.test.ts'),
    `import { describe, it, expect } from 'vitest';
describe('Fake Suite', () => {
  it('swallows failure inside catch', () => {
    try {
      expect(1).toBe(2);
    } catch {
      // Swallowed failure
    }
  });
});`
  );

  // Plant 7: prod-constant-expected
  fs.writeFileSync(
    path.join(tempDir, 'fake-prod-constant.test.ts'),
    `import { describe, it, expect } from 'vitest';
import { RULES_REGISTRY } from '../packages/core-engine/src/supply-chain/rules-registry.js';
describe('Fake Suite', () => {
  it('uses production table as expected value', () => {
    const r = 'val';
    expect(r).toBe(RULES_REGISTRY);
  });
});`
  );

  // Plant 8: forbidden-mock
  fs.writeFileSync(
    path.join(tempDir, 'fake-forbidden-mock.test.ts'),
    `import { describe, it, expect, vi } from 'vitest';
vi.mock('../src/supply-chain/detectors/install-script.detector');
describe('Fake Suite', () => {
  it('mocks internal engine', () => {
    expect(1).toBe(1 + 0);
  });
});`
  );

  // Plant 9: snapshot-only
  fs.writeFileSync(
    path.join(tempDir, 'fake-snapshot-only.test.ts'),
    `import { describe, it, expect } from 'vitest';
describe('Fake Suite', () => {
  it('snapshot only test', () => {
    expect({ val: 123 }).toMatchSnapshot();
  });
});`
  );

  // Plant 10: async-missing-await
  fs.writeFileSync(
    path.join(tempDir, 'fake-async-no-await.test.ts'),
    `import { describe, it, expect } from 'vitest';
describe('Fake Suite', () => {
  it('async test without await', async () => {
    const res = 42;
    expect(res).toBe(42);
  });
});`
  );

  // Plant 11: unfaked-timer
  fs.writeFileSync(
    path.join(tempDir, 'fake-unfaked-timer.test.ts'),
    `import { describe, it, expect } from 'vitest';
describe('Fake Suite', () => {
  it('asserts on real elapsed time', () => {
    const start = Date.now();
    for (let i = 0; i < 1000; i++) {}
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(100);
  });
});`
  );

  console.log('Running verify-test-integrity against planted test directory: ' + tempDir);
  const report = runIntegrityAudit([tempDir]);

  console.log('Auditor Results on Plants:');
  console.log('- Total Scanned Files: ' + report.scannedFiles);
  console.log('- Total Violations Caught: ' + report.totalViolations);
  console.log('\nCategory Catch Verification:');

  const expectedCategories = [
    'zero-assertions',
    'tautology',
    'weak-only',
    'skip-only-todo',
    'commented-assertion',
    'swallowed-catch',
    'prod-constant-expected',
    'forbidden-mock',
    'snapshot-only',
    'async-missing-await',
    'unfaked-timer',
  ];

  let allCaught = true;
  for (const cat of expectedCategories) {
    const count = report.violationsByCategory[cat] || 0;
    const caught = count > 0;
    console.log(`  [${caught ? 'PASS' : 'FAIL'}] Category '${cat}': caught ${count} instance(s)`);
    if (!caught) allCaught = false;
  }

  if (!allCaught) {
    console.error('\n❌ Auditor failed to catch all planted fake test categories!');
    process.exit(1);
  } else {
    console.log(
      '\n✔ PROOF SUCCESSFUL: Auditor caught 100% of planted fake tests across all 11 categories.'
    );
  }
} finally {
  // Always clean up temp dir
  fs.rmSync(tempDir, { recursive: true, force: true });
  console.log('\nCleaned up and deleted all planted fake test fixtures.');
}
