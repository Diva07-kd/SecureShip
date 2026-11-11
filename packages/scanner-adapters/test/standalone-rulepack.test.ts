import { describe, it, expect } from 'vitest';
import path from 'node:path';
import { resolveDefaultRulePack } from '../src/adapters/opengrep.adapter.js';

describe('B8: Opengrep resolveDefaultRulePack Priority & Standalone Resolution', () => {
  it('config.defaultRulePath wins over every candidate directory', () => {
    const customRulePath = path.resolve('/custom/rules/pack');
    const fakeModuleDir = path.resolve('/opt/module');
    const fakeCwd = path.resolve('/opt/cwd');
    const fakeExecDir = path.resolve('/opt/exec');

    const resolved = resolveDefaultRulePack(
      { defaultRulePath: customRulePath },
      {
        moduleDir: fakeModuleDir,
        cwd: fakeCwd,
        execDir: fakeExecDir,
        exists: () => true,
      }
    );

    expect(resolved).toBe(customRulePath);
  });

  it('table-driven priority: lowest-numbered existing candidate wins', () => {
    const fakeModuleDir = path.resolve('/opt/module');
    const fakeCwd = path.resolve('/opt/cwd');
    const fakeExecDir = path.resolve('/opt/exec');

    const candidates = [
      path.resolve(fakeModuleDir, 'rules/secureship-sast'),
      path.resolve(fakeModuleDir, '../rules/secureship-sast'),
      path.resolve(fakeModuleDir, '../../rules/secureship-sast'),
      path.resolve(fakeModuleDir, '../../../../rules/secureship-sast'),
      path.resolve(fakeExecDir, 'rules/secureship-sast'),
    ];

    for (let winnerIdx = 0; winnerIdx < candidates.length; winnerIdx++) {
      const existing = new Set(candidates.slice(winnerIdx));
      // Also add cwd fallback to existing set
      existing.add(path.resolve(fakeCwd, 'rules/secureship-sast'));

      const resolved = resolveDefaultRulePack(
        {},
        {
          moduleDir: fakeModuleDir,
          cwd: fakeCwd,
          execDir: fakeExecDir,
          exists: (p) => existing.has(path.resolve(p)),
        }
      );

      expect(resolved).toBe(candidates[winnerIdx]);
    }
  });

  it('execDir candidate wins over cwd fallback when module candidates are absent', () => {
    const fakeModuleDir = path.resolve('/nonexistent/module');
    const fakeCwd = path.resolve('/unrelated/cwd');
    const fakeExecDir = path.resolve('/opt/secureship');
    const execRulePath = path.resolve(fakeExecDir, 'rules/secureship-sast');
    const cwdRulePath = path.resolve(fakeCwd, 'rules/secureship-sast');

    const resolved = resolveDefaultRulePack(
      {},
      {
        moduleDir: fakeModuleDir,
        cwd: fakeCwd,
        execDir: fakeExecDir,
        exists: (p) => {
          const resolvedP = path.resolve(p);
          return resolvedP === execRulePath || resolvedP === cwdRulePath;
        },
      }
    );

    expect(resolved).toBe(execRulePath);
  });

  it('returns legacy cwd fallback when nothing exists on disk', () => {
    const fakeModuleDir = path.resolve('/nonexistent/module');
    const fakeCwd = path.resolve('/unrelated/cwd');
    const fakeExecDir = path.resolve('/nonexistent/exec');
    const cwdFallback = path.resolve(fakeCwd, 'rules/secureship-sast');

    const resolved = resolveDefaultRulePack(
      {},
      {
        moduleDir: fakeModuleDir,
        cwd: fakeCwd,
        execDir: fakeExecDir,
        exists: () => false,
      }
    );

    expect(resolved).toBe(cwdFallback);
  });

  it('omits execDir candidate when execDir is null', () => {
    const fakeModuleDir = path.resolve('/nonexistent/module');
    const fakeCwd = path.resolve('/unrelated/cwd');
    const checkedPaths: string[] = [];

    const resolved = resolveDefaultRulePack(
      {},
      {
        moduleDir: fakeModuleDir,
        cwd: fakeCwd,
        execDir: null,
        exists: (p) => {
          checkedPaths.push(path.resolve(p));
          return false;
        },
      }
    );

    expect(resolved).toBe(path.resolve(fakeCwd, 'rules/secureship-sast'));
    expect(checkedPaths.some((p) => p.includes('null'))).toBe(false);
  });
});
