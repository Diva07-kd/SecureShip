import * as os from 'node:os';
import * as path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockGetConfiguration = vi.fn();
vi.mock('vscode', () => ({
  workspace: {
    getConfiguration: (...args: unknown[]) => mockGetConfiguration(...args),
  },
  window: {
    showWarningMessage: vi.fn(),
    createTerminal: vi.fn(),
  },
  env: {
    openExternal: vi.fn(),
  },
  Uri: {
    parse: vi.fn(),
  },
}));

const mockExistsSync = vi.fn();
vi.mock('node:fs', () => ({
  existsSync: (p: string) => mockExistsSync(p),
}));

const mockExecSync = vi.fn();
vi.mock('node:child_process', () => ({
  execSync: (...args: unknown[]) => mockExecSync(...args),
}));

import { findSecureShipCli } from '../src/cli/cli-locator.js';

describe('cli-locator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns user setting path when file exists', async () => {
    mockGetConfiguration.mockReturnValue({
      get: (key: string) => (key === 'cliPath' ? '/custom/secureship' : undefined),
    });
    mockExistsSync.mockImplementation((p: string) => p === '/custom/secureship');

    const result = await findSecureShipCli();

    expect(result).toBe('/custom/secureship');
  });

  it('skips invalid user setting and falls to user bin path', async () => {
    mockGetConfiguration.mockReturnValue({
      get: (key: string) => (key === 'cliPath' ? '/bad/path' : undefined),
    });

    const home = os.homedir();
    const expectedBin = path.join(home, '.secureship', 'bin');

    mockExistsSync.mockImplementation((p: string) => {
      if (p === '/bad/path') return false;
      return p.startsWith(expectedBin);
    });

    const result = await findSecureShipCli();

    expect(result).not.toBeNull();
    expect(result).toContain(expectedBin);
  });

  it('falls to PATH when user bin not found', async () => {
    mockGetConfiguration.mockReturnValue({
      get: () => '',
    });

    mockExistsSync.mockImplementation((p: string) => {
      return p === '/usr/local/bin/secureship';
    });

    mockExecSync.mockReturnValue('/usr/local/bin/secureship\n');

    const result = await findSecureShipCli();

    expect(result).toBe('/usr/local/bin/secureship');
  });

  it('returns null when all three sources fail', async () => {
    mockGetConfiguration.mockReturnValue({
      get: () => '',
    });

    mockExistsSync.mockReturnValue(false);
    mockExecSync.mockImplementation(() => {
      throw new Error('Command failed: which secureship');
    });

    const result = await findSecureShipCli();

    expect(result).toBeNull();
  });
});
