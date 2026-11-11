import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { TsConfigResolver } from '../src/js/tsconfig-resolver.js';

describe('TsConfigResolver Unit Suite', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(
      os.tmpdir(),
      `secureship-tsconfig-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  it('returns empty object when tsconfig.json does not exist', () => {
    const res = TsConfigResolver.load(tmpDir);
    expect(res).toEqual({});
  });

  it('rejects customConfigPath that escapes the project root', () => {
    const parentDir = path.dirname(tmpDir);
    const outsideConfig = path.join(parentDir, 'outside-tsconfig.json');
    fs.writeFileSync(outsideConfig, JSON.stringify({ compilerOptions: {} }));

    const res = TsConfigResolver.load(tmpDir, '../outside-tsconfig.json');
    expect(res).toEqual({});
    try {
      fs.unlinkSync(outsideConfig);
    } catch {}
  });

  it('parses comments in tsconfig.json correctly', () => {
    const tsconfig = `{
      // Single line comment
      /* Multi
         line comment */
      "compilerOptions": {
        "baseUrl": "./src",
        "paths": {
          "@components/*": ["components/*"],
          "@utils": ["utils/index.ts"]
        }
      }
    }`;
    fs.writeFileSync(path.join(tmpDir, 'tsconfig.json'), tsconfig);

    const res = TsConfigResolver.load(tmpDir);
    expect(res.baseUrl).toBe(path.resolve(tmpDir, 'src'));
    expect(res.paths?.['@components/*']).toEqual(['components/*']);
    expect(res.paths?.['@utils']).toEqual(['utils/index.ts']);
  });

  it('resets baseUrl to realRoot if baseUrl escapes root', () => {
    const tsconfig = JSON.stringify({
      compilerOptions: {
        baseUrl: '../../outside',
      },
    });
    fs.writeFileSync(path.join(tmpDir, 'tsconfig.json'), tsconfig);

    const res = TsConfigResolver.load(tmpDir);
    expect(res.baseUrl).toBe(fs.realpathSync(tmpDir));
  });

  it('resolves alias with wildcard * pattern and exact match pattern', () => {
    fs.mkdirSync(path.join(tmpDir, 'src', 'components'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'src', 'components', 'Button.tsx'),
      'export const Button = () => {};'
    );

    const config = {
      baseUrl: path.join(tmpDir, 'src'),
      paths: {
        '@components/*': ['components/*'],
        '@btn': ['components/Button.tsx'],
      },
    };

    const wildResolved = TsConfigResolver.resolveAlias('@components/Button.tsx', config, tmpDir);
    expect(wildResolved).toBe(path.resolve(tmpDir, 'src', 'components', 'Button.tsx'));

    const exactResolved = TsConfigResolver.resolveAlias('@btn', config, tmpDir);
    expect(exactResolved).toBe(path.resolve(tmpDir, 'src', 'components', 'Button.tsx'));

    const unmapped = TsConfigResolver.resolveAlias('@other/foo', config, tmpDir);
    expect(unmapped).toBeNull();
  });

  it('resolves direct baseUrl specifiers when baseUrl is set and not projectRoot', () => {
    fs.mkdirSync(path.join(tmpDir, 'src', 'helpers'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'src', 'helpers', 'format.ts'), 'export const fmt = 1;');

    const config = {
      baseUrl: path.join(tmpDir, 'src'),
    };

    const resolved = TsConfigResolver.resolveAlias('helpers/format.ts', config, tmpDir);
    expect(resolved).toBe(path.resolve(tmpDir, 'src', 'helpers', 'format.ts'));
  });
});
