import { defineConfig } from 'tsup';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8')) as {
  version: string;
};

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm'],
  target: 'node20',
  outDir: 'dist',
  clean: true,
  sourcemap: true,
  dts: true,
  noExternal: [
    '@secureship/contracts',
    '@secureship/core-engine',
    '@secureship/reachability',
    '@secureship/ai',
    '@secureship/context-slicer',
    '@secureship/patch-engine',
    '@secureship/sandbox',
    '@secureship/scanner-adapters',
    '@secureship/fleet',
  ],
  define: {
    __CLI_VERSION__: JSON.stringify(pkg.version),
  },
  banner: {
    js: '#!/usr/bin/env node',
  },
});
