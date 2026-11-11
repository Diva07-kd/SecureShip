import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/extension.ts'],
  format: ['cjs'],
  outDir: 'dist',
  clean: true,
  bundle: true,
  external: ['vscode'],
  sourcemap: true,
  minify: false,
  target: 'node18',
  shims: false,
});
