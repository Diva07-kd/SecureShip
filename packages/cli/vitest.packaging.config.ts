import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '../..');

export default defineConfig({
  resolve: {
    alias: {
      '@secureship/contracts': path.resolve(repoRoot, 'packages/contracts/src/index.ts'),
      '@secureship/reachability': path.resolve(repoRoot, 'packages/reachability/src/index.ts'),
      '@secureship/sandbox': path.resolve(repoRoot, 'packages/sandbox/src/index.ts'),
      '@secureship/ai/testing': path.resolve(repoRoot, 'packages/ai/src/testing/fake.provider.ts'),
      '@secureship/ai': path.resolve(repoRoot, 'packages/ai/src/index.ts'),
      '@secureship/context-slicer': path.resolve(repoRoot, 'packages/context-slicer/src/index.ts'),
      '@secureship/patch-engine': path.resolve(repoRoot, 'packages/patch-engine/src/index.ts'),
      '@secureship/scanner-adapters': path.resolve(
        repoRoot,
        'packages/scanner-adapters/src/index.ts'
      ),
      '@secureship/core-engine': path.resolve(repoRoot, 'packages/core-engine/src/index.ts'),
      '@secureship/fleet': path.resolve(repoRoot, 'packages/fleet/src/index.ts'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
    setupFiles: [path.resolve(repoRoot, 'vitest.setup.ts')],
    include: ['test/packaging/**/*.test.ts', 'packages/cli/test/packaging/**/*.test.ts'],
    testTimeout: 60000,
    fileParallelism: false,
  },
});
