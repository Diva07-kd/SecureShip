import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { EntrypointDetector } from '../src/entrypoints/entrypoint-detector.js';

describe('EntrypointDetector Comprehensive Suite', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(
      os.tmpdir(),
      `secureship-entrypoint-test-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  it('detects userConfigEntrypoints and separates resolved from unresolved', () => {
    const validFile = path.join(tmpDir, 'custom.ts');
    fs.writeFileSync(validFile, 'console.log("custom");');

    const result = EntrypointDetector.detect(tmpDir, ['custom.ts', 'missing.ts']);
    expect(result.entrypoints).toContain(path.resolve(validFile));
    expect(result.unresolvedEntrypoints).toContain('missing.ts');
  });

  it('maps package.json main, module, bin and exports back to source via tsconfig outDir', () => {
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'src', 'index.ts'), 'export const a = 1;');
    fs.writeFileSync(path.join(tmpDir, 'src', 'cli.ts'), 'console.log("cli");');
    fs.writeFileSync(path.join(tmpDir, 'src', 'extra.ts'), 'export const b = 2;');

    fs.writeFileSync(
      path.join(tmpDir, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: {
          outDir: './dist',
          rootDir: './src',
        },
      })
    );

    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'test-lib',
        main: './dist/index.js',
        module: './dist/index.mjs',
        bin: {
          mycli: './dist/cli.js',
        },
        exports: {
          '.': './dist/index.js',
          './extra': {
            import: './dist/extra.js',
            require: './dist/extra.cjs',
            default: './dist/extra.js',
          },
        },
      })
    );

    const result = EntrypointDetector.detect(tmpDir);
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'src', 'index.ts'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'src', 'cli.ts'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'src', 'extra.ts'));
  });

  it('detects string bin in package.json', () => {
    fs.writeFileSync(path.join(tmpDir, 'run.js'), 'console.log("run");');
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'cli-pkg',
        bin: './run.js',
      })
    );

    const result = EntrypointDetector.detect(tmpDir);
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'run.js'));
  });

  it('records unresolved entrypoints when package.json main/exports do not exist', () => {
    fs.writeFileSync(
      path.join(tmpDir, 'package.json'),
      JSON.stringify({
        name: 'ghost-pkg',
        main: './dist/ghost.js',
      })
    );

    const result = EntrypointDetector.detect(tmpDir);
    expect(result.unresolvedEntrypoints).toContain('./dist/ghost.js');
  });

  it('detects HTML <script src="..."> tags', () => {
    fs.writeFileSync(path.join(tmpDir, 'app.js'), 'console.log("app");');
    fs.writeFileSync(
      path.join(tmpDir, 'index.html'),
      '<!DOCTYPE html><html><body><script src="./app.js"></script><script src="https://cdn.example.com/lib.js"></script></body></html>'
    );

    const result = EntrypointDetector.detect(tmpDir);
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'app.js'));
  });

  it('detects Next.js and Remix framework conventions', () => {
    fs.mkdirSync(path.join(tmpDir, 'pages'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'app'), { recursive: true });

    fs.writeFileSync(
      path.join(tmpDir, 'pages', 'index.tsx'),
      'export default () => <div>Home</div>;'
    );
    fs.writeFileSync(
      path.join(tmpDir, 'app', 'layout.tsx'),
      'export default () => <div>Layout</div>;'
    );
    fs.writeFileSync(path.join(tmpDir, 'app', 'page.tsx'), 'export default () => <div>Page</div>;');

    const result = EntrypointDetector.detect(tmpDir);
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'pages', 'index.tsx'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'app', 'layout.tsx'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'app', 'page.tsx'));
  });

  it('detects Python entrypoints (__main__.py, pyproject.toml scripts, setup.py, manage.py, app.py, wsgi, asgi)', () => {
    fs.mkdirSync(path.join(tmpDir, 'mypkg'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, '__main__.py'), 'print("main")');
    fs.writeFileSync(path.join(tmpDir, 'mypkg', '__init__.py'), '# init');
    fs.writeFileSync(path.join(tmpDir, 'manage.py'), '# django');
    fs.writeFileSync(path.join(tmpDir, 'app.py'), '# flask/fastapi');
    fs.writeFileSync(path.join(tmpDir, 'wsgi.py'), '# wsgi');
    fs.writeFileSync(path.join(tmpDir, 'asgi.py'), '# asgi');

    fs.writeFileSync(
      path.join(tmpDir, 'pyproject.toml'),
      `[project.scripts]
my-cli = "mypkg.cli:main"
`
    );
    fs.writeFileSync(path.join(tmpDir, 'mypkg', 'cli.py'), 'def main(): pass');

    const result = EntrypointDetector.detect(tmpDir);
    expect(result.entrypoints).toContain(path.resolve(tmpDir, '__main__.py'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'mypkg', '__init__.py'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'manage.py'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'app.py'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'wsgi.py'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'asgi.py'));
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'mypkg', 'cli.py'));
  });

  it('detects Dockerfile CMD / ENTRYPOINT targets', () => {
    fs.writeFileSync(path.join(tmpDir, 'server.js'), 'console.log("server");');
    fs.writeFileSync(
      path.join(tmpDir, 'Dockerfile'),
      `FROM node:20
WORKDIR /app
COPY . .
CMD ["node", "server.js"]
`
    );

    const result = EntrypointDetector.detect(tmpDir);
    expect(result.entrypoints).toContain(path.resolve(tmpDir, 'server.js'));
  });

  it('isTestOrMockFile accurately classifies test, mock, fixture, and spec patterns', () => {
    expect(EntrypointDetector.isTestOrMockFile('src/__tests__/foo.ts')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('tests/unit.test.js')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('src/foo.spec.tsx')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('test_service.py')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('service_test.py')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('mocks/auth.ts')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('fixtures/payload.json')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('examples/demo.ts')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('docs/guide.ts')).toBe(true);
    expect(EntrypointDetector.isTestOrMockFile('src/index.ts')).toBe(false);
    expect(EntrypointDetector.isTestOrMockFile('app/main.py')).toBe(false);
  });
});
