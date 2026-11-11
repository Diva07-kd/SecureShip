import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { CommandDetector } from '../src/detector/command-detector.js';
import { SandboxConfigSchema } from '@secureship/contracts';

describe('CommandDetector Project Command Resolution', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secureship-detector-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('detects Node scripts from package.json and tsconfig.json', () => {
    fs.writeFileSync(
      path.join(tempDir, 'package.json'),
      JSON.stringify({
        scripts: {
          typecheck: 'tsc --noEmit',
          build: 'tsup src/index.ts',
          test: 'vitest run',
        },
      })
    );

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.typecheck).toEqual({ command: 'npm', args: ['run', 'typecheck'] });
    expect(cmds.build).toEqual({ command: 'npm', args: ['run', 'build'] });
    expect(cmds.test).toEqual({ command: 'npm', args: ['test'] });
  });

  it('rejects scripts containing --watch to prevent hanging', () => {
    fs.writeFileSync(
      path.join(tempDir, 'package.json'),
      JSON.stringify({
        scripts: {
          test: 'jest --watch',
          build: 'rollup -c --watch',
        },
      })
    );

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.test).toBeUndefined();
    expect(cmds.build).toBeUndefined();
  });

  it('falls back to npx tsc when tsconfig.json exists without typecheck script', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ scripts: {} }));
    fs.writeFileSync(path.join(tempDir, 'tsconfig.json'), '{}');

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.typecheck).toEqual({ command: 'npx', args: ['tsc', '--noEmit'] });
  });

  it('detects Python compileall and pytest commands', () => {
    fs.writeFileSync(path.join(tempDir, 'pyproject.toml'), '[project]\nname = "test"');
    fs.mkdirSync(path.join(tempDir, 'tests'), { recursive: true });

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.build).toEqual({ command: 'python', args: ['-m', 'compileall', '-q', '.'] });
    expect(cmds.test).toEqual({ command: 'python', args: ['-m', 'pytest', '-x', '-q'] });
  });

  it('honors user config command overrides', () => {
    fs.writeFileSync(
      path.join(tempDir, 'package.json'),
      JSON.stringify({
        scripts: { test: 'npm test' },
      })
    );

    const config = SandboxConfigSchema.parse({
      commands: {
        test: ['pnpm', 'run', 'custom-test'],
      },
    });

    const cmds = CommandDetector.detect(tempDir, config);
    expect(cmds.test).toEqual({ command: 'pnpm', args: ['run', 'custom-test'] });
  });

  it('detects pnpm commands when pnpm-lock.yaml is present', () => {
    fs.writeFileSync(
      path.join(tempDir, 'package.json'),
      JSON.stringify({
        scripts: {
          typecheck: 'tsc --noEmit',
          build: 'vite build',
          test: 'vitest run',
        },
      })
    );
    fs.writeFileSync(path.join(tempDir, 'pnpm-lock.yaml'), 'lockfileVersion: "9.0"');

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.typecheck).toEqual({ command: 'pnpm', args: ['run', 'typecheck'] });
    expect(cmds.build).toEqual({ command: 'pnpm', args: ['run', 'build'] });
    expect(cmds.test).toEqual({ command: 'pnpm', args: ['test'] });
  });

  it('detects Go build and test commands when go.mod is present', () => {
    fs.writeFileSync(path.join(tempDir, 'go.mod'), 'module example.com/myapp\n\ngo 1.22\n');

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.typecheck).toEqual({ command: 'go', args: ['vet', './...'] });
    expect(cmds.build).toEqual({ command: 'go', args: ['build', './...'] });
    expect(cmds.test).toEqual({ command: 'go', args: ['test', './...'] });
  });

  it('detects Rust cargo commands when Cargo.toml is present', () => {
    fs.writeFileSync(
      path.join(tempDir, 'Cargo.toml'),
      '[package]\nname = "mycrate"\nversion = "0.1.0"'
    );

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.typecheck).toEqual({ command: 'cargo', args: ['check'] });
    expect(cmds.build).toEqual({ command: 'cargo', args: ['build'] });
    expect(cmds.test).toEqual({ command: 'cargo', args: ['test'] });
  });

  it('detects Java Maven commands when pom.xml is present', () => {
    fs.writeFileSync(path.join(tempDir, 'pom.xml'), '<project></project>');

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.build).toEqual({ command: 'mvn', args: ['compile'] });
    expect(cmds.test).toEqual({ command: 'mvn', args: ['test'] });
  });

  it('detects Java Gradle commands when build.gradle is present', () => {
    fs.writeFileSync(path.join(tempDir, 'build.gradle'), 'plugins { id "java" }');

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.build).toEqual({ command: 'gradle', args: ['classes'] });
    expect(cmds.test).toEqual({ command: 'gradle', args: ['test'] });
  });

  it('detects .NET commands when csproj file is present', () => {
    fs.writeFileSync(
      path.join(tempDir, 'App.csproj'),
      '<Project Sdk="Microsoft.NET.Sdk"></Project>'
    );

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.build).toEqual({ command: 'dotnet', args: ['build'] });
    expect(cmds.test).toEqual({ command: 'dotnet', args: ['test'] });
  });

  it('detects Ruby test command when Gemfile is present', () => {
    fs.writeFileSync(path.join(tempDir, 'Gemfile'), 'source "https://rubygems.org"');

    const cmds = CommandDetector.detect(tempDir);
    expect(cmds.test).toEqual({ command: 'bundle', args: ['exec', 'rake', 'test'] });
  });
});
