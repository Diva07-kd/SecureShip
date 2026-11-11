import fs from 'node:fs';
import path from 'node:path';
import type { SandboxConfig } from '@secureship/contracts';

export interface DetectedStageCommand {
  command: string;
  args: string[];
}

export interface DetectedProjectCommands {
  typecheck?: DetectedStageCommand;
  build?: DetectedStageCommand;
  test?: DetectedStageCommand;
}

export class CommandDetector {
  /**
   * Detects typecheck, build, and test commands for a repository.
   * Respects user config overrides, and rejects any commands with --watch.
   */
  public static detect(shadowDir: string, config?: SandboxConfig): DetectedProjectCommands {
    const result: DetectedProjectCommands = {};

    // 1. Check user config overrides first
    if (config?.commands) {
      if (config.commands.typecheck && config.commands.typecheck.length > 0) {
        result.typecheck = {
          command: config.commands.typecheck[0]!,
          args: config.commands.typecheck.slice(1),
        };
      }
      if (config.commands.build && config.commands.build.length > 0) {
        result.build = {
          command: config.commands.build[0]!,
          args: config.commands.build.slice(1),
        };
      }
      if (config.commands.test && config.commands.test.length > 0) {
        result.test = {
          command: config.commands.test[0]!,
          args: config.commands.test.slice(1),
        };
      }
    }

    // 2. JS/Node Detection (package.json)
    const pkgJsonPath = path.join(shadowDir, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      try {
        const raw = fs.readFileSync(pkgJsonPath, 'utf8');
        const pkg = JSON.parse(raw);
        const scripts = pkg.scripts || {};

        let pm = 'npm';
        if (fs.existsSync(path.join(shadowDir, 'pnpm-lock.yaml'))) {
          pm = 'pnpm';
        } else if (fs.existsSync(path.join(shadowDir, 'yarn.lock'))) {
          pm = 'yarn';
        } else if (fs.existsSync(path.join(shadowDir, 'bun.lockb'))) {
          pm = 'bun';
        }

        if (!result.typecheck) {
          if (scripts.typecheck && !scripts.typecheck.includes('--watch')) {
            result.typecheck = { command: pm, args: ['run', 'typecheck'] };
          } else if (fs.existsSync(path.join(shadowDir, 'tsconfig.json'))) {
            result.typecheck = { command: 'npx', args: ['tsc', '--noEmit'] };
          }
        }

        if (!result.build) {
          if (scripts.build && !scripts.build.includes('--watch')) {
            result.build = { command: pm, args: ['run', 'build'] };
          }
        }

        if (!result.test) {
          if (scripts.test && !scripts.test.includes('--watch')) {
            // Avoid placeholder "echo \"Error: no test specified\" && exit 1"
            if (!scripts.test.includes('no test specified')) {
              result.test = { command: pm, args: ['test'] };
            }
          }
        }
      } catch {
        // Fall through
      }
    }

    // 3. Python Detection (pyproject.toml, requirements.txt, setup.py)
    const hasPyproject = fs.existsSync(path.join(shadowDir, 'pyproject.toml'));
    const hasSetupPy = fs.existsSync(path.join(shadowDir, 'setup.py'));
    const hasRequirements = fs.existsSync(path.join(shadowDir, 'requirements.txt'));
    const hasTestsDir =
      fs.existsSync(path.join(shadowDir, 'tests')) || fs.existsSync(path.join(shadowDir, 'test'));

    if (hasPyproject || hasSetupPy || hasRequirements) {
      if (!result.build) {
        result.build = { command: 'python', args: ['-m', 'compileall', '-q', '.'] };
      }

      if (!result.test && hasTestsDir) {
        result.test = { command: 'python', args: ['-m', 'pytest', '-x', '-q'] };
      }
    }

    // 4. Go Detection (go.mod)
    if (fs.existsSync(path.join(shadowDir, 'go.mod'))) {
      if (!result.typecheck) {
        result.typecheck = { command: 'go', args: ['vet', './...'] };
      }
      if (!result.build) {
        result.build = { command: 'go', args: ['build', './...'] };
      }
      if (!result.test) {
        result.test = { command: 'go', args: ['test', './...'] };
      }
    }

    // 5. Rust Detection (Cargo.toml)
    if (fs.existsSync(path.join(shadowDir, 'Cargo.toml'))) {
      if (!result.typecheck) {
        result.typecheck = { command: 'cargo', args: ['check'] };
      }
      if (!result.build) {
        result.build = { command: 'cargo', args: ['build'] };
      }
      if (!result.test) {
        result.test = { command: 'cargo', args: ['test'] };
      }
    }

    // 6. Java / JVM Detection (Maven pom.xml or Gradle build.gradle)
    if (fs.existsSync(path.join(shadowDir, 'pom.xml'))) {
      if (!result.build) {
        result.build = { command: 'mvn', args: ['compile'] };
      }
      if (!result.test) {
        result.test = { command: 'mvn', args: ['test'] };
      }
    } else if (
      fs.existsSync(path.join(shadowDir, 'build.gradle')) ||
      fs.existsSync(path.join(shadowDir, 'build.gradle.kts'))
    ) {
      if (!result.build) {
        result.build = { command: 'gradle', args: ['classes'] };
      }
      if (!result.test) {
        result.test = { command: 'gradle', args: ['test'] };
      }
    }

    // 7. .NET / C# Detection (*.csproj, *.sln, *.fsproj)
    try {
      const files = fs.readdirSync(shadowDir);
      const hasDotnet = files.some(
        (f) => f.endsWith('.csproj') || f.endsWith('.sln') || f.endsWith('.fsproj')
      );
      if (hasDotnet) {
        if (!result.build) {
          result.build = { command: 'dotnet', args: ['build'] };
        }
        if (!result.test) {
          result.test = { command: 'dotnet', args: ['test'] };
        }
      }
    } catch {
      // Ignore directory read failure
    }

    // 8. Ruby Detection (Gemfile)
    if (fs.existsSync(path.join(shadowDir, 'Gemfile'))) {
      if (!result.test) {
        result.test = { command: 'bundle', args: ['exec', 'rake', 'test'] };
      }
    }

    return result;
  }
}
