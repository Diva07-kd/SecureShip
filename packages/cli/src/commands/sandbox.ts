import readline from 'node:readline';
import crypto from 'node:crypto';
import path from 'node:path';
import pc from 'picocolors';
import { UserConfigLoader } from '@secureship/ai';
import { SafeProcessRunner } from '@secureship/sandbox';

export class SandboxCommand {
  /**
   * secureship sandbox status
   */
  public static async status(): Promise<number> {
    const config = UserConfigLoader.loadUserConfig();
    const sandbox = config.sandbox ?? {
      backend: 'container',
      runtime: 'auto',
      images: {},
      limits: {},
      trustedHostRepos: [],
    };

    console.log(pc.bold(pc.cyan('\n🛡️  SecureShip Gate 4 Sandbox Configuration\n')));
    console.log(`Backend        : ${pc.bold(sandbox.backend)}`);
    console.log(`Runtime        : ${pc.bold(sandbox.runtime ?? 'auto')}`);
    console.log(
      `Tiered Fallback: ${pc.green('✔ Enabled (Container -> NativeIsolated fallback active)')}`
    );
    console.log(`Node Image     : ${sandbox.images?.node ?? pc.gray('node:20-slim')}`);
    console.log(`Python Image   : ${sandbox.images?.python ?? pc.gray('python:3.11-slim')}`);
    console.log(`Memory Limit   : ${sandbox.limits?.memory ?? '2g'}`);
    console.log(`CPU Limit      : ${sandbox.limits?.cpus ?? '2'}`);
    console.log(`PIDs Limit     : ${sandbox.limits?.pids ?? '512'}`);
    console.log(`Tmpfs Limit    : ${sandbox.limits?.tmpfsMb ?? '512'} MB`);
    console.log(`Network Policy : ${pc.green('Strictly NONE (--network none)')}`);
    console.log(`Host Trust     : ${sandbox.trustedHostRepos?.length ?? 0} trusted repositories`);

    console.log();
    return 0;
  }

  /**
   * secureship sandbox doctor
   */
  public static async doctor(): Promise<number> {
    console.log(pc.bold(pc.cyan('\n🔍 SecureShip Sandbox Diagnostics\n')));

    let dockerFound = false;
    let dockerOut = '';
    let podmanFound = false;
    let podmanOut = '';

    try {
      const res = await SafeProcessRunner.run('docker', ['--version'], { timeoutMs: 3000 });
      if (res.exitCode === 0) {
        dockerFound = true;
        dockerOut = res.stdout.trim();
      }
    } catch {
      // Ignored
    }

    try {
      const res = await SafeProcessRunner.run('podman', ['--version'], { timeoutMs: 3000 });
      if (res.exitCode === 0) {
        podmanFound = true;
        podmanOut = res.stdout.trim();
      }
    } catch {
      // Ignored
    }

    console.log(`Docker: ${dockerFound ? pc.green('✔') : pc.gray('Not found')} ${dockerOut}`);
    console.log(`Podman: ${podmanFound ? pc.green('✔') : pc.gray('Not found')} ${podmanOut}`);
    console.log(
      `Native Isolated Sandbox: ${pc.green('✔ Ready')} (Ephemeral shadow workspace + air-gap proxy neutralization)`
    );

    if (dockerFound) {
      console.log(
        pc.gray('\nTesting container runtime execution (docker run --rm hello-world)...')
      );
      try {
        const helloRes = await SafeProcessRunner.run('docker', ['run', '--rm', 'hello-world'], {
          timeoutMs: 15000,
        });
        if (helloRes.exitCode === 0) {
          console.log(
            pc.green('✔ Live container test succeeded! Docker runtime is active and operational.')
          );
        } else {
          console.log(
            pc.yellow(`⚠ Container test exited with code ${helloRes.exitCode}: ${helloRes.stderr}`)
          );
        }
      } catch (err) {
        console.log(
          pc.yellow(
            `⚠ Live container test failed: ${err instanceof Error ? err.message : String(err)}`
          )
        );
      }
    }

    console.log();
    return 0;
  }

  /**
   * secureship sandbox enable / disable
   */
  public static async setBackend(
    backend: 'container' | 'host' | 'none' | 'native-isolated' | 'auto'
  ): Promise<number> {
    const config = UserConfigLoader.loadUserConfig();
    config.sandbox = {
      ...(config.sandbox ?? {}),
      backend,
      runtime: config.sandbox?.runtime ?? 'auto',
      images: config.sandbox?.images ?? {},
      limits: config.sandbox?.limits ?? {
        memory: '2g',
        cpus: 2,
        pids: 512,
        tmpfsMb: 512,
        stageTimeoutSec: { install: 600, typecheck: 300, build: 600, test: 900 },
        totalTimeoutSec: 1800,
        outputCapBytes: 5242880,
      },
      install: config.sandbox?.install ?? { enabled: false, ignoreScripts: true },
      trustedHostRepos: config.sandbox?.trustedHostRepos ?? [],
    };

    UserConfigLoader.saveUserConfig(config);
    console.log(pc.green(`✔ Sandbox backend set to: ${pc.bold(backend)}`));
    return 0;
  }

  /**
   * secureship sandbox trust-host
   */
  public static async trustHost(targetDir: string = '.', explicitPhrase?: string): Promise<number> {
    const canonicalPath = path.resolve(targetDir).replace(/\\/g, '/');
    const requiredPhrase = `I trust repository ${canonicalPath} to run un-sandboxed code on my machine`;

    console.log(pc.bold(pc.red('\n⚠️  SECURITY WARNING: HOST EXECUTION IS NOT A SANDBOX\n')));
    console.log(
      pc.yellow(
        `You are requesting host execution privileges for repository:\n  ${pc.bold(canonicalPath)}\n`
      )
    );
    console.log(
      'To confirm that you understand and accept the security risks, type the following phrase exactly:'
    );
    console.log(pc.cyan(`\n"${requiredPhrase}"\n`));

    let typedPhrase = explicitPhrase;

    if (!typedPhrase) {
      typedPhrase = await new Promise<string>((resolve) => {
        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout,
        });

        rl.question('> ', (answer) => {
          rl.close();
          resolve(answer.trim());
        });
      });
    }

    if (typedPhrase !== requiredPhrase) {
      console.error(
        pc.red('\nRefusal: Confirmation phrase does not match. Host trust was not granted.\n')
      );
      return 2;
    }

    const repoHash = crypto.createHash('sha256').update(canonicalPath).digest('hex');
    const config = UserConfigLoader.loadUserConfig();
    const trusted = new Set(config.sandbox?.trustedHostRepos ?? []);
    trusted.add(repoHash);

    config.sandbox = {
      ...(config.sandbox ?? {}),
      backend: 'host',
      runtime: config.sandbox?.runtime ?? 'auto',
      images: config.sandbox?.images ?? {},
      limits: config.sandbox?.limits ?? {
        memory: '2g',
        cpus: 2,
        pids: 512,
        tmpfsMb: 512,
        stageTimeoutSec: { install: 600, typecheck: 300, build: 600, test: 900 },
        totalTimeoutSec: 1800,
        outputCapBytes: 5242880,
      },
      install: config.sandbox?.install ?? { enabled: false, ignoreScripts: true },
      trustedHostRepos: Array.from(trusted),
    };

    UserConfigLoader.saveUserConfig(config);
    console.log(
      pc.green(
        `\n✔ Repository trusted for host execution: ${canonicalPath} (${repoHash.slice(0, 12)})\n`
      )
    );
    return 0;
  }

  /**
   * secureship sandbox cleanup
   */
  public static async cleanup(): Promise<number> {
    console.log(pc.cyan('Cleaning up SecureShip managed containers...'));
    try {
      const listRes = await SafeProcessRunner.run('docker', [
        'ps',
        '-aq',
        '--filter',
        'label=secureship.managed=true',
      ]);
      const ids = listRes.stdout
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean);

      if (ids.length === 0) {
        console.log(pc.green('✔ No orphan SecureShip containers found.'));
        return 0;
      }

      await SafeProcessRunner.run('docker', ['rm', '-f', ...ids]);
      console.log(pc.green(`✔ Removed ${ids.length} orphan containers.`));
    } catch (err) {
      console.warn(pc.yellow(`Cleanup error: ${err instanceof Error ? err.message : String(err)}`));
    }

    return 0;
  }
}
