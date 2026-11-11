import pc from 'picocolors';
import { BinaryResolver, getDefaultToolDir } from '@secureship/scanner-adapters';
import { InstallToolsCommand, type ToolName } from '../commands/install-tools.js';

export interface BootstrapOptions {
  silent?: boolean;
  offline?: boolean;
  force?: boolean;
  targetDir?: string;
}

export class EngineBootstrapper {
  public static readonly CORE_ENGINES: ToolName[] = [
    'opengrep',
    'gitleaks',
    'trivy',
    'osv-scanner',
  ];

  /**
   * Identifies which core security engines are not yet available on PATH or in ~/.secureship/bin
   */
  public static getMissingEngines(targetDir: string = process.cwd()): ToolName[] {
    const missing: ToolName[] = [];
    for (const tool of EngineBootstrapper.CORE_ENGINES) {
      let resolved = BinaryResolver.resolve(tool, targetDir);
      if (!resolved && tool === 'opengrep') {
        resolved = BinaryResolver.resolve('semgrep', targetDir);
      }
      if (!resolved) {
        missing.push(tool);
      }
    }
    return missing;
  }

  /**
   * Automatically provisions missing core engines into ~/.secureship/bin
   * without requiring manual developer downloads.
   */
  public static async autoProvision(options: BootstrapOptions = {}): Promise<boolean> {
    if (options.offline) {
      return false;
    }

    const missing = EngineBootstrapper.getMissingEngines(options.targetDir);
    if (missing.length === 0) {
      return true;
    }

    const binDir = getDefaultToolDir();

    if (!options.silent) {
      console.log(
        pc.cyan(
          `\n⚙ [SecureShip Auto-Bootstrap] Provisioning ${missing.length} missing security sub-engines...`
        )
      );
    }

    try {
      const exitCode = await InstallToolsCommand.run({
        tools: missing,
        dir: binDir,
        force: options.force ?? false,
        json: false,
        silent: options.silent ?? true,
      });
      return exitCode === 0;
    } catch {
      return false;
    }
  }
}
