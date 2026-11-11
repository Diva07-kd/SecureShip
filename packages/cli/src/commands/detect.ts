import path from 'node:path';
import pc from 'picocolors';
import { ProjectDetector } from '@secureship/core-engine';

export interface DetectOptions {
  json?: boolean;
}

export class DetectCommand {
  public static async run(targetPath = '.', options: DetectOptions = {}): Promise<void> {
    const resolvedPath = path.resolve(targetPath);

    try {
      const profile = ProjectDetector.detect(resolvedPath);

      if (options.json) {
        console.log(JSON.stringify(profile, null, 2));
        return;
      }

      console.log(pc.bold(pc.cyan('\n📦 SecureShip Project Intelligence Profile\n')));
      console.log(`Workspace Root : ${pc.bold(profile.workspaceRoot)}`);
      console.log(
        `Git Repository : ${profile.hasGit ? pc.green('Yes') : pc.yellow('No (.git missing)')}`
      );
      console.log(`Files Scanned  : ${pc.bold(String(profile.totalFilesScanned))}`);

      // Languages
      console.log(
        `Languages      : ${
          profile.languages.length > 0
            ? profile.languages.map((l) => pc.green(l)).join(', ')
            : pc.gray('None detected')
        }`
      );

      // Package Managers
      console.log(
        `Package Mgrs   : ${
          profile.packageManagers.length > 0
            ? profile.packageManagers.map((p) => pc.cyan(p)).join(', ')
            : pc.gray('None detected')
        }`
      );

      // Lockfiles
      console.log(`Lockfiles (${profile.lockfiles.length}):`);
      if (profile.lockfiles.length > 0) {
        for (const lf of profile.lockfiles) {
          console.log(`  • ${pc.yellow(lf)}`);
        }
      } else {
        console.log(pc.gray('  • None found'));
      }

      // IaC Manifests
      console.log(`IaC Manifests (${profile.iacManifests.length}):`);
      if (profile.iacManifests.length > 0) {
        for (const iac of profile.iacManifests) {
          console.log(`  • ${pc.magenta(iac)}`);
        }
      } else {
        console.log(pc.gray('  • None found'));
      }

      // Gate 1 Test/Mock Folders
      console.log(`Test/Mock Dirs (${profile.testDirectories.length}) [Gate 1 Scope]:`);
      if (profile.testDirectories.length > 0) {
        for (const td of profile.testDirectories) {
          console.log(`  • ${pc.dim(td)} ${pc.gray('(Auto-downgraded to Low Confidence)')}`);
        }
      } else {
        console.log(pc.gray('  • None found'));
      }

      // Recommended Scanners
      console.log(pc.bold('\nRecommended Scanner Adapters:'));
      for (const s of profile.recommendedScanners) {
        console.log(`  ✔ ${pc.cyan(pc.bold(s))}`);
      }
      console.log('');
    } catch (err) {
      console.error(
        pc.red(`Detection failed: ${err instanceof Error ? err.message : String(err)}`)
      );
      process.exit(1);
    }
  }
}
