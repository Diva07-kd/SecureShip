import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import { z } from 'zod';
import { OfflineBundleService } from '@secureship/core-engine';
import { loadToolsLock } from '@secureship/scanner-adapters';
import { CLI_VERSION } from '../version.js';

export const ImportOfflineOptionsSchema = z.object({
  trustKey: z.array(z.string()).optional(),
  allowUnsigned: z.boolean().optional(),
  allowDowngrade: z.boolean().optional(),
  dryRun: z.boolean().optional(),
  verifyOnly: z.boolean().optional(),
  rollback: z.boolean().optional(),
  dbDir: z.string().optional(),
  toolsDir: z.string().optional(),
  force: z.boolean().optional(),
  json: z.boolean().optional(),
});

export type ImportOfflineOptions = z.infer<typeof ImportOfflineOptionsSchema>;

export class ImportOfflineCommand {
  public static async run(bundleArg?: string, options: ImportOfflineOptions = {}): Promise<number> {
    try {
      if (!options.json) {
        console.log(pc.bold(pc.cyan('\n📥 SecureShip Offline Database & Engine Importer\n')));
      }

      // Handle Rollback mode
      if (options.rollback) {
        const rollbackResult = await OfflineBundleService.rollback(options.dbDir);
        if (options.json) {
          console.log(JSON.stringify(rollbackResult, null, 2));
        } else {
          console.log(pc.green(`✔ ${rollbackResult.message}`));
        }
        return 0;
      }

      if (!bundleArg) {
        throw new Error(
          'Missing bundle argument. Usage: secureship import-offline <bundle.tar.gz> [--trust-key <pem>]'
        );
      }

      const bundlePath = path.resolve(bundleArg);
      if (!fs.existsSync(bundlePath)) {
        throw new Error(`Bundle file not found: '${bundlePath}'`);
      }

      // Read trusted public key PEM files
      const trustKeyPems: string[] = [];
      if (options.trustKey && options.trustKey.length > 0) {
        for (const keyPath of options.trustKey) {
          const resolved = path.resolve(keyPath);
          if (!fs.existsSync(resolved)) {
            throw new Error(`Trusted public key file not found: '${resolved}'`);
          }
          trustKeyPems.push(fs.readFileSync(resolved, 'utf-8'));
        }
      }

      const toolsLock = loadToolsLock();

      const result = await OfflineBundleService.importBundle({
        bundlePath,
        trustKeyPems: trustKeyPems.length > 0 ? trustKeyPems : undefined,
        allowUnsigned: options.allowUnsigned,
        allowDowngrade: options.allowDowngrade,
        dryRun: options.dryRun,
        verifyOnly: options.verifyOnly,
        dbDir: options.dbDir,
        toolsDir: options.toolsDir,
        cliVersion: CLI_VERSION,
        toolPins: toolsLock.tools as Record<string, unknown>,
      });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (options.verifyOnly) {
          console.log(pc.green(`✔ Bundle verification PASSED:`));
          console.log(`  Bundle ID:   ${result.bundleId}`);
          console.log(
            `  Trust:       ${result.trust === 'VERIFIED' ? pc.green('VERIFIED (Ed25519)') : pc.yellow('UNSIGNED')}`
          );
          console.log(`  Components:  ${result.manifest.components.length}`);
        } else if (options.dryRun) {
          console.log(pc.cyan(`ℹ Dry-Run completed successfully (no files changed):`));
          console.log(`  Bundle ID:   ${result.bundleId}`);
          console.log(`  Trust:       ${result.trust}`);
        } else {
          console.log(pc.green(`✔ Successfully imported offline bundle:`));
          console.log(`  Generation:  ${pc.bold(result.generationId ?? 'unknown')}`);
          console.log(`  Bundle ID:   ${result.bundleId}`);
          console.log(
            `  Trust:       ${result.trust === 'VERIFIED' ? pc.green('VERIFIED (Ed25519)') : pc.yellow('UNSIGNED')}`
          );
          console.log(`  Components:  ${result.manifest.components.map((c) => c.id).join(', ')}`);
          console.log(pc.cyan(`\nYou can now run offline scans with zero network access:`));
          console.log(pc.cyan(`  secureship scan --offline .`));
        }
      }

      return 0;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (options.json) {
        console.log(JSON.stringify({ success: false, error: msg }, null, 2));
      } else {
        console.error(pc.red(`\n✖ Import failed: ${msg}\n`));
      }
      return 1;
    }
  }
}
