import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import { z } from 'zod';
import { OfflineBundleService } from '@secureship/core-engine';
import { loadToolsLock } from '@secureship/scanner-adapters';
import { CLI_VERSION } from '../version.js';

export const BundleOfflineOptionsSchema = z.object({
  output: z.string().optional(),
  platform: z.string().optional(),
  ecosystems: z.string().optional(),
  includeJavaDb: z.boolean().optional(),
  tools: z.boolean().default(true),
  signKey: z.string().optional(),
  keyId: z.string().optional(),
  workDir: z.string().optional(),
  force: z.boolean().optional(),
  skipDownload: z.boolean().optional(),
  json: z.boolean().optional(),
});

export type BundleOfflineOptions = z.infer<typeof BundleOfflineOptionsSchema>;

export class BundleOfflineCommand {
  public static async run(options: BundleOfflineOptions): Promise<number> {
    try {
      if (!options.json) {
        console.log(pc.bold(pc.cyan('\n📦 SecureShip Offline Database & Engine Bundler\n')));
      }

      // Parse platform list
      const platforms = options.platform
        ? options.platform
            .split(',')
            .map((p) => p.trim())
            .filter(Boolean)
        : [`${process.platform}-${process.arch}`];

      // Parse ecosystems list
      const ecosystems = options.ecosystems
        ? options.ecosystems
            .split(',')
            .map((e) => e.trim())
            .filter(Boolean)
        : ['npm', 'PyPI', 'Go', 'Maven'];

      // Read signing key if specified
      let signKeyPem: string | undefined;
      if (options.signKey) {
        const keyPath = path.resolve(options.signKey);
        if (!fs.existsSync(keyPath)) {
          throw new Error(`Signing key file not found: '${keyPath}'`);
        }
        signKeyPem = fs.readFileSync(keyPath, 'utf-8');
      }

      const toolsLock = loadToolsLock();

      const result = await OfflineBundleService.createBundle({
        outputPath: options.output,
        platforms,
        ecosystems,
        includeJavaDb: options.includeJavaDb,
        noTools: options.tools === false,
        signKeyPem,
        keyId: options.keyId ?? (signKeyPem ? 'default-signer' : undefined),
        workDir: options.workDir,
        force: options.force,
        skipDownload: options.skipDownload,
        cliVersion: CLI_VERSION,
        toolPins: toolsLock.tools as Record<string, unknown>,
      });

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              success: true,
              outputPath: result.outputPath,
              bundleId: result.bundleId,
              totalSizeBytes: result.totalSize,
              componentCount: result.componentCount,
              signed: result.signed,
              manifest: result.manifest,
            },
            null,
            2
          )
        );
      } else {
        console.log(pc.green(`✔ Successfully created offline bundle:`));
        console.log(`  File:        ${pc.bold(result.outputPath)}`);
        console.log(`  Bundle ID:   ${result.bundleId}`);
        console.log(`  Total Size:  ${(result.totalSize / (1024 * 1024)).toFixed(2)} MB`);
        console.log(`  Components:  ${result.componentCount}`);
        console.log(
          `  Signature:   ${result.signed ? pc.green('Ed25519 SIGNED') : pc.yellow('UNSIGNED')}`
        );
        console.log(`\nTo transfer and import on an air-gapped host, run:`);
        console.log(
          pc.cyan(
            `  secureship import-offline ${path.basename(result.outputPath)}` +
              (result.signed ? ` --trust-key <public-key.pem>` : ` --allow-unsigned`)
          )
        );
      }

      return 0;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (options.json) {
        console.log(JSON.stringify({ success: false, error: msg }, null, 2));
      } else {
        console.error(pc.red(`\n✖ Bundle creation failed: ${msg}\n`));
      }
      return 1;
    }
  }
}
