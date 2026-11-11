import pc from 'picocolors';
import { SymbolDatasetLoader } from '@secureship/reachability';

export interface ReachabilitySymbolsOptions {
  json?: boolean;
  dataset?: string;
}

export class ReachabilitySymbolsCommand {
  public static async run(options: ReachabilitySymbolsOptions): Promise<void> {
    const result = SymbolDatasetLoader.loadDataset(options.dataset);

    if (options.json) {
      const output = {
        ok: result.ok,
        integrity: {
          verified: result.ok,
          sha256: result.manifest?.sha256 || null,
          bytes: result.manifest?.bytes || null,
          updatedAt: result.manifest?.updatedAt || null,
        },
        dataset: {
          id: result.dataset?.datasetId || null,
          version: result.dataset?.version || null,
          description: result.dataset?.description || null,
          entryCount: result.dataset?.entries?.length || 0,
          sourcePath: result.sourcePath,
        },
        error: result.error || null,
        warning: result.warning || null,
        entries: result.dataset?.entries || [],
      };
      console.log(JSON.stringify(output, null, 2));
      return;
    }

    // Human-readable formatted terminal output
    console.log(pc.bold(pc.cyan('\n📦 SecureShip Curated Vulnerable Symbols Database\n')));

    if (!result.ok || !result.dataset) {
      console.log(pc.red(`✖ Failed to load dataset: ${result.error || 'Unknown error'}`));
      if (result.warning) {
        console.log(pc.yellow(`⚠ ${result.warning}`));
      }
      return;
    }

    console.log(pc.bold('Dataset Metadata:'));
    console.log(`  ID:          ${pc.green(result.dataset.datasetId)}`);
    console.log(`  Version:     ${result.dataset.version}`);
    console.log(`  Source:      ${result.sourcePath}`);
    console.log(
      `  Integrity:   ${pc.green('✔ VERIFIED')} (SHA-256: ${result.manifest?.sha256?.substring(0, 16)}... offline match)`
    );
    console.log(`  Entries:     ${result.dataset.entries.length}\n`);

    console.log(pc.bold('Curated Vulnerability Entries:'));
    console.log(
      '-----------------------------------------------------------------------------------------------'
    );
    console.log(
      ` ${'ID'.padEnd(18)} ${'Ecosystem'.padEnd(10)} ${'Package'.padEnd(20)} ${'Trigger'.padEnd(12)} ${'Complete?'.padEnd(11)} Entry Points`
    );
    console.log(
      '-----------------------------------------------------------------------------------------------'
    );

    for (const entry of result.dataset.entries) {
      const epDesc = entry.entryPoints
        .map((ep) => (ep.module === '.' ? ep.export : `${ep.module}:${ep.export}`))
        .join(', ');
      const completeStr = entry.entryPointsComplete ? pc.green('YES') : pc.yellow('NO');
      const triggerStr =
        entry.triggeredOn === 'CALL' ? pc.green(entry.triggeredOn) : pc.yellow(entry.triggeredOn);

      console.log(
        ` ${pc.bold(entry.id.padEnd(18))} ${entry.ecosystem.padEnd(10)} ${entry.package.padEnd(20)} ${triggerStr.padEnd(21)} ${completeStr.padEnd(20)} ${epDesc}`
      );
    }
    console.log(
      '-----------------------------------------------------------------------------------------------\n'
    );
    console.log(
      pc.gray(
        'Notice: Function-level analysis is static and best-effort; vulnerable-symbol data may be incomplete.'
      )
    );
  }
}
