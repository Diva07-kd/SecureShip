import path from 'node:path';
import pc from 'picocolors';
import { ImportGraph } from '@secureship/reachability';

export interface GraphCommandOptions {
  json?: boolean;
  format?: 'dot' | 'json' | 'text';
  noCache?: boolean;
}

export class GraphCommand {
  public static async run(targetDirRaw?: string, options: GraphCommandOptions = {}): Promise<void> {
    const targetDir = path.resolve(targetDirRaw ?? process.cwd());

    let graph: ImportGraph;
    try {
      graph = await ImportGraph.build(targetDir, {
        noCache: options.noCache,
      });
    } catch (err: unknown) {
      if (options.json || options.format === 'json') {
        console.log(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
      } else {
        console.error(
          pc.red(
            `Failed to build import graph: ${err instanceof Error ? err.message : String(err)}`
          )
        );
      }
      process.exit(1);
    }

    if (options.format === 'dot') {
      console.log(graph.toDot());
      return;
    }

    const stats = graph.computeStats();

    if (options.json || options.format === 'json') {
      console.log(JSON.stringify(stats, null, 2));
      return;
    }

    // Human readable text
    console.log(pc.bold(pc.cyan(`\n🕸️  SecureShip Import Graph: ${targetDir}\n`)));

    console.log(pc.bold('Entrypoints:'));
    if (stats.entrypoints.length === 0) {
      console.log(pc.yellow('  (None detected - verdicts degrade to UNKNOWN)'));
    } else {
      for (const ep of stats.entrypoints) {
        console.log(`  • ${pc.green(ep)}`);
      }
    }

    console.log(pc.bold('\nGraph Metrics:'));
    console.log(`  Total Source Files   : ${pc.bold(String(stats.totalFiles))}`);
    console.log(`  Reachable from Roots : ${pc.green(String(stats.reachableFiles))}`);
    console.log(
      `  Unreachable (Dead)   : ${pc.yellow(String(stats.unreachableFiles))} (${stats.unreachableProdFiles ?? 0} production, ${stats.unreachableTestFiles ?? 0} test/mock)`
    );
    console.log(
      `  Dynamic Import Files : ${
        stats.dynamicFiles.length > 0 ? pc.yellow(String(stats.dynamicFiles.length)) : pc.green('0')
      }`
    );
    console.log(
      `  Unresolved Imports   : ${
        stats.unresolvedImports.length > 0
          ? pc.yellow(String(stats.unresolvedImports.length))
          : pc.green('0')
      }`
    );
    console.log(
      `  Parse Failures       : ${
        stats.parseFailures.length > 0 ? pc.red(String(stats.parseFailures.length)) : pc.green('0')
      }`
    );

    if (stats.dynamicFiles.length > 0) {
      console.log(pc.bold('\nDynamic Execution Markers Detected:'));
      for (const f of stats.dynamicFiles) {
        console.log(`  ⚠ ${pc.yellow(f)}`);
      }
    }

    if (stats.unresolvedImports.length > 0) {
      console.log(pc.bold('\nUnresolved Imports:'));
      for (const u of stats.unresolvedImports) {
        console.log(`  ✖ ${pc.yellow(u.fromFile)} -> ${pc.red(u.specifier)} (${u.reason})`);
      }
    }

    if (stats.parseFailures.length > 0) {
      console.log(pc.bold('\nParse Failures:'));
      for (const pf of stats.parseFailures) {
        console.log(`  ✖ ${pc.red(pf.filePath)}: ${pf.reason}`);
      }
    }

    console.log();
  }
}
