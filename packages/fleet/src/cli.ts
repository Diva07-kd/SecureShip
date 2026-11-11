#!/usr/bin/env node
import { FleetServer } from './server/fleet-server.js';
import { FleetStore } from './storage/fleet-store.js';
import {
  buildFleetRuntimeConfig,
  formatAuthLabel,
  formatDisplayUrl,
  formatReadHint,
} from './config/fleet-config.js';

export interface ShutdownOptions {
  server: { stop(): Promise<void> };
  onExit?: (code: number) => void;
  setTimeoutFn?: typeof setTimeout;
  clearTimeoutFn?: typeof clearTimeout;
}

/**
 * Installs graceful shutdown signal handlers for SIGINT, SIGTERM (and SIGBREAK on win32) (DEV-4).
 * A second signal, or a 10s watchdog timer, forces exit 1.
 */
export function installSignalHandlers(options: ShutdownOptions): () => void {
  const {
    server,
    onExit = (code: number) => process.exit(code),
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
  } = options;

  let isShuttingDown = false;
  let forceTimer: ReturnType<typeof setTimeout> | null = null;

  const handleSignal = async () => {
    if (isShuttingDown) {
      if (forceTimer) clearTimeoutFn(forceTimer);
      onExit(1);
      return;
    }
    isShuttingDown = true;

    // 10s watchdog forces exit 1
    forceTimer = setTimeoutFn(() => {
      onExit(1);
    }, 10000);
    if (typeof (forceTimer as unknown as { unref?: () => void })?.unref === 'function') {
      (forceTimer as unknown as { unref: () => void }).unref();
    }

    try {
      await server.stop();
      if (forceTimer) clearTimeoutFn(forceTimer);
      onExit(0);
    } catch {
      if (forceTimer) clearTimeoutFn(forceTimer);
      onExit(1);
    }
  };

  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];
  if (process.platform === 'win32') {
    signals.push('SIGBREAK' as NodeJS.Signals);
  }

  for (const sig of signals) {
    process.on(sig, handleSignal);
  }

  return () => {
    for (const sig of signals) {
      process.removeListener(sig, handleSignal);
    }
    if (forceTimer) clearTimeoutFn(forceTimer);
  };
}

async function main(): Promise<void> {
  const positionalPort = process.argv[2];

  let config;
  try {
    config = await buildFleetRuntimeConfig({
      env: process.env,
      argvPositionalPort: positionalPort,
    });
  } catch (err: unknown) {
    console.error(
      `Failed to start SecureShip Fleet server: ${err instanceof Error ? err.message : String(err)}`
    );
    if (process.env.FLEET_DEBUG === '1' && err instanceof Error && err.stack) {
      console.error(err.stack);
    }
    process.exit(1);
  }

  // Print any warnings to stderr
  for (const w of config.warnings) {
    console.error(w);
  }

  const store = new FleetStore({
    storageFile: config.dataPath,
    dbPath: config.dataPath,
  });

  const server = new FleetServer({
    ...config.serverOptions,
    store,
  });

  try {
    const activePort = await server.start();
    installSignalHandlers({ server });

    const displayUrl = formatDisplayUrl(config.host, activePort);

    console.log(`\n🛡️  SecureShip Fleet: Enterprise CISO Cockpit & Telemetry Hub`);
    console.log(`  🌐 Web Dashboard : ${displayUrl}`);
    console.log(`  📥 Central Ingest : ${displayUrl}/api/ingest`);
    console.log(`  📋 Corporate Policy: ${displayUrl}/api/policy`);
    console.log(`  💾 State Storage  : ${config.dataPath}`);
    console.log(
      `  🔒 Auth           : required (source: ${formatAuthLabel(config.tokenSource, config.tokenFilePath)})`
    );
    if (config.tokenSource === 'generated' && config.tokenFilePath) {
      console.log(`  🔑 Token Read Hint: ${formatReadHint(config.tokenFilePath)}`);
    }
    console.log('\n  Zero-Code-Leak: Running in sovereign metadata-only mode.\n');
  } catch (err: unknown) {
    console.error(
      `Failed to start SecureShip Fleet server: ${err instanceof Error ? err.message : String(err)}`
    );
    if (process.env.FLEET_DEBUG === '1' && err instanceof Error && err.stack) {
      console.error(err.stack);
    }
    process.exit(1);
  }
}

// Only run automatically when executed directly as entry script
const isDirectEntry =
  import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/')}` ||
  process.argv[1]?.endsWith('cli.js') ||
  process.argv[1]?.endsWith('cli.ts');

if (isDirectEntry) {
  main().catch((err: unknown) => {
    console.error(
      `Failed to start SecureShip Fleet server: ${err instanceof Error ? err.message : String(err)}`
    );
    process.exit(1);
  });
}
