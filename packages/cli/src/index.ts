import { Command } from 'commander';
import { DoctorCommand } from './commands/doctor.js';
import { DetectCommand } from './commands/detect.js';
import { StatusCommand } from './commands/status.js';
import { ScanCommand, type ScanCommandOptions } from './commands/scan.js';
import { GraphCommand, type GraphCommandOptions } from './commands/graph.js';
import { AiCommand, type AiEnableOptions } from './commands/ai.js';
import { ExplainCommand, type ExplainOptions } from './commands/explain.js';
import { FixCommand, type FixCommandOptions } from './commands/fix.js';
import { VerifyCommand, type VerifyCommandOptions } from './commands/verify.js';
import { SandboxCommand } from './commands/sandbox.js';
import { InstallToolsCommand, type InstallToolsOptions } from './commands/install-tools.js';
import { InitCommand, type InitOptions } from './commands/init.js';
import { SbomCommand, type SbomOptions } from './commands/sbom.js';
import { LicenseCommand, type LicenseActivateOptions } from './commands/license.js';
import {
  FleetCommand,
  type FleetStartOptions,
  type FleetStatusOptions,
  type FleetExportCraOptions,
} from './commands/fleet.js';
import { CLI_VERSION } from './version.js';
import {
  ReachabilitySymbolsCommand,
  type ReachabilitySymbolsOptions,
} from './commands/reachability-symbols.js';
import { BundleOfflineCommand, type BundleOfflineOptions } from './commands/bundle-offline.js';
import { ImportOfflineCommand, type ImportOfflineOptions } from './commands/import-offline.js';

import pc from 'picocolors';
import { EngineBootstrapper } from './engine/bootstrapper.js';

const program = new Command();

program
  .name('secureship')
  .description(
    'SecureShip: Zero-False-Positive DevSecOps Intelligence Engine & Verification Platform'
  )
  .version(CLI_VERSION);

program
  .command('setup')
  .description('Automatically provision and verify all SecureShip security sub-engines')
  .option('--force', 'Force re-provisioning of sub-engines even if present')
  .action(async (options: { force?: boolean }) => {
    console.log(pc.bold(pc.cyan('\n⚙ SecureShip Sub-Engine Setup & Auto-Provisioning\n')));
    const ok = await EngineBootstrapper.autoProvision({ silent: false, force: options.force });
    if (ok) {
      console.log(pc.green('\n✔ All SecureShip security sub-engines are ready.'));
    } else {
      console.log(pc.yellow('\n⚠ Setup completed with warnings.'));
    }
  });

program
  .command('install-tools')
  .description('Download and verify external scanner engines into local tool directory')
  .option('--tools <list>', 'Comma-separated list of tools to install (default: all)')
  .option('--dir <path>', 'Destination directory for scanner binaries')
  .option(
    '--target-platform <plat-arch>',
    'Target platform architecture (e.g. linux-x64, linux-arm64, darwin-arm64, win32-x64)'
  )
  .option('--libc <type>', 'Target libc type for linux (glibc or musl)')
  .option('--force', 'Force re-download and re-install even if already present')
  .option('--dry-run', 'Inspect download URLs and paths without writing files to disk')
  .option('--json', 'Output results as machine-readable JSON')
  .option('--verbose', 'Enable verbose logging')
  .action(async (options: InstallToolsOptions) => {
    const exitCode = await InstallToolsCommand.run(options);
    process.exitCode = exitCode;
  });

program
  .command('doctor')
  .description(
    'Run system diagnostics, verify Node/Git environment, check scanner binaries, and inspect AI configuration'
  )
  .action(async () => {
    await DoctorCommand.run();
  });

program
  .command('detect')
  .description(
    'Analyze project stack, languages, lockfiles, and test/mock folders for Gate 1 Scope Filtering'
  )
  .argument('[path]', 'Target directory to analyze', '.')
  .option('--json', 'Output results as JSON')
  .action(async (targetPath: string, options: { json?: boolean }) => {
    await DetectCommand.run(targetPath, options);
  });

program
  .command('graph')
  .description('Build and inspect whole-repository import dependency graph')
  .argument('[path]', 'Target directory to analyze', '.')
  .option('--json', 'Output graph statistics as JSON')
  .option('--format <fmt>', 'Output format: text, json, dot', 'text')
  .option('--no-cache', 'Bypass reachability extraction cache')
  .action(async (targetPath: string, options: GraphCommandOptions) => {
    await GraphCommand.run(targetPath, options);
  });

const reachabilityCmd = program
  .command('reachability')
  .description('Inspect SCA reachability engines, call paths, and vulnerable symbol datasets');

reachabilityCmd
  .command('symbols')
  .description(
    'List curated vulnerable symbol entries with sources, completeness, and cryptographic integrity status'
  )
  .option('--json', 'Output entries and integrity metadata as JSON')
  .option('--dataset <path>', 'Custom symbol dataset path (user-level only)')
  .action(async (options: ReachabilitySymbolsOptions) => {
    await ReachabilitySymbolsCommand.run(options);
  });

program
  .command('status')
  .description('Display active license tier, capabilities, and quota status')
  .option('--json', 'Output license status as JSON')
  .action(async (options: { json?: boolean }) => {
    await StatusCommand.run(options);
  });

const licenseCmd = program
  .command('license')
  .description('Manage SecureShip license tier, cryptographic activation, and capabilities');

licenseCmd
  .command('activate <key>')
  .description(
    'Activate a PRO_TEAM or ENTERPRISE license using an activation key or offline JWT file'
  )
  .option('--server <url>', 'License validation server URL', 'https://license.secureship.dev')
  .option('--offline-file <path>', 'Path to offline-signed license.jwt file')
  .option('--force', 'Overwrite existing license file without prompt')
  .action(async (key: string, options: LicenseActivateOptions) => {
    const code = await LicenseCommand.activate(key, options);
    process.exit(code);
  });

licenseCmd
  .command('status')
  .description('Display current license status, organization, seat count, and monthly AI quota')
  .option('--json', 'Output license status as JSON')
  .action(async (options: { json?: boolean }) => {
    const code = await LicenseCommand.status(options);
    process.exit(code);
  });

licenseCmd
  .command('upgrade')
  .description('Open pricing portal and instructions to upgrade to PRO_TEAM or ENTERPRISE')
  .action(() => {
    LicenseCommand.upgrade();
  });

licenseCmd
  .command('remove')
  .description('Remove locally stored license token and revert to FREE_BYOK tier')
  .action(async () => {
    const code = await LicenseCommand.remove();
    process.exit(code);
  });

program
  .command('init')
  .description(
    'Initialize SecureShip configuration (secureship.config.json), CI/CD workflows, and baseline'
  )
  .argument('[dir]', 'Project directory to initialize', '.')
  .option('--dir <path>', 'Project directory to initialize')
  .option(
    '--fail-on <severity>',
    'Default severity threshold to fail CI (CRITICAL, HIGH, MEDIUM, LOW, INFO, NONE)',
    'HIGH'
  )
  .option(
    '--scanners <list>',
    'Comma-separated list of scanners to enable (e.g. opengrep,gitleaks,trivy,osv-scanner)'
  )
  .option(
    '--gate2 <mode>',
    'Gate 2 reachability analysis mode: annotate, suppress, off',
    'annotate'
  )
  .option(
    '--generate-action',
    'Generate GitHub Actions CI workflow (.github/workflows/secureship.yml)',
    true
  )
  .option('--no-generate-action', 'Skip generating GitHub Actions CI workflow')
  .option(
    '--create-baseline',
    'Scan current codebase and record existing findings into baseline',
    false
  )
  .option('--yes', 'Non-interactive mode accepting all defaults without prompting', false)
  .option('--force', 'Overwrite existing configuration files without prompting', false)
  .action(async (targetDir: string, options: InitOptions) => {
    const finalDir =
      options.dir ??
      (targetDir && targetDir !== '.' ? targetDir : (options.dir ?? targetDir ?? '.'));
    if (typeof options.scanners === 'string') {
      options.scanners = (options.scanners as unknown as string)
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
    }
    const exitCode = await InitCommand.run(finalDir, options);
    process.exitCode = exitCode;
  });

// Gate 3 AI management commands (A1, A3)
const aiProgram = program
  .command('ai')
  .description('Manage Gate 3 AI triage configuration, consent, and status');

aiProgram
  .command('enable')
  .description('Configure and enable Gate 3 AI triage (consent binds scheme+host+port)')
  .option('--provider <provider>', 'LLM provider (openai, anthropic)')
  .option('--model <model>', 'Model name (required, e.g. gpt-4o, claude-3-5-sonnet)')
  .option('--base-url <url>', 'Endpoint base URL (loopback or https required)')
  .option('--gate3 <mode>', 'Gate 3 mode: annotate or suppress (default: annotate)', 'annotate')
  .option('--yes', 'Non-interactive mode (required in CI, never hangs)')
  .action(async (options: AiEnableOptions) => {
    const code = await AiCommand.enable(options);
    process.exitCode = code;
  });

aiProgram
  .command('disable')
  .description('Disable Gate 3 AI triage')
  .action(async () => {
    const code = await AiCommand.disable();
    process.exitCode = code;
  });

aiProgram
  .command('status')
  .description('Display AI triage enablement, configured provider, model, and consent binding')
  .action(async () => {
    const code = await AiCommand.status();
    process.exitCode = code;
  });

aiProgram
  .command('test')
  .description(
    'Send a fixed ping prompt to test provider connectivity and measure round-trip latency'
  )
  .action(async () => {
    const code = await AiCommand.test();
    process.exitCode = code;
  });

// explain command (A11, R9b)
program
  .command('explain')
  .description('Request advisory AI explanation for a specific finding in an untrusted ScanReport')
  .argument(
    '[target]',
    'Finding fingerprint, ID, or 1-based index (or report file in legacy syntax)'
  )
  .option('--report <file>', 'Path to ScanReport JSON file')
  .option('--finding <id>', 'Finding ID, fingerprint, or index (alias for [target])')
  .option('--root <dir>', 'Jail root directory for finding source files (default: cwd)', '.')
  .option('--json', 'Output explanation as JSON')
  .action(async (targetArg: string | undefined, options: ExplainOptions) => {
    const code = await ExplainCommand.run(targetArg, options);
    process.exitCode = code;
  });

// Phase 5 Gate 4 Remediation: fix command
const fixProgram = program
  .command('fix')
  .description('Generate and verify remediation patches for security findings (Gate 4)')
  .argument('[target]', 'Finding fingerprint, ID, or 1-based index')
  .option('--report <file>', 'Path to ScanReport JSON file')
  .option('--finding <id>', 'Finding ID, fingerprint, or index (alias for [target])')
  .option('--root <dir>', 'Jail root directory for source files (default: cwd)', '.')
  .option(
    '--require <status>',
    'Required verification status (VERIFIED_STATIC, VERIFIED_RUNTIME, UNVERIFIED)',
    'VERIFIED_STATIC'
  )
  .option('--verify <level>', 'Verification depth: all, static, none', 'all')
  .option('--attempts <n>', 'Maximum repair retry attempts', '2')
  .option('--json', 'Output FixReport as JSON')
  .option('--no-cache', 'Bypass local proposal HMAC cache')
  .action(async (targetArg: string | undefined, options: FixCommandOptions) => {
    const code = await FixCommand.run(targetArg, options);
    process.exitCode = code;
  });

fixProgram
  .command('apply <id>')
  .description('Atomically apply a verified fix bundle to the working tree')
  .option('--allow-non-git', 'Allow applying outside a Git repository')
  .option('--allow-dirty', 'Allow applying with uncommitted changes in Git working tree')
  .option('--root <dir>', 'Target repository root directory (default: cwd)', '.')
  .action(
    async (id: string, options: { allowNonGit?: boolean; allowDirty?: boolean; root?: string }) => {
      const code = await FixCommand.apply(id, options);
      process.exitCode = code;
    }
  );

fixProgram
  .command('list')
  .description('List all stored remediation fixes for repository')
  .option('--root <dir>', 'Target repository root directory (default: cwd)', '.')
  .option('--json', 'Output as JSON')
  .action(async (options: { root?: string; json?: boolean }) => {
    const code = await FixCommand.list(options);
    process.exitCode = code;
  });

fixProgram
  .command('show <id>')
  .description('Display detailed fix proposal report and unified diff')
  .option('--root <dir>', 'Target repository root directory (default: cwd)', '.')
  .action(async (id: string, options: { root?: string }) => {
    const code = await FixCommand.show(id, options);
    process.exitCode = code;
  });

fixProgram
  .command('discard <id>')
  .description('Discard a stored fix bundle')
  .option('--root <dir>', 'Target repository root directory (default: cwd)', '.')
  .action(async (id: string, options: { root?: string }) => {
    const code = await FixCommand.discard(id, options);
    process.exitCode = code;
  });

// Phase 5 Gate 4 Remediation: verify command
program
  .command('verify <patch-file>')
  .description('Verify a human-authored patch file against a security finding')
  .requiredOption('--finding <id>', 'Finding ID, fingerprint, or 1-based index')
  .option('--report <file>', 'Path to ScanReport JSON file')
  .option('--root <dir>', 'Jail root directory for source files (default: cwd)', '.')
  .option('--require <status>', 'Required verification status', 'VERIFIED_STATIC')
  .option('--verify <level>', 'Verification depth: all, static, none', 'all')
  .option('--json', 'Output FixReport as JSON')
  .action(async (patchFile: string, options: VerifyCommandOptions) => {
    const code = await VerifyCommand.run(patchFile, options);
    process.exitCode = code;
  });

// Phase 5 Gate 4 Remediation: sandbox command
const sandboxProgram = program
  .command('sandbox')
  .description('Manage Gate 4 execution sandboxes, container runtimes, and host trust');

sandboxProgram
  .command('status')
  .description('Display sandbox backend, runtime, container limits, and trust settings')
  .action(async () => {
    const code = await SandboxCommand.status();
    process.exitCode = code;
  });

sandboxProgram
  .command('doctor')
  .description('Test container runtime availability and execute live sandbox test')
  .action(async () => {
    const code = await SandboxCommand.doctor();
    process.exitCode = code;
  });

sandboxProgram
  .command('enable')
  .description('Enable isolated container sandbox for dynamic verification')
  .action(async () => {
    const code = await SandboxCommand.setBackend('container');
    process.exitCode = code;
  });

sandboxProgram
  .command('disable')
  .description('Disable sandbox for verification (skips dynamic stages)')
  .action(async () => {
    const code = await SandboxCommand.setBackend('none');
    process.exitCode = code;
  });

sandboxProgram
  .command('use-native')
  .description('Enforce native isolated process sandbox (offline shadow air-gap without Docker)')
  .action(async () => {
    const code = await SandboxCommand.setBackend('native-isolated');
    process.exitCode = code;
  });

sandboxProgram
  .command('trust-host [path]')
  .description(
    'Grant un-sandboxed host execution privilege to a repository with typed confirmation'
  )
  .option('--phrase <phrase>', 'Explicit confirmation phrase for non-interactive automation')
  .action(async (repoPath: string = '.', options: { phrase?: string }) => {
    const code = await SandboxCommand.trustHost(repoPath, options.phrase);
    process.exitCode = code;
  });

sandboxProgram
  .command('cleanup')
  .description('Clean up orphan SecureShip managed containers')
  .action(async () => {
    const code = await SandboxCommand.cleanup();
    process.exitCode = code;
  });

program
  .command('scan')
  .description(
    'Run multi-scanner security analysis pipeline with Gate 1 scope filtering, Gate 2 reachability, and Gate 3 AI triage'
  )
  .argument('[path]', 'Target directory or file to scan', '.')
  .option(
    '--scanners <list>',
    'Comma-separated list of scanners to execute (opengrep, gitleaks, trivy, osv-scanner, checkov)'
  )
  .option('--diff <ref>', 'Run incremental scan against specified git reference')
  .option('--staged', 'Run incremental scan against staged git changes')
  .option('--diff-lines', 'Filter SAST and IaC findings strictly to changed line numbers in diff')
  .option(
    '--fail-on <severity>',
    'Exit with failure code 1 if findings at or above severity exist (CRITICAL, HIGH, MEDIUM, LOW, INFO, NONE)',
    'HIGH'
  )
  .option('--json', 'Output ScanReport as pure JSON to stdout')
  .option('--output <file>', 'Write ScanReport JSON to specified file')
  .option('--sarif <file>', 'Export standardized SARIF 2.1.0 to specified file')
  .option('--include-suppressed', 'Include suppressed findings in report and SARif export')
  .option(
    '--include-nonproduction',
    'Keep non-production findings reported instead of suppressing with Gate 1'
  )
  .option('--baseline <file>', 'Path to baseline file (.secureship/baseline.json)')
  .option(
    '--update-baseline',
    'Update baseline with current findings (cannot be used with --diff or --staged)'
  )
  .option('--config <file>', 'Path to custom secureship.config.json')
  .option('--timeout <ms>', 'Scanner execution timeout in milliseconds')
  .option('--concurrency <n>', 'Maximum parallel scanner processes', '4')
  .option('--offline', 'Operate strictly offline without outbound network calls')
  .option('--db-dir <path>', 'Custom directory for offline vulnerability databases')
  .option(
    '--supply-chain-only',
    'Run supply-chain threat engine exclusively without external scanners'
  )
  .option('--strict', 'Fail scan with exit code 3 if any individual scanner fails or is missing')
  .option('--no-color', 'Disable ANSI color formatting in human output')
  .option('--verbose', 'Enable verbose logging output to stderr')
  .option(
    '--gate2 <mode>',
    'Gate 2 reachability analysis mode: off, annotate, suppress',
    'annotate'
  )
  .option('--no-cache', 'Bypass reachability extraction cache')
  .option(
    '--reachability-filter <mode>',
    'Filter findings by reachability status: reachable, no-info, not-applicable, all'
  )
  .option(
    '--no-function-level',
    'Disable symbol-level reachability refinement and fall back to package-level analysis'
  )
  // Phase 4 Gate 3 AI Triage flags (A1, A3, A8, A9, A10, A15)
  .option('--ai', 'Enable Gate 3 AI triage analysis')
  .option(
    '--gate3 <mode>',
    'Gate 3 mode: off, annotate, suppress [EXPERIMENTAL: suppress]',
    'annotate'
  )
  .option('--ai-provider <provider>', 'AI provider (openai, anthropic)')
  .option('--ai-model <model>', 'Model name (required when AI enabled, no default)')
  .option('--ai-base-url <url>', 'Endpoint base URL (loopback or https required)')
  .option('--ai-max-findings <n>', 'Maximum findings to send to AI (default: 10)')
  .option('--ai-budget-tokens <n>', 'Maximum total token budget (default: 100000)')
  .option('--ai-concurrency <n>', 'Maximum concurrent AI provider requests (default: 2)')
  .option('--no-ai-cache', 'Bypass Gate 3 external AI HMAC cache')
  .option(
    '--ai-dry-run',
    'Assemble, redact and validate slices without outbound network transmission'
  )
  .option('--ai-estimate', 'Estimate token usage and finding count without network transmission')
  .option(
    '--ai-trace [path]',
    'Emit redacted AI triage trace telemetry to path or per-user data dir'
  )
  .option('--watch', 'Continuously monitor repository files and re-scan automatically on change')
  .option('--new-only', 'Filter scan results to only report new findings absent from baseline')
  .option(
    '--check-licenses',
    'Evaluate component licenses against allow and deny compliance policies',
    false
  )
  .option(
    '--allow <licenses...>',
    'Approved licenses (comma-separated or list, e.g. MIT,Apache-2.0,ISC)'
  )
  .option(
    '--deny <licenses...>',
    'Prohibited licenses (comma-separated or list, e.g. GPL-3.0,AGPL-3.0)'
  )
  .option(
    '--report-to <url>',
    'Stream privacy-preserving security metadata to SecureShip Fleet central dashboard'
  )
  .option('--fleet-token <token>', 'Corporate fleet authentication token for report ingestion')
  .option(
    '--repo-name <name>',
    'Custom repository name override (defaults to Git origin repository or directory name)'
  )
  .option(
    '--fleet-policy',
    'Fetch and enforce central security & license compliance policy from Fleet server'
  )
  .action(
    async (
      targetPath: string,
      options: ScanCommandOptions & { allow?: string | string[]; deny?: string | string[] }
    ) => {
      if (options.allow) {
        const raw = Array.isArray(options.allow) ? options.allow : [options.allow];
        options.allow = raw
          .flatMap((s: unknown) => String(s).split(/[,\s]+/))
          .map((s: string) => s.trim())
          .filter(Boolean);
      }
      if (options.deny) {
        const raw = Array.isArray(options.deny) ? options.deny : [options.deny];
        options.deny = raw
          .flatMap((s: unknown) => String(s).split(/[,\s]+/))
          .map((s: string) => s.trim())
          .filter(Boolean);
      }
      const exitCode = await ScanCommand.run(targetPath, options);
      process.exitCode = exitCode;
    }
  );

program
  .command('sbom')
  .description(
    'Generate EU Cyber Resilience Act & US EO 14028 compliant Software Bill of Materials (CycloneDX / SPDX)'
  )
  .argument('[dir]', 'Target project directory (default: current directory)', '.')
  .option('--dir <path>', 'Target project directory (default: current directory)')
  .option('--format <fmt>', 'SBOM output specification format: cyclonedx, spdx', 'cyclonedx')
  .option('--output <file>', 'Output destination file path for generated SBOM JSON')
  .option('--with-vulns', 'Enrich SBOM components with security vulnerability findings', false)
  .option(
    '--signed',
    'Cryptographically sign the SBOM for compliance audit (requires PRO_TEAM or ENTERPRISE)',
    false
  )
  .option('--report <file>', 'Path to explicit ScanReport JSON to correlate with SBOM components')
  .option(
    '--check-licenses',
    'Evaluate component licenses against allow and deny compliance policies',
    false
  )
  .option(
    '--allow <licenses...>',
    'Approved licenses (comma-separated or list, e.g. MIT,Apache-2.0,ISC)'
  )
  .option(
    '--deny <licenses...>',
    'Prohibited licenses (comma-separated or list, e.g. GPL-3.0,AGPL-3.0)'
  )
  .option('--json', 'Output SBOM as machine-readable JSON to stdout')
  .action(
    async (
      targetDir: string,
      options: SbomOptions & { allow?: string | string[]; deny?: string | string[] }
    ) => {
      const finalDir =
        options.dir ??
        (targetDir && targetDir !== '.' ? targetDir : (options.dir ?? targetDir ?? '.'));
      // Windows cmd.exe / PowerShell comma-to-space desugaring:
      // When unquoted comma strings like --allow MIT,Apache-2.0 are passed via .cmd,
      // cmd.exe converts ',' to ' ' producing separate argv tokens. Reconstruct them.
      const allowIdx = process.argv.indexOf('--allow');
      if (allowIdx !== -1) {
        const extra: string[] = [];
        for (let i = allowIdx + 1; i < process.argv.length; i++) {
          const arg = process.argv[i];
          if (!arg || arg.startsWith('-')) break;
          extra.push(arg);
        }
        if (extra.length > 0) {
          options.allow = extra;
        }
      }
      const denyIdx = process.argv.indexOf('--deny');
      if (denyIdx !== -1) {
        const extra: string[] = [];
        for (let i = denyIdx + 1; i < process.argv.length; i++) {
          const arg = process.argv[i];
          if (!arg || arg.startsWith('-')) break;
          extra.push(arg);
        }
        if (extra.length > 0) {
          options.deny = extra;
        }
      }

      if (options.allow) {
        const raw = Array.isArray(options.allow) ? options.allow : [options.allow];
        options.allow = raw
          .flatMap((s: unknown) => String(s).split(/[,\s]+/))
          .map((s: string) => s.trim())
          .filter(Boolean);
      }
      if (options.deny) {
        const raw = Array.isArray(options.deny) ? options.deny : [options.deny];
        options.deny = raw
          .flatMap((s: unknown) => String(s).split(/[,\s]+/))
          .map((s: string) => s.trim())
          .filter(Boolean);
      }
      const exitCode = await SbomCommand.run(finalDir, options);
      process.exitCode = exitCode;
    }
  );

// Phase 6 Centralized Multi-Repo Fleet Dashboard (CISO Cockpit)
const fleetProgram = program
  .command('fleet')
  .description(
    'Manage self-hosted SecureShip Fleet cockpit, central risk telemetry, and EU CRA compliance'
  );

fleetProgram
  .command('start')
  .description(
    'Launch self-hosted SecureShip Fleet web server, ingest API, and CISO cockpit dashboard'
  )
  .option('--port <port>', 'HTTP server listening port (default: 4000)')
  .option('--host <string>', 'HTTP server listening host interface (default: 127.0.0.1)')
  .option('--data <path>', 'Path to local SQLite/JSON fleet database file')
  .option(
    '--token <token>',
    'DEPRECATED: visible to other users via the process list and shell history; prefer FLEET_TOKEN_FILE or FLEET_TOKEN'
  )
  .option(
    '--token-file <path>',
    'Path to file containing secret authorization token (e.g. /run/secrets/fleet_token)'
  )
  .option('--allowed-host <host...>', 'Additional allowed Host headers beyond loopback interfaces')
  .option(
    '--allowed-origin <origin...>',
    'Explicit allowed Origin URLs (e.g. https://ciso.internal.corp)'
  )
  .action(async (options: FleetStartOptions) => {
    if (options.token) {
      process.stderr.write(
        'Warning: --token is deprecated. It is visible to other users via the process list and shell history. Use FLEET_TOKEN_FILE or FLEET_TOKEN instead.\n'
      );
    }
    const code = await FleetCommand.start(options);
    process.exitCode = code;
  });

fleetProgram
  .command('status')
  .description(
    'Fetch and display executive multi-repo risk summary, grade, and active critical findings'
  )
  .option(
    '--endpoint <url>',
    'Fleet server endpoint URL (default: http://127.0.0.1:4000)',
    'http://127.0.0.1:4000'
  )
  .option(
    '--token <token>',
    'DEPRECATED: visible to other users via the process list and shell history; prefer FLEET_TOKEN_FILE or FLEET_TOKEN'
  )
  .option(
    '--token-file <path>',
    'Path to file containing secret authorization token (e.g. /run/secrets/fleet_token)'
  )
  .option('--json', 'Output executive summary and repository breakdown as JSON')
  .action(async (options: FleetStatusOptions) => {
    if (options.token) {
      process.stderr.write(
        'Warning: --token is deprecated. It is visible to other users via the process list and shell history. Use FLEET_TOKEN_FILE or FLEET_TOKEN instead.\n'
      );
    }
    const code = await FleetCommand.status(options);
    process.exitCode = code;
  });

fleetProgram
  .command('export-cra')
  .description(
    'Export EU Cyber Resilience Act (CRA) Annex I, Part II compliant CycloneDX 1.5 JSON report'
  )
  .option(
    '--endpoint <url>',
    'Fleet server endpoint URL (default: http://127.0.0.1:4000)',
    'http://127.0.0.1:4000'
  )
  .option(
    '--token <token>',
    'DEPRECATED: visible to other users via the process list and shell history; prefer FLEET_TOKEN_FILE or FLEET_TOKEN'
  )
  .option(
    '--token-file <path>',
    'Path to file containing secret authorization token (e.g. /run/secrets/fleet_token)'
  )
  .option(
    '--output <file>',
    'Output destination file path (default: eu-cra-cyclonedx-1.5.json)',
    'eu-cra-cyclonedx-1.5.json'
  )
  .action(async (options: FleetExportCraOptions) => {
    if (options.token) {
      process.stderr.write(
        'Warning: --token is deprecated. It is visible to other users via the process list and shell history. Use FLEET_TOKEN_FILE or FLEET_TOKEN instead.\n'
      );
    }
    const code = await FleetCommand.exportCra(options);
    process.exitCode = code;
  });

program
  .command('bundle-offline')
  .description(
    'Snapshot and export vulnerability databases and engine binaries into a deterministic, signed offline bundle'
  )
  .option(
    '-o, --output <file>',
    'Output destination bundle path (default: secureship-offline-bundle-YYYY-MM-DD.tar.gz)'
  )
  .option('--platform <list>', 'Comma-separated target platforms (default: current host platform)')
  .option(
    '--ecosystems <list>',
    'Comma-separated ecosystems for OSV database (default: npm,PyPI,Go,Maven)'
  )
  .option('--include-java-db', 'Include Trivy Java vulnerability database')
  .option('--no-tools', 'Exclude scanner engine binaries from bundle')
  .option(
    '--sign-key <pem>',
    'Path to Ed25519 private key PEM file to cryptographically sign bundle'
  )
  .option('--key-id <id>', 'Identifier for the signing key')
  .option('--work-dir <dir>', 'Temporary directory for staging')
  .option('-f, --force', 'Force overwrite output bundle if it already exists')
  .option('--json', 'Output bundle manifest and metadata as machine-readable JSON')
  .action(async (options: BundleOfflineOptions) => {
    const code = await BundleOfflineCommand.run(options);
    process.exitCode = code;
  });

program
  .command('import-offline')
  .description(
    'Verify and import an air-gap database bundle, atomically publishing a verified generation'
  )
  .argument('[bundle]', 'Path to the offline bundle archive (.tar.gz)')
  .option('--trust-key <pem...>', 'One or more paths to trusted Ed25519 public key PEM files')
  .option(
    '--allow-unsigned',
    'Permit importing unsigned bundles or bundles without matching trusted keys'
  )
  .option(
    '--allow-downgrade',
    'Permit importing older bundles than the active generation (override anti-rollback)'
  )
  .option('--dry-run', 'Validate bundle integrity and signatures without making changes')
  .option('--verify-only', 'Cryptographically verify bundle signature and contents only')
  .option('--rollback', 'Roll back active database generation to the previous installed generation')
  .option('--db-dir <dir>', 'Custom database storage directory')
  .option('--tools-dir <dir>', 'Custom tool binaries directory')
  .option('-f, --force', 'Force import')
  .option('--json', 'Output import result as machine-readable JSON')
  .action(async (bundle: string | undefined, options: ImportOfflineOptions) => {
    const code = await ImportOfflineCommand.run(bundle, options);
    process.exitCode = code;
  });

program.parse(process.argv);
