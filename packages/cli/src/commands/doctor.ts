import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import {
  SafeProcessRunner,
  getLicenseStatusReport,
  resolveSecureshipHome,
  resolveToolDirs,
  resolveDbDir,
  isContainerEnvironment,
  checkDirWritable,
} from '@secureship/core-engine';
import { getEngineBrand } from '@secureship/contracts';
import {
  BinaryResolver,
  loadSupportedVersions,
  getInstallHint,
  isVersionSupported,
  resolveToolAsset,
  detectLibc,
} from '@secureship/scanner-adapters';

export interface BinaryCheckResult {
  binary: string;
  category: string;
  found: boolean;
  resolvedPath?: string;
  version?: string;
  supported?: boolean;
  installHint?: string;
  sha256?: string;
  pinMatch?: boolean;
  expectedSha256?: string;
}

export class DoctorCommand {
  public static async run(): Promise<void> {
    console.log(pc.bold(pc.cyan('\n🔍 SecureShip Environment & Security Doctor\n')));

    // 1. Node.js environment
    const nodeVer = process.version;
    const major = parseInt(nodeVer.replace('v', '').split('.')[0] ?? '0', 10);
    const nodeOk = major >= 18;
    console.log(
      `Node.js: ${nodeOk ? pc.green('✔') : pc.red('✖')} ${pc.bold(nodeVer)} ${
        nodeOk ? pc.gray('(Supported >= 18)') : pc.red('(Unsupported, upgrade to >= 18)')
      }`
    );

    // 2. Platform info
    console.log(`OS Platform: ${pc.cyan(process.platform)} (${process.arch})`);

    // Container Environment & Process Identity (D6, D10)
    const inContainer = isContainerEnvironment();
    const uidInfo = process.getuid
      ? `UID: ${process.getuid()}, GID: ${process.getgid ? process.getgid() : 'N/A'}`
      : 'Windows Identity';
    console.log(
      `Container:   ${inContainer ? pc.green('✔ Container Detected (Docker/OCI runtime)') : pc.gray('○ Host Environment')}`
    );
    console.log(`Process ID:  ${pc.gray(uidInfo)}`);

    // Storage Paths & Writability (D6, D10)
    console.log(pc.bold('\nSecureShip Storage Directories:'));
    const homeDir = resolveSecureshipHome();
    const homeW = checkDirWritable(homeDir);
    console.log(
      `  • SECURESHIP_HOME     : ${pc.cyan(homeDir)} [${homeW.writable ? pc.green('Writable ✔') : pc.red(`Non-writable: ${homeW.error}`)}]`
    );

    const toolDirs = resolveToolDirs();
    console.log(`  • Tool Candidate Dirs :`);
    for (const td of toolDirs) {
      const tdW = checkDirWritable(td);
      const isSystem = td.startsWith('/opt/secureship');
      console.log(
        `    ↳ ${pc.cyan(td)} [${tdW.writable ? pc.green('Writable ✔') : isSystem ? pc.gray('System Read-Only (0555) ✔') : pc.yellow(`Read-Only: ${tdW.error}`)}]`
      );
    }

    const dbDir = resolveDbDir();
    const dbW = checkDirWritable(dbDir);
    console.log(
      `  • Vulnerability DB Dir: ${pc.cyan(dbDir)} [${dbW.writable ? pc.green('Writable ✔') : pc.red(`Non-writable: ${dbW.error}`)}]`
    );

    // 3. Git availability
    let gitFound = false;
    let gitVersion = 'Not found';
    try {
      const gitRes = await SafeProcessRunner.run('git', ['--version'], {
        timeoutMs: 5000,
      });
      if (gitRes.exitCode === 0) {
        gitFound = true;
        gitVersion = gitRes.stdout.trim();
      }
    } catch {
      // Not installed or errored
    }
    console.log(`Git: ${gitFound ? pc.green('✔') : pc.yellow('⚠')} ${pc.bold(gitVersion)}`);

    // 4. White-labeled Security Sub-Engines Check
    console.log(pc.bold('\nCore Security Sub-Engines:'));
    const supportedVersions = loadSupportedVersions();

    const scanners = [
      { binary: 'opengrep', alt: 'semgrep', category: 'SAST (Source Code)' },
      { binary: 'gitleaks', alt: undefined, category: 'Secrets & Credentials' },
      { binary: 'trivy', alt: undefined, category: 'Dependencies & Containers' },
      { binary: 'osv-scanner', alt: undefined, category: 'SCA / Lockfile CVEs' },
      { binary: 'checkov', alt: undefined, category: 'Infrastructure as Code' },
    ];

    const results: BinaryCheckResult[] = await Promise.all(
      scanners.map(async (item) => {
        let resolved = BinaryResolver.resolveOnPath(item.binary);
        let nameUsed = item.binary;

        if (!resolved && item.alt) {
          resolved = BinaryResolver.resolveOnPath(item.alt);
          if (resolved) {
            nameUsed = item.alt;
          }
        }

        let versionStr: string | undefined;
        if (resolved) {
          try {
            const versionArgs = item.binary === 'gitleaks' ? ['version'] : ['--version'];
            const runRes = await SafeProcessRunner.run(resolved, versionArgs, {
              timeoutMs: item.binary === 'checkov' ? 10_000 : 5000,
            });
            if (runRes.exitCode === 0 && runRes.stdout.trim()) {
              versionStr = runRes.stdout.trim().split('\n')[0];
            }
          } catch {
            // Version command might vary
          }
        }

        let sha256: string | undefined;
        let pinMatch: boolean | undefined;
        let expectedSha256: string | undefined;

        if (resolved) {
          try {
            if (fs.existsSync(resolved)) {
              const fileBytes = fs.readFileSync(resolved);
              sha256 = crypto.createHash('sha256').update(fileBytes).digest('hex');
              const platKey = `${process.platform}-${process.arch}`;
              const libc = detectLibc();
              const assetRes = resolveToolAsset(item.binary, platKey, libc);
              if (assetRes.asset) {
                expectedSha256 = assetRes.asset.sha256;
                pinMatch = sha256 === expectedSha256;
              }
            }
          } catch {
            // Read or hash calculation error ignored
          }
        }

        const suppInfo = supportedVersions[nameUsed] ?? supportedVersions[item.binary];
        const isSupported = Boolean(
          resolved && versionStr && suppInfo && isVersionSupported(versionStr, suppInfo.minVersion)
        );
        const hint = getInstallHint(item.binary);

        return {
          binary: item.binary,
          category: item.category,
          found: Boolean(resolved),
          resolvedPath: resolved ?? undefined,
          version: versionStr,
          supported: isSupported,
          installHint: hint,
          sha256,
          pinMatch,
          expectedSha256,
        };
      })
    );

    for (const item of results) {
      const brand = getEngineBrand(item.binary);
      const suppInfo = supportedVersions[item.binary];

      const icon = item.found ? pc.green('✔ Active') : pc.yellow('○ Auto-Provision Ready');

      console.log(
        `  ${icon.padEnd(22)} ${pc.bold(brand.brandName.padEnd(36))} [${pc.blue(item.category.padEnd(25))}]`
      );

      if (item.found && item.resolvedPath) {
        console.log(`    ↳ Engine Core : ${pc.cyan(brand.shortLabel)}`);
        console.log(`    ↳ Runtime Path: ${pc.gray(item.resolvedPath)}`);
        if (item.version) {
          if (suppInfo && isVersionSupported(item.version, suppInfo.minVersion)) {
            console.log(
              `    ↳ Version     : ${pc.cyan(item.version)} ${pc.green(`(supported: ${suppInfo.recommended}, tested: ${suppInfo.testedVersion})`)}`
            );
          } else if (suppInfo) {
            console.log(
              `    ↳ Version     : ${pc.yellow(item.version)} ${pc.yellow(`(unsupported: min ${suppInfo.minVersion}, tested: ${suppInfo.testedVersion})`)}`
            );
          } else {
            console.log(`    ↳ Version     : ${pc.cyan(item.version)}`);
          }
        } else {
          console.log(`    ↳ Version     : ${pc.gray('(Embedded / Active)')}`);
        }

        if (item.sha256) {
          if (item.pinMatch === true) {
            console.log(
              `    ↳ Pin Status  : ${pc.green('✔ Matches tools.lock.json')} ${pc.gray(`(sha256:${item.sha256.slice(0, 12)}...)`)}`
            );
          } else if (item.expectedSha256) {
            console.log(
              `    ↳ Pin Status  : ${pc.yellow('⚠ Pin mismatch')} ${pc.yellow(`(actual: ${item.sha256.slice(0, 12)}..., lock: ${item.expectedSha256.slice(0, 12)}...)`)}`
            );
          } else {
            console.log(
              `    ↳ Pin Status  : ${pc.gray(`○ Unpinned / System distribution (sha256:${item.sha256.slice(0, 12)}...)`)}`
            );
          }
        }
      } else {
        console.log(`    ↳ Status       : ${pc.gray(`Auto-provisions on demand via SecureShip`)}`);
      }
    }

    console.log(
      pc.gray(
        '\nNote: SecureShip sub-engines are fully managed and automatically provisioned,\nenabling unified security analysis with zero manual configuration.\n'
      )
    );

    // 5. WASM Grammar Integrity (Phase 3 Gate 2 Reachability Engine)
    console.log(pc.bold('Reachability Engine WASM Grammars:'));
    try {
      const { verifyBundledWasm } = await import('@secureship/reachability');
      const check = verifyBundledWasm();
      for (const res of check.results) {
        const icon = res.valid ? pc.green('✔') : pc.red('✖');
        const statusText = res.valid
          ? pc.green(`Verified (${res.expectedSize} bytes)`)
          : pc.red(`Integrity Mismatch: ${res.error ?? 'Hash mismatch'}`);
        console.log(`  ${icon} ${pc.bold(res.filename.padEnd(30))} ${statusText}`);
      }
    } catch (err: unknown) {
      console.log(
        `  ${pc.red('✖')} WASM integrity check error: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // 5.1 Function-Level Reachability Symbol Dataset (Phase B)
    console.log(pc.bold('\nFunction-Level Reachability Symbol Dataset:'));
    try {
      const { SymbolDatasetLoader } = await import('@secureship/reachability');
      const loadRes = SymbolDatasetLoader.loadBundledDataset();
      console.log(
        `  • Dataset ID        : ${pc.cyan(loadRes.dataset?.datasetId ?? 'vulnerable-symbols')}`
      );
      console.log(
        `  • Curated Entries   : ${pc.cyan(String(loadRes.dataset?.entries.length ?? 0))} verified entries`
      );
      console.log(
        `  • Cryptographic Hash: ${loadRes.ok ? pc.green('✔ Verified (SHA-256 match)') : pc.red('✖ Integrity check failed')}`
      );
    } catch (err: unknown) {
      console.log(
        `  ${pc.red('✖')} Dataset verification error: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // 6. Gate 3 AI Triage Diagnostics (Phase 4)
    console.log(pc.bold('\nGate 3 AI Triage Configuration & Environment:'));
    try {
      const { UserConfigLoader } = await import('@secureship/ai');
      const userConfig = UserConfigLoader.loadUserConfig();
      const aiEnabled = Boolean(userConfig.ai);
      console.log(
        `  • AI Enablement: ${aiEnabled ? pc.green('Enabled') : pc.yellow('Disabled (enable via `secureship ai enable`)')}`
      );
      if (userConfig.provider) console.log(`  • Provider     : ${pc.cyan(userConfig.provider)}`);
      if (userConfig.model) console.log(`  • Model        : ${pc.cyan(userConfig.model)}`);
      if (userConfig.baseUrl) console.log(`  • Base URL     : ${pc.cyan(userConfig.baseUrl)}`);

      // Environment variable keys check (never print actual keys)
      const anthropicKey = process.env.ANTHROPIC_API_KEY;
      const openaiKey = process.env.OPENAI_API_KEY;
      const genericKey = process.env.SECURESHIP_AI_API_KEY;
      console.log(
        `  • ANTHROPIC_API_KEY    : ${anthropicKey ? pc.green('Configured') : pc.gray('Not set')}`
      );
      console.log(
        `  • OPENAI_API_KEY       : ${openaiKey ? pc.green('Configured') : pc.gray('Not set')}`
      );
      console.log(
        `  • SECURESHIP_AI_API_KEY: ${genericKey ? pc.green('Configured') : pc.gray('Not set')}`
      );

      // Gitleaks secondary payload scanner
      const hasGitleaks = results.some((r) => r.binary === 'gitleaks' && r.found);
      console.log(
        `  • Gitleaks Redaction   : ${hasGitleaks ? pc.green('Active (secondary egress scan)') : pc.yellow('Not on PATH (optional regex-only fallback)')}`
      );
    } catch (err: unknown) {
      console.log(
        `  ${pc.yellow('⚠')} Could not load AI configuration: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // 7. Gate 4 Sandbox Environment (Phase 5)
    console.log(pc.bold('\nGate 4 Remediation Sandbox Environment:'));
    try {
      let dockerFound = false;
      let podmanFound = false;
      let dockerVersion = '';
      let podmanVersion = '';

      try {
        const dRes = await SafeProcessRunner.run('docker', ['--version'], { timeoutMs: 3000 });
        if (dRes.exitCode === 0) {
          dockerFound = true;
          dockerVersion = dRes.stdout.trim();
        }
      } catch {
        // Ignored
      }

      try {
        const pRes = await SafeProcessRunner.run('podman', ['--version'], { timeoutMs: 3000 });
        if (pRes.exitCode === 0) {
          podmanFound = true;
          podmanVersion = pRes.stdout.trim();
        }
      } catch {
        // Ignored
      }

      const hasContainerRuntime = dockerFound || podmanFound;
      const primaryInfo = dockerFound ? dockerVersion : podmanVersion;

      console.log(
        `  • Container Runtime : ${hasContainerRuntime ? pc.green('✔') : pc.yellow('⚠')} ${
          hasContainerRuntime
            ? pc.bold(primaryInfo)
            : pc.yellow('Neither Docker nor Podman detected on PATH')
        }`
      );
      console.log(
        `  • Sandbox Readiness : ${
          hasContainerRuntime
            ? pc.green('Ready for isolated container remediation')
            : pc.yellow(
                'Requires Docker/Podman for container sandbox; host fallback requires explicit trust'
              )
        }`
      );
    } catch (err: unknown) {
      console.log(
        `  ${pc.yellow('⚠')} Could not inspect container runtime: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    // 8. License Tier & Capabilities (Stage 5)
    console.log(pc.bold('\nLicense Tier & Operational Capabilities:'));
    try {
      const licReport = await getLicenseStatusReport();
      const tColor =
        licReport.tier === 'ENTERPRISE'
          ? pc.magenta
          : licReport.tier === 'PRO_TEAM'
            ? pc.cyan
            : pc.green;
      console.log(`  • Active Tier       : ${tColor(pc.bold(licReport.tier))}`);
      console.log(
        `  • License Status    : ${
          licReport.status === 'ACTIVE'
            ? pc.green('✔ Active')
            : licReport.status === 'EXPIRED'
              ? pc.red('✖ Expired')
              : pc.dim('Unlicensed (Community Free)')
        }`
      );
      if (licReport.email) {
        console.log(
          `  • Licensed To       : ${pc.bold(licReport.email)} (${licReport.orgId ?? 'Individual'})`
        );
        if (licReport.daysRemaining !== undefined) {
          console.log(`  • Expiry            : ${licReport.daysRemaining} days remaining`);
        }
      }
      const quotaStr =
        licReport.monthlyAiUsage.limit === null
          ? 'Unlimited'
          : String(licReport.monthlyAiUsage.limit);
      console.log(
        `  • Monthly AI Quota  : ${licReport.monthlyAiUsage.fixesUsed} / ${quotaStr} used`
      );
      console.log(
        `  • CI/CD Suppress    : ${
          licReport.capabilities.allowCiCdGatekeeper
            ? pc.green('✔ Enabled')
            : pc.dim('Gated (PRO_TEAM required)')
        }`
      );
    } catch {
      console.log(`  • Active Tier       : ${pc.green('FREE_BYOK')}`);
    }

    // 9. Offline Vulnerability Database Status (D10)
    console.log(pc.bold('\nOffline Vulnerability Database:'));
    try {
      const dbLocation = resolveDbDir();
      const currentPointerPath = path.join(dbLocation, 'CURRENT');
      if (fs.existsSync(currentPointerPath)) {
        const generationId = fs.readFileSync(currentPointerPath, 'utf-8').trim();
        const genDir = path.join(dbLocation, 'generations', generationId);
        const manifestPath = path.join(genDir, 'manifest.json');
        if (fs.existsSync(manifestPath)) {
          const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
          const upstreamTime = manifest.upstreamUpdatedAt ?? manifest.createdAt ?? 'Unknown';
          const importedTime = manifest.importedAt ?? manifest.createdAt ?? 'Unknown';
          let ageDaysStr = 'N/A';
          if (upstreamTime !== 'Unknown') {
            const diffMs = Date.now() - new Date(upstreamTime).getTime();
            const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
            ageDaysStr = `${days} day${days === 1 ? '' : 's'}`;
          }
          console.log(`  • Generation ID       : ${pc.cyan(generationId)}`);
          console.log(
            `  • Bundle ID           : ${pc.cyan(manifest.bundleId ?? 'bundle-offline')}`
          );
          console.log(`  • Schema Version      : ${pc.cyan(manifest.schemaVersion ?? '1.0')}`);
          console.log(`  • Upstream Date       : ${pc.cyan(upstreamTime)} (Age: ${ageDaysStr})`);
          console.log(`  • Imported At         : ${pc.cyan(importedTime)}`);
          console.log(
            `  • Cryptographic Trust : ${
              manifest.signatureValid
                ? pc.green('✔ Verified Ed25519 Signature')
                : pc.yellow('○ Unsigned Bundle (--allow-unsigned)')
            }`
          );
        } else {
          console.log(`  • Generation ID       : ${pc.cyan(generationId)} (Staged generation)`);
        }
      } else {
        console.log(
          `  • Status              : ${pc.gray('○ No offline bundle installed (online mode or run `secureship import-offline`)')}`
        );
        console.log(`  • Database Directory  : ${pc.gray(dbLocation)}`);
      }
    } catch (err: unknown) {
      console.log(
        `  ${pc.yellow('⚠')} Could not inspect offline DB: ${err instanceof Error ? err.message : String(err)}`
      );
    }
    console.log();
  }
}
