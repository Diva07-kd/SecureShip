import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { hostname } from 'node:os';
import pc from 'picocolors';
import {
  writeLicenseFile,
  deleteLicenseFile,
  getDefaultLicensePath,
  verifyLicenseJwt,
} from '@secureship/core-engine';
import { StatusCommand } from './status.js';

export function getMachineFingerprint(): string {
  // Deterministic but non-sensitive: combination of hostname + platform + arch
  // Does NOT collect: IP, username, disk serial, MAC address (zero PII)
  const raw = [hostname(), process.platform, process.arch].join('|');
  return createHash('sha256').update(raw).digest('hex').slice(0, 16);
}

export interface LicenseActivateOptions {
  server?: string;
  offlineFile?: string;
  force?: boolean;
}

export class LicenseCommand {
  /**
   * Activates a license using an online activation code or an offline JWT file.
   */
  public static async activate(
    activationCodeOrFile: string,
    options: LicenseActivateOptions = {}
  ): Promise<number> {
    const licensePath = getDefaultLicensePath();
    const serverUrl = options.server ?? 'https://license.secureship.dev';

    console.log(pc.bold(pc.cyan('\n🔑 SecureShip License Activation\n')));

    let jwtToken: string;

    // Mode A: Offline file activation (air-gapped enterprise environments)
    if (
      options.offlineFile ||
      (fs.existsSync(activationCodeOrFile) && activationCodeOrFile.endsWith('.jwt'))
    ) {
      const filePath = path.resolve(options.offlineFile ?? activationCodeOrFile);
      console.log(`Loading offline license file: ${pc.bold(filePath)}...`);

      if (!fs.existsSync(filePath)) {
        console.error(pc.red(`✖ Error: Specified license file not found at "${filePath}"`));
        return 1;
      }

      jwtToken = fs.readFileSync(filePath, 'utf-8').trim();
    } else {
      // Mode B: Online activation code
      const code = activationCodeOrFile.trim();
      console.log(`Connecting to SecureShip License Server: ${pc.cyan(serverUrl)}...`);
      console.log(`Validating activation key: ${pc.bold(code.slice(0, 4) + '-****-****')}...`);

      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000); // 8s timeout

        const res = await fetch(`${serverUrl}/v1/activate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify({
            activationCode: code,
            machineFingerprint: getMachineFingerprint(),
          }),
          signal: controller.signal,
        });
        clearTimeout(timeout);

        if (!res.ok) {
          const errBody = (await res.json().catch(() => ({}))) as {
            message?: string;
            error?: string;
          };
          const errorMsg =
            errBody.message || errBody.error || `HTTP ${res.status}: ${res.statusText}`;
          console.error(pc.red(`\n✖ Activation Failed: ${errorMsg}`));
          console.error(
            pc.dim('  Please check your activation key or visit https://secureship.dev/support.\n')
          );
          return 1;
        }

        const data = (await res.json()) as { jwt?: string; message?: string };
        if (!data.jwt) {
          console.error(pc.red('\n✖ Invalid response from license server: missing JWT payload.'));
          return 1;
        }

        jwtToken = data.jwt;
      } catch (err: unknown) {
        console.error(
          pc.red(
            `\n✖ Network Error: Unable to reach license server (${err instanceof Error ? err.message : String(err)}).`
          )
        );
        console.error(
          pc.yellow(
            '  Tip: If running in an air-gapped on-premise environment, use "--offline-file <license.jwt>".\n'
          )
        );
        return 1;
      }
    }

    // Cryptographic validation of the JWT before writing to disk
    const validation = verifyLicenseJwt(jwtToken);
    if (!validation.valid || !validation.payload) {
      console.error(pc.red(`\n✖ Cryptographic Verification Failed: ${validation.error}`));
      console.error(pc.red('  The license token cannot be trusted. Activation aborted.\n'));
      return 1;
    }

    // Persist to ~/.secureship/license.jwt
    writeLicenseFile(jwtToken, licensePath);

    console.log(pc.green('\n✔ License Activated Successfully!'));
    console.log(`  • Organization : ${pc.bold(validation.payload.orgId)}`);
    console.log(`  • User/Sub     : ${pc.bold(validation.payload.sub)}`);
    const tierColor = validation.payload.tier === 'ENTERPRISE' ? pc.magenta : pc.cyan;
    console.log(`  • Active Tier  : ${tierColor(pc.bold(validation.payload.tier))}`);
    console.log(`  • Seats        : ${pc.bold(String(validation.payload.seats))}`);
    console.log(
      `  • Valid Until  : ${new Date(validation.payload.exp * 1000).toISOString().split('T')[0]} (${validation.daysRemaining} days remaining)`
    );
    console.log(`  • Token Path   : ${licensePath}\n`);

    return 0;
  }

  /**
   * Displays the current license status and active feature capabilities.
   */
  public static async status(options: { json?: boolean } = {}): Promise<number> {
    await StatusCommand.run(options);
    return 0;
  }

  /**
   * Opens the upgrade portal or displays pricing tiers.
   */
  public static upgrade(): void {
    const pricingUrl = 'https://secureship.dev/pricing';
    console.log(pc.bold(pc.cyan('\n🚀 SecureShip Tier Upgrade & Pricing\n')));
    console.log('Compare feature tiers and unlock advanced enterprise capabilities:');
    console.log(
      `  • ${pc.bold('FREE_BYOK')}: 15 AI fixes/mo, Import Reachability, Community Support (Free forever)`
    );
    console.log(
      `  • ${pc.bold('PRO_TEAM')} : 100 AI fixes/mo, Gate 2 Suppress Mode, Signed SBOM Exports, Call-path reachability ($29/dev/mo)`
    );
    console.log(
      `  • ${pc.bold('ENTERPRISE')}: Unlimited AI fixes, Air-gapped on-premise SLA, Custom model routing, Dedicated support`
    );
    console.log(`\nVisit: ${pc.underline(pc.bold(pricingUrl))}`);

    // Attempt to open browser in interactive desktop environment
    if (process.platform === 'darwin' || process.platform === 'win32' || process.env.DISPLAY) {
      import('node:child_process')
        .then(({ exec }) => {
          const cmd =
            process.platform === 'win32'
              ? `start ${pricingUrl}`
              : process.platform === 'darwin'
                ? `open ${pricingUrl}`
                : `xdg-open ${pricingUrl}`;
          exec(cmd, () => {});
        })
        .catch(() => {});
    }
    console.log();
  }

  /**
   * Removes the local license token, reverting to FREE_BYOK.
   */
  public static async remove(): Promise<number> {
    const licensePath = getDefaultLicensePath();
    const removed = deleteLicenseFile(licensePath);

    if (removed) {
      console.log(pc.green('\n✔ License token removed successfully.'));
      console.log(pc.dim(`  Deleted: ${licensePath}`));
      console.log(pc.yellow('  SecureShip has reverted to the FREE_BYOK tier.\n'));
      return 0;
    }

    console.log(pc.dim('\nℹ No active license file found to remove.\n'));
    return 0;
  }
}
