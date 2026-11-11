import fs from 'node:fs';
import path from 'node:path';
import pc from 'picocolors';
import { z } from 'zod';
import {
  type CycloneDxBom,
  type LicenseComplianceResult,
  type ScanReport,
  type SpdxBom,
  SupplyChainPolicySchema,
} from '@secureship/contracts';
import {
  analyzeSupplyChain,
  discoverPackages,
  evaluateLicenseCompliance,
  generateCycloneDXSbom,
  generateSpdxSbom,
  resolveTierCapabilities,
  type PackageTarget,
} from '@secureship/core-engine';
import { CLI_VERSION } from '../version.js';

export const SbomOptionsSchema = z.object({
  format: z.enum(['cyclonedx', 'spdx']).default('cyclonedx'),
  output: z.string().optional(),
  withVulns: z.boolean().default(false),
  signed: z.boolean().default(false),
  report: z.string().optional(),
  checkLicenses: z.boolean().default(false),
  allow: z.array(z.string()).optional(),
  deny: z.array(z.string()).optional(),
  json: z.boolean().default(false),
  dir: z.string().default('.'),
});
export type SbomOptions = z.infer<typeof SbomOptionsSchema>;

export class SbomCommand {
  /**
   * Main execution entry point for 'secureship sbom'.
   */
  public static async run(targetDir = '.', rawOptions: Partial<SbomOptions> = {}): Promise<number> {
    const finalDir = path.resolve(rawOptions.dir ?? targetDir);
    const options = SbomOptionsSchema.parse({ ...rawOptions, dir: finalDir });

    if (!fs.existsSync(finalDir)) {
      console.error(pc.red(`\n✖ Error: Target directory does not exist: ${finalDir}`));
      return 1;
    }

    // Validate signed compliance export capability under active tier (Stage 5)
    if (options.signed) {
      const tierState = await resolveTierCapabilities();
      if (!tierState.capabilities.allowSignedComplianceExport) {
        console.error(
          pc.red(
            `\n✖ License Gated: Cryptographically signed compliance export requires PRO_TEAM or ENTERPRISE tier.`
          )
        );
        console.error(
          pc.yellow(
            `  Your current tier is: ${tierState.tier}. Run 'secureship license upgrade' to unlock signed compliance exports.\n`
          )
        );
        console.error(pc.dim('  Pricing: https://secureship.dev/pricing'));
        console.error(pc.dim('  Run: secureship license upgrade  to open the pricing portal.'));
        return 1;
      }
    }

    // 1. Discover all packages in project
    const packages: PackageTarget[] = discoverPackages(finalDir);

    // 2. Load or compute vulnerability findings if --with-vulns requested
    let scanReport: ScanReport | undefined;
    if (options.withVulns) {
      scanReport = await resolveScanReport(finalDir, options.report);
    }

    // 3. Generate SBOM according to format (CycloneDX 1.5 or SPDX 2.3)
    let bomData: CycloneDxBom | SpdxBom;
    if (options.format === 'spdx') {
      bomData = generateSpdxSbom({
        rootDir: finalDir,
        packages,
        cliVersion: CLI_VERSION,
      });
    } else {
      bomData = generateCycloneDXSbom({
        rootDir: finalDir,
        packages,
        scanReport,
        cliVersion: CLI_VERSION,
      });
    }

    // 4. Evaluate license compliance if requested
    let complianceResult: LicenseComplianceResult | undefined;
    if (options.checkLicenses) {
      complianceResult = evaluateLicenseCompliance(packages, {
        allow: options.allow,
        deny: options.deny,
      });
    }

    // 5. Output handling
    const formattedJson = JSON.stringify(bomData, null, 2);

    if (options.output) {
      const outputPath = path.resolve(options.output);
      const outputDir = path.dirname(outputPath);
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }
      fs.writeFileSync(outputPath, formattedJson, 'utf-8');

      if (!options.json) {
        console.log(pc.bold(pc.green(`\n✔ SBOM successfully written to: ${outputPath}`)));
        console.log(
          pc.cyan(
            `  • Format: ${options.format.toUpperCase()} (${options.format === 'cyclonedx' ? '1.5' : '2.3'})`
          )
        );
        console.log(pc.cyan(`  • Total Components: ${packages.length}`));
        if (options.withVulns) {
          const vulnCount =
            'vulnerabilities' in bomData && Array.isArray(bomData.vulnerabilities)
              ? bomData.vulnerabilities.length
              : 0;
          console.log(pc.cyan(`  • Vulnerabilities Linked: ${vulnCount}`));
        }
      }
    } else if (options.json) {
      if (complianceResult) {
        console.log(
          JSON.stringify(
            {
              sbom: bomData,
              compliance: complianceResult,
            },
            null,
            2
          )
        );
      } else {
        console.log(formattedJson);
      }
    } else {
      // Human-readable terminal output
      console.log(
        pc.bold(
          pc.cyan(
            `\n📦 SecureShip Software Bill of Materials (${options.format === 'cyclonedx' ? 'CycloneDX 1.5' : 'SPDX 2.3'})\n`
          )
        )
      );
      console.log(`Target Directory : ${finalDir}`);
      console.log(`Total Packages   : ${packages.length}`);
      if (packages.length > 0) {
        console.log(pc.bold('\nDiscovered Components:'));
        for (const pkg of packages.slice(0, 20)) {
          console.log(`  • ${pc.bold(pkg.name)}@${pkg.version} (${pc.dim(pkg.ecosystem)})`);
        }
        if (packages.length > 20) {
          console.log(pc.dim(`  ... and ${packages.length - 20} more packages`));
        }
      }
      console.log(
        pc.dim(
          '\nTip: Use --output <file.json> to export full machine-readable SBOM specification.'
        )
      );
    }

    // 6. Report license compliance results in terminal if enabled
    if (complianceResult && !options.json) {
      console.log(pc.bold(pc.cyan('\n⚖ License Compliance Analysis:')));
      console.log(`  Total Packages Evaluated : ${complianceResult.totalPackages}`);
      console.log(`  Compliant Packages       : ${pc.green(complianceResult.compliantCount)}`);
      console.log(
        `  Violations Detected      : ${complianceResult.violationCount > 0 ? pc.red(complianceResult.violationCount) : pc.green(0)}`
      );

      if (complianceResult.violations.length > 0) {
        console.log(pc.bold(pc.red('\nLicense Violations:')));
        for (const v of complianceResult.violations) {
          const badge =
            v.severity === 'CRITICAL'
              ? pc.bgRed(pc.white(` ${v.severity} `))
              : pc.yellow(`[${v.severity}]`);
          console.log(
            `  ${badge} ${pc.bold(v.packageName)}@${v.version} — License: ${pc.underline(v.license)}`
          );
          console.log(`     ↳ ${pc.dim(v.reason)}`);
        }
      } else {
        console.log(pc.green('\n✔ All package licenses comply with configured policy.'));
      }
    }

    // If license compliance failed, exit code 1
    if (complianceResult && complianceResult.violations.length > 0) {
      return 1;
    }

    return 0;
  }
}

/**
 * Resolves or computes a ScanReport to enrich SBOM components with vulnerability data.
 */
async function resolveScanReport(
  rootDir: string,
  explicitReportPath?: string
): Promise<ScanReport | undefined> {
  // 1. Explicit report path
  if (explicitReportPath) {
    const resolvedPath = path.resolve(explicitReportPath);
    if (fs.existsSync(resolvedPath)) {
      try {
        return JSON.parse(fs.readFileSync(resolvedPath, 'utf-8')) as ScanReport;
      } catch (err) {
        console.warn(
          pc.yellow(`⚠ Failed to parse explicit scan report at ${resolvedPath}: ${String(err)}`)
        );
      }
    }
  }

  // 2. Existing report candidates
  const candidates = [
    path.join(rootDir, '.secureship', 'scan-report.json'),
    path.join(rootDir, 'secureship-report.json'),
  ];
  for (const cand of candidates) {
    if (fs.existsSync(cand)) {
      try {
        return JSON.parse(fs.readFileSync(cand, 'utf-8')) as ScanReport;
      } catch {
        // Ignore
      }
    }
  }

  // 3. Fallback: Run fast supply-chain scanner live to collect findings
  try {
    const policy = SupplyChainPolicySchema.parse({ enabled: true });
    const fallbackStart = Date.now();
    const scResult = await analyzeSupplyChain({
      rootDir,
      policy,
    });
    const elapsed = Date.now() - fallbackStart;

    const nowIso = new Date().toISOString();
    return {
      schemaVersion: '1.2',
      tool: {
        name: 'SecureShip CLI',
        version: CLI_VERSION,
      },
      target: rootDir,
      mode: 'FULL',
      startedAt: nowIso,
      durationMs: elapsed,
      scanners: [
        {
          name: 'generic',
          version: '1.0.0',
          status: 'SUCCESS',
          durationMs: elapsed,
          rawFindingCount: scResult.findings.length,
        },
      ],
      findings: scResult.findings,
      suppressed: [],
      warnings: [],
      summary: {
        totalRaw: scResult.findings.length,
        totalReported: scResult.findings.length,
        totalSuppressed: 0,
        totalOutOfScope: 0,
        bySeverity: {
          CRITICAL: scResult.findings.filter((f) => f.severity === 'CRITICAL').length,
          HIGH: scResult.findings.filter((f) => f.severity === 'HIGH').length,
          MEDIUM: scResult.findings.filter((f) => f.severity === 'MEDIUM').length,
          LOW: scResult.findings.filter((f) => f.severity === 'LOW').length,
          INFO: scResult.findings.filter((f) => f.severity === 'INFO').length,
        },
        byCategory: {
          SUPPLY_CHAIN: scResult.findings.length,
        },
        suppressedByReason: {},
      },
    };
  } catch {
    return undefined;
  }
}
