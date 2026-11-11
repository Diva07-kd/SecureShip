import fs from 'node:fs';
import path from 'node:path';
import { select, checkbox, confirm } from '@inquirer/prompts';
import pc from 'picocolors';
import { z } from 'zod';
import {
  ConfigSchema,
  type SecureShipConfig,
  type FailOnSeverity,
  type ScannerName,
} from '@secureship/contracts';

export const InitOptionsSchema = z.object({
  failOn: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'NONE']).default('HIGH'),
  scanners: z.array(z.string()).default(['opengrep', 'gitleaks', 'trivy', 'osv-scanner']),
  gate2: z.enum(['annotate', 'suppress', 'off']).default('annotate'),
  generateAction: z.boolean().default(true),
  createBaseline: z.boolean().default(false),
  yes: z.boolean().default(false),
  dir: z.string().default('.'),
  force: z.boolean().default(false),
});
export type InitOptions = z.infer<typeof InitOptionsSchema>;

export class InitCommand {
  public static async run(targetDir = '.', options: Partial<InitOptions> = {}): Promise<number> {
    const resolvedDir = path.resolve(targetDir);
    const parsedOptions = InitOptionsSchema.parse({ ...options, dir: resolvedDir });

    const configPath = path.join(resolvedDir, 'secureship.config.json');
    if (fs.existsSync(configPath) && !parsedOptions.force) {
      console.error(
        pc.red(
          `\n✖ Error: Configuration file already exists at ${configPath}. Use --force to overwrite.`
        )
      );
      return 1;
    }

    let failOn: FailOnSeverity = parsedOptions.failOn as FailOnSeverity;
    let enabledScanners: string[] = parsedOptions.scanners;
    let gate2Mode: 'annotate' | 'suppress' | 'off' = parsedOptions.gate2;
    let generateAction = parsedOptions.generateAction;
    let createBaseline = parsedOptions.createBaseline;

    // Interactive wizard when TTY is available and --yes is not set
    if (!parsedOptions.yes && process.stdin.isTTY) {
      console.log(pc.bold(pc.cyan('\n⚙  SecureShip Interactive Project Setup Wizard\n')));

      failOn = (await select({
        message: 'Fail CI/CD pipeline on severity at or above:',
        choices: [
          { value: 'CRITICAL', name: 'CRITICAL — Only block on critical issues' },
          { value: 'HIGH', name: 'HIGH — Block on critical + high (recommended)' },
          { value: 'MEDIUM', name: 'MEDIUM — Block on critical + high + medium' },
          { value: 'NONE', name: 'NONE — Never fail CI' },
        ],
        default: 'HIGH',
      })) as FailOnSeverity;

      const scannerChoices = await checkbox({
        message: 'Enable security scanners:',
        choices: [
          { value: 'opengrep', name: 'opengrep — SAST static analysis', checked: true },
          { value: 'gitleaks', name: 'gitleaks — Secrets detection', checked: true },
          { value: 'trivy', name: 'trivy — SCA + IaC scanning', checked: true },
          { value: 'osv-scanner', name: 'osv-scanner — OSV vulnerability database', checked: true },
          { value: 'checkov', name: 'checkov — Infrastructure-as-Code', checked: false },
        ],
      });
      enabledScanners = scannerChoices;

      gate2Mode = (await select({
        message: 'Reachability verification mode (Gate 2):',
        choices: [
          { value: 'annotate', name: 'annotate — Tag findings with reachability info (default)' },
          { value: 'suppress', name: 'suppress — Suppress unreachable SCA findings (PRO tier)' },
          { value: 'off', name: 'off — Disable reachability analysis' },
        ],
        default: 'annotate',
      })) as 'annotate' | 'suppress' | 'off';

      generateAction = await confirm({
        message: 'Generate GitHub Actions CI workflow (.github/workflows/secureship.yml)?',
        default: true,
      });

      createBaseline = await confirm({
        message: 'Scan now and create initial baseline (.secureship/baseline.json)?',
        default: false,
      });
    }

    // Build configuration object
    const scannerMap: Record<ScannerName, boolean> = {
      opengrep: enabledScanners.includes('opengrep'),
      gitleaks: enabledScanners.includes('gitleaks'),
      trivy: enabledScanners.includes('trivy'),
      'osv-scanner': enabledScanners.includes('osv-scanner'),
      checkov: enabledScanners.includes('checkov'),
      semgrep: enabledScanners.includes('semgrep'),
      generic: false,
    };

    const configData: SecureShipConfig = {
      failOn,
      scanners: scannerMap,
      gate1: {
        enabled: true,
        keepProviderSecrets: true,
        customTestDirs: [],
      },
      gate2: {
        mode: gate2Mode,
        neverSuppressSeverities: ['CRITICAL'],
        maxFileBytes: 1_048_576,
        parseTimeoutMs: 5000,
      },
      baselinePath: '.secureship/baseline.json',
      ignore: [],
      extraRulePacks: [],
      checkovDefaultSeverity: 'MEDIUM',
    };

    // Strict validation against ConfigSchema
    const validated = ConfigSchema.parse(configData);

    // Write secureship.config.json
    if (!fs.existsSync(resolvedDir)) {
      fs.mkdirSync(resolvedDir, { recursive: true });
    }
    fs.writeFileSync(configPath, JSON.stringify(validated, null, 2) + '\n', 'utf-8');
    console.log(`  ${pc.green('✔')} Created ${pc.bold('secureship.config.json')}`);

    // Generate GitHub Actions workflow if selected
    if (generateAction) {
      InitCommand.scaffoldGithubActionWorkflow(resolvedDir);
      console.log(`  ${pc.green('✔')} Created ${pc.bold('.github/workflows/secureship.yml')}`);
    }

    // Generate initial baseline if requested
    if (createBaseline) {
      await InitCommand.initializeBaseline(resolvedDir);
      console.log(`  ${pc.green('✔')} Created ${pc.bold('.secureship/baseline.json')}`);
    }

    console.log(pc.bold(pc.green('\n🎉 SecureShip successfully initialized for this project!\n')));
    console.log('Next steps:');
    console.log(`  - Run ${pc.cyan('secureship scan .')} to execute your first security scan.`);
    console.log(`  - Run ${pc.cyan('secureship doctor')} to ensure all scanner engines are ready.`);
    console.log();
    return 0;
  }

  public static scaffoldGithubActionWorkflow(rootDir: string): void {
    const workflowsDir = path.join(rootDir, '.github', 'workflows');
    if (!fs.existsSync(workflowsDir)) {
      fs.mkdirSync(workflowsDir, { recursive: true });
    }
    const workflowPath = path.join(workflowsDir, 'secureship.yml');
    const content = `name: SecureShip Security Verification

on:
  push:
    branches: [main, master, develop]
  pull_request:
    branches: [main, master, develop]

permissions:
  contents: read
  security-events: write

jobs:
  secureship:
    name: Security Scan & Reachability Verification
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Install SecureShip CLI
        run: |
          npm install -g @secureship/cli
          secureship install-tools

      - name: Incremental Diff Scan (Pull Request)
        if: github.event_name == 'pull_request'
        run: |
          secureship scan . \\
            --diff \${{ github.event.pull_request.base.sha }} \\
            --sarif secureship.sarif \\
            --new-only \\
            --baseline .secureship/baseline.json \\
            --fail-on HIGH
        continue-on-error: true

      - name: Upload SARIF to GitHub Code Scanning (Pull Request)
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secureship.sarif
          category: secureship

      - name: Full Repository Scan (Push)
        if: github.event_name == 'push'
        run: |
          secureship scan . \\
            --sarif secureship.sarif \\
            --fail-on HIGH

      - name: Upload SARIF to GitHub Code Scanning (Push)
        uses: github/codeql-action/upload-sarif@v3
        if: github.event_name == 'push'
        with:
          sarif_file: secureship.sarif
          category: secureship
`;
    fs.writeFileSync(workflowPath, content, 'utf-8');
  }

  public static async initializeBaseline(rootDir: string): Promise<void> {
    const baselineDir = path.join(rootDir, '.secureship');
    if (!fs.existsSync(baselineDir)) {
      fs.mkdirSync(baselineDir, { recursive: true });
    }
    const baselineFile = path.join(baselineDir, 'baseline.json');
    const { BaselineEvaluator } = await import('@secureship/core-engine');
    BaselineEvaluator.writeBaseline(baselineFile, []);
  }
}
