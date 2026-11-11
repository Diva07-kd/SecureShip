import pc from 'picocolors';
import { getLicenseStatusReport } from '@secureship/core-engine';
import { CLI_VERSION } from '../version.js';

export class StatusCommand {
  private static readVersion(): string {
    return CLI_VERSION;
  }

  public static async run(options: { json?: boolean } = {}): Promise<void> {
    const version = StatusCommand.readVersion();
    const report = await getLicenseStatusReport();

    if (options.json) {
      console.log(JSON.stringify(report, null, 2));
      return;
    }

    console.log(pc.bold(pc.cyan('\n🛡️  SecureShip Engine Status & License Tier\n')));
    console.log(`Engine Version : ${pc.bold(version)}`);

    const tierColor =
      report.tier === 'ENTERPRISE' ? pc.magenta : report.tier === 'PRO_TEAM' ? pc.cyan : pc.green;
    console.log(`Active Tier    : ${tierColor(pc.bold(report.tier))}`);

    const statusBadge =
      report.status === 'ACTIVE'
        ? pc.green('✔ ACTIVE')
        : report.status === 'EXPIRED'
          ? pc.red('✖ EXPIRED (Fallback to FREE_BYOK)')
          : report.status === 'INVALID_SIGNATURE'
            ? pc.red('✖ INVALID SIGNATURE')
            : pc.dim('Unlicensed (Community Free)');
    console.log(`License Status : ${statusBadge}`);

    if (report.email) {
      console.log(`Licensed To    : ${pc.bold(report.email)} (${report.orgId ?? 'Individual'})`);
      console.log(`Seats Allocated: ${pc.bold(String(report.seats ?? 1))}`);
      if (report.daysRemaining !== undefined) {
        const expiryColor = report.daysRemaining <= 7 ? pc.yellow : pc.dim;
        console.log(
          `Expires In     : ${expiryColor(`${report.daysRemaining} days`)} (${report.expiresAt ? report.expiresAt.split('T')[0] : 'N/A'})`
        );
      }
    }

    const aiLimitStr =
      report.monthlyAiUsage.limit === null ? 'Unlimited' : String(report.monthlyAiUsage.limit);
    console.log(
      `Monthly AI Fix : ${report.monthlyAiUsage.fixesUsed} / ${aiLimitStr} used (Month: ${report.monthlyAiUsage.month})`
    );

    console.log(pc.bold('\nPipeline Capabilities & Feature Gates:'));
    console.log(
      `  • Multi-Scanner Integration   : ${pc.green('✔ Enabled (SAST, Secrets, SCA, IaC)')}`
    );
    console.log(
      `  • Gate 1 Scope & Diff Filtering: ${pc.green('✔ Active (Git diff, test/mock suppression)')}`
    );
    console.log(`  • Import-level reachability   : ${pc.green('included (AST BFS analysis)')}`);
    console.log(
      `  • Gate 2 CI/CD Suppress Gate  : ${
        report.capabilities.allowCiCdGatekeeper
          ? pc.green('✔ Active (PRO_TEAM feature unlocked)')
          : pc.yellow('⚠ Gated (Requires PRO_TEAM for --gate2 suppress)')
      }`
    );
    let datasetDetail = '';
    try {
      const { SymbolDatasetLoader } = await import('@secureship/reachability');
      const ds = SymbolDatasetLoader.loadBundledDataset();
      datasetDetail = ` (Dataset: ${ds.dataset?.datasetId ?? 'vulnerable-symbols'}, ${ds.dataset?.entries.length ?? 0} entries, ${ds.ok ? 'Verified' : 'Tampered'})`;
    } catch {
      // Ignored
    }

    console.log(
      `  • Function-level reachability : ${
        report.capabilities.allowCallPathReachability
          ? pc.green(`✔ Active${datasetDetail}`)
          : pc.yellow(`⚠ Gated (Requires PRO_TEAM / ENTERPRISE)${datasetDetail}`)
      }`
    );
    console.log(
      `  • AI Triage & Skeptic (Gate 3): ${pc.green('✔ Active - included for BYOK (OpenAI, Anthropic, or local endpoints: Ollama, LM Studio, vLLM)')}`
    );
    console.log(
      `  • Remediation Engine (Gate 4) : ${pc.green('✔ Active - Verified remediation (BYOK), commercial tier limits not enforced')}`
    );
    console.log(
      `  • Signed Compliance Export    : ${
        report.capabilities.allowSignedComplianceExport
          ? pc.green('✔ Active (Cryptographic SBOM signatures unlocked)')
          : pc.yellow('⚠ Gated (Requires PRO_TEAM or ENTERPRISE)')
      }`
    );
    console.log(
      `  • Enterprise Support & Private Deployments: ${
        report.capabilities.allowAirGappedOnPrem
          ? pc.green('✔ Active (Enterprise license)')
          : pc.yellow('Enterprise tier')
      }\n`
    );

    if (report.tier === 'FREE_BYOK') {
      console.log(
        pc.dim(
          '💡 Tip: To unlock CI/CD suppress mode and higher AI fix quotas, run "secureship license upgrade" or "secureship license activate <key>".\n'
        )
      );
    }
  }
}
