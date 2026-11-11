import * as vscode from 'vscode';
import type { ExtNormalizedFinding, ExtSeverity } from '../types/extension-types.js';

const SEVERITY_ORDER: ExtSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/**
 * Normalizes an import specifier string to its base package name.
 * Strips subpaths, ignores relative paths, and handles npm scoped packages.
 */
export function normalizePackageName(rawSpecifier: string): string | null {
  const trimmed = rawSpecifier.trim();
  if (trimmed.startsWith('.') || trimmed.startsWith('/') || trimmed.startsWith('\\')) {
    return null;
  }

  if (trimmed.startsWith('@')) {
    const parts = trimmed.split('/');
    if (parts.length >= 2) {
      return `${parts[0]}/${parts[1]}`;
    }
    return trimmed;
  }

  const parts = trimmed.split('/');
  return parts[0] || null;
}

/**
 * Extracts a candidate npm package name from an import/require statement line.
 */
export function extractPackageFromLine(line: string): string | null {
  const trimmed = line.trim();

  // 1. from 'specifier' or from "specifier"
  const fromMatch = trimmed.match(/\bfrom\s+['"]([^'"]+)['"]/);
  if (fromMatch && fromMatch[1]) {
    return normalizePackageName(fromMatch[1]);
  }

  // 2. require('specifier') or require("specifier")
  const reqMatch = trimmed.match(/\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/);
  if (reqMatch && reqMatch[1]) {
    return normalizePackageName(reqMatch[1]);
  }

  // 3. import('specifier') or import("specifier")
  const dynamicImportMatch = trimmed.match(/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/);
  if (dynamicImportMatch && dynamicImportMatch[1]) {
    return normalizePackageName(dynamicImportMatch[1]);
  }

  // 4. import 'specifier' or import "specifier"
  const sideEffectMatch = trimmed.match(/\bimport\s+['"]([^'"]+)['"]/);
  if (sideEffectMatch && sideEffectMatch[1]) {
    return normalizePackageName(sideEffectMatch[1]);
  }

  return null;
}

/**
 * Provides rich, interactive hover cards on package imports when
 * supply-chain vulnerabilities are detected.
 */
export class SecureShipHoverProvider implements vscode.HoverProvider {
  private findings: ExtNormalizedFinding[] = [];

  /**
   * Updates cached findings from the latest scan report.
   */
  public updateFindings(findings: ExtNormalizedFinding[]): void {
    this.findings = findings;
  }

  public provideHover(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.Hover | null {
    const lineText = document.lineAt(position.line).text;
    const packageName = extractPackageFromLine(lineText);
    if (!packageName) {
      return null;
    }

    // Filter strictly to SUPPLY_CHAIN category matching package name
    const matching = this.findings.filter(
      (f) => f.category === 'SUPPLY_CHAIN' && f.package?.name === packageName
    );

    if (matching.length === 0) {
      return null;
    }

    // Determine highest severity
    const sorted = [...matching].sort(
      (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
    );
    const highestFinding = sorted[0];
    if (!highestFinding) {
      return null;
    }
    const highestSeverity = highestFinding.severity;

    // Determine installed and fixed versions
    const installedVersion =
      matching.find((f) => f.package?.version)?.package?.version ?? 'Unknown';
    const safeVersion =
      matching.find((f) => f.package?.fixedVersion)?.package?.fixedVersion ?? 'None available';

    // Construct Theme-Adaptive Codicon Markdown Card
    const md = new vscode.MarkdownString('', true);
    md.isTrusted = true;
    md.supportHtml = true;

    const severityIcon =
      highestSeverity === 'CRITICAL'
        ? '$(error)'
        : highestSeverity === 'HIGH'
          ? '$(warning)'
          : '$(info)';

    md.appendMarkdown(`### $(shield) SecureShip Supply-Chain Threat Alert\n\n`);

    md.appendMarkdown(`| Metric | Details |\n`);
    md.appendMarkdown(`| :--- | :--- |\n`);
    md.appendMarkdown(`| **Package** | \`${packageName}\` |\n`);
    md.appendMarkdown(`| **Installed Version** | \`${installedVersion}\` |\n`);
    md.appendMarkdown(`| **Safe Version** | \`${safeVersion}\` |\n`);
    md.appendMarkdown(`| **Highest Severity** | ${severityIcon} **${highestSeverity}** |\n\n`);

    md.appendMarkdown(`**Known Vulnerabilities (${matching.length}):**\n`);
    const topFindings = matching.slice(0, 4);
    for (const f of topFindings) {
      md.appendMarkdown(`- **${f.ruleId}** (${f.severity}): ${f.title}\n`);
    }
    if (matching.length > 4) {
      md.appendMarkdown(`- *...and ${matching.length - 4} more finding(s)*\n`);
    }

    md.appendMarkdown(`\n---\n`);

    // Action footer
    const fixFinding = matching.find((f) => f.fixRecommendation) ?? highestFinding;
    const fixArg = encodeURIComponent(JSON.stringify(fixFinding.fingerprint || fixFinding.id));
    const ruleUrl = `https://secureship.dev/rules/${encodeURIComponent(highestFinding.ruleId)}`;

    md.appendMarkdown(
      `[$(sparkle) Quick-Fix with Gate 4 Sandbox](command:secureship.fixFinding?${fixArg}) | [$(book) Rule Docs](${ruleUrl}) | [$(list-unordered) View All Findings](command:secureship.openFindings)`
    );

    return new vscode.Hover(md);
  }
}
