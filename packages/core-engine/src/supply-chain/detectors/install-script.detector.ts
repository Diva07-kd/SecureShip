import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { SupplyChainEvidenceItem, SupplyChainPolicy } from '@secureship/contracts';
import type { DetectorContext, RuleHit } from '../internal/types.js';
import { RULES_REGISTRY } from '../rules-registry.js';

const DANGEROUS_FETCH_PATTERNS = [
  /curl\s+[^|;&]+\|\s*(?:bash|sh|zsh|node|python|perl)/i,
  /wget\s+[^|;&]+\|\s*(?:bash|sh|zsh|node|python|perl)/i,
  /invoke-webrequest\s+[^|;&]+\|\s*iex/i,
  /bash\s+-c\s+["'].*curl/i,
  /bash\s+-c\s+["'].*wget/i,
];

const DANGEROUS_OBFUSCATION_PATTERNS = [
  /base64\s+(?:-d|--decode)/i,
  /\[Convert\]::FromBase64String/i,
  /Buffer\.from\([^)]+,\s*['"]base64['"]\)/i,
];

const DANGEROUS_EXFIL_PATTERNS = [
  /(?:\.ssh|\.aws|\.npmrc|\/etc\/passwd|\/etc\/shadow|id_rsa)/i,
  /(?:curl|wget|nc|netcat)\s+.*(?:\$|\b)(?:AWS_|NPM_|GITHUB_|SECRET|TOKEN|KEY)/i,
];

function computeHash(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

export function detectInstallScripts(
  packageJson: Record<string, unknown>,
  packageDir: string,
  _policy: SupplyChainPolicy,
  ctx: DetectorContext
): RuleHit[] {
  const hits: RuleHit[] = [];
  const purl = `pkg:${ctx.ecosystem}/${ctx.packageName}@${ctx.version}`;
  const scripts = (
    packageJson.scripts && typeof packageJson.scripts === 'object' ? packageJson.scripts : {}
  ) as Record<string, unknown>;

  const hookNames = ['preinstall', 'install', 'postinstall'];

  for (const hook of hookNames) {
    const scriptVal = scripts[hook];
    if (typeof scriptVal !== 'string' || !scriptVal.trim()) {
      continue;
    }

    const scriptStr = scriptVal.trim();
    const scriptHash = computeHash(scriptStr);

    // Default safe allowlist: exact standard "node-gyp rebuild"
    if (scriptStr === 'node-gyp rebuild') {
      continue;
    }

    // Check for dangerous patterns
    let isDangerous = false;
    let dangerousReason = '';

    for (const pat of DANGEROUS_FETCH_PATTERNS) {
      if (pat.test(scriptStr)) {
        isDangerous = true;
        dangerousReason = 'Remote fetch-and-execute pattern detected in lifecycle script';
        break;
      }
    }

    if (!isDangerous) {
      for (const pat of DANGEROUS_OBFUSCATION_PATTERNS) {
        if (pat.test(scriptStr)) {
          isDangerous = true;
          dangerousReason = 'Base64 decode execution detected in lifecycle script';
          break;
        }
      }
    }

    if (!isDangerous) {
      for (const pat of DANGEROUS_EXFIL_PATTERNS) {
        if (pat.test(scriptStr)) {
          isDangerous = true;
          dangerousReason =
            'Sensitive environment or credential access detected in lifecycle script';
          break;
        }
      }
    }

    const evidenceItem: SupplyChainEvidenceItem = {
      file: 'package.json',
      startLine: 1,
      startCol: 1,
      endLine: 1,
      endCol: Math.min(200, scriptStr.length + 1),
      snippetSha256: scriptHash,
      redactedSnippet: `"${hook}": "${scriptStr.slice(0, 180)}"`,
      note: isDangerous ? dangerousReason : `Lifecycle hook '${hook}' detected`,
    };

    if (isDangerous) {
      const reg = RULES_REGISTRY['SC-INSTALL-003'];
      hits.push({
        ruleId: 'SC-INSTALL-003',
        packageName: ctx.packageName,
        version: ctx.version,
        ecosystem: ctx.ecosystem,
        purl,
        severity: reg.defaultSeverity,
        confidence: 'HIGH',
        evidence: [evidenceItem],
        metadataUnavailable: false,
        blocking: true,
        title: reg.title,
        description: `${reg.description} (${dangerousReason})`,
        reachabilityGated: false,
        remediationText: reg.remediationText,
        capabilities: { hasInstallScript: true, hasShell: true },
        scReachability: 'REACHABLE',
      });
    } else {
      const reg = RULES_REGISTRY['SC-INSTALL-001'];
      hits.push({
        ruleId: 'SC-INSTALL-001',
        packageName: ctx.packageName,
        version: ctx.version,
        ecosystem: ctx.ecosystem,
        purl,
        severity: reg.defaultSeverity,
        confidence: 'HIGH',
        evidence: [evidenceItem],
        metadataUnavailable: false,
        blocking: false,
        title: reg.title,
        description: `Package defines lifecycle script '${hook}': "${scriptStr.slice(0, 80)}"`,
        reachabilityGated: false,
        remediationText: reg.remediationText,
        capabilities: { hasInstallScript: true },
        scReachability: 'REACHABLE',
      });
    }
  }

  // Check SC-INSTALL-002: binding.gyp present but no install or preinstall script in package.json
  const bindingGypPath = path.join(packageDir, 'binding.gyp');
  const hasInstallScript = Boolean(scripts.install || scripts.preinstall);
  if (fs.existsSync(bindingGypPath) && !hasInstallScript) {
    const reg = RULES_REGISTRY['SC-INSTALL-002'];
    let gypContent = '';
    try {
      gypContent = fs.readFileSync(bindingGypPath, 'utf-8');
    } catch {
      gypContent = 'binding.gyp';
    }
    const evidenceItem: SupplyChainEvidenceItem = {
      file: 'binding.gyp',
      startLine: 1,
      startCol: 1,
      endLine: 1,
      endCol: 1,
      snippetSha256: computeHash(gypContent),
      redactedSnippet: gypContent.slice(0, 180),
      note: 'binding.gyp triggers implicit native node-gyp build without an explicit install script',
    };

    hits.push({
      ruleId: 'SC-INSTALL-002',
      packageName: ctx.packageName,
      version: ctx.version,
      ecosystem: ctx.ecosystem,
      purl,
      severity: reg.defaultSeverity,
      confidence: 'HIGH',
      evidence: [evidenceItem],
      metadataUnavailable: false,
      blocking: false,
      title: reg.title,
      description: reg.description,
      reachabilityGated: false,
      remediationText: reg.remediationText,
      capabilities: { hasInstallScript: true },
      scReachability: 'REACHABLE',
    });
  }

  return hits;
}
