import fs from 'node:fs';
import path from 'node:path';
import type { LicenseComplianceResult, LicenseViolation } from '@secureship/contracts';
import type { PackageTarget } from '../supply-chain/supply-chain-analyzer.js';

export interface LicenseComplianceOptions {
  allow?: string[];
  deny?: string[];
}

const COMMON_STRONG_COPYLEFT = new Set([
  'GPL-1.0',
  'GPL-1.0-ONLY',
  'GPL-1.0-OR-LATER',
  'GPL-2.0',
  'GPL-2.0-ONLY',
  'GPL-2.0-OR-LATER',
  'GPL-3.0',
  'GPL-3.0-ONLY',
  'GPL-3.0-OR-LATER',
  'AGPL-1.0',
  'AGPL-3.0',
  'AGPL-3.0-ONLY',
  'AGPL-3.0-OR-LATER',
  'SSPL-1.0',
  'EUPL-1.1',
  'EUPL-1.2',
  'CC-BY-SA-4.0',
  'OSL-3.0',
]);

const LICENSE_NORMALIZATION_MAP: Record<string, string> = {
  'apache 2.0': 'Apache-2.0',
  'apache-2': 'Apache-2.0',
  'apache 2': 'Apache-2.0',
  'apache-2.0': 'Apache-2.0',
  'apache v2': 'Apache-2.0',
  'apache license 2.0': 'Apache-2.0',
  mit: 'MIT',
  'mit license': 'MIT',
  isc: 'ISC',
  'isc license': 'ISC',
  bsd: 'BSD-3-Clause',
  'bsd-2-clause': 'BSD-2-Clause',
  'bsd 2-clause': 'BSD-2-Clause',
  'bsd-3-clause': 'BSD-3-Clause',
  'bsd 3-clause': 'BSD-3-Clause',
  '0bsd': '0BSD',
  cc0: 'CC0-1.0',
  'cc0-1.0': 'CC0-1.0',
  'public domain': 'CC0-1.0',
  unlicense: 'Unlicense',
  'the unlicense': 'Unlicense',
  'gpl-2.0': 'GPL-2.0-only',
  gplv2: 'GPL-2.0-only',
  'gpl-3.0': 'GPL-3.0-only',
  gplv3: 'GPL-3.0-only',
  'agpl-3.0': 'AGPL-3.0-only',
  agplv3: 'AGPL-3.0-only',
  'mpl-2.0': 'MPL-2.0',
  mpl2: 'MPL-2.0',
  'lgpl-2.1': 'LGPL-2.1-only',
  'lgpl-3.0': 'LGPL-3.0-only',
  'python-2.0': 'Python-2.0',
  zlib: 'Zlib',
};

/**
 * Normalizes a raw license string to a standard SPDX license identifier if recognized.
 */
export function normalizeLicense(raw: string): string {
  const trimmed = raw.trim();
  const lower = trimmed.toLowerCase();
  return LICENSE_NORMALIZATION_MAP[lower] ?? trimmed;
}

/**
 * Inspects a PackageTarget and discovers all declared or inferred licenses.
 */
export function extractPackageLicenses(pkg: PackageTarget): string[] {
  const found: string[] = [];

  // 1. Inspect packageJson if present (npm or simulated Python)
  if (pkg.packageJson) {
    // string license: "MIT", "(MIT OR Apache-2.0)", etc.
    if (typeof pkg.packageJson.license === 'string' && pkg.packageJson.license.trim()) {
      found.push(...parseLicenseExpression(pkg.packageJson.license));
    } else if (
      typeof pkg.packageJson.license === 'object' &&
      pkg.packageJson.license !== null &&
      'type' in pkg.packageJson.license &&
      typeof (pkg.packageJson.license as { type?: unknown }).type === 'string'
    ) {
      found.push(normalizeLicense((pkg.packageJson.license as { type: string }).type));
    }

    // array licenses: [{ type: "MIT" }]
    if (Array.isArray(pkg.packageJson.licenses)) {
      for (const lic of pkg.packageJson.licenses) {
        if (typeof lic === 'string' && lic.trim()) {
          found.push(...parseLicenseExpression(lic));
        } else if (
          typeof lic === 'object' &&
          lic !== null &&
          'type' in lic &&
          typeof (lic as { type?: unknown }).type === 'string'
        ) {
          found.push(normalizeLicense((lic as { type: string }).type));
        }
      }
    }
  }

  // 2. Python specific inspection in .dist-info/METADATA
  if (pkg.ecosystem === 'pypi' && pkg.dir) {
    try {
      const metadataPath = path.join(pkg.dir, 'METADATA');
      if (fs.existsSync(metadataPath)) {
        const content = fs.readFileSync(metadataPath, 'utf-8');
        const lines = content.split(/\r?\n/);
        for (const line of lines) {
          const licMatch = line.match(/^License:\s*(.+)$/i);
          if (licMatch?.[1] && licMatch[1].trim() && licMatch[1].trim() !== 'UNKNOWN') {
            found.push(normalizeLicense(licMatch[1].trim()));
          }
          const classMatch = line.match(
            /^Classifier:\s*License\s*::\s*(?:OSI Approved\s*::\s*)?(.+)$/i
          );
          if (classMatch?.[1] && classMatch[1].trim()) {
            found.push(normalizeLicense(classMatch[1].trim()));
          }
        }
      }
    } catch {
      // Ignore read errors
    }
  }

  // 3. Fallback: Check LICENSE / NOTICE file in directory if empty
  if (found.length === 0 && pkg.dir && fs.existsSync(pkg.dir)) {
    try {
      const licenseFiles = ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'COPYING', 'NOTICE'];
      for (const f of licenseFiles) {
        const full = path.join(pkg.dir, f);
        if (fs.existsSync(full)) {
          const content = fs.readFileSync(full, { encoding: 'utf-8', flag: 'r' }).slice(0, 4096);
          if (
            /MIT\s+License/i.test(content) ||
            /Permission is hereby granted, free of charge/i.test(content)
          ) {
            found.push('MIT');
            break;
          }
          if (/Apache License/i.test(content) && /Version 2\.0/i.test(content)) {
            found.push('Apache-2.0');
            break;
          }
          if (/GNU GENERAL PUBLIC LICENSE/i.test(content) || /GPL/i.test(content)) {
            if (/version 3/i.test(content)) {
              found.push('GPL-3.0-only');
            } else if (/version 2/i.test(content)) {
              found.push('GPL-2.0-only');
            } else {
              found.push('GPL-3.0-only');
            }
            break;
          }
          if (/BSD 2-Clause/i.test(content)) {
            found.push('BSD-2-Clause');
            break;
          }
          if (/BSD 3-Clause/i.test(content) || /BSD License/i.test(content)) {
            found.push('BSD-3-Clause');
            break;
          }
          if (/ISC License/i.test(content)) {
            found.push('ISC');
            break;
          }
        }
      }
    } catch {
      // Ignore read errors
    }
  }

  if (found.length === 0) {
    return ['NOASSERTION'];
  }

  // Deduplicate results
  return Array.from(new Set(found));
}

/**
 * Splits compound license expressions such as "(MIT OR Apache-2.0)" into individual licenses.
 */
export function parseLicenseExpression(expr: string): string[] {
  const cleaned = expr.replace(/[()]/g, ' ').trim();
  const parts = cleaned.split(/\s+(?:OR|AND)\s+/i);
  return parts.map((p) => normalizeLicense(p.trim())).filter(Boolean);
}

/**
 * Checks if a specific license satisfies an allowed list.
 */
function isLicenseAllowed(lic: string, allowedSet: Set<string>): boolean {
  const norm = normalizeLicense(lic).toUpperCase();
  const raw = lic.toUpperCase();
  for (const allowed of allowedSet) {
    if (raw === allowed || norm === allowed) return true;
    if (raw.startsWith(`${allowed}-`) || norm.startsWith(`${allowed}-`)) return true;
  }
  return false;
}

/**
 * Checks if a specific license matches a deny list.
 */
function isLicenseDenied(lic: string, deniedSet: Set<string>): boolean {
  const norm = normalizeLicense(lic).toUpperCase();
  const raw = lic.toUpperCase();
  for (const denied of deniedSet) {
    if (raw === denied || norm === denied) return true;
    if (raw.startsWith(`${denied}-`) || norm.startsWith(`${denied}-`)) return true;
  }
  return false;
}

/**
 * Evaluates license compliance across discovered packages against allow/deny policy rules.
 */
export function evaluateLicenseCompliance(
  packages: PackageTarget[],
  options: LicenseComplianceOptions = {}
): LicenseComplianceResult {
  const allowedSet =
    options.allow && options.allow.length > 0
      ? new Set(options.allow.map((a) => a.trim().toUpperCase()))
      : null;

  const deniedSet =
    options.deny && options.deny.length > 0
      ? new Set(options.deny.map((d) => d.trim().toUpperCase()))
      : null;

  const violations: LicenseViolation[] = [];
  let compliantCount = 0;

  for (const pkg of packages) {
    const rawLicenseStr =
      typeof pkg.packageJson?.license === 'string' ? pkg.packageJson.license : '';
    const isOrExpression = /\bOR\b/i.test(rawLicenseStr);
    const licenses = extractPackageLicenses(pkg);
    let pkgViolated = false;

    // 1. Explicit Deny Check (Any denied license triggers critical violation)
    if (deniedSet) {
      for (const lic of licenses) {
        if (isLicenseDenied(lic, deniedSet)) {
          violations.push({
            packageName: pkg.name,
            version: pkg.version,
            license: lic,
            reason: `License '${lic}' is explicitly prohibited by policy deny list.`,
            severity: 'CRITICAL',
            ecosystem: pkg.ecosystem,
            path: pkg.dir,
          });
          pkgViolated = true;
          break;
        }
      }
    }

    if (pkgViolated) {
      continue;
    }

    // 2. Explicit Allow Check
    if (allowedSet) {
      if (isOrExpression) {
        // In an OR expression, if at least ONE option is allowed, the package is compliant
        const hasAllowedOption = licenses.some((lic) => isLicenseAllowed(lic, allowedSet));
        if (!hasAllowedOption) {
          violations.push({
            packageName: pkg.name,
            version: pkg.version,
            license: licenses.join(' OR '),
            reason: `None of the licenses in '${licenses.join(' OR ')}' are included in the allowed license policy.`,
            severity: 'HIGH',
            ecosystem: pkg.ecosystem,
            path: pkg.dir,
          });
          pkgViolated = true;
        }
      } else {
        // Non-OR: every declared license must be allowed
        for (const lic of licenses) {
          if (!isLicenseAllowed(lic, allowedSet)) {
            violations.push({
              packageName: pkg.name,
              version: pkg.version,
              license: lic,
              reason: `License '${lic}' is not included in the allowed license policy.`,
              severity: 'HIGH',
              ecosystem: pkg.ecosystem,
              path: pkg.dir,
            });
            pkgViolated = true;
            break;
          }
        }
      }
    }

    // 3. Default Strong Copyleft Guard (when neither allow nor deny is specified)
    if (!allowedSet && !deniedSet && !pkgViolated) {
      for (const lic of licenses) {
        const upperLic = normalizeLicense(lic).toUpperCase();
        if (
          COMMON_STRONG_COPYLEFT.has(upperLic) ||
          Array.from(COMMON_STRONG_COPYLEFT).some((c) => upperLic.startsWith(c))
        ) {
          violations.push({
            packageName: pkg.name,
            version: pkg.version,
            license: lic,
            reason: `Strong copyleft license '${lic}' detected without an explicit allow policy.`,
            severity: 'MEDIUM',
            ecosystem: pkg.ecosystem,
            path: pkg.dir,
          });
          pkgViolated = true;
          break;
        }
      }
    }

    if (!pkgViolated) {
      compliantCount++;
    }
  }

  return {
    status: violations.length === 0 ? 'COMPLIANT' : 'NON_COMPLIANT',
    totalPackages: packages.length,
    compliantCount,
    violationCount: violations.length,
    allowedList: options.allow,
    deniedList: options.deny,
    violations,
  };
}
