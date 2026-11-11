import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type {
  CycloneDxBom,
  CycloneDxComponent,
  CycloneDxVulnerability,
  ScanReport,
  SpdxBom,
  SpdxPackage,
} from '@secureship/contracts';
import { CycloneDxBomSchema, SpdxBomSchema } from '@secureship/contracts';
import type { PackageTarget } from '../supply-chain/supply-chain-analyzer.js';
import { extractPackageLicenses } from './license-checker.js';

export interface GenerateCycloneDxOptions {
  rootDir: string;
  packages: PackageTarget[];
  scanReport?: ScanReport;
  cliVersion?: string;
  applicationName?: string;
}

export interface GenerateSpdxOptions {
  rootDir: string;
  packages: PackageTarget[];
  cliVersion?: string;
  applicationName?: string;
}

/**
 * Computes a deterministic SHA-256 hash for a given package directory.
 */
export function computePackageHash(pkgDir: string): string {
  const hash = crypto.createHash('sha256');

  if (fs.existsSync(pkgDir)) {
    try {
      const candidates = ['package.json', 'METADATA', 'pyproject.toml', 'setup.py'];
      let foundManifest = false;
      for (const cand of candidates) {
        const full = path.join(pkgDir, cand);
        if (fs.existsSync(full)) {
          hash.update(fs.readFileSync(full));
          foundManifest = true;
          break;
        }
      }

      if (!foundManifest) {
        // Fallback: hash the directory path and mtime
        const stat = fs.statSync(pkgDir);
        hash.update(`${path.basename(pkgDir)}:${stat.size}`);
      }
    } catch {
      hash.update(path.basename(pkgDir));
    }
  } else {
    hash.update(path.basename(pkgDir));
  }

  return hash.digest('hex');
}

/**
 * Constructs a compliant Package URL (purl) according to package-url specification.
 */
export function generatePurl(pkg: PackageTarget): string {
  if (pkg.ecosystem === 'npm') {
    if (pkg.name.startsWith('@') && pkg.name.includes('/')) {
      const slashIdx = pkg.name.indexOf('/');
      const scope = pkg.name.slice(0, slashIdx);
      const name = pkg.name.slice(slashIdx + 1);
      const encodedScope = encodeURIComponent(scope);
      return `pkg:npm/${encodedScope}/${name}@${pkg.version}`;
    }
    return `pkg:npm/${pkg.name}@${pkg.version}`;
  }

  if (pkg.ecosystem === 'pypi') {
    return `pkg:pypi/${pkg.name.toLowerCase()}@${pkg.version}`;
  }

  return `pkg:generic/${pkg.name}@${pkg.version}`;
}

/**
 * Extracts and maps vulnerability findings to a package component.
 */
function extractVulnerabilitiesForPackage(
  pkg: PackageTarget,
  scanReport?: ScanReport
): CycloneDxVulnerability[] {
  if (!scanReport || !scanReport.findings || scanReport.findings.length === 0) {
    return [];
  }

  const matches = scanReport.findings.filter((f) => {
    // Exact package name match from the finding's package metadata
    if (f.package?.name === pkg.name || f.package?.name?.toLowerCase() === pkg.name.toLowerCase()) {
      return true;
    }
    // Fallback: scoped package path match (handles @scope/name in node_modules)
    if (f.location?.filePath) {
      const normalizedFilePath = (
        f.location.filePath.startsWith('/') || f.location.filePath.startsWith('\\')
          ? f.location.filePath
          : '/' + f.location.filePath
      ).replace(/\\/g, '/');
      if (
        normalizedFilePath.includes('/node_modules/' + pkg.name + '/') ||
        normalizedFilePath.includes(
          '/node_modules/' + pkg.name.replace('@', '').replace('/', '/') + '/'
        )
      ) {
        return true;
      }
    }
    return false;
  });

  return matches.map((f) => ({
    id: f.ruleId,
    source: { name: 'SecureShip' },
    ratings: [
      {
        severity: f.severity.toLowerCase(),
      },
    ],
    description:
      f.description ??
      f.evidence?.[0]?.message ??
      f.title ??
      'Security finding detected by SecureShip',
  }));
}

/**
 * Generates an EU Cyber Resilience Act (CRA) & US EO 14028 compliant CycloneDX 1.5 JSON SBOM.
 */
export function generateCycloneDXSbom(options: GenerateCycloneDxOptions): CycloneDxBom {
  const cliVersion = options.cliVersion ?? '1.0.0-beta.1';
  const rootDir = path.resolve(options.rootDir);
  const appName = options.applicationName ?? (path.basename(rootDir) || 'application');

  // Read root package.json if present for root component metadata
  let rootVersion = '1.0.0';
  let rootDescription = 'Application root';
  const rootPkgJsonPath = path.join(rootDir, 'package.json');
  if (fs.existsSync(rootPkgJsonPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(rootPkgJsonPath, 'utf-8')) as {
        version?: string;
        description?: string;
      };
      if (parsed.version) rootVersion = parsed.version;
      if (parsed.description) rootDescription = parsed.description;
    } catch {
      // Ignore
    }
  }

  // Map package targets to CycloneDX components
  const components: CycloneDxComponent[] = options.packages.map((pkg) => {
    const licenses = extractPackageLicenses(pkg);
    const purl = generatePurl(pkg);
    const hash = computePackageHash(pkg.dir);
    const vulns = extractVulnerabilitiesForPackage(pkg, options.scanReport);

    return {
      type: 'library',
      name: pkg.name,
      version: pkg.version,
      purl,
      description: `Package ${pkg.name} (${pkg.ecosystem})`,
      hashes: [
        {
          alg: 'SHA-256',
          content: hash,
        },
      ],
      licenses: licenses.map((lic) => {
        if (lic === 'NOASSERTION' || lic === 'UNKNOWN') {
          return { license: { name: lic } };
        }
        return { license: { id: lic } };
      }),
      vulnerabilities: vulns.length > 0 ? vulns : undefined,
    };
  });

  const allVulns = components.flatMap((c) => c.vulnerabilities ?? []);

  const bom: CycloneDxBom = {
    $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'SecureShip',
          name: 'SecureShip CLI',
          version: cliVersion,
        },
      ],
      component: {
        type: 'application',
        name: appName,
        version: rootVersion,
        description: rootDescription,
      },
    },
    components,
    dependencies: [
      {
        ref: `pkg:generic/${appName}@${rootVersion}`,
        dependsOn: components.map((c) => c.purl ?? `${c.name}@${c.version}`),
      },
    ],
    vulnerabilities: allVulns.length > 0 ? allVulns : undefined,
  };

  // Validate output against Zod schema to guarantee contract compliance
  return CycloneDxBomSchema.parse(bom);
}

/**
 * Sanitizes arbitrary strings for safe use inside an SPDXID identifier.
 */
function sanitizeSpdxId(name: string): string {
  return name.replace(/[^A-Za-z0-9.-]/g, '-');
}

/**
 * Generates an ISO/IEC 5962:2021 standard SPDX 2.3 JSON SBOM.
 */
export function generateSpdxSbom(options: GenerateSpdxOptions): SpdxBom {
  const cliVersion = options.cliVersion ?? '1.0.0-beta.1';
  const rootDir = path.resolve(options.rootDir);
  const appName = options.applicationName ?? (path.basename(rootDir) || 'application');

  const packages: SpdxPackage[] = options.packages.map((pkg) => {
    const licenses = extractPackageLicenses(pkg);
    const purl = generatePurl(pkg);
    const hash = computePackageHash(pkg.dir);
    const spdxId = `SPDXRef-Package-${sanitizeSpdxId(pkg.name)}-${sanitizeSpdxId(pkg.version)}`;

    const concludedLicense = licenses[0] ?? 'NOASSERTION';
    const declaredLicense = licenses.length > 0 ? licenses.join(' OR ') : 'NOASSERTION';

    return {
      name: pkg.name,
      SPDXID: spdxId,
      versionInfo: pkg.version,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: concludedLicense,
      licenseDeclared: declaredLicense,
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: purl,
        },
      ],
      checksums: [
        {
          algorithm: 'SHA256',
          checksumValue: hash,
        },
      ],
    };
  });

  const spdx: SpdxBom = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: appName,
    documentNamespace: `https://secureship.dev/spdx/${crypto.randomUUID()}`,
    creationInfo: {
      creators: [`Tool: SecureShip-${cliVersion}`],
      created: new Date().toISOString(),
    },
    packages,
    relationships: packages.map((pkg) => ({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relatedSpdxElement: pkg.SPDXID,
      relationshipType: 'DESCRIBES',
    })),
  };

  // Validate output against Zod schema to guarantee contract compliance
  return SpdxBomSchema.parse(spdx);
}
