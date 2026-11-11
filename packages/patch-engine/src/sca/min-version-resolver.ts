export interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  preRelease: string;
  range: string;
  isValid: boolean;
}

export class MinVersionResolver {
  /**
   * Parses a version string like "1.2.3", "^1.2.3", "~1.2.3", ">=1.2.3", "1.2.3-beta.1", "v1.2.3".
   * Never throws on malformed strings; returns fallback.
   */
  public static parseVersion(raw: string): ParsedSemver {
    if (!raw || typeof raw !== 'string') {
      return { major: 0, minor: 0, patch: 0, preRelease: '', range: '', isValid: false };
    }

    const trimmed = raw.trim();

    // Extract range prefix: ^, ~, >=, <=, >, <, =, ==, etc.
    const rangeMatch = trimmed.match(/^(\^|~|>=|<=|>|<|==|=|\s*)/);
    const range = rangeMatch ? rangeMatch[1]!.trim() : '';
    const withoutRange = trimmed.substring(range.length).trim();

    // Strip optional leading 'v'
    const withoutV =
      withoutRange.startsWith('v') || withoutRange.startsWith('V')
        ? withoutRange.substring(1)
        : withoutRange;

    // Separate prerelease tag: e.g. 1.2.3-beta.1
    const [coreVersion, ...prereleaseParts] = withoutV.split('-');
    const preRelease = prereleaseParts.join('-');

    const parts = (coreVersion ?? '').split('.');
    const major = parseInt(parts[0] ?? '0', 10);
    const minor = parts.length > 1 ? parseInt(parts[1] ?? '0', 10) : 0;
    const patch = parts.length > 2 ? parseInt(parts[2] ?? '0', 10) : 0;

    const isValid = !isNaN(major) && !isNaN(minor) && !isNaN(patch);

    return {
      major: isNaN(major) ? 0 : major,
      minor: isNaN(minor) ? 0 : minor,
      patch: isNaN(patch) ? 0 : patch,
      preRelease,
      range,
      isValid,
    };
  }

  /**
   * Compares two parsed semver versions.
   * Returns:
   *   1 if v1 > v2
   *  -1 if v1 < v2
   *   0 if v1 === v2
   */
  public static compare(v1: ParsedSemver, v2: ParsedSemver): number {
    if (v1.major !== v2.major) return v1.major > v2.major ? 1 : -1;
    if (v1.minor !== v2.minor) return v1.minor > v2.minor ? 1 : -1;
    if (v1.patch !== v2.patch) return v1.patch > v2.patch ? 1 : -1;

    // Prerelease version is considered lower than release version
    if (v1.preRelease && !v2.preRelease) return -1;
    if (!v1.preRelease && v2.preRelease) return 1;

    return 0;
  }

  /**
   * Returns true if targetVersion is a breaking (major) bump relative to currentVersion.
   * Note: In 0.x versions (0.y.z), a minor bump (0.1 -> 0.2) is also breaking.
   */
  public static isMajorBump(currentVersion: string, targetVersion: string): boolean {
    const cur = MinVersionResolver.parseVersion(currentVersion);
    const target = MinVersionResolver.parseVersion(targetVersion);

    if (!cur.isValid || !target.isValid) return false;

    if (cur.major === 0 && target.major === 0) {
      return target.minor > cur.minor;
    }

    return target.major > cur.major;
  }

  /**
   * Resolves the minimum safe version that addresses the vulnerability.
   * If fixedVersion is given, returns the cleanest target version string.
   */
  public static resolve(currentVersion: string, fixedVersion: string | undefined): string {
    if (!fixedVersion || fixedVersion.trim().length === 0) {
      return currentVersion;
    }

    const cur = MinVersionResolver.parseVersion(currentVersion);
    const fixed = MinVersionResolver.parseVersion(fixedVersion);

    if (!fixed.isValid) {
      // Return fixedVersion as-is for non-standard semver
      return fixedVersion.trim();
    }

    // Preserve range prefix from currentVersion if present (e.g. ^1.2.3 -> ^1.2.5)
    const prefix = cur.range.length > 0 ? cur.range : '';
    const cleanFixed = `${fixed.major}.${fixed.minor}.${fixed.patch}${
      fixed.preRelease ? `-${fixed.preRelease}` : ''
    }`;

    // If prefix is present, format as prefix + cleanFixed (e.g. ^1.2.5)
    // If prefix already had space or operator, format cleanly
    if (prefix === '^' || prefix === '~') {
      return `${prefix}${cleanFixed}`;
    }

    return cleanFixed;
  }
}
