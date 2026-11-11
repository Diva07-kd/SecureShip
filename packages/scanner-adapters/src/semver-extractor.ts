/**
 * Utility to extract clean semantic version strings from raw scanner version CLI outputs.
 */
export function extractCleanSemver(raw: string): string {
  if (!raw || typeof raw !== 'string') return 'Unknown';
  // Matches e.g. "osv-scanner version: 2.7.0", "Version: 0.76.0", "8.30.1", "v1.2.3-rc1"
  const match = raw.match(/\bv?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)\b/);
  if (match && match[1]) {
    return match[1];
  }
  return raw.trim().split(/\r?\n/)[0]?.slice(0, 15) ?? 'Unknown';
}
