/**
 * Docker Windows Volume Parser Oracle (Moby Engine v27.0.0).
 *
 * Source: github.com/moby/moby
 * Path: volume/mounts/windows_parser.go
 * Tag: v27.0.0 (commit b24dd580b06b0d911a0ab845b796440263625299)
 *
 * Real Docker Windows Volume Parsing Rules:
 * 1. A volume mount argument (-v <spec>) has the syntax:
 *    <source>:<destination>[:<mode>]
 * 2. On Windows, the parser splits on ':' but must respect Windows drive letters
 *    (a colon at index 1 in source is part of the drive letter, e.g. 'C:').
 * 3. Classification of host source:
 *    - BIND MOUNT: Must match an absolute Windows drive path (^[a-zA-Z]:[/\\])
 *      or extended-length drive path (^(\\\\\?\\|//\?/)[a-zA-Z]:[/\\]).
 *      Forward and backward slashes are accepted by modern Docker CLI.
 *    - NAMED VOLUME: Any host source that does NOT start with a drive letter is treated
 *      as a named volume identifier.
 * 4. Named volume identifier rules:
 *    - Valid volume names must match: ^[a-zA-Z0-9][a-zA-Z0-9_.-]+$
 *    - Cannot contain path separators ('/' or '\').
 *    - If a path like '/c/Users/...' or 'Users/dev' is provided as source without a drive,
 *      it is classified as a named volume candidate, which fails validation with:
 *      "includes invalid characters for a local volume name"
 * 5. Destination must be an absolute path (for Linux container, starts with '/').
 */

export interface DockerBindSpecResult {
  accepted: boolean;
  reason?: string;
  isBind: boolean;
  isNamedVolume: boolean;
  source: string;
  destination: string;
  mode?: string;
}

/**
 * Validates a volume specification (-v <source>:<destination>[:<mode>]) against
 * Moby's Windows volume parser rules (moby volume/mounts/windows_parser.go v27.0.0).
 */
export function dockerWindowsBindSpecAccepts(spec: string): DockerBindSpecResult {
  if (typeof spec !== 'string' || spec.trim() === '') {
    return {
      accepted: false,
      reason: 'Volume specification cannot be empty',
      isBind: false,
      isNamedVolume: false,
      source: '',
      destination: '',
    };
  }

  // Parse mode (last segment if it looks like rw, ro, z, Z, etc.)
  let source = '';
  let destination = '';
  let mode: string | undefined;

  // Split on colons, being careful of drive letter at index 1
  // Examples:
  // C:/path:/work:rw -> source: C:/path, dest: /work, mode: rw
  // C:\path:/work:rw -> source: C:\path, dest: /work, mode: rw
  // /c/path:/work:rw -> source: /c/path, dest: /work, mode: rw
  // Users/dev:/work:rw -> source: Users/dev, dest: /work, mode: rw
  // \\server\share\path:/work:rw -> source: \\server\share\path, dest: /work, mode: rw

  let working = spec;
  const lastColon = working.lastIndexOf(':');
  if (lastColon === -1) {
    return {
      accepted: false,
      reason: 'Invalid volume specification: missing destination separator',
      isBind: false,
      isNamedVolume: false,
      source: working,
      destination: '',
    };
  }

  const potentialMode = working.slice(lastColon + 1);
  if (
    ['rw', 'ro', 'z', 'Z', 'rprivate', 'private', 'rshared', 'shared', 'rslave', 'slave'].includes(
      potentialMode
    )
  ) {
    mode = potentialMode;
    working = working.slice(0, lastColon);
  }

  // Now find the colon separating source and destination
  // If working starts with X: (or \\?\X:), the first colon at index 1 (or 5) is part of source!
  let destColonIndex = -1;
  let searchStart = 0;

  if (/^\\\\\?\\[a-zA-Z]:/.test(working)) {
    searchStart = 6;
  } else if (/^[a-zA-Z]:/.test(working)) {
    searchStart = 2;
  }

  destColonIndex = working.indexOf(':', searchStart);
  if (destColonIndex === -1) {
    return {
      accepted: false,
      reason: 'Invalid volume specification: missing destination path',
      isBind: false,
      isNamedVolume: false,
      source: working,
      destination: '',
      mode,
    };
  }

  source = working.slice(0, destColonIndex);
  destination = working.slice(destColonIndex + 1);

  if (!destination.startsWith('/')) {
    return {
      accepted: false,
      reason: `Invalid destination path '${destination}': Linux container destination must be absolute starting with '/'`,
      isBind: false,
      isNamedVolume: false,
      source,
      destination,
      mode,
    };
  }

  // Is it an absolute Windows drive path?
  // In Moby Windows volume parser, absolute drive paths start with [a-zA-Z]:[/\\]
  // or extended prefix \\?\ (with backslashes). Slashes //?/ are NOT valid extended paths.
  const isDrivePath = /^[a-zA-Z]:[/\\]/.test(source) || /^\\\\\?\\[a-zA-Z]:[/\\]/.test(source);

  // Is it UNC?
  const isUNC =
    /^[\\/]{2}[^\\/]+[\\/][^\\/]+/.test(source) || /^(\\\\\?\\|\/\/\?\/)UNC[/\\]/.test(source);

  if (isDrivePath) {
    // Valid Windows host bind mount!
    return {
      accepted: true,
      isBind: true,
      isNamedVolume: false,
      source,
      destination,
      mode,
    };
  }

  if (isUNC) {
    // In Moby Windows volume parser, UNC mounts without SMB credential configuration
    // are rejected or require special plugins. We reject UNC sources.
    return {
      accepted: false,
      reason: `UNC network paths ('${source}') are not accepted as standard host bind mounts by Docker Windows daemon`,
      isBind: true,
      isNamedVolume: false,
      source,
      destination,
      mode,
    };
  }

  // If not a drive path and not UNC, Docker treats source as a NAMED VOLUME
  const validNamedVolume = /^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/.test(source);

  if (validNamedVolume) {
    return {
      accepted: true,
      isBind: false,
      isNamedVolume: true,
      source,
      destination,
      mode,
    };
  }

  // Named volume containing slashes or invalid characters fails Docker validation
  return {
    accepted: false,
    reason: `create ${source}: includes invalid characters for a local volume name`,
    isBind: false,
    isNamedVolume: true,
    source,
    destination,
    mode,
  };
}
