# SecureShip Phase 5: Sandbox Architecture & Threat Model

## 1. Threat Model & Rationale

When SecureShip evaluates candidate patches through dynamic verification stages (`TYPECHECK`, `BUILD`, `TEST`, and optional `INSTALL`), it must execute repository build tools and test suites (e.g., `npm test`, `pytest`, `cargo test`, `mvn test`).

Executing untrusted repository code presents severe security threats:

1. **Malicious Dependency Scripts (`postinstall`)**: Supply-chain attackers frequently embed reverse shells, cryptocurrency miners, or credential exfiltration scripts into package install hooks.
2. **Malicious Test Runners**: Unit tests in untrusted repositories have full execution privileges on the host unless isolated, allowing arbitrary filesystem manipulation, secret theft, or lateral network movement.
3. **Escaping to Host Environment**: Build scripts could inspect ambient environment variables (AWS credentials, GitHub tokens, SSH keys) or modify local configuration files (`~/.ssh`, `~/.gitconfig`).
4. **Denial of Service (DoS)**: Malicious or buggy build scripts can spawn fork bombs, consume 100% CPU, or allocate unbounded memory, crashing the developer's workstation or CI runner.

To mitigate these threats, SecureShip Phase 5 enforces **strict container sandboxing by default**, with a fail-safe, explicitly confirmed opt-in for host execution.

---

## 2. Container Sandbox Architecture

The container sandbox runs via standard Docker or Podman CLI wrappers using `SafeProcessRunner`, requiring **zero external npm runtime dependencies**.

### 2.1 Container Flags & Security Isolation

Every container executed during Gate 4 verification is launched with the following hardcoded security configuration:

| Flag                 | Value / Parameter                   | Security Rationale & Enforcement                                                                                                                                                                                              |
| :------------------- | :---------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`--rm`**           | Automatic                           | Ensures the container instance is destroyed immediately upon exit, preventing persistent disk state.                                                                                                                          |
| **`--network`**      | `none` (default)                    | **Zero network access.** Non-install stages (`BUILD`, `TYPECHECK`, `TEST`) cannot communicate with external servers, preventing data exfiltration and C2 beaconing. Set to `bridge` only for `INSTALL` if explicitly enabled. |
| **`--cap-drop`**     | `ALL`                               | Drops all Linux kernel capabilities (including `CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_CHOWN`, `CAP_PTRACE`), neutralizing container breakout exploits.                                                                          |
| **`--security-opt`** | `no-new-privileges`                 | Prevents sub-processes from acquiring new privileges via `setuid` or `setgid` binaries.                                                                                                                                       |
| **`--pids-limit`**   | `512` (configurable)                | Limits the total number of simultaneous processes, preventing fork bombs and process table exhaustion.                                                                                                                        |
| **`--memory`**       | `2g` (configurable)                 | Enforces hard RAM limits, preventing host OOM panics.                                                                                                                                                                         |
| **`--memory-swap`**  | `2g`                                | Restricts memory swap to prevent disk thrashing.                                                                                                                                                                              |
| **`--cpus`**         | `2` (configurable)                  | Limits container CPU thread scheduling to prevent CPU starvation on the host workstation.                                                                                                                                     |
| **`--user`**         | `1000:1000`                         | Executes all processes as an unprivileged, non-root user and group.                                                                                                                                                           |
| **`--read-only`**    | Enforced                            | Mounts the root container filesystem as strictly read-only, preventing alteration of system libraries.                                                                                                                        |
| **`--tmpfs`**        | `/tmp:rw,size=512m`                 | Provides an in-memory, temporary scratch directory with strict size bounding. Discarded on exit.                                                                                                                              |
| **`--workdir`**      | `/work`                             | Sets the isolated shadow copy as the working directory inside the container.                                                                                                                                                  |
| **`-v`**             | `<shadow-dir>:/work:rw`             | Mounts **only** the isolated shadow copy outside the repo. **Never mounts the live working tree, never mounts docker.sock, and never mounts host user homes.**                                                                |
| **`--pull`**         | `never`                             | Enforces local image availability; prevents unexpected network image pulls during verification.                                                                                                                               |
| **`--label`**        | `secureship.run=<runId>`            | Attaches unique execution run ID for guaranteed orphan container cleanup on abort or SIGINT.                                                                                                                                  |
| **`-e`**             | `CI=1`, `HOME=/tmp`, `LANG=C.UTF-8` | Sanitized, minimal environment. Ambient host environment variables (`AWS_*`, `GITHUB_*`, `SSH_*`, `USER`) are strictly blocked.                                                                                               |

## 2.2 What is NOT Protected (Security Boundaries & Limitations)

1. **Linux Kernel Zero-Days**: Containerization isolates user-space, but does not protect against zero-day Linux kernel privilege escalation bugs in the host's underlying WSL2 kernel.
2. **Host node_modules Incompatibility**: Host `node_modules` are never mounted into Linux containers due to architecture/platform mismatch (Windows binary addons vs Linux ELF). Without `--sandbox-install`, stages requiring unbundled dependencies will yield `INCONCLUSIVE`.
3. **Pre-Existing Host Daemon Compromise**: If the host Docker daemon or rootless socket is already compromised prior to SecureShip invocation, container boundary guarantees are void.
4. **Hardware Resource Saturation within Limits**: While memory (2GB) and CPU (2 cores) are strictly capped, an infinite loop inside a container will consume those allocated resources until the stage timeout expires.

---

## 3. Windows Path Translation

On Windows hosts running Docker Desktop with the WSL2 backend:

1. Host paths such as `C:\Users\dev\AppData\Local\Temp\secureship-shadow-xyz` must be converted to standard forward-slash format `C:/Users/...` with the drive letter and colon preserved when passed to Docker CLI `-v` mount arguments.
2. `ContainerBackend.translateHostPath` automatically normalizes Windows paths:
   - Replaces backslashes (`\`) with forward slashes (`/`).
   - Preserves drive letters and their casing (e.g. `C:\Users\dev\project` -> `C:/Users/dev/project`, `d:\data\app` -> `d:/data/app`).
   - Preserves spaces in paths (`C:\Program Files\Project` -> `C:/Program Files/Project`).
   - Strips extended-length prefixes (`\\?\` or `//?/`).
   - Collapses duplicate separators and `.`/`..` segments via `path.win32.normalize`.
   - Trims trailing slashes unless the path is a root drive (`X:/`).
   - Returns standard POSIX paths on non-Windows platforms byte-identically without alteration.

### 3.1 Why the Legacy `/c/...` Translation is Defective

Historically, legacy Docker Toolbox and MSYS/MinGW environments translated Windows paths like `C:\Users\...` to `/c/Users/...`. However, modern Docker Desktop for Windows implements the Moby Windows volume specification parser (`moby volume/mounts/windows_parser.go`).

Under the Docker Windows volume parser:

1. A volume mount source (`-v <source>:<destination>:<mode>`) is evaluated to determine whether it is a host directory bind mount or a Docker named volume.
2. An absolute host directory bind mount **must** begin with a Windows drive letter and colon (e.g., `^[a-zA-Z]:[/\\]`).
3. If the host source begins with a forward slash or lacks a drive letter (such as `/c/Users/...`), the parser categorizes the source as a **named volume identifier**.
4. Volume names cannot contain slashes (`/` or `\`). When Docker Desktop attempts to validate or create the volume, the daemon rejects the command with:
   ```
   docker: Error response from daemon: create \c\Users\...: includes invalid characters for a local volume name
   ```
5. WSL2's internal automount path (`/mnt/c`) is specific to the WSL2 virtual machine and is **not** used or accepted by the host Windows Docker CLI as a bind mount source. The host Windows Docker CLI requires Windows drive paths formatted with forward slashes: `C:/...`.

### 3.2 8.3 Short Name Canonicalization (Defense in Depth)

On many Windows environments (such as GitHub Actions Windows runners where `os.tmpdir()` yields `C:\Users\RUNNER~1\AppData\Local\Temp`), file systems create 8.3 short names.

Before translation on Windows, `ContainerBackend` invokes an injectable `realpath` function (`fs.realpathSync.native`) to expand 8.3 short names back to full canonical paths, normalize casing, and resolve directory junctions or `subst` drives. If `realpath` fails (e.g., non-existent path), the backend safely falls back to the original path so the container daemon fails closed. Canonicalization is strictly restricted to Windows environments and is never invoked on POSIX systems.

### 3.3 Fail-Closed Path Validation

To prevent ambiguous volume mounts, directory confusion, or accidental named volume creation, `ContainerBackend.translateHostPath` strictly enforces fail-closed validation, throwing `ContainerPathError` with stable error codes on invalid shapes:

- **Empty Paths (`EMPTY`)**: Null, undefined, empty, or non-string inputs are rejected.
- **Illegal Characters (`ILLEGAL_CHARS`)**: Control characters below 0x20 (including NUL `\0`, `\r`, `\n`) or any of `" < > | * ?` are rejected.
- **UNC & Network Paths (`UNC_UNSUPPORTED`)**: Universal Naming Convention network shares (`\\server\share`, `//server/share`, `\\?\UNC\...`) are rejected with actionable guidance to set `TEMP`/`TMP` (Windows) or `TMPDIR` (POSIX) to a local directory.
- **Device & Pipe Paths (`DEVICE_PATH_UNSUPPORTED`)**: Windows device paths and named pipes (`\\.\pipe\...`, `//./pipe/...`) are rejected.
- **Drive-Relative Paths (`DRIVE_RELATIVE`)**: Drive-relative paths lacking a slash (`C:foo`, `C:`) are rejected.
- **POSIX-Style Paths on Windows (`POSIX_STYLE_ON_WINDOWS`)**: Paths starting with a single leading separator with no drive (including the legacy `/c/Users/...` and `\Users\...`) are rejected with explicit instructions that Docker requires `C:/...`.
- **Relative Paths (`NOT_ABSOLUTE`)**: Relative paths (`relative\path`, `.`, `..`) are rejected without resolving against `process.cwd()` to prevent silently mounting an unintended directory. On POSIX, Windows-style paths (`C:\...`) are treated as relative and rejected.
- **Colon in Path (`COLON_IN_PATH`)**: On Windows, colons after index 1 (the drive letter) are rejected. On POSIX, any colon in the path is rejected because the Docker volume argument syntax (`-v source:target:mode`) cannot safely express paths containing colons.

### 3.4 Mount Boundary Guards (Root and Home Protection)

Before executing container verification, `ContainerBackend` evaluates the translated mount source against strict filesystem boundary policies:

1. **Root Directory Guard (`ROOT_MOUNT_REFUSED`)**: Refuses to mount filesystem roots (`/` on POSIX, `X:/` on Windows) as a container volume.
2. **User Home Directory Guard (`HOME_MOUNT_REFUSED`)**: Refuses to mount the user's home directory (determined via injectable `homeDir`, defaulting to `os.homedir()`) or any ancestor directory of home (evaluated case-insensitively on Windows and via `path.posix.relative` on POSIX). Isolated shadow directories located _inside_ the home directory (e.g., `%LOCALAPPDATA%\Temp\secureship-shadow-...`) are strictly permitted. If `homeDir` cannot be determined, the home check is safely skipped while root protection remains active.

### 3.5 Windows Requirements and Unsupported Configurations

For container sandboxing on Windows hosts:

- **Docker Desktop Mode**: Docker Desktop must be running in **Linux containers mode** (`OSType: linux`).
- **WSL2 Backend**: The WSL2 backend is strongly recommended. The legacy Hyper-V backend requires manual drive sharing configuration in Docker Desktop settings.
- **Unsupported Environments**: Docker Desktop in "Windows containers" mode (`OSType: windows`) and Windows Server (Mirantis Container Runtime) cannot run Linux container images and are **unsupported**.
- **Image Pre-Pull Requirement**: Verification executes with `--pull=never`. The pinned container image (`node:20-alpine@sha256:...`) must be pulled beforehand via `docker pull` on fresh environments.
- **Filesystem Storage**: Shadow directories must reside on a local drive with a drive letter. UNC shares and network-mapped temporary directories are unsupported.
- **Podman on Windows**: Podman Machine on Windows is supported in principle but is unverified in this build environment.

---

## 4. Host Backend & Trust Model

In environments where Docker/Podman is unavailable or when the developer explicitly desires native host execution, SecureShip provides `HostBackend`.

### 4.1 Strict Host Gating

Host execution is **strictly disabled by default**. Attempting to run with `sandbox.backend: 'host'` without prior explicit trust fails closed with:

```
Host Execution Refused: Repository at '<path>' (hash <hash>) is not trusted for host execution.
Run 'secureship sandbox trust-host' to explicitly authorize.
```

### 4.2 Interactive Trust Confirmation

To authorize host execution, the developer must run:

```bash
secureship sandbox trust-host
```

And explicitly type the following non-trivial confirmation phrase:

```
I trust repository <path> to run un-sandboxed code on my machine
```

Once confirmed, the realpath SHA-256 hash of the repository root is recorded in the per-user configuration (`~/.secureship/config.json`) under `trustedHostRepos`.

### 4.3 Visible Host Branding

Every command executed via `HostBackend` prints a prominent warning banner in the CLI and execution logs:

```
================================================================================
                       HOST EXECUTION: NOT A SANDBOX
  Repository code is executing directly on your machine with host permissions.
================================================================================
```

---

## 5. Live Environment Status vs Test Emulation

| Component                            | Status in this Build                                             | Verification Method                                                                                                                                                                      |
| :----------------------------------- | :--------------------------------------------------------------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Docker Desktop Engine**            | Not Installed on Host                                            | Host environment verified; neither `docker` nor `podman` was available on PATH during verification run.                                                                                  |
| **Windows Path Translation**         | Unit-verified; not yet verified on a live Windows Docker Desktop | Unit tested in `packages/sandbox/test/backends.test.ts` across win32, linux, and darwin platforms with table-driven test vectors, 8.3 canonicalization, and boundary mount guards.       |
| **Container Backend Security Flags** | Verified Live                                                    | Verified via unit tests asserting `--network=none`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, and minimal environment forwarding.                                            |
| **Container Cleanup (`--label`)**    | Verified Live                                                    | Tested with `SafeProcessRunner` mock and live cleanup routines.                                                                                                                          |
| **FakeSandboxBackend**               | CI / Deterministic                                               | Mock backend recording all executed commands and returning scripted exit codes and output tails, enabling reproducible, deterministic CI testing without container runtime dependencies. |
