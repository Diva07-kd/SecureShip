"""
Subprocess Runner for SecureShip CLI.
Executes CLI scans using an argument list with a 300-second hard timeout.
Treats exit codes 0 and 1 as successful scans with valid ScanReport JSON.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("securescan.runner")

DEFAULT_TIMEOUT_SECONDS = 300


class ScannerError(Exception):
    """Base exception for scanner execution errors."""

    def __init__(self, message: str = ""):
        super().__init__(message)
        self.message = message


class ScannerNotFoundError(ScannerError):
    """Raised when Node.js binary or CLI script cannot be located."""
    pass


class ScannerTimeoutError(ScannerError, TimeoutError):
    """Raised when scanner CLI execution exceeds the timeout limit."""

    def __init__(self, message: str, timeout_seconds: int):
        super().__init__(message)
        self.timeout_seconds = timeout_seconds


class ScannerExecutionError(ScannerError):
    """Raised when scanner CLI exits with error code (>1) or produces corrupt output."""

    def __init__(self, message: str, exit_code: int, stdout: str = "", stderr: str = ""):
        super().__init__(message)
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


def resolve_cli_paths(
    custom_node: Optional[str] = None,
    custom_cli: Optional[str] = None,
) -> tuple[str, str]:
    """
    Locates Node.js binary and SecureShip CLI index.js.
    """
    node_bin = custom_node or os.environ.get("NODE_PATH") or shutil.which("node")
    if not node_bin:
        raise ScannerNotFoundError("Node.js executable not found in PATH or NODE_PATH.")

    candidates: list[Path] = []
    if custom_cli:
        candidates.append(Path(custom_cli))
    if os.environ.get("SECURESHIP_CLI_PATH"):
        candidates.append(Path(os.environ["SECURESHIP_CLI_PATH"]))

    # Standard container and repository locations
    candidates.extend([
        Path("/secureship/dist/index.js"),
        Path("/secureship/cli/dist/index.js"),
        Path("/opt/secureship/cli/dist/index.js"),
        Path("/opt/secureship/dist/index.js"),
        Path(__file__).resolve().parents[3] / "packages" / "cli" / "dist" / "index.js",
        Path("packages/cli/dist/index.js").resolve(),
    ])

    for candidate in candidates:
        if candidate.is_file():
            return str(node_bin), str(candidate)

    # Check if 'secureship' executable is in system PATH
    secureship_bin = shutil.which("secureship")
    if secureship_bin and Path(secureship_bin).is_file():
        return str(node_bin), str(secureship_bin)

    raise ScannerNotFoundError(
        f"SecureShip CLI not found. Checked candidate paths: {[str(c) for c in candidates]}"
    )


async def run_secureship_cli(
    scan_target_dir: Path | str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    extra_args: Optional[list[str]] = None,
    node_path: Optional[str] = None,
    cli_path: Optional[str] = None,
    cwd: Optional[Path | str] = None,
) -> dict[str, Any]:
    """
    Executes SecureShip CLI in argument-list form (strictly avoiding shell execution) and returns parsed JSON.
    Exit codes 0 and 1 are parsed as successful scans.
    """
    target = Path(scan_target_dir).resolve()
    if not target.is_dir():
        raise ValueError(f"Scan target directory does not exist or is not a directory: {target}")

    node_bin, cli_script = resolve_cli_paths(node_path, cli_path)

    cmd_args: list[str] = [
        str(node_bin),
        str(cli_script),
        "scan",
        str(target),
        "--json",
    ]
    if extra_args:
        cmd_args.extend(extra_args)

    if cwd and Path(cwd).is_dir():
        work_dir = Path(cwd).resolve()
    elif Path("/secureship").is_dir():
        work_dir = Path("/secureship").resolve()
    else:
        work_dir = target

    logger.info("Starting SecureShip scan: target=%s, timeout=%ds", target, timeout_seconds)

    process = await asyncio.create_subprocess_exec(
        *cmd_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(work_dir),
        env={**os.environ, "NODE_ENV": "production", "NO_COLOR": "1"},
    )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout_seconds),
        )
    except asyncio.CancelledError:
        logger.warning("Scan task cancelled on %s; terminating child process", target)
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            await asyncio.shield(asyncio.wait_for(process.wait(), timeout=5.0))
        except Exception:
            pass
        raise
    except asyncio.TimeoutError:
        logger.error("Scan exceeded timeout of %ds on %s; terminating child process", timeout_seconds, target)
        try:
            process.kill()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except Exception:
            pass
        raise ScannerTimeoutError(
            f"SecureShip CLI scan timed out after {timeout_seconds} seconds on target '{target}'",
            timeout_seconds=timeout_seconds,
        )

    stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
    stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()
    returncode = process.returncode if process.returncode is not None else -1

    logger.info(
        "SecureShip CLI finished with exit code %d (stdout=%d bytes, stderr=%d bytes)",
        returncode, len(stdout_bytes), len(stderr_bytes)
    )

    # Exit code 0 (clean) and 1 (findings detected) are BOTH SUCCESSFUL scans
    if returncode in (0, 1):
        if not stdout_str:
            raise ScannerExecutionError(
                f"SecureShip CLI exited with code {returncode} but produced empty stdout.",
                exit_code=returncode,
                stdout=stdout_str,
                stderr=stderr_str,
            )
        try:
            report_data = json.loads(stdout_str)
            return report_data
        except json.JSONDecodeError as exc:
            # Fallback: recover JSON object if extraneous output (node/scanner warnings) was prepended
            start = stdout_str.find("{")
            end = stdout_str.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(stdout_str[start : end + 1])
                except json.JSONDecodeError:
                    pass
            raise ScannerExecutionError(
                f"SecureShip CLI exited with code {returncode} but produced invalid JSON: {exc}\n"
                f"Stdout snippet: {stdout_str[:300]}",
                exit_code=returncode,
                stdout=stdout_str,
                stderr=stderr_str,
            ) from exc

    # Exit code > 1 represents configuration or infrastructure errors
    error_msg = stderr_str
    try:
        parsed_err = json.loads(stderr_str)
        if isinstance(parsed_err, dict) and "error" in parsed_err:
            error_msg = str(parsed_err["error"])
    except Exception:
        pass

    raise ScannerExecutionError(
        f"SecureShip CLI scan failed with exit code {returncode}: {error_msg or 'Execution error'}",
        exit_code=returncode,
        stdout=stdout_str,
        stderr=stderr_str,
    )
