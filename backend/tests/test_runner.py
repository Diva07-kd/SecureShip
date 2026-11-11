"""
Unit tests for Subprocess Runner (backend/app/core/runner.py).
Tests argument list invocation, exit code semantics (0 and 1 handled as success),
300s timeout killing process, corrupt JSON handling, and path resolution.
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.runner import (
    ScannerError,
    ScannerExecutionError,
    ScannerNotFoundError,
    ScannerTimeoutError,
    resolve_cli_paths,
    run_secureship_cli,
)

SAMPLE_REPORT_JSON = json.dumps({
    "schemaVersion": "1.3",
    "tool": {"name": "secureship", "version": "1.0.0"},
    "target": "/workspace/target",
    "mode": "FULL",
    "findings": [
        {
            "id": "finding-test-1",
            "ruleId": "secureship-py-sql-format",
            "severity": "HIGH",
            "category": "SAST",
            "location": {"filePath": "app.py", "startLine": 10, "endLine": 10},
        }
    ],
    "summary": {"totalReported": 1, "bySeverity": {"HIGH": 1}},
})

CLEAN_REPORT_JSON = json.dumps({
    "schemaVersion": "1.3",
    "tool": {"name": "secureship", "version": "1.0.0"},
    "target": "/workspace/target",
    "mode": "FULL",
    "findings": [],
    "summary": {"totalReported": 0, "bySeverity": {"CRITICAL": 0, "HIGH": 0}},
})


@pytest.fixture
def mock_proc():
    proc = MagicMock()
    proc.kill = MagicMock()
    proc.wait = AsyncMock(return_value=0)
    proc.communicate = AsyncMock()
    return proc


@pytest.mark.asyncio
async def test_runner_success_exit_code_0(tmp_path, mock_proc):
    """Exit code 0 (clean scan) must parse stdout JSON and return report."""
    mock_proc.returncode = 0
    mock_proc.communicate.return_value = (CLEAN_REPORT_JSON.encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            report = await run_secureship_cli(tmp_path)
            assert report["schemaVersion"] == "1.3"
            assert len(report["findings"]) == 0
            assert report["summary"]["totalReported"] == 0


@pytest.mark.asyncio
async def test_runner_success_exit_code_1_with_findings(tmp_path, mock_proc):
    """Exit code 1 (findings present) must be handled as SUCCESS and parse stdout JSON."""
    mock_proc.returncode = 1
    mock_proc.communicate.return_value = (SAMPLE_REPORT_JSON.encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            report = await run_secureship_cli(tmp_path)
            assert report["schemaVersion"] == "1.3"
            assert len(report["findings"]) == 1
            assert report["findings"][0]["ruleId"] == "secureship-py-sql-format"


@pytest.mark.asyncio
async def test_runner_failure_exit_code_2_usage_error(tmp_path, mock_proc):
    """Exit code 2 (usage/config error) must raise ScannerExecutionError with stderr message."""
    mock_proc.returncode = 2
    mock_proc.communicate.return_value = (
        b"",
        json.dumps({"error": "Invalid --gate2 mode 'invalid'"}).encode("utf-8"),
    )

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            with pytest.raises(ScannerExecutionError) as exc_info:
                await run_secureship_cli(tmp_path)
            assert exc_info.value.exit_code == 2
            assert "Invalid --gate2 mode 'invalid'" in exc_info.value.message


@pytest.mark.asyncio
async def test_runner_failure_exit_code_3_infrastructure_error(tmp_path, mock_proc):
    """Exit code 3 (engine failure) must raise ScannerExecutionError."""
    mock_proc.returncode = 3
    mock_proc.communicate.return_value = (b"", b"Critical scanner failure: strict mode violation")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            with pytest.raises(ScannerExecutionError) as exc_info:
                await run_secureship_cli(tmp_path)
            assert exc_info.value.exit_code == 3
            assert "Critical scanner failure" in exc_info.value.message


@pytest.mark.asyncio
async def test_runner_timeout_kills_process(tmp_path, mock_proc):
    """Subprocess exceeding timeout must be killed and raise ScannerTimeoutError."""
    mock_proc.communicate.side_effect = asyncio.TimeoutError()

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            with pytest.raises(ScannerTimeoutError) as exc_info:
                await run_secureship_cli(tmp_path, timeout_seconds=1)
            assert exc_info.value.timeout_seconds == 1
            mock_proc.kill.assert_called_once()


@pytest.mark.asyncio
async def test_runner_argument_list_no_shell(tmp_path, mock_proc):
    """Subprocess runner must invoke create_subprocess_exec with argument list, no shell."""
    mock_proc.returncode = 0
    mock_proc.communicate.return_value = (CLEAN_REPORT_JSON.encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc) as mock_exec:
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            await run_secureship_cli(tmp_path, extra_args=["--gate2", "annotate"])
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args[0]
            # Verify argument list structure
            assert call_args[0] == "node"
            assert call_args[1] == "/cli/dist/index.js"
            assert call_args[2] == "scan"
            assert call_args[3] == str(tmp_path.resolve())
            assert call_args[4] == "--json"
            assert call_args[5] == "--gate2"
            assert call_args[6] == "annotate"
            # Verify shell is not enabled
            assert "shell" not in mock_exec.call_args[1] or mock_exec.call_args[1]["shell"] is False


@pytest.mark.asyncio
async def test_runner_corrupt_json_stdout(tmp_path, mock_proc):
    """Corrupted JSON on exit code 0 or 1 must raise ScannerExecutionError."""
    mock_proc.returncode = 0
    mock_proc.communicate.return_value = (b"Fatal: Node heap out of memory", b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            with pytest.raises(ScannerExecutionError) as exc_info:
                await run_secureship_cli(tmp_path)
            assert "invalid json" in exc_info.value.message.lower()


@pytest.mark.asyncio
async def test_runner_stdout_with_extraneous_node_warning(tmp_path, mock_proc):
    """Extraneous Node.js deprecation warning prepended to JSON stdout must be recovered."""
    mock_proc.returncode = 0
    raw_output = f"(node:12345) [DEP0040] DeprecationWarning: The `punycode` module is deprecated.\n{CLEAN_REPORT_JSON}\n"
    mock_proc.communicate.return_value = (raw_output.encode("utf-8"), b"")

    with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
        with patch("app.core.runner.resolve_cli_paths", return_value=("node", "/cli/dist/index.js")):
            report = await run_secureship_cli(tmp_path)
            assert report["schemaVersion"] == "1.3"
            assert len(report["findings"]) == 0


def test_resolve_cli_paths_custom_and_fallback(tmp_path):
    fake_cli = tmp_path / "index.js"
    fake_cli.write_text("console.log('hi');")

    node_bin, cli_script = resolve_cli_paths(custom_node="custom-node", custom_cli=str(fake_cli))
    assert node_bin == "custom-node"
    assert cli_script == str(fake_cli)


def test_resolve_cli_paths_not_found(tmp_path):
    with patch("shutil.which", return_value=None):
        with pytest.raises(ScannerNotFoundError):
            resolve_cli_paths(custom_node=None, custom_cli=str(tmp_path / "nonexistent.js"))
