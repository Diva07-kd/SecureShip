"""
Core execution engine, security defenses, and worker queue for SecureScan.
"""

from app.core.context_extractor import (
    enrich_findings_with_context,
    enrich_report_with_snippets,
    extract_code_snippet,
)
from app.core.queue import ScanJobQueue
from app.core.runner import (
    ScannerError,
    ScannerExecutionError,
    ScannerNotFoundError,
    ScannerTimeoutError,
    resolve_cli_paths,
    run_secureship_cli,
)
from app.core.safe_extract import (
    ExtractionResult,
    safe_extract,
    safe_extract_context,
    temporary_scan_dir,
)

__all__ = [
    "ExtractionResult",
    "safe_extract",
    "temporary_scan_dir",
    "safe_extract_context",
    "run_secureship_cli",
    "resolve_cli_paths",
    "ScannerError",
    "ScannerNotFoundError",
    "ScannerTimeoutError",
    "ScannerExecutionError",
    "ScanJobQueue",
    "extract_code_snippet",
    "enrich_findings_with_context",
    "enrich_report_with_snippets",
]
