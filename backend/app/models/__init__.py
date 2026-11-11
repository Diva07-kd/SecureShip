"""
Models package for SecureScan.
"""

from app.models.job import JobRecord, JobStage, JobStatus
from app.models.report import (
    CWE_TO_OWASP_INT,
    BaseSchema,
    CodeSnippet,
    FindingCategory,
    FindingLocation,
    NormalizedFinding,
    OwaspCategory,
    ReachabilityVerdict,
    ScannerExecutionSummary,
    ScannerName,
    ScanReport,
    ScanSummary,
    Severity,
    SnippetLine,
    extract_cwe_ids,
    map_cwe_to_owasp,
    normalize_cwe_id,
    normalize_reachability_verdict,
)

__all__ = [
    "Severity",
    "FindingCategory",
    "ScannerName",
    "ReachabilityVerdict",
    "OwaspCategory",
    "BaseSchema",
    "SnippetLine",
    "CodeSnippet",
    "FindingLocation",
    "NormalizedFinding",
    "ScannerExecutionSummary",
    "ScanSummary",
    "ScanReport",
    "JobStatus",
    "JobStage",
    "JobRecord",
    "normalize_cwe_id",
    "extract_cwe_ids",
    "map_cwe_to_owasp",
    "normalize_reachability_verdict",
    "CWE_TO_OWASP_INT",
]
