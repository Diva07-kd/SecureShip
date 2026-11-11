"""
Exporter service module re-exporting multi-format exporters.
Maintains dual-compatibility with ORIGINAL_REQUEST.md.
"""

from __future__ import annotations

from app.exporters import (
    SUPPORTED_FORMATS,
    export_html,
    export_json,
    export_pdf,
    export_report,
    export_sarif,
    generate_sarif_dict,
    normalize_report_dict,
)

__all__ = [
    "export_report",
    "export_json",
    "export_sarif",
    "export_html",
    "export_pdf",
    "normalize_report_dict",
    "generate_sarif_dict",
    "SUPPORTED_FORMATS",
]
