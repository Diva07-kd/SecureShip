"""
SecureScan Multi-Format Exporters Package.
Exports unified scan reports to JSON, OASIS SARIF 2.1.0, standalone HTML, and binary PDF.
"""

from __future__ import annotations

from typing import Any

from app.exporters.html_exporter import export_html
from app.exporters.json_exporter import export_json, normalize_report_dict
from app.exporters.pdf_exporter import export_pdf
from app.exporters.sarif_exporter import export_sarif, generate_sarif_dict
from app.models.report import ScanReport

SUPPORTED_FORMATS: dict[str, tuple[str, str]] = {
    "json": ("application/json", "json"),
    "sarif": ("application/sarif+json", "sarif"),
    "html": ("text/html; charset=utf-8", "html"),
    "pdf": ("application/pdf", "pdf"),
}


def export_report(
    report: ScanReport | dict[str, Any],
    format_name: str,
) -> tuple[bytes, str, str]:
    """
    Exports a scan report into the specified format.

    Args:
        report: ScanReport model or valid dictionary.
        format_name: One of 'json', 'sarif', 'html', 'pdf' (case-insensitive).

    Returns:
        tuple of (content_bytes, content_type_header, file_extension)

    Raises:
        ValueError: If format_name is not supported.
    """
    fmt = format_name.lower().strip()
    if fmt not in SUPPORTED_FORMATS:
        supported_list = ", ".join(SUPPORTED_FORMATS.keys())
        raise ValueError(
            f"Unsupported export format '{format_name}'. Supported formats: {supported_list}"
        )

    content_type, ext = SUPPORTED_FORMATS[fmt]

    if fmt == "json":
        text_content = export_json(report)
        content_bytes = text_content.encode("utf-8")
    elif fmt == "sarif":
        text_content = export_sarif(report)
        content_bytes = text_content.encode("utf-8")
    elif fmt == "html":
        text_content = export_html(report)
        content_bytes = text_content.encode("utf-8")
    elif fmt == "pdf":
        content_bytes = export_pdf(report)
    else:
        raise ValueError(f"Unhandled format '{fmt}'")

    return content_bytes, content_type, ext


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
