"""
Unified Security Finding and Scan Report Data Models.
Standardizes findings from all scanners (opengrep, gitleaks, trivy, osv-scanner, checkov)
into a strongly-typed Pydantic v2 schema mapped to CWE and OWASP Top 10 (2021).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel


# =========================================================================
# Enumerations
# =========================================================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        ranks = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return ranks.get(self, 0)

    def __ge__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            try:
                other = Severity(other)
            except ValueError:
                return NotImplemented
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            try:
                other = Severity(other)
            except ValueError:
                return NotImplemented
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            try:
                other = Severity(other)
            except ValueError:
                return NotImplemented
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: Severity | str) -> bool:
        if isinstance(other, str):
            try:
                other = Severity(other)
            except ValueError:
                return NotImplemented
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


class FindingCategory(str, Enum):
    SAST = "SAST"
    SCA = "SCA"
    SECRET = "SECRET"
    IAC = "IAC"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"


class ScannerName(str, Enum):
    OPENGREP = "opengrep"
    SEMGREP = "semgrep"
    GITLEAKS = "gitleaks"
    OSV_SCANNER = "osv-scanner"
    TRIVY = "trivy"
    CHECKOV = "checkov"
    GENERIC = "generic"


class ReachabilityVerdict(str, Enum):
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"


class OwaspCategory(str, Enum):
    A01_2021 = "A01:2021-Broken Access Control"
    A02_2021 = "A02:2021-Cryptographic Failures"
    A03_2021 = "A03:2021-Injection"
    A04_2021 = "A04:2021-Insecure Design"
    A05_2021 = "A05:2021-Security Misconfiguration"
    A06_2021 = "A06:2021-Vulnerable and Outdated Components"
    A07_2021 = "A07:2021-Identification and Authentication Failures"
    A08_2021 = "A08:2021-Software and Data Integrity Failures"
    A09_2021 = "A09:2021-Security Logging and Monitoring Failures"
    A10_2021 = "A10:2021-Server-Side Request Forgery (SSRF)"
    UNKNOWN = "A00:2021-Other/Unknown"


# =========================================================================
# Base Model with CamelCase Aliasing
# =========================================================================

class BaseSchema(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        alias_generator=to_camel,
        extra="ignore",
    )


# =========================================================================
# Code Snippet Models
# =========================================================================

class SnippetLine(BaseSchema):
    line_number: int
    content: str
    is_target: bool = False


class CodeSnippet(BaseSchema):
    file_path: str
    start_line: int          # 1-indexed start line of context window
    end_line: int            # 1-indexed end line of context window
    target_start: int        # 1-indexed start line of vulnerable finding
    target_end: int          # 1-indexed end line of vulnerable finding
    lines: List[SnippetLine]
    raw_content: str         # Full context window content with line breaks


# =========================================================================
# Finding Location & Normalized Finding Models
# =========================================================================

class FindingLocation(BaseSchema):
    file_path: str
    start_line: int = 1
    end_line: int = 1
    start_column: Optional[int] = None
    end_column: Optional[int] = None
    snippet: Optional[str] = None


class NormalizedFinding(BaseSchema):
    id: str
    rule_id: str
    scanner_name: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    location: FindingLocation
    cwe_ids: List[str] = Field(default_factory=list)
    owasp_category: str = OwaspCategory.UNKNOWN.value
    reachability: ReachabilityVerdict = ReachabilityVerdict.UNKNOWN
    confidence: str = "MEDIUM"
    fingerprint: Optional[str] = None
    fix_recommendation: Optional[str] = None
    snippet_context: Optional[CodeSnippet] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[datetime] = None

    @field_validator("reachability", mode="before")
    @classmethod
    def _validate_reachability(cls, v: Any) -> ReachabilityVerdict:
        if isinstance(v, ReachabilityVerdict):
            return v
        return normalize_reachability_verdict(v)

    @field_validator("cwe_ids", mode="before")
    @classmethod
    def _validate_cwe_ids(cls, v: Any) -> List[str]:
        return extract_cwe_ids(v)


# =========================================================================
# Summary & Scan Report Models
# =========================================================================

class ScannerExecutionSummary(BaseSchema):
    name: str
    status: str             # "SUCCESS", "FAILED", "SKIPPED", "TIMED_OUT"
    duration_ms: float = 0.0
    raw_finding_count: int = 0
    error_message: Optional[str] = None


class ScanSummary(BaseSchema):
    total_findings: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_owasp: Dict[str, int] = Field(default_factory=dict)
    by_scanner: Dict[str, int] = Field(default_factory=dict)
    by_reachability: Dict[str, int] = Field(default_factory=dict)


class ScanReport(BaseSchema):
    id: str                                  # Job UUID or scan report UUID
    target_name: Optional[str] = None       # Original zip filename or path
    status: str = "done"                    # "queued", "running", "done", "failed"
    duration_ms: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scanners: List[ScannerExecutionSummary] = Field(default_factory=list)
    findings: List[NormalizedFinding] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    warnings: List[str] = Field(default_factory=list)


# =========================================================================
# CWE Normalization & OWASP Top 10 (2021) Mapping Engine
# =========================================================================

CWE_TO_OWASP_INT: Dict[int, OwaspCategory] = {
    # A01:2021 - Broken Access Control
    22: OwaspCategory.A01_2021, 23: OwaspCategory.A01_2021, 35: OwaspCategory.A01_2021,
    59: OwaspCategory.A01_2021, 200: OwaspCategory.A01_2021, 201: OwaspCategory.A01_2021,
    219: OwaspCategory.A01_2021, 264: OwaspCategory.A01_2021, 275: OwaspCategory.A01_2021,
    276: OwaspCategory.A01_2021, 284: OwaspCategory.A01_2021, 285: OwaspCategory.A01_2021,
    352: OwaspCategory.A01_2021, 359: OwaspCategory.A01_2021, 377: OwaspCategory.A01_2021,
    402: OwaspCategory.A01_2021, 425: OwaspCategory.A01_2021, 441: OwaspCategory.A01_2021,
    497: OwaspCategory.A01_2021, 538: OwaspCategory.A01_2021, 540: OwaspCategory.A01_2021,
    548: OwaspCategory.A01_2021, 552: OwaspCategory.A01_2021, 566: OwaspCategory.A01_2021,
    601: OwaspCategory.A01_2021, 639: OwaspCategory.A01_2021, 651: OwaspCategory.A01_2021,
    668: OwaspCategory.A01_2021, 706: OwaspCategory.A01_2021, 862: OwaspCategory.A01_2021,
    863: OwaspCategory.A01_2021, 913: OwaspCategory.A01_2021, 922: OwaspCategory.A01_2021,
    1275: OwaspCategory.A01_2021,

    # A02:2021 - Cryptographic Failures
    261: OwaspCategory.A02_2021, 296: OwaspCategory.A02_2021, 310: OwaspCategory.A02_2021,
    311: OwaspCategory.A02_2021, 312: OwaspCategory.A02_2021, 319: OwaspCategory.A02_2021,
    320: OwaspCategory.A02_2021, 321: OwaspCategory.A02_2021, 322: OwaspCategory.A02_2021,
    323: OwaspCategory.A02_2021, 324: OwaspCategory.A02_2021, 325: OwaspCategory.A02_2021,
    326: OwaspCategory.A02_2021, 327: OwaspCategory.A02_2021, 328: OwaspCategory.A02_2021,
    329: OwaspCategory.A02_2021, 330: OwaspCategory.A02_2021, 331: OwaspCategory.A02_2021,
    335: OwaspCategory.A02_2021, 336: OwaspCategory.A02_2021, 337: OwaspCategory.A02_2021,
    338: OwaspCategory.A02_2021, 340: OwaspCategory.A02_2021, 347: OwaspCategory.A02_2021,
    522: OwaspCategory.A02_2021, 523: OwaspCategory.A02_2021, 780: OwaspCategory.A02_2021,
    916: OwaspCategory.A02_2021,

    # A03:2021 - Injection
    20: OwaspCategory.A03_2021, 74: OwaspCategory.A03_2021, 75: OwaspCategory.A03_2021,
    77: OwaspCategory.A03_2021, 78: OwaspCategory.A03_2021, 79: OwaspCategory.A03_2021,
    80: OwaspCategory.A03_2021, 83: OwaspCategory.A03_2021, 87: OwaspCategory.A03_2021,
    88: OwaspCategory.A03_2021, 89: OwaspCategory.A03_2021, 90: OwaspCategory.A03_2021,
    91: OwaspCategory.A03_2021, 93: OwaspCategory.A03_2021, 94: OwaspCategory.A03_2021,
    95: OwaspCategory.A03_2021, 96: OwaspCategory.A03_2021, 97: OwaspCategory.A03_2021,
    98: OwaspCategory.A03_2021, 99: OwaspCategory.A03_2021, 113: OwaspCategory.A03_2021,
    116: OwaspCategory.A03_2021, 138: OwaspCategory.A03_2021, 184: OwaspCategory.A03_2021,
    470: OwaspCategory.A03_2021, 506: OwaspCategory.A03_2021, 564: OwaspCategory.A03_2021,
    610: OwaspCategory.A03_2021, 643: OwaspCategory.A03_2021, 644: OwaspCategory.A03_2021,
    652: OwaspCategory.A03_2021, 917: OwaspCategory.A03_2021,

    # A04:2021 - Insecure Design
    73: OwaspCategory.A04_2021, 183: OwaspCategory.A04_2021, 209: OwaspCategory.A04_2021,
    213: OwaspCategory.A04_2021, 235: OwaspCategory.A04_2021, 256: OwaspCategory.A04_2021,
    257: OwaspCategory.A04_2021, 266: OwaspCategory.A04_2021, 269: OwaspCategory.A04_2021,
    280: OwaspCategory.A04_2021, 313: OwaspCategory.A04_2021, 316: OwaspCategory.A04_2021,
    419: OwaspCategory.A04_2021, 430: OwaspCategory.A04_2021, 434: OwaspCategory.A04_2021,
    444: OwaspCategory.A04_2021, 451: OwaspCategory.A04_2021, 472: OwaspCategory.A04_2021,
    501: OwaspCategory.A04_2021, 525: OwaspCategory.A04_2021, 539: OwaspCategory.A04_2021,
    579: OwaspCategory.A04_2021, 598: OwaspCategory.A04_2021, 602: OwaspCategory.A04_2021,
    642: OwaspCategory.A04_2021, 646: OwaspCategory.A04_2021, 653: OwaspCategory.A04_2021,
    656: OwaspCategory.A04_2021, 657: OwaspCategory.A04_2021, 799: OwaspCategory.A04_2021,
    807: OwaspCategory.A04_2021, 840: OwaspCategory.A04_2021, 841: OwaspCategory.A04_2021,
    927: OwaspCategory.A04_2021, 1021: OwaspCategory.A04_2021, 1173: OwaspCategory.A04_2021,

    # A05:2021 - Security Misconfiguration
    2: OwaspCategory.A05_2021, 11: OwaspCategory.A05_2021, 13: OwaspCategory.A05_2021,
    15: OwaspCategory.A05_2021, 16: OwaspCategory.A05_2021, 260: OwaspCategory.A05_2021,
    315: OwaspCategory.A05_2021, 520: OwaspCategory.A05_2021, 526: OwaspCategory.A05_2021,
    537: OwaspCategory.A05_2021, 541: OwaspCategory.A05_2021, 547: OwaspCategory.A05_2021,
    611: OwaspCategory.A05_2021, 614: OwaspCategory.A05_2021, 756: OwaspCategory.A05_2021,
    776: OwaspCategory.A05_2021, 942: OwaspCategory.A05_2021, 1004: OwaspCategory.A05_2021,
    1032: OwaspCategory.A05_2021, 1174: OwaspCategory.A05_2021,

    # A06:2021 - Vulnerable and Outdated Components
    937: OwaspCategory.A06_2021, 1026: OwaspCategory.A06_2021, 1035: OwaspCategory.A06_2021,
    1104: OwaspCategory.A06_2021, 1395: OwaspCategory.A06_2021,

    # A07:2021 - Identification and Authentication Failures
    255: OwaspCategory.A07_2021, 259: OwaspCategory.A07_2021, 287: OwaspCategory.A07_2021,
    288: OwaspCategory.A07_2021, 290: OwaspCategory.A07_2021, 294: OwaspCategory.A07_2021,
    295: OwaspCategory.A07_2021, 297: OwaspCategory.A07_2021, 300: OwaspCategory.A07_2021,
    302: OwaspCategory.A07_2021, 304: OwaspCategory.A07_2021, 306: OwaspCategory.A07_2021,
    307: OwaspCategory.A07_2021, 384: OwaspCategory.A07_2021, 521: OwaspCategory.A07_2021,
    613: OwaspCategory.A07_2021, 620: OwaspCategory.A07_2021, 640: OwaspCategory.A07_2021,
    798: OwaspCategory.A07_2021, 804: OwaspCategory.A07_2021, 836: OwaspCategory.A07_2021,
    839: OwaspCategory.A07_2021, 1216: OwaspCategory.A07_2021,

    # A08:2021 - Software and Data Integrity Failures
    345: OwaspCategory.A08_2021, 353: OwaspCategory.A08_2021, 426: OwaspCategory.A08_2021,
    494: OwaspCategory.A08_2021, 502: OwaspCategory.A08_2021, 565: OwaspCategory.A08_2021,
    784: OwaspCategory.A08_2021, 829: OwaspCategory.A08_2021, 830: OwaspCategory.A08_2021,
    915: OwaspCategory.A08_2021,

    # A09:2021 - Security Logging and Monitoring Failures
    117: OwaspCategory.A09_2021, 223: OwaspCategory.A09_2021, 532: OwaspCategory.A09_2021,
    778: OwaspCategory.A09_2021,

    # A10:2021 - Server-Side Request Forgery (SSRF)
    918: OwaspCategory.A10_2021,
}


def normalize_cwe_id(val: Union[str, int, None]) -> Optional[str]:
    """Normalizes an individual CWE token to 'CWE-<NUMBER>' format."""
    if val is None:
        return None
    val_str = str(val).strip()
    if not val_str:
        return None

    # 1. Check for standard CWE pattern
    m = re.search(r"(?i)\bCWE[-_:\s]?(\d+)\b", val_str)
    if m:
        return f"CWE-{int(m.group(1))}"

    # 2. Check for pure numeric string
    if re.fullmatch(r"\d+", val_str):
        return f"CWE-{int(val_str)}"

    # 3. Check for path-based CWE tag (e.g., 'external/cwe/cwe-22')
    m2 = re.search(r"(?i)cwe[-_:\s]?(\d+)", val_str)
    if m2:
        return f"CWE-{int(m2.group(1))}"

    return None


def extract_cwe_ids(raw: Union[str, int, List[Union[str, int]], None]) -> List[str]:
    """
    Extracts, deduplicates, and sorts canonical CWE IDs from string or list input.
    Guarantees output formatted as ['CWE-78', 'CWE-89', ...] sorted numerically.
    """
    if not raw:
        return []
    if isinstance(raw, (str, int)):
        raw = [raw]

    cwe_set: set[str] = set()
    for item in raw:
        if not item:
            continue
        item_str = str(item)
        matches = re.findall(r"(?i)\bCWE[-_:\s]?(\d+)\b", item_str)
        if matches:
            for num in matches:
                cwe_set.add(f"CWE-{int(num)}")
        else:
            norm = normalize_cwe_id(item_str)
            if norm:
                cwe_set.add(norm)

    return sorted(list(cwe_set), key=lambda x: int(x.split("-")[1]))


def map_cwe_to_owasp(
    cwe_ids: Optional[Union[List[str], str]] = None,
    category: Optional[Union[FindingCategory, str]] = None,
    rule_id: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    """
    Classifies a finding into an OWASP Top 10 (2021) category using a three-tier heuristic:
    1. Direct CWE Match (Authoritative)
    2. Rule ID and Description Keyword Regex
    3. Category-level Fallback
    """
    # Tier 1: Direct CWE Lookup
    extracted_cwes: List[str] = []
    if cwe_ids is not None:
        if isinstance(cwe_ids, list):
            extracted_cwes = cwe_ids
        elif isinstance(cwe_ids, str):
            extracted_cwes = extract_cwe_ids(cwe_ids)

    for cwe in extracted_cwes:
        norm = normalize_cwe_id(cwe)
        if norm:
            cwe_num = int(norm.split("-")[1])
            if cwe_num in CWE_TO_OWASP_INT:
                return CWE_TO_OWASP_INT[cwe_num].value

    # Tier 2: Rule ID and Text Match
    combined_text = f"{rule_id or ''} {description or ''}".lower()
    if re.search(r"\b(sql|sqli|inject|command|exec|eval|xss|script)\b", combined_text):
        return OwaspCategory.A03_2021.value
    if re.search(r"\b(secret|token|password|credential|jwt|api[-_]?key)\b", combined_text):
        return OwaspCategory.A07_2021.value
    if re.search(r"\b(pickle|yaml|deserializ|prototype[-_]?pollution|integrity)\b", combined_text):
        return OwaspCategory.A08_2021.value
    if re.search(r"\b(crypto|hash|md5|sha1|prng|random|cipher)\b", combined_text):
        return OwaspCategory.A02_2021.value
    if re.search(r"\b(traversal|path|directory|symlink|access|authz|idor)\b", combined_text):
        return OwaspCategory.A01_2021.value
    if re.search(r"\b(ssrf|request[-_]?forgery)\b", combined_text):
        return OwaspCategory.A10_2021.value
    if re.search(r"\b(log|logging|monitor)\b", combined_text):
        return OwaspCategory.A09_2021.value
    if re.search(r"\b(docker|terraform|iac|misconfig|permission)\b", combined_text):
        return OwaspCategory.A05_2021.value

    # Tier 3: Category Fallback
    cat_str = str(category).upper() if category else ""
    if "SECRET" in cat_str:
        return OwaspCategory.A07_2021.value
    if "SCA" in cat_str or "SUPPLY_CHAIN" in cat_str:
        return OwaspCategory.A06_2021.value
    if "IAC" in cat_str:
        return OwaspCategory.A05_2021.value

    return OwaspCategory.UNKNOWN.value


def normalize_reachability_verdict(val: Optional[str]) -> ReachabilityVerdict:
    """Normalizes multi-engine reachability indicators to REACHABLE, UNREACHABLE, or UNKNOWN."""
    if not val:
        return ReachabilityVerdict.UNKNOWN
    val_upper = str(val).strip().upper()
    if val_upper in ("REACHABLE", "REACHABLE_CALL_PATH", "REACHABLE_IMPORT", "CALL_PATH", "IMPORT"):
        return ReachabilityVerdict.REACHABLE
    if val_upper == "UNREACHABLE":
        return ReachabilityVerdict.UNREACHABLE
    return ReachabilityVerdict.UNKNOWN
