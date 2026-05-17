"""Data models for SelectInfo entities."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Asset:
    """Represents a discovered asset/subdomain."""

    task_id: int
    domain: str
    resolved_ip: Optional[str] = None
    source_module: str = ""
    first_seen: datetime = field(default_factory=datetime.now)


@dataclass
class Fingerprint:
    """Represents a web service fingerprint."""

    task_id: int
    url: str
    ip: Optional[str] = None
    port: int = 443
    status_code: Optional[int] = None
    title: Optional[str] = None
    content_type: Optional[str] = None
    server_header: Optional[str] = None
    tech_stack: list = field(default_factory=list)
    waf_detected: Optional[str] = None
    response_time_ms: Optional[int] = None


@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""

    task_id: int
    vuln_id: str
    url: str
    template: str
    severity: Severity
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    matched_at: Optional[str] = None
    extracted_results: Optional[dict] = None
    ai_validated: Optional[bool] = None
    ai_confidence: Optional[float] = None