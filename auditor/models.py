from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    severity: str
    title: str
    url: str
    evidence: str
    risk: str
    recommendation: str
    category: str = "general"
    confidence: str = "confirmed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Endpoint:
    url: str
    source: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    params: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Form:
    page_url: str
    action: str
    method: str
    fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VisibleData:
    url: str
    data_type: str
    value: str
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PageRecord:
    url: str
    status_code: int | None
    content_type: str
    title: str = ""
    final_url: str = ""
    error: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditConfig:
    url: str
    host: str
    profile: str
    depth: int
    max_pages: int
    timeout: float
    rate_limit: float
    allow_subdomains: bool
    auth_file: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    target: dict[str, Any]
    config: AuditConfig
    inventory: dict[str, Any]
    findings: list[Finding]
    metadata: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "target": self.target,
            "config": self.config.to_dict(),
            "inventory": self.inventory,
            "findings": [finding.to_dict() for finding in self.findings],
            "metadata": self.metadata,
        }

