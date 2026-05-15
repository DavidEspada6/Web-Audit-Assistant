from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class Header:
    name: str
    value: str


@dataclass(slots=True)
class HttpResponse:
    url: str
    status: int
    reason: str
    headers: list[Header]
    body: str
    elapsed_ms: float

    def get_header(self, name: str) -> str | None:
        lowered = name.lower()
        for header in self.headers:
            if header.name.lower() == lowered:
                return header.value
        return None

    def get_headers(self, name: str) -> list[str]:
        lowered = name.lower()
        return [header.value for header in self.headers if header.name.lower() == lowered]


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    recommendation: str
    url: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class AuditReport:
    target: str
    scope: list[str]
    generated_at: str
    stats: dict[str, object]
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "scope": self.scope,
            "generated_at": self.generated_at,
            "stats": self.stats,
            "findings": [finding.to_dict() for finding in self.findings],
        }

