from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(slots=True)
class ScopePolicy:
    allowed_hosts: list[str]

    def is_allowed_url(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if not parsed.hostname:
            return False
        return self.is_allowed_host(parsed.hostname)

    def is_allowed_host(self, host: str) -> bool:
        normalized_host = normalize_host(host)
        for allowed_host in self.allowed_hosts:
            if normalized_host == allowed_host:
                return True
            if normalized_host.endswith(f".{allowed_host}"):
                return True
        return False


def build_scope_policy(values: list[str]) -> ScopePolicy:
    hosts = [normalize_scope_value(value) for value in values]
    unique_hosts = sorted(set(hosts))
    if not unique_hosts:
        raise ValueError("At least one scope value is required")
    return ScopePolicy(allowed_hosts=unique_hosts)


def normalize_scope_value(value: str) -> str:
    raw = value.strip().lower()
    if not raw:
        raise ValueError("Scope value cannot be empty")

    if "://" not in raw:
        raw = f"//{raw}"

    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Invalid scope value: {value}")

    return normalize_host(host)


def normalize_host(host: str) -> str:
    return host.strip().lower().strip(".")

