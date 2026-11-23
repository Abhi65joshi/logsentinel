"""Normalized data models shared by parsers, the engine and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any


@dataclass
class Event:
    """A single log event normalized into a common schema.

    Every parser produces Events so that detection rules can be written once
    against field names (``event_type``, ``user``, ``src_ip`` ...) instead of
    raw log formats.
    """

    timestamp: datetime
    source: str            # linux_auth | windows | web
    event_type: str        # e.g. ssh_failed_login, win_logon_failure, web_request
    host: str = ""
    user: str = ""
    src_ip: str = ""
    message: str = ""
    raw: str = ""
    fields: dict[str, Any] = field(default_factory=dict)

    def get(self, name: str) -> Any:
        """Return a top-level attribute or an extra field (``fields``)."""
        if name in ("timestamp", "source", "event_type", "host", "user",
                    "src_ip", "message", "raw"):
            return getattr(self, name)
        return self.fields.get(name)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


@dataclass
class Alert:
    """A detection produced when a rule fires."""

    rule_id: str
    title: str
    severity: str
    mitre: list[str]
    description: str
    first_seen: datetime
    last_seen: datetime
    count: int
    group: dict[str, Any]
    evidence: list[Event]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "mitre": self.mitre,
            "description": self.description,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "group": self.group,
            "evidence": [e.raw or e.message for e in self.evidence],
        }


SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
