"""Detection rule loading, validation and field matching.

Rule format (JSON)::

    {
      "id": "LS-001",
      "title": "SSH brute force",
      "severity": "high",                 # informational|low|medium|high|critical
      "mitre": ["T1110.001"],
      "source": "linux_auth",             # optional: string or list
      "type": "threshold",                # match | threshold | sequence
      "match": {"event_type": "ssh_failed_login"},
      "threshold": {"count": 5, "window_seconds": 300, "group_by": ["src_ip"],
                    "distinct": "user"}   # distinct is optional
    }

Field conditions inside ``match``:

* ``"field": "value"``                 - case-insensitive equality
* ``"field": ["a", "b"]``              - value is one of the list
* ``"field": {"regex": "..."}``        - regular expression search (case-insensitive)
* ``"field": {"contains": "x"}``       - substring (or list of substrings, any)
* ``"field": {"gte": 400, "lte": 499}``- numeric comparisons (gt/lt too)
* ``"field": {"exists": true}``
* ``"field": {"not": <condition>}``    - negation
* ``"any_of": [{...}, {...}]``         - OR of sub-matches
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .models import Event, SEVERITY_ORDER

VALID_TYPES = {"match", "threshold", "sequence"}


class RuleError(ValueError):
    """Raised when a rule file is invalid."""


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    type: str
    match: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    mitre: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    threshold: dict[str, Any] = field(default_factory=dict)
    sequence: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def applies_to(self, event: Event) -> bool:
        return not self.sources or event.source in self.sources


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _to_number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def condition_matches(value: Any, cond: Any) -> bool:
    """Evaluate a single field condition against ``value``."""
    if isinstance(cond, dict):
        for op, expected in cond.items():
            if op == "not":
                if condition_matches(value, expected):
                    return False
            elif op == "exists":
                if bool(value not in (None, "")) != bool(expected):
                    return False
            elif value is None:
                return False
            elif op == "equals":
                if not condition_matches(value, expected):
                    return False
            elif op == "in":
                if not condition_matches(value, list(expected)):
                    return False
            elif op == "regex":
                patterns = expected if isinstance(expected, list) else [expected]
                if not any(_compile(p).search(str(value)) for p in patterns):
                    return False
            elif op == "contains":
                needles = expected if isinstance(expected, list) else [expected]
                hay = str(value).lower()
                if not any(str(n).lower() in hay for n in needles):
                    return False
            elif op in ("startswith", "endswith"):
                needles = expected if isinstance(expected, list) else [expected]
                fn = str.startswith if op == "startswith" else str.endswith
                if not any(fn(str(value).lower(), str(n).lower()) for n in needles):
                    return False
            elif op in ("gt", "gte", "lt", "lte"):
                num = _to_number(value)
                if num is None:
                    return False
                limit = float(expected)
                ok = {"gt": num > limit, "gte": num >= limit,
                      "lt": num < limit, "lte": num <= limit}[op]
                if not ok:
                    return False
            else:
                raise RuleError(f"Unknown condition operator: {op!r}")
        return True
    if isinstance(cond, list):
        return any(condition_matches(value, c) for c in cond)
    if value is None:
        return False
    if isinstance(cond, str) or isinstance(value, str):
        return str(value).lower() == str(cond).lower()
    return value == cond


def event_matches(event: Event, match: dict[str, Any]) -> bool:
    """Return True if ``event`` satisfies every condition in ``match``."""
    for key, cond in match.items():
        if key == "any_of":
            if not any(event_matches(event, sub) for sub in cond):
                return False
        elif not condition_matches(event.get(key), cond):
            return False
    return True


def _validate(raw: dict[str, Any], origin: str) -> Rule:
    for required in ("id", "title", "severity"):
        if required not in raw:
            raise RuleError(f"{origin}: rule missing required key '{required}'")
    rtype = raw.get("type", "match")
    if rtype not in VALID_TYPES:
        raise RuleError(f"{origin}: rule {raw['id']} has invalid type '{rtype}'")
    severity = str(raw["severity"]).lower()
    if severity not in SEVERITY_ORDER:
        raise RuleError(f"{origin}: rule {raw['id']} has invalid severity '{severity}'")
    if rtype == "threshold":
        th = raw.get("threshold") or {}
        if int(th.get("count", 0)) < 1 or int(th.get("window_seconds", 0)) < 1:
            raise RuleError(f"{origin}: rule {raw['id']} needs threshold.count and window_seconds")
    if rtype == "sequence":
        seq = raw.get("sequence") or {}
        if "first" not in seq or "then" not in seq:
            raise RuleError(f"{origin}: rule {raw['id']} sequence needs 'first' and 'then'")
    if rtype in ("match", "threshold") and not raw.get("match"):
        raise RuleError(f"{origin}: rule {raw['id']} needs a 'match' block")
    source = raw.get("source", [])
    return Rule(
        id=raw["id"], title=raw["title"], severity=severity, type=rtype,
        match=raw.get("match", {}), description=raw.get("description", ""),
        mitre=list(raw.get("mitre", [])),
        sources=[source] if isinstance(source, str) else list(source),
        threshold=raw.get("threshold", {}), sequence=raw.get("sequence", {}),
        enabled=raw.get("enabled", True),
    )


def load_rules(*paths: str | Path) -> list[Rule]:
    """Load rules from JSON files or directories of JSON files."""
    rules: list[Rule] = []
    files: list[Path] = []
    for p in paths:
        p = Path(p)
        files.extend(sorted(p.glob("*.json")) if p.is_dir() else [p])
    seen: set[str] = set()
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuleError(f"{f}: invalid JSON ({exc})") from exc
        items = data.get("rules", data) if isinstance(data, dict) else data
        for raw in items:
            rule = _validate(raw, str(f))
            if rule.id in seen:
                raise RuleError(f"{f}: duplicate rule id {rule.id}")
            seen.add(rule.id)
            if rule.enabled:
                rules.append(rule)
    return rules


def default_rules_path() -> Path:
    return Path(__file__).resolve().parent / "ruleset"
