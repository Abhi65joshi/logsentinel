"""Log parsers that turn raw log lines into normalized :class:`Event` objects.

Supported sources
-----------------
* ``linux_auth`` - Linux ``/var/log/auth.log`` / ``secure`` (classic syslog or
  RFC 3339 timestamps): sshd, sudo, su, useradd, usermod.
* ``windows``    - Windows Security / PowerShell events exported to JSON
  (see ``docs/export-windows-events.ps1``).
* ``web``        - Apache / Nginx access logs in combined log format.

All timestamps are normalised to timezone-aware UTC.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import unquote_plus

from .models import Event

UTC = timezone.utc

# --------------------------------------------------------------------------- #
# Linux auth.log
# --------------------------------------------------------------------------- #
_SYSLOG_CLASSIC = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

_AUTH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ssh_failed_login", re.compile(
        r"Failed (?P<method>password|publickey) for (?:(?P<invalid>invalid user) )?"
        r"(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)")),
    ("ssh_successful_login", re.compile(
        r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for "
        r"(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port (?P<port>\d+)")),
    ("ssh_invalid_user", re.compile(
        r"Invalid user (?P<user>\S*) from (?P<ip>[\d.:a-fA-F]+)")),
    ("sudo_command", re.compile(
        r"^\s*(?P<user>\S+)\s*:.*?USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)$")),
    ("su_session", re.compile(
        r"session opened for user (?P<target_user>\S+?)(?:\(uid=\d+\))? by (?P<user>[^\s(]*)")),
    ("user_created", re.compile(r"new user: name=(?P<target_user>[^,\s]+)")),
    ("user_added_to_group", re.compile(
        r"add '(?P<target_user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
]


def _parse_syslog_ts(ts: str, year: int) -> datetime:
    if ts[0].isdigit():
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)
    dt = datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=UTC)


def parse_linux_auth(lines: Iterable[str], year: int | None = None) -> Iterator[Event]:
    """Parse Linux auth.log lines. ``year`` fills in classic syslog timestamps."""
    year = year or datetime.now(UTC).year
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        m = _SYSLOG_ISO.match(line) or _SYSLOG_CLASSIC.match(line)
        if not m:
            continue
        try:
            ts = _parse_syslog_ts(m.group("ts"), year)
        except ValueError:
            continue
        proc, msg = m.group("proc"), m.group("msg")
        event = Event(timestamp=ts, source="linux_auth", event_type="generic",
                      host=m.group("host"), message=msg, raw=line,
                      fields={"process": proc})
        for etype, pattern in _AUTH_PATTERNS:
            pm = pattern.search(msg)
            if not pm:
                continue
            if etype == "sudo_command" and proc != "sudo":
                continue
            groups = pm.groupdict()
            event.event_type = etype
            event.user = groups.pop("user", "") or ""
            event.src_ip = groups.pop("ip", "") or ""
            if etype == "ssh_failed_login":
                groups["invalid_user"] = bool(groups.pop("invalid"))
            event.fields.update({k: v for k, v in groups.items() if v is not None})
            break
        yield event


# --------------------------------------------------------------------------- #
# Windows events (JSON)
# --------------------------------------------------------------------------- #
WINDOWS_EVENT_TYPES = {
    4624: "win_logon_success",
    4625: "win_logon_failure",
    4648: "win_explicit_credential_logon",
    4672: "win_special_privileges",
    4688: "win_process_created",
    4697: "win_service_installed",
    4720: "win_user_created",
    4726: "win_user_deleted",
    4728: "win_group_member_added",
    4732: "win_group_member_added",
    4756: "win_group_member_added",
    4740: "win_account_locked",
    1102: "win_log_cleared",
    7045: "win_service_installed",
    4104: "ps_scriptblock",
}

_MS_DATE = re.compile(r"/Date\((?P<ms>-?\d+)\)/")


def _parse_windows_ts(value) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, UTC)
    value = str(value)
    m = _MS_DATE.search(value)
    if m:  # PowerShell 5.1 ConvertTo-Json format
        return datetime.fromtimestamp(int(m.group("ms")) / 1000, UTC)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    # Trim sub-microsecond precision (.NET emits 7 digits)
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    dt = datetime.fromisoformat(value)
    return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)


def _ci_get(record: dict, *names, default=""):
    lowered = {k.lower(): v for k, v in record.items()}
    for name in names:
        if name.lower() in lowered and lowered[name.lower()] not in (None, "-"):
            return lowered[name.lower()]
    return default


def _load_json_records(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    if text.startswith("{") and "\n" not in text:
        return [json.loads(text)]
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def parse_windows_json(text: str) -> Iterator[Event]:
    """Parse Windows events exported as a JSON array or JSON Lines."""
    for rec in _load_json_records(text):
        data = dict(rec)
        if isinstance(data.get("EventData"), dict):  # flatten nested EventData
            data.update(data.pop("EventData"))
        event_id = int(_ci_get(data, "EventID", "Id", "EventId", default=0) or 0)
        ts = _parse_windows_ts(_ci_get(data, "TimeCreated", "TimeGenerated", "@timestamp"))
        user = _ci_get(data, "TargetUserName", "SubjectUserName", "UserName")
        if event_id in (4728, 4732, 4756):
            user = _ci_get(data, "SubjectUserName", default=user)
        ip = _ci_get(data, "IpAddress", "SourceAddress", "ClientAddress")
        fields = {k: v for k, v in data.items()}
        fields["event_id"] = event_id
        fields["target_user"] = _ci_get(data, "TargetUserName", "MemberName")
        fields["group"] = _ci_get(data, "TargetUserName") if event_id in (4728, 4732, 4756) else ""
        if event_id in (4728, 4732, 4756):
            fields["target_user"] = _ci_get(data, "MemberName", "MemberSid")
        if "LogonType" in data or "logontype" in {k.lower() for k in data}:
            try:
                fields["logon_type"] = int(_ci_get(data, "LogonType", default=0))
            except (TypeError, ValueError):
                pass
        message = _ci_get(data, "Message", default="") or \
            f"EventID {event_id} {WINDOWS_EVENT_TYPES.get(event_id, 'event')}"
        yield Event(
            timestamp=ts, source="windows",
            event_type=WINDOWS_EVENT_TYPES.get(event_id, f"win_event_{event_id}"),
            host=str(_ci_get(data, "Computer", "MachineName", "Hostname")),
            user=str(user or ""), src_ip=str(ip or ""), message=str(message),
            raw=json.dumps(rec, default=str), fields=fields,
        )


# --------------------------------------------------------------------------- #
# Web access log (combined format)
# --------------------------------------------------------------------------- #
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>HTTP/[\d.]+))?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_web_access(lines: Iterable[str]) -> Iterator[Event]:
    for line in lines:
        line = line.rstrip("\n")
        m = _COMBINED.match(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
        except ValueError:
            continue
        path = m.group("path")
        yield Event(
            timestamp=ts, source="web", event_type="web_request",
            user="" if m.group("user") == "-" else m.group("user"),
            src_ip=m.group("ip"), message=f'{m.group("method")} {path}', raw=line,
            fields={
                "method": m.group("method"),
                "path": path,
                "path_decoded": unquote_plus(path),
                "status": int(m.group("status")),
                "bytes": 0 if m.group("size") == "-" else int(m.group("size")),
                "referrer": m.group("referrer") or "",
                "user_agent": m.group("ua") or "",
            },
        )


# --------------------------------------------------------------------------- #
# Dispatch helpers
# --------------------------------------------------------------------------- #
def detect_format(path: Path, sample: str) -> str:
    """Guess the log format from file name and the first non-empty line."""
    first = next((l for l in sample.splitlines() if l.strip()), "")
    if path.suffix.lower() in (".json", ".jsonl", ".ndjson") or first.lstrip().startswith(("[", "{")):
        return "windows"
    if _COMBINED.match(first):
        return "web"
    return "linux_auth"


def parse_file(path: str | Path, fmt: str = "auto", year: int | None = None) -> list[Event]:
    path = Path(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    if fmt == "auto":
        fmt = detect_format(path, text[:4096])
    if fmt == "windows":
        return list(parse_windows_json(text))
    if fmt == "web":
        return list(parse_web_access(text.splitlines()))
    if fmt == "linux_auth":
        return list(parse_linux_auth(text.splitlines(), year=year))
    raise ValueError(f"Unknown log format: {fmt}")
