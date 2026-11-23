"""Output formatters: console summary, JSON and a self-contained HTML report."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone

from .models import Alert, Event

SEV_COLORS = {"critical": "#b3261e", "high": "#e8590c", "medium": "#d4a017",
              "low": "#2f7ed8", "informational": "#6c757d"}
_ANSI = {"critical": "\033[1;41m", "high": "\033[1;31m", "medium": "\033[1;33m",
         "low": "\033[1;34m", "informational": "\033[0;37m"}
_RESET = "\033[0m"


def mitre_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def _fmt_group(group: dict) -> str:
    parts = []
    for k, v in group.items():
        if isinstance(v, list):
            v = ", ".join(map(str, v[:6])) + (" ..." if len(v) > 6 else "")
        parts.append(f"{k}={v}")
    return " ".join(parts)


def console_report(alerts: list[Alert], events: list[Event], color: bool = True) -> str:
    lines = []
    lines.append(f"LogSentinel - analysed {len(events)} events, raised {len(alerts)} alerts")
    sev = Counter(a.severity for a in alerts)
    if alerts:
        lines.append("Severity: " + ", ".join(
            f"{s}={sev[s]}" for s in ("critical", "high", "medium", "low", "informational") if sev[s]))
    lines.append("-" * 78)
    for a in alerts:
        tag = f"[{a.severity.upper():<8}]"
        if color:
            tag = f"{_ANSI.get(a.severity, '')}{tag}{_RESET}"
        lines.append(f"{tag} {a.rule_id} {a.title}  ({', '.join(a.mitre)})")
        lines.append(f"           {a.first_seen:%Y-%m-%d %H:%M:%S} -> {a.last_seen:%H:%M:%S} UTC"
                     f" | events={a.count} | {_fmt_group(a.group)}")
    return "\n".join(lines)


def json_report(alerts: list[Alert], events: list[Event]) -> str:
    return json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "events_analysed": len(events),
        "alert_count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }, indent=2, default=str)


def html_report(alerts: list[Alert], events: list[Event], title: str = "LogSentinel Report") -> str:
    esc = html.escape
    sev = Counter(a.severity for a in alerts)
    techniques = Counter(t for a in alerts for t in a.mitre)
    sources = Counter(e.source for e in events)
    span = ""
    if events:
        ts = sorted(e.timestamp for e in events)
        span = f"{ts[0]:%Y-%m-%d %H:%M} &rarr; {ts[-1]:%Y-%m-%d %H:%M} UTC"

    cards = "".join(
        f'<div class="card" style="border-top:4px solid {SEV_COLORS[s]}">'
        f'<div class="num">{sev[s]}</div><div>{s.title()}</div></div>'
        for s in ("critical", "high", "medium", "low") )

    rows = []
    for i, a in enumerate(alerts):
        mitre = " ".join(f'<a href="{mitre_url(t)}" target="_blank" rel="noopener">{esc(t)}</a>'
                         for t in a.mitre)
        evidence = "\n".join(esc(e.raw or e.message) for e in a.evidence)
        rows.append(
            f'<tr><td><span class="sev" style="background:{SEV_COLORS[a.severity]}">'
            f'{esc(a.severity)}</span></td><td>{esc(a.rule_id)}</td>'
            f'<td><b>{esc(a.title)}</b><div class="muted">{esc(a.description)}</div>'
            f'<details><summary>Evidence ({len(a.evidence)} of {a.count})</summary>'
            f'<pre>{evidence}</pre></details></td>'
            f'<td>{mitre}</td><td>{a.first_seen:%Y-%m-%d %H:%M:%S}</td><td>{a.count}</td>'
            f'<td class="mono">{esc(_fmt_group(a.group))}</td></tr>')

    tech_rows = "".join(
        f'<li><a href="{mitre_url(t)}" target="_blank" rel="noopener">{esc(t)}</a> &times; {n}</li>'
        for t, n in techniques.most_common())
    src_rows = "".join(f"<li>{esc(s)}: {n} events</li>" for s, n in sources.most_common())

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title>
<style>
 body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f5f6f8;color:#1d2330}}
 header{{background:#111827;color:#fff;padding:24px 32px}} header h1{{margin:0 0 4px;font-size:22px}}
 main{{padding:24px 32px;max-width:1400px}} .muted{{color:#6b7280;font-size:13px}}
 .cards{{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}}
 .card{{background:#fff;border-radius:8px;padding:16px 24px;min-width:120px;box-shadow:0 1px 3px #0001}}
 .num{{font-size:28px;font-weight:700}}
 .grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}}
 .panel{{background:#fff;border-radius:8px;padding:16px 24px;box-shadow:0 1px 3px #0001}}
 table{{width:100%;border-collapse:collapse;background:#fff;box-shadow:0 1px 3px #0001;border-radius:8px;overflow:hidden}}
 th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #e5e7eb;vertical-align:top;font-size:14px}}
 th{{background:#f9fafb;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#4b5563}}
 .sev{{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;text-transform:uppercase;font-weight:600}}
 pre{{background:#0f172a;color:#e2e8f0;padding:10px;border-radius:6px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}}
 .mono{{font-family:ui-monospace,Consolas,monospace;font-size:12px}} a{{color:#2563eb}}
</style></head><body>
<header><h1>{esc(title)}</h1>
<div>{len(events)} events analysed &middot; {len(alerts)} alerts &middot; {span}</div></header>
<main>
<div class="cards">{cards}</div>
<div class="grid">
 <div class="panel"><h3>MITRE ATT&amp;CK techniques observed</h3><ul>{tech_rows or '<li>None</li>'}</ul></div>
 <div class="panel"><h3>Log sources</h3><ul>{src_rows or '<li>None</li>'}</ul></div>
</div>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Detection</th><th>ATT&amp;CK</th>
<th>First seen (UTC)</th><th>Events</th><th>Entity</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="7">No alerts - nothing suspicious found.</td></tr>'}</tbody></table>
<p class="muted">Generated by LogSentinel on {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC</p>
</main></body></html>"""
