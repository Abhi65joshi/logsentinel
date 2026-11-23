"""The detection engine: runs rules over a time-ordered stream of events."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable

from .models import Alert, Event, SEVERITY_ORDER
from .rules import Rule, event_matches

MAX_EVIDENCE = 10


def _group_key(event: Event, fields: list[str]) -> tuple:
    return tuple(event.get(f) or "" for f in fields)


def _new_alert(rule: Rule, events: list[Event], group: dict, count: int | None = None) -> Alert:
    return Alert(
        rule_id=rule.id, title=rule.title, severity=rule.severity, mitre=rule.mitre,
        description=rule.description, first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp, count=count if count is not None else len(events),
        group=group, evidence=list(events[:MAX_EVIDENCE]),
    )


class Engine:
    """Evaluate detection rules against events.

    * ``match`` rules fire once per matching event.
    * ``threshold`` rules fire when ``count`` matching events (or ``count``
      distinct values of a field) are seen for the same group inside a sliding
      window. While the activity continues the existing alert is extended
      instead of creating duplicates.
    * ``sequence`` rules fire when ``first`` happens ``count`` times and is
      followed by ``then`` for the same group inside the window.
    """

    def __init__(self, rules: Iterable[Rule]):
        self.rules = list(rules)

    def run(self, events: Iterable[Event]) -> list[Alert]:
        ordered = sorted(events, key=lambda e: e.timestamp)
        alerts: list[Alert] = []
        for rule in self.rules:
            candidates = [e for e in ordered if rule.applies_to(e)]
            if rule.type == "match":
                alerts.extend(self._run_match(rule, candidates))
            elif rule.type == "threshold":
                alerts.extend(self._run_threshold(rule, candidates))
            elif rule.type == "sequence":
                alerts.extend(self._run_sequence(rule, candidates))
        alerts.sort(key=lambda a: (-SEVERITY_ORDER[a.severity], a.first_seen))
        return alerts

    # ------------------------------------------------------------------ #
    @staticmethod
    def _run_match(rule: Rule, events: list[Event]) -> list[Alert]:
        out = []
        for e in events:
            if event_matches(e, rule.match):
                group = {k: v for k, v in (("host", e.host), ("user", e.user),
                                           ("src_ip", e.src_ip),
                                           ("target_user", e.get("target_user")),
                                           ("group", e.get("group"))) if v}
                out.append(_new_alert(rule, [e], group))
        return out

    @staticmethod
    def _run_threshold(rule: Rule, events: list[Event]) -> list[Alert]:
        th = rule.threshold
        need = int(th["count"])
        window = timedelta(seconds=int(th["window_seconds"]))
        group_by = list(th.get("group_by", []))
        distinct = th.get("distinct")

        buffers: dict[tuple, deque[Event]] = defaultdict(deque)
        active: dict[tuple, Alert] = {}
        out: list[Alert] = []

        for e in events:
            if not event_matches(e, rule.match):
                continue
            key = _group_key(e, group_by)
            current = active.get(key)
            if current and e.timestamp - current.last_seen <= window:
                current.count += 1
                current.last_seen = e.timestamp
                if len(current.evidence) < MAX_EVIDENCE:
                    current.evidence.append(e)
                continue
            active.pop(key, None)

            buf = buffers[key]
            buf.append(e)
            while buf and e.timestamp - buf[0].timestamp > window:
                buf.popleft()
            metric = len({ev.get(distinct) for ev in buf}) if distinct else len(buf)
            if metric >= need:
                group = dict(zip(group_by, key))
                if distinct:
                    group[f"distinct_{distinct}"] = sorted(
                        {str(ev.get(distinct)) for ev in buf})[:25]
                alert = _new_alert(rule, list(buf), group)
                out.append(alert)
                active[key] = alert
                buf.clear()
        return out

    @staticmethod
    def _run_sequence(rule: Rule, events: list[Event]) -> list[Alert]:
        seq = rule.sequence
        first, then = seq["first"], seq["then"]
        need = int(first.get("count", 1))
        window = timedelta(seconds=int(seq.get("window_seconds", 600)))
        group_by = list(seq.get("group_by", []))
        buffers: dict[tuple, deque[Event]] = defaultdict(deque)
        out: list[Alert] = []

        for e in events:
            key = _group_key(e, group_by)
            buf = buffers[key]
            while buf and e.timestamp - buf[0].timestamp > window:
                buf.popleft()
            if event_matches(e, first["match"]):
                buf.append(e)
            elif event_matches(e, then["match"]) and len(buf) >= need:
                evidence = list(buf)[-(MAX_EVIDENCE - 1):] + [e]
                group = dict(zip(group_by, key))
                if e.user:
                    group["compromised_user"] = e.user
                alert = _new_alert(rule, evidence, group, count=len(buf) + 1)
                alert.first_seen = buf[0].timestamp
                out.append(alert)
                buf.clear()
        return out
