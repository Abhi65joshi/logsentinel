import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from logsentinel.engine import Engine  # noqa: E402
from logsentinel.models import Event  # noqa: E402
from logsentinel.parsers import (parse_file, parse_linux_auth,  # noqa: E402
                                 parse_web_access, parse_windows_json)
from logsentinel.rules import (RuleError, _validate, condition_matches,  # noqa: E402
                               default_rules_path, load_rules)

T0 = datetime(2026, 11, 20, 3, 0, tzinfo=timezone.utc)


def ev(seconds, etype="ssh_failed_login", ip="10.0.0.5", user="root", source="linux_auth", **fields):
    return Event(timestamp=T0 + timedelta(seconds=seconds), source=source, event_type=etype,
                 user=user, src_ip=ip, fields=fields)


def rule(**kw):
    base = {"id": "T-1", "title": "test", "severity": "high"}
    base.update(kw)
    return _validate(base, "test")


class ParserTests(unittest.TestCase):
    def test_ssh_failed_invalid_user(self):
        line = "Nov 20 03:15:00 web01 sshd[2211]: Failed password for invalid user admin from 192.168.56.101 port 42000 ssh2"
        (e,) = parse_linux_auth([line], year=2026)
        self.assertEqual(e.event_type, "ssh_failed_login")
        self.assertEqual(e.user, "admin")
        self.assertEqual(e.src_ip, "192.168.56.101")
        self.assertTrue(e.fields["invalid_user"])
        self.assertEqual(e.timestamp, datetime(2026, 11, 20, 3, 15, tzinfo=timezone.utc))

    def test_iso_syslog_and_accepted(self):
        line = "2026-11-20T03:15:00.123+00:00 web01 sshd[1]: Accepted publickey for abhi from 10.1.1.1 port 5 ssh2"
        (e,) = parse_linux_auth([line])
        self.assertEqual(e.event_type, "ssh_successful_login")
        self.assertEqual(e.user, "abhi")

    def test_sudo_and_usermod(self):
        lines = [
            "Nov 20 03:19:10 web01 sudo[9]:  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
            "Nov 20 03:19:55 web01 usermod[9]: add 'sysupdate' to group 'sudo'",
        ]
        sudo, mod = parse_linux_auth(lines, year=2026)
        self.assertEqual((sudo.event_type, sudo.user, sudo.fields["command"]),
                         ("sudo_command", "deploy", "/bin/bash"))
        self.assertEqual((mod.fields["target_user"], mod.fields["group"]), ("sysupdate", "sudo"))

    def test_garbage_lines_ignored(self):
        self.assertEqual(list(parse_linux_auth(["", "not a log line"])), [])

    def test_windows_powershell51_date_and_eventdata(self):
        rec = {"TimeCreated": "/Date(1763607000000)/", "Id": 4625, "MachineName": "PC1",
               "EventData": {"TargetUserName": "bob", "IpAddress": "10.0.0.9", "LogonType": "10"}}
        (e,) = parse_windows_json(json.dumps([rec]))
        self.assertEqual(e.event_type, "win_logon_failure")
        self.assertEqual((e.user, e.src_ip, e.host), ("bob", "10.0.0.9", "PC1"))
        self.assertEqual(e.fields["logon_type"], 10)

    def test_windows_jsonl_and_dotnet_precision(self):
        text = '{"TimeCreated": "2026-11-20T03:00:00.1234567Z", "EventID": 1102}\n' \
               '{"TimeCreated": "2026-11-20T03:00:01Z", "EventID": 4720, "TargetUserName": "x"}'
        a, b = parse_windows_json(text)
        self.assertEqual(a.event_type, "win_log_cleared")
        self.assertEqual(b.event_type, "win_user_created")

    def test_web_combined_and_decoding(self):
        line = ('10.0.0.7 - - [20/Nov/2026:03:07:00 +0000] "GET /p.php?id=3%27%20OR%20%271%27%3D%271 HTTP/1.1" '
                '200 1300 "-" "sqlmap/1.8"')
        (e,) = parse_web_access([line])
        self.assertEqual(e.fields["status"], 200)
        self.assertIn("' OR '1'='1", e.fields["path_decoded"])
        self.assertEqual(e.fields["user_agent"], "sqlmap/1.8")


class ConditionTests(unittest.TestCase):
    def test_operators(self):
        self.assertTrue(condition_matches("Root", "root"))
        self.assertTrue(condition_matches("sudo", ["wheel", "sudo"]))
        self.assertTrue(condition_matches("powershell -enc AAA", {"regex": r"-enc\s"}))
        self.assertTrue(condition_matches(404, {"gte": 400, "lt": 500}))
        self.assertFalse(condition_matches(200, {"gte": 400}))
        self.assertTrue(condition_matches("abc", {"not": "xyz"}))
        self.assertFalse(condition_matches(None, {"exists": True}))
        self.assertTrue(condition_matches("Hello World", {"contains": ["world"]}))

    def test_unknown_operator(self):
        with self.assertRaises(RuleError):
            condition_matches("x", {"bogus": 1})

    def test_validation(self):
        with self.assertRaises(RuleError):
            _validate({"id": "x", "title": "t", "severity": "huge", "match": {"a": 1}}, "t")
        with self.assertRaises(RuleError):
            _validate({"id": "x", "title": "t", "severity": "low", "type": "threshold",
                       "match": {"a": 1}, "threshold": {"count": 0}}, "t")


class EngineTests(unittest.TestCase):
    def test_threshold_fires_once_and_extends(self):
        r = rule(type="threshold", match={"event_type": "ssh_failed_login"},
                 threshold={"count": 5, "window_seconds": 60, "group_by": ["src_ip"]})
        events = [ev(i * 2) for i in range(12)]
        (alert,) = Engine([r]).run(events)
        self.assertEqual(alert.count, 12)

    def test_threshold_respects_window(self):
        r = rule(type="threshold", match={"event_type": "ssh_failed_login"},
                 threshold={"count": 5, "window_seconds": 60, "group_by": ["src_ip"]})
        events = [ev(i * 30) for i in range(10)]  # only 3 inside any 60s window
        self.assertEqual(Engine([r]).run(events), [])

    def test_threshold_groups_separately(self):
        r = rule(type="threshold", match={"event_type": "ssh_failed_login"},
                 threshold={"count": 3, "window_seconds": 60, "group_by": ["src_ip"]})
        events = [ev(i, ip="1.1.1.1") for i in range(2)] + [ev(i, ip="2.2.2.2") for i in range(3)]
        alerts = Engine([r]).run(events)
        self.assertEqual([a.group["src_ip"] for a in alerts], ["2.2.2.2"])

    def test_distinct_password_spray(self):
        r = rule(type="threshold", match={"event_type": "ssh_failed_login"},
                 threshold={"count": 3, "window_seconds": 60, "group_by": ["src_ip"], "distinct": "user"})
        same_user = [ev(i, user="root") for i in range(10)]
        self.assertEqual(Engine([r]).run(same_user), [])
        spray = [ev(i, user=u) for i, u in enumerate(["a", "b", "c"])]
        (alert,) = Engine([r]).run(spray)
        self.assertEqual(alert.group["distinct_user"], ["a", "b", "c"])

    def test_sequence_success_after_failures(self):
        r = rule(type="sequence", sequence={
            "first": {"match": {"event_type": "ssh_failed_login"}, "count": 3},
            "then": {"match": {"event_type": "ssh_successful_login"}},
            "window_seconds": 120, "group_by": ["src_ip"]})
        events = [ev(i) for i in range(3)] + [ev(10, etype="ssh_successful_login", user="deploy")]
        (alert,) = Engine([r]).run(events)
        self.assertEqual(alert.group["compromised_user"], "deploy")
        # success without enough prior failures -> no alert
        self.assertEqual(Engine([r]).run([ev(0), ev(5, etype="ssh_successful_login")]), [])

    def test_source_filter(self):
        r = rule(type="match", source="windows", match={"event_type": "ssh_failed_login"})
        self.assertEqual(Engine([r]).run([ev(0)]), [])


class EndToEndTests(unittest.TestCase):
    def test_bundled_rules_load(self):
        rules = load_rules(default_rules_path())
        self.assertGreaterEqual(len(rules), 20)

    def test_samples_detect_full_attack_chain(self):
        events = []
        for f in sorted((ROOT / "samples").iterdir()):
            events.extend(parse_file(f, year=2026))
        ids = {a.rule_id for a in Engine(load_rules(default_rules_path())).run(events)}
        for expected in ("LS-001", "LS-002", "LS-003", "LS-004", "LS-006", "LS-009",
                         "LS-011", "LS-012", "LS-013", "LS-014", "LS-016", "LS-017", "LS-020"):
            self.assertIn(expected, ids)

    def test_benign_activity_not_flagged(self):
        events = []
        for f in sorted((ROOT / "samples").iterdir()):
            events.extend(parse_file(f, year=2026))
        alerts = Engine(load_rules(default_rules_path())).run(events)
        flagged_ips = {a.group.get("src_ip") for a in alerts if a.group.get("src_ip")}
        self.assertNotIn("192.168.56.20", flagged_ips)
        self.assertNotIn("192.168.56.21", flagged_ips)
        self.assertFalse(any(a.rule_id == "LS-004" and a.group.get("user") == "abhi" for a in alerts))

    def test_cli_outputs_and_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_json, out_html = Path(tmp, "a.json"), Path(tmp, "r.html")
            proc = subprocess.run(
                [sys.executable, "-m", "logsentinel", str(ROOT / "samples"), "--year", "2026",
                 "--json", str(out_json), "--html", str(out_html), "--fail-on", "critical"],
                cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            data = json.loads(out_json.read_text())
            self.assertGreater(data["alert_count"], 0)
            self.assertIn("<!DOCTYPE html>", out_html.read_text())

    def test_html_escapes_untrusted_log_content(self):
        from logsentinel.report import html_report
        r = rule(type="match", source="web", match={"event_type": "web_request"})
        e = Event(timestamp=T0, source="web", event_type="web_request", src_ip="1.2.3.4",
                  raw='GET /?q=<script>alert(1)</script>')
        page = html_report(Engine([r]).run([e]), [e])
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
