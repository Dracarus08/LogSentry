"""Generates the synthetic demo corpus for LogSentry.

Every line this writes is fake. The corpus seeds a realistic mix of routine
activity and deliberate incidents so a reviewer sees each detection fire. Dates
are fixed so the digest output is stable no matter when the demo runs.
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = datetime(2026, 7, 14, 8, 0, 0)
RNG = random.Random(20260714)

USERS = ["jsmith", "mjones", "kdavis", "rlopez", "twilson", "achen", "bpatel", "sgarcia"]
WORKSTATIONS = ["WS-FIN01", "WS-HR02", "WS-ENG05", "SRV-APP01"]
INTERNAL_IPS = ["10.0.4.21", "10.0.4.55", "10.0.7.13", "10.0.2.9"]


def fmt(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def build_windows_rows() -> list[dict]:
    rows: list[dict] = []

    def add(ts, event_id, target="", subject="", ip="", logon_type="", group="", msg=""):
        rows.append({
            "TimeCreated": fmt(ts),
            "EventId": event_id,
            "Computer": RNG.choice(WORKSTATIONS),
            "TargetAccount": target,
            "SubjectAccount": subject,
            "IpAddress": ip,
            "LogonType": logon_type,
            "GroupName": group,
            "Message": msg,
        })

    # Routine successful logons through the morning.
    for _ in range(40):
        ts = BASE + timedelta(minutes=RNG.randint(0, 240))
        user = RNG.choice(USERS)
        add(ts, "4624", target=user, ip=RNG.choice(INTERNAL_IPS), logon_type="2",
            msg=f"An account was successfully logged on: {user}")

    # A few scattered, benign failures (mistyped passwords).
    for _ in range(6):
        ts = BASE + timedelta(minutes=RNG.randint(0, 240))
        user = RNG.choice(USERS)
        add(ts, "4625", target=user, ip=RNG.choice(INTERNAL_IPS), logon_type="2",
            msg="An account failed to log on.")

    # Incident: brute force against one account from one external IP.
    bf_ip = "203.0.113.77"
    bf_start = BASE + timedelta(hours=1, minutes=5)
    for i in range(14):
        add(bf_start + timedelta(seconds=25 * i), "4625", target="administrator",
            ip=bf_ip, logon_type="3", msg="An account failed to log on.")

    # Incident: password spray across many accounts from one IP, then a success.
    spray_ip = "198.51.100.32"
    spray_start = BASE + timedelta(hours=2, minutes=30)
    for i, user in enumerate(USERS + ["administrator", "svc-sql"]):
        add(spray_start + timedelta(seconds=30 * i), "4625", target=user,
            ip=spray_ip, logon_type="3", msg="An account failed to log on.")
    add(spray_start + timedelta(minutes=6), "4624", target="bpatel", ip=spray_ip,
        logon_type="3", msg="An account was successfully logged on.")

    # Incident: account lockout.
    add(BASE + timedelta(hours=1, minutes=12), "4740", target="administrator",
        subject="SYSTEM", msg="A user account was locked out.")

    # Incident: user added to Administrators.
    add(BASE + timedelta(hours=3, minutes=15), "4732", target="tconsult",
        subject="admin.mjones", group="Administrators",
        msg="A member was added to a security-enabled local group.")

    # Incident: special privileges assigned.
    add(BASE + timedelta(hours=3, minutes=20), "4672", target="svc-backup",
        msg="Special privileges assigned to new logon.")

    # Incident: security log cleared.
    add(BASE + timedelta(hours=4, minutes=2), "1102", subject="admin.mjones",
        msg="The audit log was cleared.")

    # Incident: off-hours admin logon at 02:14.
    add(datetime(2026, 7, 14, 2, 14, 0), "4624", target="admin.jsmith",
        ip="203.0.113.90", logon_type="10",
        msg="An account was successfully logged on.")

    rows.sort(key=lambda r: r["TimeCreated"])
    return rows


def build_syslog_lines() -> list[str]:
    lines: list[str] = []

    def line(ts, host, proc, msg):
        lines.append(f"{ts.strftime('%b %e %H:%M:%S').replace('  ', ' ')} {host} {proc}: {msg}")

    host = "web01"
    # Routine accepted logons.
    for _ in range(10):
        ts = BASE + timedelta(minutes=RNG.randint(0, 240))
        user = RNG.choice(["deploy", "kaleb", "ops"])
        line(ts, host, "sshd[2201]", f"Accepted publickey for {user} from {RNG.choice(INTERNAL_IPS)} port 51000 ssh2")

    # Incident: ssh brute force from an external IP.
    ssh_ip = "203.0.113.140"
    bf = BASE + timedelta(hours=1, minutes=40)
    for i in range(11):
        line(bf + timedelta(seconds=20 * i), host, "sshd[3300]",
             f"Failed password for invalid user admin from {ssh_ip} port {40000 + i} ssh2")
    # Then a success from the same IP.
    line(bf + timedelta(minutes=5), host, "sshd[3300]",
         f"Accepted password for oracle from {ssh_ip} port 40999 ssh2")

    # Incident: sudo to root.
    line(BASE + timedelta(hours=3, minutes=45), host, "sudo",
         "deploy : TTY=pts/1 ; PWD=/opt/app ; USER=root ; COMMAND=/bin/bash")

    lines.sort()
    return lines


def main() -> None:
    rows = build_windows_rows()
    fieldnames = ["TimeCreated", "EventId", "Computer", "TargetAccount",
                  "SubjectAccount", "IpAddress", "LogonType", "GroupName", "Message"]
    with open(HERE / "demo_security.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    lines = build_syslog_lines()
    (HERE / "demo_auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Wrote {len(rows)} Windows events and {len(lines)} syslog lines.")


if __name__ == "__main__":
    main()
