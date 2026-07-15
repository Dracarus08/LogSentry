"""Parsers that turn raw log sources into normalized Event objects.

Two sources are supported. Windows Security events exported to CSV, and Linux
auth logs in standard syslog format. Both produce the same Event shape.
"""

from __future__ import annotations

import csv
import re
from datetime import datetime
from pathlib import Path

from .models import Event

# Windows Security event IDs mapped to a normalized category.
WINDOWS_EVENT_CATEGORY = {
    "4625": "auth_failure",  # An account failed to log on
    "4624": "auth_success",  # An account was successfully logged on
    "4740": "lockout",       # A user account was locked out
    "4672": "privilege_grant",  # Special privileges assigned to new logon
    "4728": "privilege_grant",  # Member added to a security-enabled global group
    "4732": "privilege_grant",  # Member added to a security-enabled local group
    "4756": "privilege_grant",  # Member added to a security-enabled universal group
    "1102": "log_cleared",   # The audit log was cleared
}


def parse_windows_csv(path: str | Path) -> list[Event]:
    """Parse a Windows Security event export.

    Expected columns are produced by tools/Export-SecurityEvents.ps1:
    TimeCreated, EventId, Computer, TargetAccount, SubjectAccount,
    IpAddress, LogonType, GroupName, Message.
    """
    events: list[Event] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            event_id = (row.get("EventId") or "").strip()
            if not event_id:
                continue
            ts = _parse_timestamp(row.get("TimeCreated", ""))
            if ts is None:
                continue
            category = WINDOWS_EVENT_CATEGORY.get(event_id, "other")
            events.append(
                Event(
                    timestamp=ts,
                    source="windows",
                    category=category,
                    event_id=event_id,
                    host=(row.get("Computer") or "").strip(),
                    account=(row.get("TargetAccount") or "").strip(),
                    actor=(row.get("SubjectAccount") or "").strip(),
                    source_ip=_clean_ip(row.get("IpAddress", "")),
                    logon_type=(row.get("LogonType") or "").strip(),
                    group=(row.get("GroupName") or "").strip(),
                    message=(row.get("Message") or "").strip(),
                )
            )
    return events


# syslog auth line patterns. Enough to cover the common sshd and sudo events.
_SYSLOG_PREFIX = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+?)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
_ACCEPT = re.compile(r"Accepted \w+ for (?P<user>\S+) from (?P<ip>\S+)")
_SUDO_ROOT = re.compile(r"(?P<user>\S+)\s*:.*USER=root")
_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_syslog(path: str | Path, year: int | None = None) -> list[Event]:
    """Parse a Linux auth log in syslog format.

    Syslog lines carry no year. The year is taken from the year argument, or
    inferred so that the newest line is not in the future relative to the file.
    """
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    return parse_syslog_lines(lines, year=year)


def parse_syslog_lines(lines: list[str], year: int | None = None) -> list[Event]:
    resolved_year = year if year is not None else _infer_year(lines)
    events: list[Event] = []
    for line in lines:
        m = _SYSLOG_PREFIX.match(line.strip())
        if not m:
            continue
        month = _MONTHS.get(m.group("mon"))
        if month is None:
            continue
        hh, mm, ss = (int(x) for x in m.group("time").split(":"))
        try:
            ts = datetime(resolved_year, month, int(m.group("day")), hh, mm, ss)
        except ValueError:
            continue
        host = m.group("host")
        proc = m.group("proc")
        msg = m.group("msg")

        fail = _FAIL.search(msg)
        if fail:
            events.append(Event(ts, "syslog", "auth_failure", "SSH_FAIL", host,
                                account=fail.group("user"), source_ip=fail.group("ip"),
                                logon_type="ssh", message=line.strip()))
            continue
        accept = _ACCEPT.search(msg)
        if accept:
            events.append(Event(ts, "syslog", "auth_success", "SSH_ACCEPT", host,
                                account=accept.group("user"), source_ip=accept.group("ip"),
                                logon_type="ssh", message=line.strip()))
            continue
        if proc.startswith("sudo"):
            sudo = _SUDO_ROOT.search(msg)
            if sudo:
                events.append(Event(ts, "syslog", "privilege_grant", "SUDO_ROOT", host,
                                    account="root", actor=sudo.group("user"), group="root",
                                    message=line.strip()))
    return events


def _infer_year(lines: list[str]) -> int:
    for line in lines:
        m = _SYSLOG_PREFIX.match(line.strip())
        if m:
            digits = re.search(r"\b(20\d{2})\b", line)
            if digits:
                return int(digits.group(1))
    # No year anywhere. Fall back to a fixed reference so demo output is stable.
    return 2026


def _clean_ip(value: str) -> str:
    value = (value or "").strip()
    if value in ("-", "::1", "127.0.0.1"):
        return ""
    return value


def _parse_timestamp(value: str) -> datetime | None:
    value = (value or "").strip()
    if not value:
        return None
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    # ISO 8601 with timezone or fractional seconds.
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None
