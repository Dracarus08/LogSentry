"""The detection rules.

Every rule has the signature rule(events, config) -> list[Finding]. Keeping the
signature uniform lets the engine treat rules as a list and lets each rule be
tested against a small handmade event set.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..models import Event, Finding

# Windows privileged groups that make a membership-add worth flagging.
PRIVILEGED_GROUPS = {
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "account operators",
    "backup operators",
    "server operators",
    "print operators",
}

DEFAULT_CONFIG = {
    "brute_force_threshold": 5,
    "brute_force_window_minutes": 10,
    "business_start_hour": 7,
    "business_end_hour": 19,
}


def _cfg(config: dict | None, key: str):
    if config and key in config:
        return config[key]
    return DEFAULT_CONFIG[key]


def _window_key(ip: str, account: str) -> str:
    return ip or f"account:{account}"


def detect_brute_force(events: list[Event], config: dict | None = None) -> list[Finding]:
    """Repeated failed authentication from one source in a short window."""
    threshold = _cfg(config, "brute_force_threshold")
    window = timedelta(minutes=_cfg(config, "brute_force_window_minutes"))

    failures: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.category == "auth_failure":
            failures[_window_key(e.source_ip, e.account)].append(e)

    findings: list[Finding] = []
    for key, evs in failures.items():
        evs.sort(key=lambda x: x.timestamp)
        # Slide a window across the sorted failures and take the densest burst.
        best_start = 0
        best_count = 0
        start = 0
        for end in range(len(evs)):
            while evs[end].timestamp - evs[start].timestamp > window:
                start += 1
            if end - start + 1 > best_count:
                best_count = end - start + 1
                best_start = start
        if best_count >= threshold:
            burst = evs[best_start:best_start + best_count]
            accounts = sorted({e.account for e in burst if e.account})
            entity = burst[0].source_ip or key.replace("account:", "")
            spray = len(accounts) >= 3
            title = (
                f"Password spray from {entity}" if spray
                else f"Brute force against {accounts[0] if accounts else entity}"
            )
            detail = (
                f"{best_count} failed logons from {entity} in "
                f"{_cfg(config, 'brute_force_window_minutes')} minutes across "
                f"{len(accounts)} account(s)."
            )
            findings.append(Finding(
                detection_id="BRUTE-FORCE",
                title=title,
                severity="High",
                attack=["T1110"],
                detail=detail,
                when=burst[0].timestamp,
                entity=entity,
                count=best_count,
                evidence=[_ev(e) for e in burst[:5]],
            ))
    return findings


def detect_spray_success(events: list[Event], config: dict | None = None) -> list[Finding]:
    """A successful logon right after a burst of failures from the same source."""
    window = timedelta(minutes=_cfg(config, "brute_force_window_minutes"))
    threshold = _cfg(config, "brute_force_threshold")

    by_source: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.category in ("auth_failure", "auth_success") and e.source_ip:
            by_source[e.source_ip].append(e)

    findings: list[Finding] = []
    for ip, evs in by_source.items():
        evs.sort(key=lambda x: x.timestamp)
        for i, e in enumerate(evs):
            if e.category != "auth_success":
                continue
            recent_fails = [
                f for f in evs[:i]
                if f.category == "auth_failure" and e.timestamp - f.timestamp <= window
            ]
            if len(recent_fails) >= threshold:
                findings.append(Finding(
                    detection_id="SPRAY-SUCCESS",
                    title=f"Successful logon after failures from {ip}",
                    severity="High",
                    attack=["T1110", "T1078"],
                    detail=(
                        f"Account {e.account} logged on from {ip} after "
                        f"{len(recent_fails)} failed attempts in the prior "
                        f"{_cfg(config, 'brute_force_window_minutes')} minutes."
                    ),
                    when=e.timestamp,
                    entity=e.account or ip,
                    count=len(recent_fails),
                    evidence=[_ev(f) for f in recent_fails[-3:]] + [_ev(e)],
                ))
                break
    return findings


def detect_lockouts(events: list[Event], config: dict | None = None) -> list[Finding]:
    """Account lockout events."""
    findings: list[Finding] = []
    for e in events:
        if e.category == "lockout":
            findings.append(Finding(
                detection_id="LOCKOUT",
                title=f"Account locked out: {e.account}",
                severity="Medium",
                attack=["T1110"],
                detail=f"Account {e.account} was locked out on {e.host or 'host'}.",
                when=e.timestamp,
                entity=e.account,
                count=1,
                evidence=[_ev(e)],
            ))
    return findings


def detect_privilege_grants(events: list[Event], config: dict | None = None) -> list[Finding]:
    """Additions to privileged groups, special privileges, and sudo to root."""
    findings: list[Finding] = []
    for e in events:
        if e.category != "privilege_grant":
            continue
        if e.event_id in ("4728", "4732", "4756"):
            if e.group and e.group.lower() not in PRIVILEGED_GROUPS:
                continue
            findings.append(Finding(
                detection_id="PRIV-GRANT",
                title=f"{e.account} added to {e.group}",
                severity="High",
                attack=["T1098", "T1078"],
                detail=f"{e.actor or 'someone'} added {e.account} to {e.group}.",
                when=e.timestamp,
                entity=e.account,
                count=1,
                evidence=[_ev(e)],
            ))
        elif e.event_id == "SUDO_ROOT":
            findings.append(Finding(
                detection_id="PRIV-GRANT",
                title=f"sudo to root by {e.actor}",
                severity="Medium",
                attack=["T1078"],
                detail=f"{e.actor} ran a command as root on {e.host or 'host'}.",
                when=e.timestamp,
                entity=e.actor,
                count=1,
                evidence=[_ev(e)],
            ))
        elif e.event_id == "4672":
            findings.append(Finding(
                detection_id="PRIV-GRANT",
                title=f"Special privileges assigned to {e.account}",
                severity="Medium",
                attack=["T1078"],
                detail=f"Sensitive privileges were assigned to {e.account} at logon.",
                when=e.timestamp,
                entity=e.account,
                count=1,
                evidence=[_ev(e)],
            ))
    return findings


def detect_log_cleared(events: list[Event], config: dict | None = None) -> list[Finding]:
    """The security audit log was cleared."""
    findings: list[Finding] = []
    for e in events:
        if e.category == "log_cleared":
            findings.append(Finding(
                detection_id="LOG-CLEARED",
                title=f"Security log cleared on {e.host or 'host'}",
                severity="High",
                attack=["T1070.001"],
                detail=(
                    f"The Windows Security audit log was cleared"
                    f"{' by ' + e.actor if e.actor else ''}. This is a common step "
                    "taken to hide activity."
                ),
                when=e.timestamp,
                entity=e.host,
                count=1,
                evidence=[_ev(e)],
            ))
    return findings


def detect_off_hours_admin(events: list[Event], config: dict | None = None) -> list[Finding]:
    """Successful privileged logon outside business hours."""
    start = _cfg(config, "business_start_hour")
    end = _cfg(config, "business_end_hour")
    findings: list[Finding] = []
    for e in events:
        if e.category != "auth_success":
            continue
        account = (e.account or "").lower()
        is_admin = account.startswith("admin") or account.endswith("-adm") or "admin." in account
        if not is_admin:
            continue
        hour = e.timestamp.hour
        if hour < start or hour >= end:
            findings.append(Finding(
                detection_id="OFF-HOURS-ADMIN",
                title=f"Off-hours admin logon: {e.account}",
                severity="Medium",
                attack=["T1078"],
                detail=(
                    f"Privileged account {e.account} logged on at "
                    f"{e.timestamp.strftime('%H:%M')} from "
                    f"{e.source_ip or 'unknown source'}, outside business hours."
                ),
                when=e.timestamp,
                entity=e.account,
                count=1,
                evidence=[_ev(e)],
            ))
    return findings


def _ev(e: Event) -> str:
    when = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    parts = [when, e.event_id]
    if e.account:
        parts.append(f"account={e.account}")
    if e.source_ip:
        parts.append(f"ip={e.source_ip}")
    if e.host:
        parts.append(f"host={e.host}")
    return " ".join(parts)


ALL_DETECTIONS = [
    detect_brute_force,
    detect_spray_success,
    detect_lockouts,
    detect_privilege_grants,
    detect_log_cleared,
    detect_off_hours_admin,
]
