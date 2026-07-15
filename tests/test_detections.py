from datetime import datetime, timedelta

from logsentry.detections.rules import (
    detect_brute_force,
    detect_lockouts,
    detect_log_cleared,
    detect_off_hours_admin,
    detect_privilege_grants,
    detect_spray_success,
)
from logsentry.models import Event

BASE = datetime(2026, 7, 14, 9, 0, 0)


def fail(i, ip="203.0.113.5", account="administrator"):
    return Event(BASE + timedelta(seconds=20 * i), "windows", "auth_failure", "4625",
                 host="WS1", account=account, source_ip=ip)


def test_brute_force_fires_above_threshold():
    events = [fail(i) for i in range(8)]
    findings = detect_brute_force(events)
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert findings[0].count == 8
    assert "T1110" in findings[0].attack


def test_brute_force_ignores_slow_failures():
    # Eight failures spread ten minutes apart never fill a ten minute window.
    events = [
        Event(BASE + timedelta(minutes=10 * i), "windows", "auth_failure", "4625",
              account="administrator", source_ip="203.0.113.5")
        for i in range(8)
    ]
    assert detect_brute_force(events) == []


def test_password_spray_is_labelled_by_account_spread():
    events = [fail(i, account=f"user{i}") for i in range(6)]
    findings = detect_brute_force(events)
    assert len(findings) == 1
    assert "spray" in findings[0].title.lower()


def test_spray_success_detects_login_after_failures():
    events = [fail(i) for i in range(6)]
    events.append(Event(BASE + timedelta(minutes=2), "windows", "auth_success", "4624",
                        account="bpatel", source_ip="203.0.113.5"))
    findings = detect_spray_success(events)
    assert len(findings) == 1
    assert findings[0].entity == "bpatel"


def test_spray_success_ignores_clean_login():
    events = [Event(BASE, "windows", "auth_success", "4624", account="jsmith",
                    source_ip="10.0.0.5")]
    assert detect_spray_success(events) == []


def test_lockout_detection():
    events = [Event(BASE, "windows", "lockout", "4740", host="WS1", account="administrator")]
    findings = detect_lockouts(events)
    assert len(findings) == 1
    assert findings[0].entity == "administrator"


def test_privilege_grant_only_for_privileged_group():
    priv = Event(BASE, "windows", "privilege_grant", "4732", account="tconsult",
                 actor="admin.mjones", group="Administrators")
    normal = Event(BASE, "windows", "privilege_grant", "4732", account="jdoe",
                   actor="admin.mjones", group="Marketing")
    findings = detect_privilege_grants([priv, normal])
    assert len(findings) == 1
    assert findings[0].entity == "tconsult"


def test_privilege_grant_sudo_root():
    sudo = Event(BASE, "syslog", "privilege_grant", "SUDO_ROOT", host="web01",
                 actor="deploy", account="root", group="root")
    findings = detect_privilege_grants([sudo])
    assert len(findings) == 1
    assert "sudo" in findings[0].title.lower()


def test_log_cleared_detection():
    events = [Event(BASE, "windows", "log_cleared", "1102", host="SRV1", actor="admin.mjones")]
    findings = detect_log_cleared(events)
    assert len(findings) == 1
    assert findings[0].severity == "High"
    assert "T1070.001" in findings[0].attack


def test_off_hours_admin_logon():
    night = Event(datetime(2026, 7, 14, 2, 14, 0), "windows", "auth_success", "4624",
                  account="admin.jsmith", source_ip="203.0.113.90")
    day = Event(datetime(2026, 7, 14, 10, 0, 0), "windows", "auth_success", "4624",
                account="admin.jsmith", source_ip="10.0.0.5")
    findings = detect_off_hours_admin([night, day])
    assert len(findings) == 1
    assert findings[0].when.hour == 2
