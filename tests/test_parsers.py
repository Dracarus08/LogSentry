from datetime import datetime

from logsentry.parsers import parse_syslog_lines, parse_windows_csv


def test_windows_csv_parses_and_categorizes(tmp_path):
    csv_text = (
        "TimeCreated,EventId,Computer,TargetAccount,SubjectAccount,IpAddress,LogonType,GroupName,Message\n"
        "2026-07-14 09:05:00,4625,WS1,administrator,,203.0.113.5,3,,failed\n"
        "2026-07-14 09:06:00,4624,WS1,jsmith,,10.0.0.5,2,,ok\n"
        "2026-07-14 09:07:00,4740,WS1,administrator,SYSTEM,,,,lockout\n"
        "2026-07-14 09:08:00,1102,WS1,,admin.mjones,,,,cleared\n"
    )
    path = tmp_path / "win.csv"
    path.write_text(csv_text, encoding="utf-8")

    events = parse_windows_csv(path)
    assert len(events) == 4
    assert events[0].category == "auth_failure"
    assert events[0].source_ip == "203.0.113.5"
    assert events[1].category == "auth_success"
    assert events[2].category == "lockout"
    assert events[3].category == "log_cleared"
    assert all(e.source == "windows" for e in events)


def test_windows_csv_skips_blank_and_bad_rows(tmp_path):
    csv_text = (
        "TimeCreated,EventId,Computer,TargetAccount,SubjectAccount,IpAddress,LogonType,GroupName,Message\n"
        "2026-07-14 09:05:00,,WS1,x,,,,,\n"          # no event id
        "not-a-date,4625,WS1,x,,,,,\n"                # bad timestamp
        "2026-07-14 09:06:00,4624,WS1,jsmith,,,,,ok\n"
    )
    path = tmp_path / "win.csv"
    path.write_text(csv_text, encoding="utf-8")
    events = parse_windows_csv(path)
    assert len(events) == 1


def test_syslog_parses_failures_accepts_and_sudo():
    lines = [
        "Jul 14 09:40:00 web01 sshd[3300]: Failed password for invalid user admin from 203.0.113.140 port 40000 ssh2",
        "Jul 14 09:45:00 web01 sshd[3300]: Accepted password for oracle from 203.0.113.140 port 40999 ssh2",
        "Jul 14 11:45:00 web01 sudo: deploy : TTY=pts/1 ; PWD=/opt ; USER=root ; COMMAND=/bin/bash",
        "Jul 14 09:41:00 web01 CRON[1]: pam_unix(cron:session): session opened",  # ignored
    ]
    events = parse_syslog_lines(lines, year=2026)
    cats = [e.category for e in events]
    assert "auth_failure" in cats
    assert "auth_success" in cats
    assert "privilege_grant" in cats
    assert len(events) == 3
    fail = next(e for e in events if e.category == "auth_failure")
    assert fail.account == "admin"
    assert fail.source_ip == "203.0.113.140"
    assert fail.timestamp == datetime(2026, 7, 14, 9, 40, 0)
    sudo = next(e for e in events if e.category == "privilege_grant")
    assert sudo.actor == "deploy"
    assert sudo.account == "root"
