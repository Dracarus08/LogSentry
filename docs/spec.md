# LogSentry. Design Spec

## Problem

Security-relevant events are already in the logs. Failed logons, account lockouts, and privilege grants all get written the moment they happen. The problem is that nobody reads them. They sit in the Windows Security log and in syslog until an incident forces someone to go looking. By then the early signal is buried under thousands of routine lines.

LogSentry reads those logs and turns them into a short daily digest. It surfaces the handful of events that matter and correlates them into incidents. A defender reads one page instead of ten thousand lines.

## Who cares

- Sysadmins who own Windows and Linux hosts and want a morning summary instead of a raw log.
- Security engineers who need detection logic they can read, test, and extend.
- Hiring managers reading this repo. It shows I can turn operational logs into detections and explain why each one matters.

## What it does

LogSentry ingests two log sources, normalizes them into one event shape, runs a set of detections, and writes a digest as text and HTML.

Inputs:

- **Windows Security events** exported to CSV. The repo ships `tools/Export-SecurityEvents.ps1`, which produces the exact schema from a live host with `Get-WinEvent`.
- **Linux auth logs** in standard syslog format, such as `/var/log/auth.log`.

Detections:

| ID | Detection | Signal | Default severity |
|----|-----------|--------|-----------------|
| BRUTE-FORCE | Repeated failed authentication | Many failures from one source in a short window | High |
| SPRAY-SUCCESS | Success after failures | A successful logon right after a burst of failures from the same source | High |
| LOCKOUT | Account lockout | Windows 4740 or repeated failures against many accounts | Medium |
| PRIV-GRANT | Privilege granted | Added to a privileged group, special privileges assigned, or sudo to root | High |
| LOG-CLEARED | Audit log cleared | Windows 1102 | High |
| OFF-HOURS-ADMIN | Off-hours admin logon | Successful privileged logon outside business hours | Medium |

## Modes

- **File mode** reads a Windows CSV export, a syslog file, or both, and writes a digest.
- **Demo mode** (`--demo`) loads a bundled synthetic corpus with seeded incidents. It runs anywhere in seconds with no host and no logs to collect. Every line in the corpus is fake.

Both modes normalize into the same event shape, so every detection runs identically against real or synthetic input. The digest reports on the date range present in the data, not on the wall clock, so demo output is stable.

## Tech stack

Python 3.11. Standard library only at runtime. pytest for tests. Ruff for linting. GitHub Actions for CI.

## Framework mapping

Detections map to MITRE ATT&CK: T1110 Brute Force, T1098 Account Manipulation, T1078 Valid Accounts, T1070.001 Clear Windows Event Logs.

## Done means

1. `logsentry --demo` writes an HTML digest on a clean machine in seconds.
2. Every detection covered by tests against the synthetic corpus.
3. Real screenshots of the digest captured from a real run.
4. README to standard. gitleaks clean.
