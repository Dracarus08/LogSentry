# Interview Defense Pack. LogSentry

This is my preparation for defending this project in an interview. It is written the way I would explain the tool at a whiteboard.

## Two-minute pitch

Security events are already in the logs. Failed logons, lockouts, privilege grants. The problem is nobody reads them until an incident forces it. LogSentry reads Windows Security events and Linux auth logs and turns them into a one-page daily digest. It does not just count events. It correlates them into incidents. A burst of failures from one source is brute force. The same burst across many accounts is a spray. A success right after that burst is the one that matters, because that is a breach and not just an attempt. It also catches lockouts, privilege grants, and the security log being cleared. It is written in Python with no runtime dependencies, and it ships with a synthetic demo corpus so anyone can run it in seconds. I built it because I own the logs already. This turns them into something I actually read every morning.

## Architecture walkthrough

There are two parsers. One reads Windows Security events from a CSV export, the other reads Linux auth logs in syslog format. Both produce the same normalized event. Timestamp, source, category, account, source IP, and a few more fields.

Every detection is a function that takes the list of normalized events and returns findings. The detections never parse a log line. They only see normalized events. That means the same brute-force rule works on Windows and Linux with no special casing.

The engine runs all the detections, sorts the findings by severity, and computes the summary counts. Then a renderer turns the result into text or into a self-contained HTML page.

## Key decisions and tradeoffs

**All format knowledge lives in the parsers.** This is the core decision. Once every log becomes the same event, the detections are simple and source-agnostic. The tradeoff is that adding a new event type means teaching the parser to normalize it, but that is the right place for that work.

**CSV in for Windows, not EVTX.** Reading EVTX directly needs a binary parser and a third-party dependency. A CSV export keeps the tool dependency-free and matches how a sysadmin already pulls events with Get-WinEvent. I ship the export script so the workflow is one command. The tradeoff is the extra export step, which is on the roadmap to remove.

**A sliding time window for brute force.** My first version counted all failures from a source across the whole day. That flagged slow background noise as an attack. A real attack is dense in time, so I slide a window across each source's failures and take the densest burst. This matches the shape of the attack and cuts the false positives.

**The digest reports on the data window, not the wall clock.** Feed it yesterday's logs and it summarizes yesterday. This makes the output stable and testable and makes the demo produce the same digest every time.

## Known limitations

- Windows events come from a CSV export, so there is a collection step before analysis.
- The syslog parser covers sshd and sudo. Other services are not parsed yet.
- Detections are rule based, not statistical. Thresholds are sensible defaults, not per-environment baselines.
- It analyzes a batch of logs. It is not a streaming or real-time monitor.

## How would you extend this to enterprise scale

I would move from batch files to a stream. Ship logs to a central place, then run these same detections on a rolling window instead of a file. The detections do not change, because they already work on normalized events. The parser layer becomes a set of collectors. Findings go to a store keyed by source and detection, so I can dedupe repeat alerts and track whether the same attacker comes back. At that point LogSentry is the detection logic inside a small SIEM rather than a report generator. The thresholds would move from fixed defaults to per-environment baselines learned from a quiet period.

## Security concepts this project demonstrates

- **The difference between an attempt and a breach.** A pile of failed logons is noise. A success at the end of that pile is an incident. The success-after-failures detection is the whole point.
- **Brute force versus password spray.** Both are many failures. Brute force is many tries against one account. Spray is one try against many accounts to stay under lockout thresholds. Same raw events, different shape, different detection.
- **Why attackers clear logs.** Clearing the Security log is an early anti-forensics step. A single clear event is worth a High because it means someone is trying to hide.
- **Privilege escalation signals.** Being added to Administrators or Domain Admins, special privileges assigned at logon, and sudo to root are all the moment an account becomes dangerous.
- **Off-hours as a signal.** A privileged logon at 2 AM is not proof of anything, but it is worth a look, and cheap to flag.

## Likely interview questions with model answers

**1. How do you avoid false positives on brute force.** I group failures by source and slide a time window, then require a threshold within that window. Slow background failures never fill the window, so they do not fire. Real attacks are dense, so they do.

**2. What is the difference between your brute-force and spray detection.** They share the same window logic. If the dense burst of failures targets one account, it is brute force. If it spans three or more accounts, it is a spray. Spraying is designed to stay under per-account lockout, so it spreads across accounts, and that spread is the tell.

**3. Why is success-after-failures the most important detection.** Because it is the one that means the attack worked. Failures alone are attempts. A successful logon from the same source right after a burst of failures is the moment an attempt becomes access. It is a High for that reason.

**4. How do you test detection logic without real logs.** Each detection is a pure function over normalized events. I build a small list of events in memory that should and should not trigger it, and assert on the findings. No files, no host. The demo corpus exercises the same code end to end.

**5. Why CSV for Windows instead of reading the log directly.** To stay dependency-free and match how sysadmins already export events. Reading EVTX needs a binary parser and a third-party library. The export is one command with the script I ship, and removing that step is on the roadmap.

**6. Is this safe to run.** Yes. It reads logs and writes a report. The collection script only reads the event log. Nothing changes state.

**7. How would you tune this for a noisy environment.** Raise the brute-force threshold or shorten the window, and allowlist known scanners and service accounts. Longer term, learn a baseline from a quiet period instead of using fixed thresholds.

**8. What ATT&CK techniques does this cover and why does that matter.** T1110 for brute force and spray, T1078 for valid-account use like off-hours admin and spray success, T1098 for privilege grants, and T1070.001 for clearing the Windows log. Mapping to ATT&CK lets me explain each detection in attacker terms and lets a reviewer see the coverage at a glance.

**9. What happens with logs from two days.** The digest reports the full range present in the data and labels it as a range. Detections still work because they key on time windows within the data, not on today.

**10. How does this connect to your other projects.** AD-Audit-Toolkit finds the weaknesses in identity before they are used. LogSentry watches for them being used. Later projects run the attacks in a lab and confirm these detections fire. This is the detection layer of the arc.

**11. Why Python here when the last project was PowerShell.** The input is cross-platform. Windows and Linux logs both feed it, so a cross-platform language fits. Python also makes the text and HTML rendering and the testing clean. PowerShell was right for the AD tool because that lived entirely in the Windows directory. I pick the language that fits the domain.

**12. What was the hardest part.** Getting the brute-force window right. The naive all-day count looked fine on clean data and fell apart on real noise. Switching to a sliding window was a small code change and a big correctness change.
