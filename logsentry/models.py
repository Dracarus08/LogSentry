"""Core data shapes shared across parsers, detections, and the digest."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# One normalized event. Both the Windows CSV parser and the syslog parser
# produce these, so every detection runs against the same shape.
EVENT_CATEGORIES = (
    "auth_failure",
    "auth_success",
    "lockout",
    "privilege_grant",
    "log_cleared",
    "other",
)


@dataclass
class Event:
    timestamp: datetime
    source: str  # "windows" or "syslog"
    category: str
    event_id: str
    host: str = ""
    account: str = ""  # the target account the event is about
    actor: str = ""  # the account that caused the event, when known
    source_ip: str = ""
    logon_type: str = ""
    group: str = ""  # privileged group name for privilege events
    message: str = ""

    def __post_init__(self) -> None:
        if self.category not in EVENT_CATEGORIES:
            self.category = "other"


@dataclass
class Finding:
    detection_id: str
    title: str
    severity: str  # High, Medium, Low
    attack: list[str] = field(default_factory=list)
    detail: str = ""
    when: datetime | None = None
    entity: str = ""  # the account or ip the finding is about
    count: int = 0
    evidence: list[str] = field(default_factory=list)


SEVERITY_RANK = {"High": 0, "Medium": 1, "Low": 2}
