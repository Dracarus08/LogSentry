"""Runs the detections over a set of events and assembles the digest data."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from .detections import ALL_DETECTIONS
from .models import SEVERITY_RANK, Event, Finding


@dataclass
class Digest:
    events: list[Event]
    findings: list[Finding]
    hosts: list[str] = field(default_factory=list)
    start: datetime | None = None
    end: datetime | None = None
    failed_auths: int = 0
    successful_auths: int = 0
    lockouts: int = 0
    privilege_events: int = 0
    top_sources: list[tuple[str, int]] = field(default_factory=list)

    @property
    def high(self) -> int:
        return sum(1 for f in self.findings if f.severity == "High")

    @property
    def medium(self) -> int:
        return sum(1 for f in self.findings if f.severity == "Medium")

    @property
    def low(self) -> int:
        return sum(1 for f in self.findings if f.severity == "Low")


def run(events: list[Event], config: dict | None = None) -> Digest:
    findings: list[Finding] = []
    for detection in ALL_DETECTIONS:
        findings.extend(detection(events, config))
    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9),
                                 f.when or datetime.max))

    failed = [e for e in events if e.category == "auth_failure"]
    top_sources = Counter(e.source_ip for e in failed if e.source_ip).most_common(8)

    timestamps = [e.timestamp for e in events]
    return Digest(
        events=events,
        findings=findings,
        hosts=sorted({e.host for e in events if e.host}),
        start=min(timestamps) if timestamps else None,
        end=max(timestamps) if timestamps else None,
        failed_auths=len(failed),
        successful_auths=sum(1 for e in events if e.category == "auth_success"),
        lockouts=sum(1 for e in events if e.category == "lockout"),
        privilege_events=sum(1 for e in events if e.category == "privilege_grant"),
        top_sources=top_sources,
    )
