"""Extract a certificate timeline from OpenVPN client logs.

Two formats are understood:

* OpenVPN Connect 3.x (``[Mar 14, 2026, 09:30:00] SSL Handshake: peer certificate: ...``),
  where entries may be separated by the U+23CE character instead of newlines;
* OpenVPN 2.x (``2026-03-14 09:30:00 VERIFY OK: depth=0, CN=...``), or the same
  with the ctime timestamp form (``Sat Mar 14 09:30:00 2026``).

Timestamps are local time as written in the log and are kept naive.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

__all__ = ["LogEvent", "LogSummary", "parse_log", "summarize", "summarize_file"]

_CONNECT = re.compile(r"^\[(?P<ts>[A-Z][a-z]{2} \d{1,2}, \d{4}, \d{2}:\d{2}:\d{2})\] (?P<msg>.*)$")
_V2_ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<msg>.*)$")
_V2_CTIME = re.compile(r"^(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4}) (?P<msg>.*)$")

_SUCCESS = (
    re.compile(r"SSL Handshake: peer certificate"),
    re.compile(r"VERIFY OK: depth=0"),
)
_CONNECTED = (re.compile(r"EVENT: CONNECTED"), re.compile(r"Initialization Sequence Completed"))
_FAILURE = (
    re.compile(r"CERT_VERIFY_FAIL"),
    re.compile(r"certificate verify failed"),
    re.compile(r"VERIFY ERROR"),
    re.compile(r"VERIFY FAIL"),
    re.compile(r"hash verification failed"),
)
_REASON = re.compile(r"error=(?P<reason>[^:]+):|VERIFY FAIL -- (?P<reason2>.+)$")


@dataclass
class LogEvent:
    time: datetime
    kind: str  # "handshake-ok", "connected", "cert-failure"
    message: str


@dataclass
class LogSummary:
    format: str
    events: list[LogEvent] = field(default_factory=list)
    last_success: datetime | None = None
    first_failure: datetime | None = None
    failure_reason: str | None = None
    failures: int = 0

    @property
    def interval_seconds(self) -> float | None:
        """Typical gap between successful handshakes (the renegotiation period)."""
        times = [e.time for e in self.events if e.kind == "handshake-ok"]
        gaps = sorted((b - a).total_seconds() for a, b in itertools.pairwise(times) if b > a)
        return gaps[len(gaps) // 2] if gaps else None


def _timestamp(raw: str) -> datetime | None:
    for fmt in ("%b %d, %Y, %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(" ".join(raw.split()), fmt)
        except ValueError:
            continue
    return None


def parse_log(text: str) -> tuple[str, list[LogEvent]]:
    entries = text.replace("⏎", "\n").splitlines()
    events: list[LogEvent] = []
    seen_format = "unknown"
    for line in entries:
        line = line.strip()
        match = _CONNECT.match(line) or _V2_ISO.match(line) or _V2_CTIME.match(line)
        if not match:
            continue
        if seen_format == "unknown":
            seen_format = "openvpn-connect" if match.re is _CONNECT else "openvpn2"
        when = _timestamp(match.group("ts"))
        message = match.group("msg")
        if when is None:
            continue
        if any(p.search(message) for p in _SUCCESS):
            events.append(LogEvent(when, "handshake-ok", message))
        elif any(p.search(message) for p in _CONNECTED):
            events.append(LogEvent(when, "connected", message))
        elif any(p.search(message) for p in _FAILURE):
            events.append(LogEvent(when, "cert-failure", message))
    return seen_format, events


def summarize(text: str) -> LogSummary:
    fmt, events = parse_log(text)
    summary = LogSummary(fmt, events)
    for event in events:
        if event.kind in ("handshake-ok", "connected"):
            summary.last_success = event.time
            summary.first_failure = None
            summary.failure_reason = None
        elif event.kind == "cert-failure":
            summary.failures += 1
            if summary.first_failure is None:
                summary.first_failure = event.time
                found = _REASON.search(event.message)
                if found:
                    summary.failure_reason = (found.group("reason") or found.group("reason2")).strip()
                elif "certificate verify failed" in event.message:
                    summary.failure_reason = "certificate verify failed"
    return summary


def summarize_file(path: str | Path) -> LogSummary:
    return summarize(Path(path).read_text(encoding="utf-8", errors="replace"))
