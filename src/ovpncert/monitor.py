"""Expiry monitoring: Nagios/Icinga plugin output, JSON and Prometheus text format.

The earliest ``notAfter`` in the verified chain is what counts, because an
expiring CA breaks clients just as surely as an expiring server certificate.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime

from .inspector import RemoteReport

__all__ = [
    "CRITICAL",
    "OK",
    "STATE_NAMES",
    "UNKNOWN",
    "WARNING",
    "CheckResult",
    "check_remote",
    "format_json",
    "format_nagios",
    "format_prometheus",
    "overall_state",
]

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
STATE_NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}


@dataclass
class CheckResult:
    remote: str
    state: int
    message: str
    days_left: float | None = None
    not_after: datetime | None = None
    subject: str | None = None
    trusted: bool | None = None

    @property
    def state_name(self) -> str:
        return STATE_NAMES[self.state]


def _days(value: float) -> str:
    whole = abs(value)
    if whole < 1:
        hours = whole * 24
        return f"{hours:.1f} hours"
    return f"{whole:.0f} day{'s' if round(whole) != 1 else ''}"


def check_remote(report: RemoteReport, warning_days: float, critical_days: float, now: datetime):
    label = report.remote.label
    if not report.reachable or report.evaluation is None:
        return CheckResult(label, UNKNOWN, f"{label}: probe failed ({report.failure})")
    evaluation = report.evaluation
    earliest = min(evaluation.path, key=lambda c: c.not_after)
    which = "server certificate" if earliest is evaluation.leaf else f"CA '{earliest.subject}'"
    days = earliest.days_left(now)
    result = CheckResult(
        label,
        OK,
        "",
        days_left=round(days, 3),
        not_after=earliest.not_after,
        subject=evaluation.leaf.subject,
        trusted=evaluation.trusted,
    )
    blocking = [p for p in evaluation.problems if p.code in ("UNTRUSTED", "BAD_SIGNATURE", "PURPOSE", "NAME")]
    if blocking:
        result.state = CRITICAL
        result.message = f"{label}: {blocking[0].message}"
    elif days < 0:
        result.state = CRITICAL
        result.message = f"{label}: {which} expired {_days(days)} ago"
    elif days <= critical_days:
        result.state = CRITICAL
        result.message = f"{label}: {which} expires in {_days(days)}"
    elif days <= warning_days:
        result.state = WARNING
        result.message = f"{label}: {which} expires in {_days(days)}"
    else:
        result.message = f"{label}: {which} valid for {_days(days)}"
    return result


def overall_state(results: list[CheckResult]) -> int:
    states = {r.state for r in results}
    for state in (CRITICAL, WARNING, UNKNOWN):
        if state in states:
            return state
    return OK


def format_nagios(results: list[CheckResult], warning_days: float, critical_days: float) -> str:
    state = overall_state(results)
    ordered = sorted(results, key=lambda r: -{CRITICAL: 3, WARNING: 2, UNKNOWN: 1, OK: 0}[r.state])
    summary = "; ".join(r.message for r in ordered)
    perf = " ".join(
        f"'{r.remote}'={r.days_left:.2f};{warning_days:g};{critical_days:g};;"
        for r in results
        if r.days_left is not None
    )
    return f"OVPNCERT {STATE_NAMES[state]} - {summary}" + (f" | {perf}" if perf else "")


def _jsonable(result: CheckResult) -> dict:
    data = asdict(result)
    data["state"] = result.state_name
    if result.not_after is not None:
        data["not_after"] = result.not_after.isoformat()
    return data


def format_json(results: list[CheckResult]) -> str:
    return json.dumps(
        {"state": STATE_NAMES[overall_state(results)], "results": [_jsonable(r) for r in results]},
        indent=2,
    )


def _label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def format_prometheus(results: list[CheckResult]) -> str:
    lines = [
        "# HELP ovpncert_probe_success Whether the handshake-only probe retrieved a certificate.",
        "# TYPE ovpncert_probe_success gauge",
    ]
    lines += [
        f'ovpncert_probe_success{{remote="{_label(r.remote)}"}} {0 if r.state == UNKNOWN else 1}'
        for r in results
    ]
    lines += [
        "# HELP ovpncert_certificate_expiry_timestamp_seconds Earliest notAfter in the verified chain.",
        "# TYPE ovpncert_certificate_expiry_timestamp_seconds gauge",
    ]
    lines += [
        f'ovpncert_certificate_expiry_timestamp_seconds{{remote="{_label(r.remote)}"}} '
        f"{r.not_after.timestamp():.0f}"
        for r in results
        if r.not_after is not None
    ]
    lines += [
        "# HELP ovpncert_certificate_trusted Whether the chain verifies against the profile CA "
        "(time ignored).",
        "# TYPE ovpncert_certificate_trusted gauge",
    ]
    lines += [
        f'ovpncert_certificate_trusted{{remote="{_label(r.remote)}"}} {1 if r.trusted else 0}'
        for r in results
        if r.trusted is not None
    ]
    lines += [
        "# HELP ovpncert_check_state Check state (0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN).",
        "# TYPE ovpncert_check_state gauge",
    ]
    lines += [f'ovpncert_check_state{{remote="{_label(r.remote)}"}} {r.state}' for r in results]
    return "\n".join(lines) + "\n"
