"""Turn probe results into a root-cause diagnosis with an owner and next steps.

The typical symptom is the same for very different causes: OpenVPN Connect
reports "Peer certificate verification failure", OpenVPN 2.x logs
"certificate verify failed". The diagnosis separates them:

=========================  ===============================  ==================
cause                      evidence                         who can fix it
=========================  ===============================  ==================
server certificate expired leaf notAfter in the past         server operator
CA expired / not yet valid issuer outside validity window   server operator
CA replaced                no signature path to profile CA  operator (new profile)
wrong key usage            remote-cert-tls fails            server operator
client clock wrong         offset vs NTP; valid at true time client
outdated pin               peer-fingerprint mismatch         client
=========================  ===============================  ==================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .certs import CertInfo, describe
from .clock import ClockCheck
from .inspector import RemoteReport, anchors_for, reevaluate
from .logs import LogSummary
from .profile import Profile

__all__ = ["CLOCK_TOLERANCE", "Diagnosis", "Finding", "diagnose", "human_delta"]

CLOCK_TOLERANCE = 300.0  # seconds
SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}


def human_delta(seconds: float) -> str:
    value = abs(seconds)
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if value >= size:
            count = value / size
            shown = f"{count:.0f}" if count >= 10 else f"{count:.1f}".rstrip("0").rstrip(".")
            return f"{shown} {unit}{'' if shown == '1' else 's'}"
    return f"{value:.0f} seconds"


@dataclass
class Finding:
    code: str
    severity: str
    owner: str
    title: str
    detail: str
    actions: list[str] = field(default_factory=list)
    remotes: list[str] = field(default_factory=list)


@dataclass
class Diagnosis:
    findings: list[Finding]
    reports: list[RemoteReport]
    profile_ca: list[CertInfo]
    clock: ClockCheck | None
    timeline: LogSummary | None
    generated_at: datetime
    reference_time: datetime

    @property
    def primary(self) -> Finding:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])[0]

    @property
    def problem_found(self) -> bool:
        return any(f.severity in ("critical", "warning") for f in self.findings)

    @property
    def unreachable(self) -> bool:
        return not any(r.reachable for r in self.reports)


def _when(moment: datetime, now: datetime) -> str:
    delta = (now - moment).total_seconds()
    stamp = f"{moment:%Y-%m-%d %H:%M:%S} UTC"
    return f"{human_delta(delta)} ago ({stamp})" if delta >= 0 else f"in {human_delta(delta)} ({stamp})"


def _merge(findings: dict[str, Finding], finding: Finding) -> None:
    existing = findings.get(finding.code)
    if existing is None:
        findings[finding.code] = finding
    else:
        existing.remotes.extend(r for r in finding.remotes if r not in existing.remotes)


def diagnose(
    profile: Profile,
    reports: list[RemoteReport],
    *,
    now: datetime | None = None,
    clock: ClockCheck | None = None,
    timeline: LogSummary | None = None,
    warn_days: float = 30,
    profile_name: str = "PROFILE",
) -> Diagnosis:
    local_now = now or datetime.now(timezone.utc)
    offset = clock.offset_seconds if clock and clock.available else 0.0
    true_now = local_now + timedelta(seconds=offset)
    findings: dict[str, Finding] = {}

    anchors = anchors_for(profile)
    ca_infos = [describe(a) for a in anchors]
    for note in profile.notes:
        _merge(findings, Finding("PROFILE_NOTE", "info", "client", "Profile note", note))

    if not anchors and not profile.peer_fingerprints:
        _merge(
            findings,
            Finding(
                "NO_TRUST_ANCHOR",
                "critical",
                "client",
                "The profile cannot verify the server",
                "The profile contains neither a 'ca' nor a 'peer-fingerprint', so no OpenVPN client "
                "can verify the server certificate.",
                ["Obtain the complete profile from the VPN operator."],
            ),
        )
    for ca in ca_infos:
        days = ca.days_left(true_now)
        if days < 0:
            _merge(
                findings,
                Finding(
                    "CA_EXPIRED",
                    "critical",
                    "server operator",
                    "The CA in the profile has expired",
                    f"The profile's CA '{ca.subject}' expired {_when(ca.not_after, true_now)}. Every "
                    "certificate it signed is now rejected by OpenVPN clients.",
                    ["The operator must issue a new CA, new server certificates and new client profiles."],
                ),
            )
        elif days < warn_days:
            _merge(
                findings,
                Finding(
                    "CA_EXPIRING",
                    "warning",
                    "server operator",
                    "The CA in the profile expires soon",
                    f"The profile's CA '{ca.subject}' expires {_when(ca.not_after, true_now)}.",
                    ["The operator should plan a CA rollover and distribute new profiles in time."],
                ),
            )

    skewed = clock is not None and clock.available and abs(offset) > CLOCK_TOLERANCE
    if skewed:
        direction = "behind" if offset > 0 else "ahead of"
        _merge(
            findings,
            Finding(
                "CLOCK_SKEW",
                "warning",
                "client",
                "The local clock is wrong",
                f"This computer's clock is {human_delta(offset)} {direction} {clock.source}. TLS "
                "clients judge certificate validity by the local clock.",
                ["Enable automatic time synchronisation and correct the clock."],
            ),
        )

    reachable = [r for r in reports if r.reachable]
    if not reachable:
        lines = "; ".join(f"{r.remote.label}: {r.failure}" for r in reports)
        _merge(
            findings,
            Finding(
                "NO_RESPONSE",
                "critical",
                "network or client",
                "No server answered the probe",
                f"No remote returned a certificate ({lines}).",
                [
                    "Check that the host is reachable and that UDP/TCP to the port is not filtered.",
                    "If the profile uses tls-auth or tls-crypt, make sure the key, key-direction and "
                    "--auth digest are the ones the server expects: the server silently drops "
                    "packets that fail this check.",
                ],
            ),
        )

    for report in reachable:
        local_eval = report.evaluation
        evaluation = reevaluate(report, profile, true_now) if offset else local_eval
        label = report.remote.label
        leaf = evaluation.leaf
        codes = evaluation.codes()
        time_codes = {"EXPIRED", "NOT_YET_VALID", "ISSUER_EXPIRED", "ISSUER_NOT_YET_VALID"}
        if skewed and (local_eval.codes() & time_codes) and not (codes & time_codes):
            _merge(
                findings,
                Finding(
                    "CLIENT_CLOCK",
                    "critical",
                    "client",
                    "The server certificate only looks invalid because the clock is wrong",
                    f"At the local time the certificate of {label} fails its validity check, but at the "
                    f"correct time it is valid until {leaf.not_after:%Y-%m-%d %H:%M} UTC.",
                    ["Correct the system clock; nothing needs to change on the server."],
                    [label],
                ),
            )
            continue
        trusted_note = ""
        if evaluation.trusted and ca_infos:
            ca = ca_infos[0]
            trusted_note = (
                f" It is still correctly signed by the CA in the profile ('{ca.subject}', valid "
                f"until {ca.not_after:%Y-%m-%d}), so the profile itself is fine."
            )
        if "EXPIRED" in codes:
            pin_hint = (
                f"Temporary workaround: `ovpncert pin {profile_name}` writes a profile that pins "
                "this exact certificate after verifying it against the profile's CA."
            )
            actions = [
                "The VPN operator must renew the server certificate. Reissuing it from the same CA "
                "restores access for every existing client profile without redistributing profiles.",
            ]
            if evaluation.trusted and not codes & {"ISSUER_EXPIRED", "PURPOSE", "NAME"}:
                actions.append(pin_hint)
            _merge(
                findings,
                Finding(
                    "SERVER_CERT_EXPIRED",
                    "critical",
                    "server operator",
                    "The server certificate has expired",
                    f"The server presents '{leaf.subject}', which expired "
                    f"{_when(leaf.not_after, true_now)}.{trusted_note} Clients reject it during the TLS "
                    'handshake (OpenVPN Connect: "Peer certificate verification failure").',
                    actions,
                    [label],
                ),
            )
        if "NOT_YET_VALID" in codes:
            _merge(
                findings,
                Finding(
                    "SERVER_CERT_NOT_YET_VALID",
                    "critical",
                    "server operator",
                    "The server certificate is not valid yet",
                    f"The server presents '{leaf.subject}', valid only from "
                    f"{leaf.not_before:%Y-%m-%d %H:%M:%S} UTC.",
                    ["The operator deployed a certificate too early or issued it with a wrong clock."],
                    [label],
                ),
            )
        if codes & {"ISSUER_EXPIRED", "ISSUER_NOT_YET_VALID"}:
            issuer_problem = next(p for p in evaluation.problems if p.code.startswith("ISSUER_"))
            _merge(
                findings,
                Finding(
                    "ISSUER_INVALID",
                    "critical",
                    "server operator",
                    "A CA in the server's chain is outside its validity period",
                    issuer_problem.message + ".",
                    ["The operator must renew the CA or intermediate and the certificates below it."],
                    [label],
                ),
            )
        if "UNTRUSTED" in codes or "BAD_SIGNATURE" in codes:
            _merge(
                findings,
                Finding(
                    "CA_MISMATCH",
                    "critical",
                    "server operator or client",
                    "The server certificate is not signed by the CA in the profile",
                    f"The server presents '{leaf.subject}' issued by '{leaf.issuer}', which does not "
                    "chain to the profile's CA. Either the operator replaced its CA, or the connection "
                    "is being intercepted. Do not pin this certificate.",
                    ["Download a fresh profile from the operator, or confirm the new CA out of band."],
                    [label],
                ),
            )
        if "PURPOSE" in codes:
            message = next(p.message for p in evaluation.problems if p.code == "PURPOSE")
            _merge(
                findings,
                Finding(
                    "SERVER_CERT_PURPOSE",
                    "critical",
                    "server operator",
                    "The server certificate is not marked for server use",
                    message + ".",
                    [
                        "The operator must reissue the server certificate with the serverAuth "
                        "extended key usage."
                    ],
                    [label],
                ),
            )
        if "NAME" in codes:
            message = next(p.message for p in evaluation.problems if p.code == "NAME")
            _merge(
                findings,
                Finding(
                    "NAME_MISMATCH",
                    "critical",
                    "server operator or client",
                    "The server name does not match verify-x509-name",
                    message + ".",
                    ["Check the verify-x509-name line of the profile against the server certificate."],
                    [label],
                ),
            )
        if "PIN_MISMATCH" in codes:
            renewed = evaluation.library_ok and not codes & {"PURPOSE", "NAME"}
            detail = "The profile pins a certificate that the server no longer presents."
            if renewed:
                detail += (
                    " The new certificate is valid and signed by the profile's CA, which usually "
                    "means the operator has renewed it."
                )
            _merge(
                findings,
                Finding(
                    "PIN_OUTDATED",
                    "critical",
                    "client",
                    "The pinned certificate has been replaced",
                    detail,
                    ["Switch back to the original profile (without peer-fingerprint)."],
                    [label],
                ),
            )
        if not codes:
            days = leaf.days_left(true_now)
            if days < warn_days:
                _merge(
                    findings,
                    Finding(
                        "SERVER_CERT_EXPIRING",
                        "warning",
                        "server operator",
                        "The server certificate expires soon",
                        f"'{leaf.subject}' expires {_when(leaf.not_after, true_now)}.",
                        ["The operator should renew it before it expires."],
                        [label],
                    ),
                )
            else:
                _merge(
                    findings,
                    Finding(
                        "CERTIFICATE_OK",
                        "ok",
                        "none",
                        "The server certificate is valid",
                        f"'{leaf.subject}' is trusted and valid for {human_delta(days * 86400)}. If the "
                        "connection still fails, the cause is not the server certificate (check "
                        "credentials, the data-channel cipher or the network).",
                        [],
                        [label],
                    ),
                )

    if timeline is not None and timeline.first_failure is not None:
        detail = f"Last successful handshake: {timeline.last_success or 'not in the log'}; "
        detail += f"first certificate failure: {timeline.first_failure}"
        if timeline.failure_reason:
            detail += f" ({timeline.failure_reason})"
        detail += "."
        expiries = [r.leaf.not_after.astimezone().replace(tzinfo=None) for r in reachable if r.leaf]
        for expiry in sorted(set(expiries)):
            after_ok = timeline.last_success is None or timeline.last_success <= expiry
            if after_ok and expiry <= timeline.first_failure:
                detail += (
                    f" A server certificate expired at {expiry:%Y-%m-%d %H:%M:%S} (local time), "
                    "between the two: the log is consistent with the expiry."
                )
                break
        _merge(findings, Finding("LOG_TIMELINE", "info", "none", "Log timeline", detail))

    return Diagnosis(
        findings=list(findings.values()),
        reports=reports,
        profile_ca=ca_infos,
        clock=clock,
        timeline=timeline,
        generated_at=local_now,
        reference_time=true_now,
    )
