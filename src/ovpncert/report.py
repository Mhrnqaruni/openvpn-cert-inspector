"""Human-readable and JSON rendering of inspection results."""

from __future__ import annotations

import os
import ssl
from dataclasses import fields, is_dataclass
from datetime import datetime
from pathlib import Path

from . import __version__
from .certs import CertInfo
from .diagnose import Diagnosis, human_delta
from .inspector import RemoteReport
from .pin import PinResult
from .profile import Profile

__all__ = [
    "Style",
    "color_enabled",
    "diagnosis_json",
    "inspect_json",
    "render_diagnosis",
    "render_inspect",
    "render_pin",
    "to_jsonable",
]

CLIENT_NAMES = {"openvpn3": "OpenVPN 3 (Connect)", "openvpn2": "OpenVPN 2.x"}


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)


def color_enabled(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if not getattr(stream, "isatty", lambda: False)():
        return False
    if os.name == "nt":
        return bool(os.environ.get("WT_SESSION") or os.environ.get("TERM") or os.environ.get("ANSICON"))
    return True


def describe_protection(profile: Profile) -> str:
    if profile.protection == "tls-auth":
        direction = profile.key_direction if profile.key_direction is not None else "bidirectional"
        return f"tls-auth (HMAC-{profile.auth_digest.upper()}, key-direction {direction})"
    if profile.protection == "tls-crypt":
        return "tls-crypt (AES-256-CTR + HMAC-SHA256)"
    return profile.protection


def _validity(cert: CertInfo, now: datetime, style: Style) -> str:
    span = f"{cert.not_before:%Y-%m-%d %H:%M:%S} -> {cert.not_after:%Y-%m-%d %H:%M:%S} UTC"
    days = cert.days_left(now)
    if now < cert.not_before:
        return f"{span}  {style.red('NOT YET VALID')}"
    if days < 0:
        return f"{span}  {style.red('EXPIRED ' + human_delta(days * 86400) + ' ago')}"
    text = f"{human_delta(days * 86400)} left"
    return f"{span}  {style.yellow(text) if days < 30 else style.green(text)}"


def _cert_lines(cert: CertInfo, now: datetime, style: Style, indent: str) -> list[str]:
    usage = ", ".join(cert.key_usage) or "-"
    if cert.extended_key_usage:
        usage += " | " + ", ".join(cert.extended_key_usage)
    rows = [
        ("subject", cert.subject),
        ("issuer", cert.issuer),
        ("validity", _validity(cert, now, style)),
        ("sha256", cert.sha256),
        ("serial", cert.serial),
        ("key", f"{cert.public_key}, {cert.signature_algorithm}"),
        ("usage", usage),
    ]
    return [f"{indent}{style.dim(name.ljust(10))}{value}" for name, value in rows]


def _report_lines(report: RemoteReport, now: datetime, style: Style) -> list[str]:
    head = style.bold(report.remote.label)
    if report.address and report.address != report.remote.host:
        head += style.dim(f" -> {report.address}")
    if not report.reachable:
        return [f"{style.red('x')} {head}", f"    {style.red('no certificate')}  {report.failure}", ""]
    hs = report.handshake
    evaluation = report.evaluation
    meta = " ".join(x for x in (hs.tls_version, hs.cipher) if x)
    lines = [f"{style.cyan('*')} {head}   {style.dim(meta)}   {style.dim(f'{hs.elapsed_ms / 1000:.2f} s')}"]
    if hs.detail:
        lines.append(f"    {style.dim(hs.detail)}")
    lines.append(f"  {style.bold('Server certificate')}")
    lines += _cert_lines(evaluation.leaf, now, style, "    ")
    chain = ["server"]
    for depth, cert in enumerate(evaluation.path[1:], start=1):
        tag = "profile CA" if evaluation.trusted and depth == len(evaluation.path) - 1 else "intermediate"
        chain.append(f"'{cert.subject}' [{tag}, valid until {cert.not_after:%Y-%m-%d}]")
    if not evaluation.trusted:
        chain.append(style.red("(no path to the profile CA)") if evaluation.has_ca else "(no CA in profile)")
    lines.append(f"  {style.dim('chain'.ljust(12))}{' -> '.join(chain)}")
    if evaluation.clean:
        verdict = style.green("PASS") + "  trusted and within its validity period"
    else:
        verdict = style.red("FAIL") + "  " + "; ".join(p.message for p in evaluation.problems)
    lines.append(f"  {style.dim('result'.ljust(12))}{verdict}")
    clients = []
    for key, prediction in evaluation.predictions.items():
        word = style.green("accepts") if prediction.accepts else style.red("rejects")
        clients.append(f"{CLIENT_NAMES[key]}: {word}")
    lines.append(f"  {style.dim('clients'.ljust(12))}{' | '.join(clients)}")
    lines.append("")
    return lines


def render_inspect(profile: Profile, reports: list[RemoteReport], now: datetime, style: Style) -> str:
    source = profile.path.name if profile.path else "command line"
    lines = [
        style.dim(
            f"ovpncert {__version__} | {source} | {describe_protection(profile)} | "
            f"{len(reports)} remote{'s' if len(reports) != 1 else ''} | {now:%Y-%m-%d %H:%M:%S} UTC"
        ),
        "",
    ]
    for report in reports:
        lines += _report_lines(report, now, style)
    return "\n".join(lines).rstrip() + "\n"


def _wrap_text(text: str, width: int, indent: str) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(indent + current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(indent + current)
    return lines


def render_diagnosis(diagnosis: Diagnosis, style: Style) -> str:
    primary = diagnosis.primary
    colour = {"critical": style.red, "warning": style.yellow, "ok": style.green}.get(
        primary.severity, style.cyan
    )
    lines = [
        f"{style.bold('DIAGNOSIS')}  {colour(primary.title)}",
        style.dim(f"           severity: {primary.severity} | who can fix it: {primary.owner}"),
        "",
    ]
    if primary.remotes:
        lines.append("  " + style.dim("affects: " + ", ".join(primary.remotes)))
    lines += _wrap_text(primary.detail, 86, "  ")
    if primary.actions:
        lines += ["", "  " + style.bold("What to do")]
        for index, action in enumerate(primary.actions, start=1):
            wrapped = _wrap_text(action, 82, "       ")
            lines.append(f"    {index}. " + wrapped[0].strip())
            lines += wrapped[1:]
    others = [f for f in diagnosis.findings if f is not primary]
    if others:
        lines += ["", "  " + style.bold("Other findings")]
        for finding in others:
            tag = {"critical": style.red, "warning": style.yellow, "ok": style.green}.get(
                finding.severity, style.dim
            )(finding.severity.upper())
            wrapped = _wrap_text(f"{finding.title}: {finding.detail}", 80, "        ")
            lines.append(f"    {tag} " + wrapped[0].strip())
            lines += wrapped[1:]
    lines += ["", "  " + style.bold("Evidence")]
    clock = diagnosis.clock
    if clock is None:
        lines.append(f"    {'clock'.ljust(14)}not checked")
    elif clock.available:
        lines.append(f"    {'clock'.ljust(14)}offset {clock.offset_seconds:+.1f} s vs {clock.source}")
    else:
        lines.append(f"    {'clock'.ljust(14)}could not be checked ({clock.error})")
    for ca in diagnosis.profile_ca:
        state = "valid" if ca.days_left(diagnosis.reference_time) >= 0 else "EXPIRED"
        lines.append(f"    {'profile CA'.ljust(14)}{ca.subject}, {state} until {ca.not_after:%Y-%m-%d}")
    for report in diagnosis.reports:
        if not report.reachable:
            lines.append(f"    {report.remote.label}: no certificate ({report.failure})")
            continue
        leaf = report.evaluation.leaf
        problems = ", ".join(sorted(report.evaluation.codes())) or "OK"
        lines.append(
            f"    {report.remote.label}: {problems}; notAfter {leaf.not_after:%Y-%m-%d %H:%M:%S} UTC"
        )
    if diagnosis.timeline is not None:
        t = diagnosis.timeline
        lines.append(
            f"    {'log'.ljust(14)}{t.format}: {len(t.events)} certificate events, "
            f"last success {t.last_success or '-'}, first failure {t.first_failure or '-'}"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_pin(result: PinResult, output: Path | None, style: Style) -> str:
    lines = []
    for candidate in result.candidates:
        mark = style.green("pin") if candidate.ok else style.red("no ")
        lines.append(f"  {mark}  {candidate.label}  {candidate.fingerprint or ''}")
        for reason in candidate.blocked:
            lines += _wrap_text("blocked: " + reason, 84, "         ")
        for note in candidate.notes:
            lines += _wrap_text("note: " + note, 84, "         ")
    if result.ok and output is not None:
        lines += [
            "",
            f"  Wrote {output} for {CLIENT_NAMES[result.client]}.",
            "  Import it as a separate profile; keep the original for when the certificate is renewed.",
        ]
    elif not result.ok:
        lines += [
            "",
            style.red("  No pinned profile written: every reachable remote must pass the safety checks."),
        ]
    return "\n".join(lines) + "\n"


def to_jsonable(value):
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, bytes):
        return ssl.DER_cert_to_PEM_cert(value)
    return value


def _report_json(report: RemoteReport) -> dict:
    handshake = to_jsonable(report.handshake) if report.handshake else None
    if handshake is not None:
        handshake["chain_pem"] = handshake.pop("chain")
    return {
        "remote": report.remote.label,
        "host": report.remote.host,
        "port": report.remote.port,
        "proto": report.remote.kind,
        "address": report.address,
        "error": report.failure or None,
        "handshake": handshake,
        "evaluation": to_jsonable(report.evaluation) if report.evaluation else None,
    }


def inspect_json(profile: Profile, reports: list[RemoteReport], now: datetime) -> dict:
    return {
        "tool": "ovpncert",
        "version": __version__,
        "generated_at": now.isoformat(),
        "protection": profile.protection,
        "remotes": [_report_json(r) for r in reports],
    }


def diagnosis_json(diagnosis: Diagnosis) -> dict:
    return {
        "tool": "ovpncert",
        "version": __version__,
        "generated_at": diagnosis.generated_at.isoformat(),
        "reference_time": diagnosis.reference_time.isoformat(),
        "primary": to_jsonable(diagnosis.primary),
        "findings": to_jsonable(diagnosis.findings),
        "clock": to_jsonable(diagnosis.clock),
        "profile_ca": to_jsonable(diagnosis.profile_ca),
        "timeline": to_jsonable(diagnosis.timeline),
        "remotes": [_report_json(r) for r in diagnosis.reports],
    }
