"""Write a temporary profile that pins the server certificate(s) with ``peer-fingerprint``.

A pin is only written for a certificate that is verifiably signed by the CA in
the original profile and that would pass every other check; the only thing
the pin is allowed to overlook is the certificate's validity period. The
output depends on the client family, because OpenVPN 3 and OpenVPN 2.x treat
``peer-fingerprint`` differently (see :mod:`ovpncert.certs`):

* ``openvpn3`` keeps ``ca`` and adds the pin;
* ``openvpn2`` removes ``ca`` (fingerprint-only mode, OpenVPN 2.6+) and adds the pin.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import __version__
from .inspector import RemoteReport
from .profile import Profile

__all__ = ["CLIENTS", "PinCandidate", "PinResult", "assess", "build_pinned_profile", "pin_profile"]

CLIENTS = ("openvpn3", "openvpn2")

_TIME_CODES = {"EXPIRED", "NOT_YET_VALID"}
_ISSUER_TIME_CODES = {"ISSUER_EXPIRED", "ISSUER_NOT_YET_VALID"}
_BLOCK_RE = re.compile(r"^\s*<(/?)([A-Za-z0-9_-]+)>\s*$")


@dataclass
class PinCandidate:
    label: str
    fingerprint: str | None = None
    subject: str | None = None
    not_after: datetime | None = None
    blocked: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.fingerprint is not None and not self.blocked


@dataclass
class PinResult:
    client: str
    candidates: list[PinCandidate]
    text: str | None = None

    @property
    def ok(self) -> bool:
        return self.text is not None


def assess(report: RemoteReport, profile: Profile, client: str) -> PinCandidate:
    """Decide whether the certificate this remote presents may be pinned."""
    candidate = PinCandidate(report.remote.label)
    if not report.reachable or report.evaluation is None:
        candidate.blocked.append(f"no certificate retrieved ({report.failure})")
        return candidate
    evaluation = report.evaluation
    leaf = evaluation.leaf
    candidate.fingerprint, candidate.subject, candidate.not_after = leaf.sha256, leaf.subject, leaf.not_after
    codes = evaluation.codes()
    if not evaluation.has_ca:
        candidate.blocked.append(
            "the profile has no CA, so the certificate cannot be verified before pinning"
        )
    elif not evaluation.trusted:
        candidate.blocked.append(
            "the certificate is not signed by the CA in the profile; pinning it would trust an "
            "unverified certificate (the operator may have changed CA, or the connection is "
            "being intercepted)"
        )
    if codes & {"PURPOSE", "NAME"}:
        candidate.blocked.append(
            "the certificate would still fail remote-cert-tls / verify-x509-name, so a pin cannot help"
        )
    if client == "openvpn3" and codes & _ISSUER_TIME_CODES:
        candidate.blocked.append(
            "a CA in the chain is outside its validity period; OpenVPN 3 never overrides errors "
            "on a CA, so a pin cannot help (use --client openvpn2 for OpenVPN 2.6+)"
        )
    if not codes & (_TIME_CODES | _ISSUER_TIME_CODES):
        candidate.notes.append(
            "the certificate is currently valid; a pin is not needed and will stop working after "
            "the next renewal"
        )
    return candidate


def _first_token(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped[0] in "#;":
        return ""
    return stripped.split()[0].lower().lstrip("-")


def build_pinned_profile(
    original: str,
    candidates: list[PinCandidate],
    client: str,
    now: datetime | None = None,
) -> str:
    """Return the text of the pinned profile (the original text is never modified in place)."""
    if client not in CLIENTS:
        raise ValueError(f"client must be one of {CLIENTS}")
    now = now or datetime.now(timezone.utc)
    newline = "\r\n" if "\r\n" in original else "\n"
    drop_blocks = {"peer-fingerprint"} | ({"ca"} if client == "openvpn2" else set())
    drop_lines = {"peer-fingerprint"} | ({"ca", "capath"} if client == "openvpn2" else set())

    kept: list[str] = []
    insert_at: int | None = None
    skipping: str | None = None
    for line in original.splitlines():
        block = _BLOCK_RE.match(line)
        if skipping is not None:
            if block and block.group(1) == "/" and block.group(2).lower() == skipping:
                skipping = None
            continue
        if block and not block.group(1) and block.group(2).lower() in drop_blocks:
            skipping = block.group(2).lower()
            if insert_at is None:
                insert_at = len(kept)
            continue
        if _first_token(line) in drop_lines:
            if insert_at is None:
                insert_at = len(kept)
            continue
        if client == "openvpn3" and insert_at is None and block and block.group(2).lower() == "ca":
            insert_at = len(kept)
        kept.append(line)

    target = (
        "OpenVPN 3 (OpenVPN Connect, openvpn3-linux): CA kept, pin added"
        if client == "openvpn3"
        else "OpenVPN 2.6+ (fingerprint-only mode): CA removed, pin added"
    )
    pinned = [c for c in candidates if c.ok]
    header = [
        f"# --- Temporary certificate pin written by ovpncert {__version__} on {now:%Y-%m-%d %H:%M} UTC ---",
        "# The certificate(s) below were verified to be signed by the CA of the original",
        "# profile; the pin only overlooks their validity period.",
        f"# Target client: {target}.",
        "# When the operator renews the certificate this profile stops working",
        '# ("bad peer-fingerprint"); switch back to the original profile then.',
    ]
    for candidate in pinned:
        expiry = f"{candidate.not_after:%Y-%m-%d %H:%M:%S} UTC" if candidate.not_after else "?"
        header.append(f"#   {candidate.label}  {candidate.subject}  (notAfter {expiry})")
    block_lines = ["<peer-fingerprint>", *[c.fingerprint for c in pinned], "</peer-fingerprint>"]
    insertion = [*header, *block_lines, ""]
    if insert_at is None:
        if kept and kept[-1].strip():
            kept.append("")
        insert_at = len(kept)
    result = kept[:insert_at] + insertion + kept[insert_at:]
    return newline.join(result).rstrip() + newline


def pin_profile(
    profile: Profile, reports: list[RemoteReport], client: str, now: datetime | None = None
) -> PinResult:
    """Assess every remote and build the pinned profile if at least one can be pinned
    and none is blocked."""
    candidates = [assess(report, profile, client) for report in reports]
    result = PinResult(client, candidates)
    reachable = [c for c in candidates if c.fingerprint is not None]
    if reachable and all(c.ok for c in reachable):
        result.text = build_pinned_profile(profile.text, candidates, client, now)
    return result
