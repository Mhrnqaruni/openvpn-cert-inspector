"""Probe the remotes of a profile and evaluate the chain each server presents."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509

from .certs import CertInfo, ChainEvaluation, evaluate, load_pem_certificates
from .handshake import STATUS_NO_REPLY, STATUS_TRANSPORT_ERROR, ControlChannelProbe, HandshakeResult
from .profile import Profile, ProfileError, Remote
from .transport import TransportError, normalize_proto, open_transport, resolve

__all__ = ["ProbeOptions", "RemoteReport", "anchors_for", "inspect", "probe_remote", "reevaluate"]


@dataclass
class ProbeOptions:
    timeout: float = 15.0
    reset_timeout: float = 8.0
    legacy_tls: bool = False
    workers: int = 8


@dataclass
class RemoteReport:
    remote: Remote
    address: str | None = None
    handshake: HandshakeResult | None = None
    error: str | None = None
    evaluation: ChainEvaluation | None = None

    @property
    def reachable(self) -> bool:
        return self.handshake is not None and self.handshake.ok

    @property
    def leaf(self) -> CertInfo | None:
        return self.evaluation.leaf if self.evaluation else None

    @property
    def failure(self) -> str:
        if self.error:
            return self.error
        if self.handshake is not None and not self.handshake.ok:
            return f"{self.handshake.status}: {self.handshake.detail}"
        return ""


def anchors_for(profile: Profile) -> list[x509.Certificate]:
    try:
        return load_pem_certificates(profile.ca_pem)
    except ValueError as exc:
        raise ProfileError(f"--ca: cannot parse the CA certificate(s): {exc}") from exc


def reevaluate(report: RemoteReport, profile: Profile, now: datetime) -> ChainEvaluation | None:
    """Re-run verification of an already captured chain at another point in time."""
    if not report.reachable:
        return None
    return evaluate(
        report.handshake.chain,
        anchors_for(profile),
        now,
        remote_cert_tls=profile.remote_cert_tls,
        verify_x509_name=profile.verify_x509_name,
        pins=profile.peer_fingerprints,
    )


def probe_remote(profile: Profile, remote: Remote, options: ProbeOptions, now: datetime) -> RemoteReport:
    report = RemoteReport(remote)
    try:
        kind, _family = normalize_proto(remote.proto)
        addresses = resolve(remote.host, remote.port, remote.proto)
    except (socket.gaierror, ValueError) as exc:
        report.error = f"cannot resolve {remote.host}: {exc}"
        return report
    for family, sockaddr in addresses:
        report.address = sockaddr[0]
        try:
            transport = open_transport(kind, family, sockaddr, options.timeout)
        except TransportError as exc:
            report.error = str(exc)
            continue
        try:
            result = ControlChannelProbe(
                transport,
                profile.make_wrapper(),
                timeout=options.timeout,
                reset_timeout=options.reset_timeout,
                legacy_tls=options.legacy_tls,
            ).run()
        finally:
            transport.close()
        report.handshake, report.error = result, None
        if result.status not in (STATUS_NO_REPLY, STATUS_TRANSPORT_ERROR):
            break
    if report.reachable:
        report.evaluation = reevaluate(report, profile, now)
    return report


def inspect(
    profile: Profile,
    options: ProbeOptions | None = None,
    now: datetime | None = None,
    remotes: list[Remote] | None = None,
) -> list[RemoteReport]:
    """Probe every remote of ``profile`` (concurrently) and evaluate the results."""
    options = options or ProbeOptions()
    now = now or datetime.now(timezone.utc)
    targets = list(remotes or profile.remotes)
    if not targets:
        raise ProfileError("no remote to probe: the profile has no 'remote' and none was given")
    anchors_for(profile)  # fail early on a malformed CA
    workers = max(1, min(options.workers, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda r: probe_remote(profile, r, options, now), targets))
