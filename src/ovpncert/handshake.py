"""Client side of the OpenVPN control channel, up to the end of the TLS handshake.

The probe does exactly what an OpenVPN client does first: a hard reset,
followed by a TLS handshake carried in reliable ``P_CONTROL_V1`` packets. Then
it stops. It never sends the key-method-2 message, so no username, password,
client certificate or client option reaches the server.
"""

from __future__ import annotations

import secrets
import ssl
import time
from dataclasses import dataclass, field

from .tlstap import TlsTap, alert_description
from .transport import Transport, TransportError
from .wire import (
    MAX_ACKS,
    P_ACK_V1,
    P_CONTROL_HARD_RESET_CLIENT_V2,
    P_CONTROL_HARD_RESET_SERVER_V2,
    P_CONTROL_V1,
    ControlPacket,
    WireError,
)

__all__ = [
    "STATUS_NO_REPLY",
    "STATUS_OK",
    "STATUS_TIMEOUT",
    "STATUS_TLS_ERROR",
    "STATUS_TRANSPORT_ERROR",
    "STATUS_UNAUTHENTICATED",
    "ControlChannelProbe",
    "HandshakeResult",
    "peer_chain",
]

STATUS_OK = "ok"
STATUS_NO_REPLY = "no-reply"
STATUS_UNAUTHENTICATED = "unauthenticated-reply"
STATUS_TLS_ERROR = "tls-error"
STATUS_TIMEOUT = "timeout"
STATUS_TRANSPORT_ERROR = "transport-error"


@dataclass
class HandshakeResult:
    status: str
    detail: str = ""
    chain: list[bytes] = field(default_factory=list)
    tls_version: str | None = None
    cipher: str | None = None
    completed: bool = False
    elapsed_ms: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    packets_rejected: int = 0

    @property
    def ok(self) -> bool:
        return bool(self.chain)


def peer_chain(tls: ssl.SSLObject) -> list[bytes]:
    """Return the server's certificate chain (leaf first) as DER bytes.

    Uses the public API on Python 3.13+, the equivalent private method on
    3.10-3.12, and falls back to the leaf certificate only.
    """
    for owner in (tls, getattr(tls, "_sslobj", None)):
        getter = getattr(owner, "get_unverified_chain", None)
        if getter is None:
            continue
        try:
            chain = getter()
        except (ssl.SSLError, ValueError, AttributeError):
            continue
        if chain:
            return [
                item if isinstance(item, bytes) else item.public_bytes(2)  # 2 = DER
                for item in chain
            ]
    leaf = tls.getpeercert(binary_form=True)
    return [leaf] if leaf else []


class ControlChannelProbe:
    """Run one handshake-only session against an OpenVPN server."""

    def __init__(
        self,
        transport: Transport,
        wrapper,
        *,
        timeout: float = 15.0,
        reset_timeout: float = 8.0,
        retransmit_interval: float = 1.5,
        max_payload: int = 1000,
        legacy_tls: bool = False,
    ) -> None:
        self.transport = transport
        self.wrapper = wrapper
        self.timeout = timeout
        self.reset_timeout = reset_timeout
        self.retransmit_interval = retransmit_interval
        self.max_payload = max_payload
        self.legacy_tls = legacy_tls
        self._sent = self._received = self._rejected = 0

    # -- reliability layer ---------------------------------------------------

    def _take_acks(self) -> list[int]:
        if self._remote_sid is None:
            return []
        acks: list[int] = []
        while self._to_ack and len(acks) < MAX_ACKS:
            message_id = self._to_ack.pop(0)
            if message_id not in acks:
                acks.append(message_id)
        return acks

    def _packet(self, opcode: int, message_id: int | None, payload: bytes) -> ControlPacket:
        acks = self._take_acks()
        return ControlPacket(
            opcode=opcode,
            session_id=self._local_sid,
            acks=acks,
            ack_session_id=self._remote_sid if acks else None,
            message_id=message_id,
            payload=payload,
        )

    def _send(self, packet: ControlPacket) -> None:
        self.transport.send(self.wrapper.wrap(packet))
        self._sent += 1

    def _send_reliable(self, opcode: int, payload: bytes) -> None:
        message_id = self._next_id
        self._next_id += 1
        self._send(self._packet(opcode, message_id, payload))
        self._unacked[message_id] = [opcode, payload, time.monotonic()]

    def _flush_acks(self) -> None:
        while self._to_ack and self._remote_sid is not None:
            self._send(self._packet(P_ACK_V1, None, b""))

    def _retransmit(self) -> None:
        if self.transport.kind != "udp":
            return
        now = time.monotonic()
        for message_id, entry in self._unacked.items():
            if now - entry[2] >= self.retransmit_interval:
                self._send(self._packet(entry[0], message_id, entry[1]))
                entry[2] = now

    def _receive(self, timeout: float) -> ControlPacket | None:
        end = time.monotonic() + timeout
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                return None
            raw = self.transport.recv(remaining)
            if raw is None:
                return None
            self._received += 1
            try:
                packet = self.wrapper.unwrap(raw)
            except WireError:
                self._rejected += 1
                continue
            if self._remote_sid is not None and packet.session_id != self._remote_sid:
                continue
            if packet.acks and packet.ack_session_id != self._local_sid:
                continue
            for ack in packet.acks:
                self._unacked.pop(ack, None)
            return packet

    # -- session -----------------------------------------------------------------

    def _tls_context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # verification is done by ovpncert.certs
        if self.legacy_tls:
            try:
                context.minimum_version = ssl.TLSVersion.TLSv1
                context.set_ciphers("DEFAULT:@SECLEVEL=0")
            except (ValueError, ssl.SSLError):
                pass
        return context

    def run(self) -> HandshakeResult:
        started = time.monotonic()
        try:
            result = self._run()
        except TransportError as exc:
            result = HandshakeResult(STATUS_TRANSPORT_ERROR, str(exc))
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        result.packets_sent = self._sent
        result.packets_received = self._received
        result.packets_rejected = self._rejected
        return result

    def _run(self) -> HandshakeResult:
        self._local_sid = secrets.token_bytes(8)
        self._remote_sid: bytes | None = None
        self._next_id = 0
        self._unacked: dict[int, list] = {}
        self._to_ack: list[int] = []

        self._send_reliable(P_CONTROL_HARD_RESET_CLIENT_V2, b"")
        deadline = time.monotonic() + self.reset_timeout
        while self._remote_sid is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return self._no_reply()
            packet = self._receive(min(remaining, self.retransmit_interval))
            if packet is None:
                self._retransmit()
                continue
            if packet.opcode == P_CONTROL_HARD_RESET_SERVER_V2:
                self._remote_sid = packet.session_id
                self._to_ack.append(packet.message_id)
        self._flush_acks()
        return self._tls()

    def _no_reply(self) -> HandshakeResult:
        if self._rejected:
            return HandshakeResult(
                STATUS_UNAUTHENTICATED,
                f"{self._rejected} reply packet(s) failed {self.wrapper.mode} authentication: "
                "the static key, key-direction or --auth digest does not match the server",
            )
        if getattr(self.transport, "icmp_unreachable", False):
            return HandshakeResult(
                STATUS_NO_REPLY, "ICMP port unreachable: nothing is listening on that port"
            )
        hint = (
            "the server silently drops packets that fail tls-auth/tls-crypt, so a wrong "
            "key, key-direction or --auth digest looks the same as a filtered port"
            if self.wrapper.mode != "none"
            else "the port may be filtered or the server may require tls-auth/tls-crypt"
        )
        return HandshakeResult(STATUS_NO_REPLY, f"no reply to the hard reset ({hint})")

    def _tls(self) -> HandshakeResult:
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        tls = self._tls_context().wrap_bio(incoming, outgoing, server_side=False)
        tap = TlsTap()
        expected, pending = 1, {}
        error: ssl.SSLError | None = None
        completed = False
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                tls.do_handshake()
                completed = True
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as exc:
                error = exc
            data = outgoing.read()
            for start in range(0, len(data), self.max_payload):
                self._send_reliable(P_CONTROL_V1, data[start : start + self.max_payload])
            if completed or error is not None or time.monotonic() > deadline:
                break
            self._flush_acks()
            packet = self._receive(min(self.retransmit_interval, max(0.05, deadline - time.monotonic())))
            if packet is None:
                self._retransmit()
                continue
            if packet.opcode in (P_CONTROL_V1, P_CONTROL_HARD_RESET_SERVER_V2):
                self._to_ack.append(packet.message_id)
            if packet.opcode == P_CONTROL_V1 and packet.message_id >= expected:
                pending[packet.message_id] = packet.payload
                while expected in pending:
                    chunk = pending.pop(expected)
                    expected += 1
                    tap.feed(chunk)
                    incoming.write(chunk)
        self._flush_acks()

        chain = peer_chain(tls) if completed else []
        if not chain and tap.certificates:
            chain = list(tap.certificates)
        version = (tls.version() if completed else None) or tap.version
        cipher = tls.cipher()[0] if completed and tls.cipher() else None
        if chain:
            detail = ""
            if not completed:
                detail = "handshake not completed; certificate read from cleartext TLS records" + (
                    f" ({error})" if error else ""
                )
            return HandshakeResult(STATUS_OK, detail, chain, version, cipher, completed=completed)
        if error is not None:
            detail = str(error)
            if tap.alert:
                detail += f"; server sent TLS alert {alert_description(tap.alert[1])}"
            return HandshakeResult(STATUS_TLS_ERROR, detail, tls_version=version)
        return HandshakeResult(STATUS_TIMEOUT, "TLS handshake did not finish in time")
