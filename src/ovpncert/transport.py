"""UDP and TCP transports for OpenVPN packets.

Over UDP every datagram is one OpenVPN packet. Over TCP each packet is
prefixed with its length as a 16-bit big-endian integer.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Protocol

__all__ = [
    "TcpTransport",
    "Transport",
    "TransportError",
    "UdpTransport",
    "normalize_proto",
    "open_transport",
    "resolve",
]


class TransportError(OSError):
    """The connection to the server failed or was closed."""


class Transport(Protocol):
    kind: str

    def send(self, packet: bytes) -> None: ...

    def recv(self, timeout: float) -> bytes | None: ...

    def close(self) -> None: ...


def normalize_proto(proto: str) -> tuple[str, int]:
    """Return ``(kind, address_family)`` for an OpenVPN ``proto`` value.

    Accepts ``udp``, ``udp4``, ``udp6``, ``tcp``, ``tcp4``, ``tcp6`` and the
    ``-client`` variants of the TCP forms.
    """
    value = proto.strip().lower()
    if value.startswith("udp"):
        kind = "udp"
    elif value.startswith("tcp"):
        kind = "tcp"
    else:
        raise ValueError(f"unsupported protocol {proto!r}")
    rest = value[3:]
    if rest.startswith("4"):
        family = socket.AF_INET
    elif rest.startswith("6"):
        family = socket.AF_INET6
    else:
        family = socket.AF_UNSPEC
    return kind, family


def resolve(host: str, port: int, proto: str) -> list[tuple[int, tuple]]:
    """Resolve ``host`` to a de-duplicated list of ``(family, sockaddr)``."""
    kind, family = normalize_proto(proto)
    socktype = socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM
    results: list[tuple[int, tuple]] = []
    for fam, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, port, family, socktype):
        if (fam, sockaddr) not in results:
            results.append((fam, sockaddr))
    return results


class UdpTransport:
    kind = "udp"

    def __init__(self, family: int, sockaddr: tuple) -> None:
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.connect(sockaddr)
        self.icmp_unreachable = False

    def send(self, packet: bytes) -> None:
        try:
            self.sock.send(packet)
        except (ConnectionResetError, ConnectionRefusedError):
            self.icmp_unreachable = True

    def recv(self, timeout: float) -> bytes | None:
        self.sock.settimeout(max(timeout, 0.001))
        try:
            return self.sock.recv(65535)
        except TimeoutError:
            return None
        except (ConnectionResetError, ConnectionRefusedError):
            # An ICMP "port unreachable" surfaces here on connected UDP sockets.
            self.icmp_unreachable = True
            return None

    def close(self) -> None:
        self.sock.close()


class TcpTransport:
    kind = "tcp"

    def __init__(self, family: int, sockaddr: tuple, connect_timeout: float) -> None:
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.settimeout(connect_timeout)
        try:
            self.sock.connect(sockaddr)
        except OSError as exc:
            self.sock.close()
            raise TransportError(f"TCP connection failed: {exc}") from exc
        self._buffer = bytearray()

    def send(self, packet: bytes) -> None:
        try:
            self.sock.sendall(struct.pack(">H", len(packet)) + packet)
        except OSError as exc:
            raise TransportError(f"TCP send failed: {exc}") from exc

    def recv(self, timeout: float) -> bytes | None:
        deadline = time.monotonic() + timeout
        while True:
            if len(self._buffer) >= 2:
                (length,) = struct.unpack(">H", self._buffer[:2])
                if len(self._buffer) >= 2 + length:
                    packet = bytes(self._buffer[2 : 2 + length])
                    del self._buffer[: 2 + length]
                    return packet
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError:
                return None
            except OSError as exc:
                raise TransportError(f"TCP receive failed: {exc}") from exc
            if not chunk:
                raise TransportError("server closed the TCP connection")
            self._buffer += chunk

    def close(self) -> None:
        self.sock.close()


def open_transport(kind: str, family: int, sockaddr: tuple, timeout: float) -> Transport:
    if kind == "udp":
        return UdpTransport(family, sockaddr)
    return TcpTransport(family, sockaddr, timeout)
