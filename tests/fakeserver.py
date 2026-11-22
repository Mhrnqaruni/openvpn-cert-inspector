"""A minimal OpenVPN control-channel *server* used by the unit tests.

It answers the hard reset and runs the server side of the TLS handshake inside
``P_CONTROL_V1`` packets, with optional tls-auth or tls-crypt, over UDP or TCP.
It is not a VPN and stops after the TLS handshake. Interoperability with the
real OpenVPN implementation is covered separately by ``lab/run_lab.py``.
"""

from __future__ import annotations

import secrets
import socket
import ssl
import struct
import threading

from ovpncert.wire import (
    P_ACK_V1,
    P_CONTROL_HARD_RESET_CLIENT_V2,
    P_CONTROL_HARD_RESET_SERVER_V2,
    P_CONTROL_V1,
    ControlPacket,
    WireError,
)


class _Session:
    def __init__(self, server: FakeOpenVPNServer, send) -> None:
        self.server = server
        self.send_raw = send
        self.sid = secrets.token_bytes(8)
        self.peer_sid: bytes | None = None
        self.next_id = 0
        self.to_ack: list[int] = []
        self.expected = 1
        self.pending: dict[int, bytes] = {}
        self.reset_sent = False
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = server.tls_context.wrap_bio(self.incoming, self.outgoing, server_side=True)

    def _send(self, opcode: int, payload: bytes = b"", message_id: int | None = None) -> None:
        acks = self.to_ack[:8]
        del self.to_ack[:8]
        packet = ControlPacket(
            opcode,
            self.sid,
            acks=acks,
            ack_session_id=self.peer_sid if acks else None,
            message_id=message_id,
            payload=payload,
        )
        self.send_raw(self.server.wrapper.wrap(packet))

    def handle(self, packet: ControlPacket) -> None:
        if packet.opcode == P_CONTROL_HARD_RESET_CLIENT_V2:
            self.peer_sid = packet.session_id
            self.to_ack.append(packet.message_id)
            if self.server.silent:
                return
            self._send(P_CONTROL_HARD_RESET_SERVER_V2, b"", 0)
            if not self.reset_sent:
                self.reset_sent, self.next_id = True, 1
            return
        if packet.opcode != P_CONTROL_V1:
            return
        self.to_ack.append(packet.message_id)
        if packet.message_id >= self.expected:
            self.pending[packet.message_id] = packet.payload
        while self.expected in self.pending:
            self.incoming.write(self.pending.pop(self.expected))
            self.expected += 1
        try:
            self.tls.do_handshake()
            self.server.completed += 1
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLError:
            self.server.tls_failures += 1
        data = self.outgoing.read()
        for start in range(0, len(data), self.server.chunk):
            self._send(P_CONTROL_V1, data[start : start + self.server.chunk], self.next_id)
            self.next_id += 1
        if self.to_ack:
            self._send(P_ACK_V1)


class FakeOpenVPNServer:
    """Serve the OpenVPN control channel on 127.0.0.1 in a background thread."""

    def __init__(
        self,
        certfile,
        keyfile,
        wrapper,
        *,
        proto: str = "udp",
        max_tls: ssl.TLSVersion | None = None,
        client_ca=None,
        silent: bool = False,
        chunk: int = 1100,
    ) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile, keyfile)
        if max_tls is not None:
            context.maximum_version = max_tls
        if client_ca is not None:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(client_ca)
        self.tls_context = context
        self.wrapper = wrapper
        self.proto = proto
        self.silent = silent
        self.chunk = chunk
        self.completed = 0
        self.tls_failures = 0
        self.rejected = 0
        if proto == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        if proto == "tcp":
            self.sock.listen(8)
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> FakeOpenVPNServer:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()

    def _unwrap(self, raw: bytes) -> ControlPacket | None:
        try:
            return self.wrapper.unwrap(raw)
        except WireError:
            self.rejected += 1
            return None

    def _serve(self) -> None:
        if self.proto == "udp":
            self._serve_udp()
        else:
            self._serve_tcp()

    def _serve_udp(self) -> None:
        sessions: dict[tuple, _Session] = {}
        while not self._stop.is_set():
            try:
                raw, addr = self.sock.recvfrom(65535)
            except (TimeoutError, OSError):
                continue
            packet = self._unwrap(raw)
            if packet is None:
                continue
            session = sessions.get(addr)
            if session is None:
                if packet.opcode != P_CONTROL_HARD_RESET_CLIENT_V2:
                    continue
                session = _Session(self, lambda data, a=addr: self.sock.sendto(data, a))
                sessions[addr] = session
            session.handle(packet)

    def _serve_tcp(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._tcp_connection, args=(conn,), daemon=True).start()

    def _tcp_connection(self, conn: socket.socket) -> None:
        conn.settimeout(0.2)
        buffer = bytearray()
        session = _Session(self, lambda data: conn.sendall(struct.pack(">H", len(data)) + data))
        with conn:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except TimeoutError:
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                buffer += chunk
                while len(buffer) >= 2:
                    (length,) = struct.unpack(">H", buffer[:2])
                    if len(buffer) < 2 + length:
                        break
                    raw = bytes(buffer[2 : 2 + length])
                    del buffer[: 2 + length]
                    packet = self._unwrap(raw)
                    if packet is not None:
                        session.handle(packet)
