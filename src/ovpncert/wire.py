"""OpenVPN control-channel packets and the three ways they are protected.

Layout of a control packet before protection::

    opcode<<3 | key_id (1) | session_id (8)
    | ack_count (1) | acked message ids (4 each)
    | peer session_id (8, present only when ack_count > 0)
    | message id (4, absent in P_ACK_V1) | payload

``tls-auth`` inserts ``HMAC | packet_id (4) | net_time (4)`` after the session
id. The HMAC covers ``packet_id | net_time | opcode | session_id | rest``, i.e.
the replay fields are moved to the front before hashing.

``tls-crypt`` appends ``packet_id | net_time`` to the 9-byte header, then a
32-byte HMAC-SHA256 tag over ``header | plaintext``, then the plaintext
encrypted with AES-256-CTR whose initial counter block is the first 16 bytes
of the tag (a synthetic IV).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .statickey import StaticKey, direction_indices

__all__ = [
    "HEADER_LEN",
    "MAX_ACKS",
    "OPCODE_NAMES",
    "P_ACK_V1",
    "P_CONTROL_HARD_RESET_CLIENT_V2",
    "P_CONTROL_HARD_RESET_CLIENT_V3",
    "P_CONTROL_HARD_RESET_SERVER_V2",
    "P_CONTROL_SOFT_RESET_V1",
    "P_CONTROL_V1",
    "ControlPacket",
    "PlainWrapper",
    "TlsAuthWrapper",
    "TlsCryptWrapper",
    "WireError",
    "normalize_digest",
]

P_CONTROL_SOFT_RESET_V1 = 3
P_CONTROL_V1 = 4
P_ACK_V1 = 5
P_DATA_V1 = 6
P_CONTROL_HARD_RESET_CLIENT_V2 = 7
P_CONTROL_HARD_RESET_SERVER_V2 = 8
P_DATA_V2 = 9
P_CONTROL_HARD_RESET_CLIENT_V3 = 10
P_CONTROL_WKC_V1 = 11

OPCODE_NAMES = {
    P_CONTROL_SOFT_RESET_V1: "P_CONTROL_SOFT_RESET_V1",
    P_CONTROL_V1: "P_CONTROL_V1",
    P_ACK_V1: "P_ACK_V1",
    P_DATA_V1: "P_DATA_V1",
    P_CONTROL_HARD_RESET_CLIENT_V2: "P_CONTROL_HARD_RESET_CLIENT_V2",
    P_CONTROL_HARD_RESET_SERVER_V2: "P_CONTROL_HARD_RESET_SERVER_V2",
    P_DATA_V2: "P_DATA_V2",
    P_CONTROL_HARD_RESET_CLIENT_V3: "P_CONTROL_HARD_RESET_CLIENT_V3",
    P_CONTROL_WKC_V1: "P_CONTROL_WKC_V1",
}

SESSION_ID_LEN = 8
HEADER_LEN = 1 + SESSION_ID_LEN
REPLAY_LEN = 8
MAX_ACKS = 8


class WireError(ValueError):
    """A packet is malformed or failed authentication."""


@dataclass
class ControlPacket:
    """A decoded control-channel packet (without the protection layer)."""

    opcode: int
    session_id: bytes
    key_id: int = 0
    acks: list[int] = field(default_factory=list)
    ack_session_id: bytes | None = None
    message_id: int | None = None
    payload: bytes = b""

    @property
    def header(self) -> bytes:
        if len(self.session_id) != SESSION_ID_LEN:
            raise WireError("session id must be 8 bytes")
        return bytes([(self.opcode << 3) | (self.key_id & 0x07)]) + self.session_id

    def body(self) -> bytes:
        if len(self.acks) > 255:
            raise WireError("too many acknowledgements in one packet")
        out = bytearray([len(self.acks)])
        for ack in self.acks:
            out += struct.pack(">I", ack)
        if self.acks:
            if self.ack_session_id is None or len(self.ack_session_id) != SESSION_ID_LEN:
                raise WireError("acknowledgements require the peer session id")
            out += self.ack_session_id
        if self.opcode != P_ACK_V1:
            if self.message_id is None:
                raise WireError("control packets need a message id")
            out += struct.pack(">I", self.message_id)
        out += self.payload
        return bytes(out)

    @classmethod
    def from_parts(cls, header: bytes, body: bytes) -> ControlPacket:
        if len(header) != HEADER_LEN:
            raise WireError("bad header length")
        if not body:
            raise WireError("empty control packet body")
        opcode, key_id = header[0] >> 3, header[0] & 0x07
        count = body[0]
        offset = 1
        if len(body) < offset + 4 * count + (SESSION_ID_LEN if count else 0):
            raise WireError("truncated acknowledgement array")
        acks = list(struct.unpack(f">{count}I", body[offset : offset + 4 * count]))
        offset += 4 * count
        ack_session_id = None
        if count:
            ack_session_id = body[offset : offset + SESSION_ID_LEN]
            offset += SESSION_ID_LEN
        message_id = None
        if opcode != P_ACK_V1:
            if len(body) < offset + 4:
                raise WireError("truncated message id")
            (message_id,) = struct.unpack(">I", body[offset : offset + 4])
            offset += 4
        return cls(
            opcode=opcode,
            key_id=key_id,
            session_id=header[1:],
            acks=acks,
            ack_session_id=ack_session_id,
            message_id=message_id,
            payload=body[offset:],
        )


class _ReplayCounter:
    """Long-form packet id (32-bit counter + 32-bit time) used by tls-auth/tls-crypt."""

    def __init__(self, start_time: int | None = None) -> None:
        self.packet_id = 0
        self.time = int(time.time()) if start_time is None else start_time

    def next(self) -> bytes:
        self.packet_id += 1
        return struct.pack(">II", self.packet_id, self.time)


class PlainWrapper:
    """No control-channel protection (neither tls-auth nor tls-crypt)."""

    mode = "none"
    overhead = 0

    def wrap(self, packet: ControlPacket) -> bytes:
        return packet.header + packet.body()

    def unwrap(self, data: bytes) -> ControlPacket:
        if len(data) < HEADER_LEN + 1:
            raise WireError("short packet")
        return ControlPacket.from_parts(data[:HEADER_LEN], data[HEADER_LEN:])


def normalize_digest(name: str) -> str:
    """Map an OpenVPN ``--auth`` name (``SHA256``, ``SHA-512`` ...) to hashlib."""
    lowered = name.strip().lower()
    for candidate in (lowered.replace("-", ""), lowered, lowered.replace("-", "_")):
        try:
            hashlib.new(candidate)
        except ValueError:
            continue
        return candidate
    raise WireError(f"unsupported HMAC digest {name!r}")


class TlsAuthWrapper:
    """``--tls-auth``: an HMAC "firewall" in front of every control packet."""

    mode = "tls-auth"

    def __init__(
        self,
        key: StaticKey,
        key_direction: int | None,
        digest: str = "SHA1",
        *,
        start_time: int | None = None,
    ) -> None:
        self.digest = normalize_digest(digest)
        self.size = hashlib.new(self.digest).digest_size
        if self.size > 64:
            raise WireError(f"digest {digest!r} is longer than the 64-byte HMAC slot")
        out_index, in_index = direction_indices(key_direction)
        self._out_key = key.hmac_slot(out_index)[: self.size]
        self._in_key = key.hmac_slot(in_index)[: self.size]
        self._replay = _ReplayCounter(start_time)
        self.overhead = self.size + REPLAY_LEN

    def wrap(self, packet: ControlPacket) -> bytes:
        header, body = packet.header, packet.body()
        replay = self._replay.next()
        mac = hmac.new(self._out_key, replay + header + body, self.digest).digest()
        return header + mac + replay + body

    def unwrap(self, data: bytes) -> ControlPacket:
        start = HEADER_LEN + self.size + REPLAY_LEN
        if len(data) < start + 1:
            raise WireError("short packet")
        header = data[:HEADER_LEN]
        mac = data[HEADER_LEN : HEADER_LEN + self.size]
        replay = data[HEADER_LEN + self.size : start]
        body = data[start:]
        expected = hmac.new(self._in_key, replay + header + body, self.digest).digest()
        if not hmac.compare_digest(mac, expected):
            raise WireError("tls-auth HMAC verification failed")
        return ControlPacket.from_parts(header, body)


def _aes256_ctr(key: bytes, counter_block: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(counter_block)).encryptor()
    return cipher.update(data) + cipher.finalize()


class TlsCryptWrapper:
    """``--tls-crypt``: authenticated encryption of every control packet.

    The client sends with key 1 and receives with key 0 (the server uses the
    opposite), mirroring OpenVPN's fixed key direction for tls-crypt.
    """

    mode = "tls-crypt"
    TAG_LEN = 32

    def __init__(self, key: StaticKey, *, server: bool = False, start_time: int | None = None):
        out_index, in_index = (0, 1) if server else (1, 0)
        self._enc_key = key.cipher_slot(out_index)[:32]
        self._enc_mac = key.hmac_slot(out_index)[:32]
        self._dec_key = key.cipher_slot(in_index)[:32]
        self._dec_mac = key.hmac_slot(in_index)[:32]
        self._replay = _ReplayCounter(start_time)
        self.overhead = REPLAY_LEN + self.TAG_LEN

    def wrap(self, packet: ControlPacket) -> bytes:
        associated = packet.header + self._replay.next()
        plaintext = packet.body()
        tag = hmac.new(self._enc_mac, associated + plaintext, "sha256").digest()
        return associated + tag + _aes256_ctr(self._enc_key, tag[:16], plaintext)

    def unwrap(self, data: bytes) -> ControlPacket:
        start = HEADER_LEN + REPLAY_LEN + self.TAG_LEN
        if len(data) < start + 1:
            raise WireError("short packet")
        associated = data[: HEADER_LEN + REPLAY_LEN]
        tag = data[HEADER_LEN + REPLAY_LEN : start]
        plaintext = _aes256_ctr(self._dec_key, tag[:16], data[start:])
        expected = hmac.new(self._dec_mac, associated + plaintext, "sha256").digest()
        if not hmac.compare_digest(tag, expected):
            raise WireError("tls-crypt authentication failed")
        return ControlPacket.from_parts(associated[:HEADER_LEN], plaintext)
