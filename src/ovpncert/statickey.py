"""OpenVPN static key files (``-----BEGIN OpenVPN Static key V1-----``).

A static key holds 2048 bits split into two directional halves. Each half is a
64-byte cipher slot followed by a 64-byte HMAC slot::

    offset   0  key[0].cipher  (64 bytes)
    offset  64  key[0].hmac    (64 bytes)
    offset 128  key[1].cipher  (64 bytes)
    offset 192  key[1].hmac    (64 bytes)

``tls-auth`` uses only the HMAC slots, truncated to the digest size of
``--auth``. ``tls-crypt`` uses the first 32 bytes of a cipher slot for
AES-256-CTR and the first 32 bytes of an HMAC slot for HMAC-SHA256.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

__all__ = ["KEY_LEN", "StaticKey", "StaticKeyError", "direction_indices"]

KEY_LEN = 256
SLOT_LEN = 64

_BLOCK = re.compile(
    r"-----BEGIN OpenVPN Static key V1-----(.*?)-----END OpenVPN Static key V1-----",
    re.S,
)


class StaticKeyError(ValueError):
    """Raised when a static key is missing or malformed."""


@dataclass(frozen=True)
class StaticKey:
    """A parsed 2048-bit OpenVPN static key.

    Key material is deliberately kept out of ``repr()`` so that keys never end
    up in logs or tracebacks.
    """

    material: bytes

    def __post_init__(self) -> None:
        if len(self.material) != KEY_LEN:
            raise StaticKeyError(f"static key must be {KEY_LEN} bytes, got {len(self.material)}")

    def __repr__(self) -> str:
        return "StaticKey(<redacted>)"

    @classmethod
    def parse(cls, text: str) -> StaticKey:
        """Parse the PEM-like text form used by ``openvpn --genkey``."""
        match = _BLOCK.search(text)
        if match is None:
            raise StaticKeyError("no 'OpenVPN Static key V1' block found")
        digits = "".join(
            line.strip()
            for line in match.group(1).splitlines()
            if line.strip() and not line.strip().startswith(("#", ";"))
        )
        try:
            material = bytes.fromhex(digits)
        except ValueError as exc:
            raise StaticKeyError("static key contains non-hexadecimal characters") from exc
        return cls(material)

    @classmethod
    def from_file(cls, path: str | Path) -> StaticKey:
        return cls.parse(Path(path).read_text(encoding="utf-8", errors="replace"))

    def to_text(self) -> str:
        """Serialise in the ``openvpn --genkey`` format (16 lines of 16 bytes)."""
        hex_lines = [self.material[i : i + 16].hex() for i in range(0, KEY_LEN, 16)]
        return (
            "-----BEGIN OpenVPN Static key V1-----\n"
            + "\n".join(hex_lines)
            + "\n-----END OpenVPN Static key V1-----\n"
        )

    def cipher_slot(self, index: int) -> bytes:
        start = index * 2 * SLOT_LEN
        return self.material[start : start + SLOT_LEN]

    def hmac_slot(self, index: int) -> bytes:
        start = index * 2 * SLOT_LEN + SLOT_LEN
        return self.material[start : start + SLOT_LEN]


def direction_indices(key_direction: int | None) -> tuple[int, int]:
    """Return ``(outgoing, incoming)`` key indices for an OpenVPN ``key-direction``.

    ``0`` is the normal direction (send with key 0, receive with key 1), ``1``
    is the inverse, and ``None`` means bidirectional: both use key 0.
    """
    if key_direction is None:
        return 0, 0
    if key_direction == 0:
        return 0, 1
    if key_direction == 1:
        return 1, 0
    raise StaticKeyError(f"key-direction must be 0 or 1, got {key_direction!r}")
