"""Passive reader of the server's cleartext TLS records.

With TLS 1.2 and earlier the server's ``Certificate`` message travels in clear
text, so it can be captured even when the handshake is aborted later (for
instance by a server that insists on a client certificate). With TLS 1.3 the
certificate is encrypted; it is then read from the completed client side of
the handshake instead.
"""

from __future__ import annotations

__all__ = ["TlsTap", "alert_description"]

_LEGACY_VERSIONS = {b"\x03\x01": "TLSv1", b"\x03\x02": "TLSv1.1", b"\x03\x03": "TLSv1.2"}

_ALERTS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    109: "missing_extension",
    112: "unrecognized_name",
    116: "certificate_required",
    120: "no_application_protocol",
}


def alert_description(code: int) -> str:
    return _ALERTS.get(code, f"alert {code}")


class TlsTap:
    """Collect ServerHello version, the cleartext certificate list and alerts."""

    def __init__(self) -> None:
        self._records = bytearray()
        self._handshake = bytearray()
        self.version: str | None = None
        self.certificates: list[bytes] = []
        self.alert: tuple[int, int] | None = None
        self.encrypted = False

    def feed(self, data: bytes) -> None:
        if self.encrypted:
            return
        self._records += data
        while len(self._records) >= 5 and not self.encrypted:
            content_type = self._records[0]
            length = int.from_bytes(self._records[3:5], "big")
            if len(self._records) < 5 + length:
                return
            fragment = bytes(self._records[5 : 5 + length])
            del self._records[: 5 + length]
            if content_type == 22:  # handshake
                self._handshake += fragment
                self._parse_handshake()
            elif content_type == 21 and len(fragment) >= 2:  # alert
                self.alert = (fragment[0], fragment[1])
            elif content_type in (20, 23):  # change_cipher_spec / application_data
                self.encrypted = True

    def _parse_handshake(self) -> None:
        while len(self._handshake) >= 4:
            msg_type = self._handshake[0]
            length = int.from_bytes(self._handshake[1:4], "big")
            if len(self._handshake) < 4 + length:
                return
            body = bytes(self._handshake[4 : 4 + length])
            del self._handshake[: 4 + length]
            try:
                if msg_type == 2:
                    self._server_hello(body)
                elif msg_type == 11:
                    self._certificate(body)
            except (IndexError, ValueError):
                continue

    def _server_hello(self, body: bytes) -> None:
        version = _LEGACY_VERSIONS.get(body[0:2])
        offset = 2 + 32
        offset += 1 + body[offset]  # session id
        offset += 2 + 1  # cipher suite, compression method
        if offset + 2 <= len(body):
            end = offset + 2 + int.from_bytes(body[offset : offset + 2], "big")
            offset += 2
            while offset + 4 <= min(end, len(body)):
                ext_type = int.from_bytes(body[offset : offset + 2], "big")
                ext_len = int.from_bytes(body[offset + 2 : offset + 4], "big")
                if ext_type == 43 and body[offset + 4 : offset + 6] == b"\x03\x04":
                    version = "TLSv1.3"
                offset += 4 + ext_len
        self.version = version

    def _certificate(self, body: bytes) -> None:
        total = int.from_bytes(body[0:3], "big")
        offset, end = 3, min(3 + total, len(body))
        certificates = []
        while offset + 3 <= end:
            length = int.from_bytes(body[offset : offset + 3], "big")
            offset += 3
            certificates.append(body[offset : offset + length])
            offset += length
        if certificates:
            self.certificates = certificates
