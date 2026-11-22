"""Measure the local clock offset, because a wrong clock makes valid certificates
look expired (or not yet valid) to every TLS client."""

from __future__ import annotations

import socket
import struct
import time
import urllib.request
from dataclasses import dataclass
from email.utils import parsedate_to_datetime

__all__ = ["ClockCheck", "check_clock", "http_offset", "sntp_offset"]

NTP_EPOCH_OFFSET = 2208988800  # seconds between 1900-01-01 and 1970-01-01
DEFAULT_NTP_SERVERS = ("pool.ntp.org", "time.cloudflare.com")
DEFAULT_HTTP_URLS = ("https://www.cloudflare.com/", "https://www.google.com/")


@dataclass
class ClockCheck:
    offset_seconds: float | None
    source: str
    error: str | None = None

    @property
    def available(self) -> bool:
        return self.offset_seconds is not None


def sntp_offset(server: str, timeout: float = 3.0) -> float:
    """Return ``server_time - local_time`` in seconds using one SNTP (RFC 4330) exchange."""
    request = b"\x23" + 47 * b"\0"  # LI=0, VN=4, Mode=3 (client)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        t1 = time.time()
        sock.sendto(request, (server, 123))
        data, _ = sock.recvfrom(512)
        t4 = time.time()
    if len(data) < 48:
        raise OSError("short SNTP reply")

    def stamp(offset: int) -> float:
        seconds, fraction = struct.unpack("!II", data[offset : offset + 8])
        return seconds - NTP_EPOCH_OFFSET + fraction / 2**32

    t2, t3 = stamp(32), stamp(40)
    return ((t2 - t1) + (t3 - t4)) / 2


def http_offset(url: str, timeout: float = 5.0) -> float:
    """Return the offset from an HTTPS server's ``Date`` header (1 s resolution)."""
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "ovpncert"})
    t1 = time.time()
    with urllib.request.urlopen(request, timeout=timeout) as response:
        header = response.headers.get("Date")
    t2 = time.time()
    if not header:
        raise OSError("no Date header")
    return parsedate_to_datetime(header).timestamp() - (t1 + t2) / 2


def check_clock(ntp_servers=DEFAULT_NTP_SERVERS, http_urls=DEFAULT_HTTP_URLS) -> ClockCheck:
    errors = []
    for server in ntp_servers:
        try:
            return ClockCheck(sntp_offset(server), f"ntp://{server}")
        except OSError as exc:
            errors.append(f"{server}: {exc}")
    for url in http_urls:
        try:
            return ClockCheck(http_offset(url), url)
        except OSError as exc:
            errors.append(f"{url}: {exc}")
    return ClockCheck(None, "", "; ".join(errors) or "no time source configured")
