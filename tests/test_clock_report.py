import json
import socket
import socketserver
import struct
import threading
import time
from datetime import datetime, timezone
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fakeserver import FakeOpenVPNServer

from ovpncert.cli import main
from ovpncert.clock import NTP_EPOCH_OFFSET, check_clock, http_offset, sntp_offset
from ovpncert.diagnose import diagnose
from ovpncert.inspector import RemoteReport, inspect
from ovpncert.pin import pin_profile
from ovpncert.profile import Profile, Remote
from ovpncert.report import (
    Style,
    color_enabled,
    diagnosis_json,
    inspect_json,
    render_diagnosis,
    render_inspect,
    render_pin,
)
from ovpncert.statickey import StaticKey
from ovpncert.wire import TlsAuthWrapper


class FakeSntp:
    """Answers SNTP requests with a clock shifted by ``offset`` seconds."""

    def __init__(self, offset: float, mode: int = 4) -> None:
        self.offset, self.mode = offset, mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _stamp(self) -> bytes:
        now = time.time() + self.offset + NTP_EPOCH_OFFSET
        return struct.pack("!II", int(now), int((now % 1) * 2**32))

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                _data, addr = self.sock.recvfrom(512)
            except (TimeoutError, OSError):
                continue
            reply = bytes([0x20 | self.mode]) + b"\0" * 31 + self._stamp() + self._stamp()
            self.sock.sendto(reply, addr)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


class _DateHandler(BaseHTTPRequestHandler):
    offset = 0.0

    def do_HEAD(self):
        self.send_response_only(200)  # send_response() would add the real Date header first
        self.send_header("Date", formatdate(time.time() + self.offset, usegmt=True))
        self.end_headers()

    def log_message(self, *args):
        pass


class _QuickHTTPServer(HTTPServer):
    def server_bind(self):  # skip the reverse-DNS lookup HTTPServer does on bind
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


@pytest.fixture
def http_date_server():
    servers = []

    def start(offset: float):
        handler = type("Handler", (_DateHandler,), {"offset": offset})
        server = _QuickHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}/"

    yield start
    for server in servers:
        server.shutdown()


def test_sntp_offset_measures_shift():
    with FakeSntp(offset=100.0) as server:
        assert sntp_offset("127.0.0.1", 2, server.port) == pytest.approx(100.0, abs=0.5)


def test_sntp_rejects_non_server_reply():
    with FakeSntp(offset=0, mode=3) as server, pytest.raises(OSError):
        sntp_offset("127.0.0.1", 2, server.port)


def test_http_offset(http_date_server):
    assert http_offset(http_date_server(-3600), timeout=2) == pytest.approx(-3600, abs=2)


def test_check_clock_falls_back_to_http(http_date_server):
    with FakeSntp(offset=0, mode=3) as broken:
        result = check_clock([f"127.0.0.1:{broken.port}"], [http_date_server(42)], timeout=1)
    assert result.available and result.source.startswith("http://")
    assert result.offset_seconds == pytest.approx(42, abs=2)


def test_check_clock_reports_failure():
    result = check_clock(["127.0.0.1:not-a-port"], [], timeout=0.5)
    assert not result.available and "not-a-port" in result.error


def test_check_clock_prefers_ntp():
    with FakeSntp(offset=-7.0) as server:
        result = check_clock([f"127.0.0.1:{server.port}"], [], timeout=2)
    assert result.source == f"ntp://127.0.0.1:{server.port}"
    assert result.offset_seconds == pytest.approx(-7.0, abs=0.5)


@pytest.fixture
def expired_setup(pki, tmp_path, make_profile_text):
    cert, key = pki.files["expired"]
    wrapper = TlsAuthWrapper(StaticKey.parse(pki.static_key), 0, "SHA256")
    with FakeOpenVPNServer(cert, key, wrapper) as server:
        path = tmp_path / "client.ovpn"
        path.write_text(make_profile_text(server.port, ca_pem=pki.ca.cert_pem, tls_auth=pki.static_key))
        profile = Profile.from_file(path)
        now = datetime.now(timezone.utc)
        yield path, profile, inspect(profile, now=now), now


def test_render_diagnosis_and_json(expired_setup):
    _path, profile, reports, now = expired_setup
    unreachable = RemoteReport(Remote("down.lab.test"), error="cannot resolve down.lab.test")
    with FakeSntp(offset=0.3) as server:
        clock = check_clock([f"127.0.0.1:{server.port}"], [], timeout=2)
    result = diagnose(profile, [*reports, unreachable], now=now, clock=clock)
    text = render_diagnosis(result, Style(False))
    assert text.startswith("DIAGNOSIS  The server certificate has expired")
    assert "What to do" in text and "Evidence" in text and "offset +0" in text
    assert "down.lab.test:1194/udp: no certificate" in text
    coloured = render_diagnosis(result, Style(True))
    assert "\033[31m" in coloured
    data = diagnosis_json(result)
    assert data["primary"]["code"] == "SERVER_CERT_EXPIRED"
    assert json.dumps(data)  # serialisable


def test_render_inspect_and_pin(expired_setup):
    _path, profile, reports, now = expired_setup
    unreachable = RemoteReport(Remote("down.lab.test"), error="cannot resolve")
    text = render_inspect(profile, [*reports, unreachable], now, Style(False))
    assert "EXPIRED" in text and "no certificate" in text and "OpenVPN 2.x: rejects" in text
    assert inspect_json(profile, reports, now)["remotes"][0]["evaluation"]["trusted"] is True
    refused = pin_profile(profile, [unreachable], "openvpn3", now)
    assert "No pinned profile written" in render_pin(refused, None, Style(False))


def test_diagnose_cli(expired_setup, capsys):
    path, *_ = expired_setup
    assert main(["diagnose", str(path), "--no-clock-check", "--no-color"]) == 1
    assert "who can fix it: server operator" in capsys.readouterr().out
    assert main(["diagnose", str(path), "--no-clock-check", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["primary"]["owner"] == "server operator"


def test_color_detection(monkeypatch):
    class Tty:
        def isatty(self):
            return True

    monkeypatch.setenv("NO_COLOR", "1")
    assert not color_enabled(Tty())
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert color_enabled(object())
