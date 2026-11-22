import socket
import ssl

import pytest
from fakeserver import FakeOpenVPNServer

from ovpncert.handshake import (
    STATUS_NO_REPLY,
    STATUS_OK,
    STATUS_UNAUTHENTICATED,
    ControlChannelProbe,
)
from ovpncert.statickey import StaticKey
from ovpncert.transport import open_transport
from ovpncert.wire import PlainWrapper, TlsAuthWrapper, TlsCryptWrapper


def wrappers(mode: str, key_text: str):
    """(server wrapper, client wrapper) for a protection mode."""
    if mode == "none":
        return PlainWrapper(), PlainWrapper()
    key = StaticKey.parse(key_text)
    if mode == "tls-auth":
        return TlsAuthWrapper(key, 0, "SHA256"), TlsAuthWrapper(key, 1, "SHA256")
    return TlsCryptWrapper(key, server=True), TlsCryptWrapper(key)


def run_probe(server: FakeOpenVPNServer, client_wrapper, proto: str = "udp", **kwargs):
    transport = open_transport(proto, socket.AF_INET, ("127.0.0.1", server.port), 5)
    try:
        return ControlChannelProbe(transport, client_wrapper, timeout=8, **kwargs).run()
    finally:
        transport.close()


@pytest.mark.parametrize("proto", ["udp", "tcp"])
@pytest.mark.parametrize("mode", ["none", "tls-auth", "tls-crypt"])
def test_handshake_retrieves_certificate(pki, proto, mode):
    server_wrapper, client_wrapper = wrappers(mode, pki.static_key)
    cert, key = pki.files["valid"]
    with FakeOpenVPNServer(cert, key, server_wrapper, proto=proto) as server:
        result = run_probe(server, client_wrapper, proto)
    assert result.status == STATUS_OK, result.detail
    assert result.completed and result.tls_version == "TLSv1.3"
    assert result.chain[0] == pki.leaves["valid"].der
    assert result.packets_rejected == 0


def test_tls12_and_full_chain(pki):
    server_wrapper, client_wrapper = wrappers("tls-auth", pki.static_key)
    cert, key = pki.files["intermediate"]
    with FakeOpenVPNServer(cert, key, server_wrapper, max_tls=ssl.TLSVersion.TLSv1_2) as server:
        result = run_probe(server, client_wrapper)
    assert result.status == STATUS_OK and result.tls_version == "TLSv1.2"
    assert len(result.chain) == 2  # leaf + intermediate, as sent by the server


def test_small_fragments_are_reassembled(pki):
    server_wrapper, client_wrapper = wrappers("tls-crypt", pki.static_key)
    cert, key = pki.files["rsa"]
    with FakeOpenVPNServer(cert, key, server_wrapper, chunk=100) as server:
        result = run_probe(server, client_wrapper, max_payload=120)
    assert result.status == STATUS_OK
    assert result.chain[0] == pki.leaves["rsa"].der


def test_tls12_server_requiring_client_cert_still_reveals_certificate(pki):
    server_wrapper, client_wrapper = wrappers("none", pki.static_key)
    cert, key = pki.files["valid"]
    with FakeOpenVPNServer(
        cert, key, server_wrapper, max_tls=ssl.TLSVersion.TLSv1_2, client_ca=pki.ca_file
    ) as server:
        result = run_probe(server, client_wrapper)
    assert result.status == STATUS_OK
    assert not result.completed
    assert "cleartext" in result.detail
    assert result.chain[0] == pki.leaves["valid"].der


def test_tls13_server_requiring_client_cert(pki):
    server_wrapper, client_wrapper = wrappers("tls-auth", pki.static_key)
    cert, key = pki.files["valid"]
    with FakeOpenVPNServer(cert, key, server_wrapper, client_ca=pki.ca_file) as server:
        result = run_probe(server, client_wrapper)
    assert result.status == STATUS_OK and result.completed


def test_wrong_tls_auth_key_gets_no_reply(pki):
    server_wrapper, _ = wrappers("tls-auth", pki.static_key)
    _, client_wrapper = wrappers("tls-auth", pki.other_static_key)
    cert, key = pki.files["valid"]
    with FakeOpenVPNServer(cert, key, server_wrapper) as server:
        result = run_probe(server, client_wrapper, reset_timeout=1.5, retransmit_interval=0.5)
        assert server.rejected >= 1
    assert result.status == STATUS_NO_REPLY
    assert "tls-auth" in result.detail


class _WrongReplyKey:
    """Accepts the client's packets but signs replies with another key."""

    mode = "tls-auth"

    def __init__(self, good, bad):
        self.good, self.bad = good, bad

    def unwrap(self, data):
        return self.good.unwrap(data)

    def wrap(self, packet):
        return self.bad.wrap(packet)


def test_unauthenticated_reply_is_reported(pki):
    good_server, client_wrapper = wrappers("tls-auth", pki.static_key)
    bad_server, _ = wrappers("tls-auth", pki.other_static_key)
    cert, key = pki.files["valid"]
    with FakeOpenVPNServer(cert, key, _WrongReplyKey(good_server, bad_server)) as server:
        result = run_probe(server, client_wrapper, reset_timeout=1.5, retransmit_interval=0.5)
    assert result.status == STATUS_UNAUTHENTICATED
    assert result.packets_rejected >= 1


def test_silent_server(pki):
    server_wrapper, client_wrapper = wrappers("none", pki.static_key)
    cert, key = pki.files["valid"]
    with FakeOpenVPNServer(cert, key, server_wrapper, silent=True) as server:
        result = run_probe(server, client_wrapper, reset_timeout=1.0, retransmit_interval=0.4)
    assert result.status == STATUS_NO_REPLY


def test_closed_udp_port_reports_icmp_or_no_reply():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_sock:
        probe_sock.bind(("127.0.0.1", 0))
        port = probe_sock.getsockname()[1]
    transport = open_transport("udp", socket.AF_INET, ("127.0.0.1", port), 2)
    try:
        result = ControlChannelProbe(
            transport, PlainWrapper(), reset_timeout=1.0, retransmit_interval=0.3
        ).run()
    finally:
        transport.close()
    assert result.status == STATUS_NO_REPLY
