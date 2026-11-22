import struct

import pytest

from lab.pki import make_static_key
from ovpncert.statickey import StaticKey, StaticKeyError, direction_indices
from ovpncert.wire import (
    P_ACK_V1,
    P_CONTROL_HARD_RESET_CLIENT_V2,
    P_CONTROL_V1,
    ControlPacket,
    PlainWrapper,
    TlsAuthWrapper,
    TlsCryptWrapper,
    WireError,
    normalize_digest,
)

SID_A, SID_B = b"\x01" * 8, b"\x02" * 8


def test_static_key_round_trip_and_redaction():
    text = make_static_key()
    key = StaticKey.parse("# comment\n" + text)
    assert StaticKey.parse(key.to_text()) == key
    assert "redacted" in repr(key) and text.split("\n")[1] not in repr(key)
    assert len(key.cipher_slot(1)) == 64 and key.hmac_slot(0) == key.material[64:128]


def test_static_key_rejects_bad_input():
    with pytest.raises(StaticKeyError):
        StaticKey.parse("nothing here")
    with pytest.raises(StaticKeyError):
        StaticKey.parse("-----BEGIN OpenVPN Static key V1-----\nabcd\n-----END OpenVPN Static key V1-----")
    with pytest.raises(StaticKeyError):
        direction_indices(2)


def test_direction_indices():
    assert direction_indices(None) == (0, 0)
    assert direction_indices(0) == (0, 1)
    assert direction_indices(1) == (1, 0)


def test_control_packet_layout():
    packet = ControlPacket(
        P_CONTROL_V1, SID_A, acks=[7, 8], ack_session_id=SID_B, message_id=3, payload=b"hi"
    )
    body = packet.body()
    assert packet.header == bytes([P_CONTROL_V1 << 3]) + SID_A
    assert body == b"\x02" + struct.pack(">II", 7, 8) + SID_B + struct.pack(">I", 3) + b"hi"
    decoded = ControlPacket.from_parts(packet.header, body)
    assert decoded == packet


def test_ack_packet_has_no_message_id():
    packet = ControlPacket(P_ACK_V1, SID_A, acks=[1], ack_session_id=SID_B)
    assert ControlPacket.from_parts(packet.header, packet.body()).message_id is None


@pytest.mark.parametrize(
    "body",
    [b"", b"\x02\x00\x00\x00\x01", bytes([0]) + b"\x00\x00"],
)
def test_truncated_bodies_raise(body):
    with pytest.raises(WireError):
        ControlPacket.from_parts(bytes([P_CONTROL_V1 << 3]) + SID_A, body)


def test_plain_wrapper_round_trip():
    packet = ControlPacket(P_CONTROL_HARD_RESET_CLIENT_V2, SID_A, message_id=0)
    wrapper = PlainWrapper()
    assert wrapper.unwrap(wrapper.wrap(packet)) == packet


@pytest.mark.parametrize("digest", ["SHA1", "SHA256", "SHA512", "sha-384"])
def test_tls_auth_round_trip_between_client_and_server(digest):
    key = StaticKey.parse(make_static_key())
    client = TlsAuthWrapper(key, 1, digest)
    server = TlsAuthWrapper(key, 0, digest)
    packet = ControlPacket(
        P_CONTROL_V1, SID_A, acks=[0], ack_session_id=SID_B, message_id=1, payload=b"x" * 50
    )
    wire = client.wrap(packet)
    assert len(wire) == 9 + client.size + 8 + len(packet.body())
    assert server.unwrap(wire) == packet
    with pytest.raises(WireError):
        client.unwrap(wire)  # the client verifies with the other direction's key


def test_tls_auth_hmac_covers_replay_fields_first():
    key = StaticKey.parse(make_static_key())
    wrapper = TlsAuthWrapper(key, None, "SHA256", start_time=1000)
    packet = ControlPacket(P_CONTROL_HARD_RESET_CLIENT_V2, SID_A, message_id=0)
    wire = wrapper.wrap(packet)
    import hashlib
    import hmac

    replay = wire[9 + 32 : 9 + 32 + 8]
    assert replay == struct.pack(">II", 1, 1000)
    expected = hmac.new(key.hmac_slot(0)[:32], replay + wire[:9] + wire[9 + 40 :], hashlib.sha256).digest()
    assert wire[9 : 9 + 32] == expected


def test_tls_auth_detects_tampering_and_wrong_key():
    key = StaticKey.parse(make_static_key())
    other = StaticKey.parse(make_static_key())
    packet = ControlPacket(P_CONTROL_V1, SID_A, message_id=5, payload=b"payload")
    wire = bytearray(TlsAuthWrapper(key, 1, "SHA256").wrap(packet))
    wire[-1] ^= 1
    with pytest.raises(WireError):
        TlsAuthWrapper(key, 0, "SHA256").unwrap(bytes(wire))
    with pytest.raises(WireError):
        TlsAuthWrapper(other, 0, "SHA256").unwrap(TlsAuthWrapper(key, 1, "SHA256").wrap(packet))


def test_tls_crypt_round_trip_encrypts_payload():
    key = StaticKey.parse(make_static_key())
    client, server = TlsCryptWrapper(key), TlsCryptWrapper(key, server=True)
    packet = ControlPacket(P_CONTROL_V1, SID_A, message_id=2, payload=b"ClientHello" * 10)
    wire = client.wrap(packet)
    assert b"ClientHello" not in wire
    assert server.unwrap(wire) == packet
    reply = ControlPacket(P_CONTROL_V1, SID_B, acks=[2], ack_session_id=SID_A, message_id=1, payload=b"ok")
    assert client.unwrap(server.wrap(reply)) == reply


def test_tls_crypt_rejects_tampering():
    key = StaticKey.parse(make_static_key())
    wire = bytearray(TlsCryptWrapper(key).wrap(ControlPacket(P_CONTROL_V1, SID_A, message_id=1)))
    wire[20] ^= 0x80
    with pytest.raises(WireError):
        TlsCryptWrapper(key, server=True).unwrap(bytes(wire))


def test_normalize_digest():
    assert normalize_digest("SHA512") == "sha512"
    assert normalize_digest("SHA-256") == "sha256"
    with pytest.raises(WireError):
        normalize_digest("NOT-A-DIGEST")
