from datetime import datetime, timedelta, timezone

from ovpncert.certs import describe, evaluate, fingerprint

NOW = datetime.now(timezone.utc)


def ev(pki, name, anchors=None, pins=(), now=NOW, **kwargs):
    leaf = pki.leaves[name]
    chain = [leaf.der] + ([pki.intermediate.der] if name == "intermediate" else [])
    anchors = [pki.ca.cert] if anchors is None else anchors
    return evaluate(chain, anchors, now, remote_cert_tls="server", pins=pins, **kwargs)


def test_valid_chain(pki):
    result = ev(pki, "valid")
    assert result.trusted and result.clean
    assert [p.accepts for p in result.predictions.values()] == [True, True]
    assert result.path[-1].subject == "O=Lab, CN=Lab CA"


def test_describe_fields(pki):
    info = describe(pki.leaves["rsa"].cert)
    assert info.public_key == "RSA 2048"
    assert info.signature_algorithm == "ecdsa-with-SHA256"
    assert "TLS Web Server Authentication" in info.extended_key_usage
    assert info.sha256 == fingerprint(pki.leaves["rsa"].der)


def test_expired_leaf_is_rejected_by_both_clients(pki):
    result = ev(pki, "expired")
    assert result.trusted
    assert result.codes() == {"EXPIRED"}
    assert not result.predictions["openvpn3"].accepts
    assert not result.predictions["openvpn2"].accepts


def test_expired_leaf_with_matching_pin(pki):
    pin = fingerprint(pki.leaves["expired"].der)
    result = ev(pki, "expired", pins=[pin])
    assert result.pin_match is True
    assert result.predictions["openvpn3"].accepts  # fingerprint overrides the leaf verdict
    assert not result.predictions["openvpn2"].accepts  # a CA is configured: errors are final


def test_fingerprint_only_mode(pki):
    pin = fingerprint(pki.leaves["expired"].der)
    result = ev(pki, "expired", anchors=[], pins=[pin])
    assert not result.has_ca and result.untrusted_depth == 0
    assert result.predictions["openvpn2"].accepts  # library errors ignored without a CA
    assert result.predictions["openvpn3"].accepts  # only the leaf was sent: depth-0 error


def test_fingerprint_only_with_full_chain_fails_on_openvpn3(pki):
    pin = fingerprint(pki.leaves["intermediate"].der)
    result = ev(pki, "intermediate", anchors=[], pins=[pin])
    assert result.untrusted_depth == 1
    assert not result.predictions["openvpn3"].accepts  # depth >= 1 error is never overridden
    assert result.predictions["openvpn2"].accepts


def test_pin_mismatch(pki):
    result = ev(pki, "valid", pins=[fingerprint(pki.leaves["expired"].der)])
    assert "PIN_MISMATCH" in result.codes()
    assert not any(p.accepts for p in result.predictions.values())


def test_not_yet_valid(pki):
    result = ev(pki, "future")
    assert result.codes() == {"NOT_YET_VALID"}


def test_untrusted_issuer(pki):
    result = ev(pki, "rogue")
    assert not result.trusted
    assert result.codes() == {"UNTRUSTED"}
    pinned = ev(pki, "rogue", pins=[fingerprint(pki.leaves["rogue"].der)])
    # OpenVPN 3 would accept a pinned leaf from a foreign CA (depth-0 error) - which is why
    # ``ovpncert pin`` refuses to pin certificates that do not chain to the profile CA.
    assert pinned.predictions["openvpn3"].accepts


def test_expired_issuer(pki):
    result = evaluate([pki.leaves["old_ca"].der], [pki.old_ca.cert], NOW, remote_cert_tls="server")
    assert result.trusted
    assert result.codes() == {"ISSUER_EXPIRED"}
    pinned = evaluate(
        [pki.leaves["old_ca"].der],
        [pki.old_ca.cert],
        NOW,
        pins=[fingerprint(pki.leaves["old_ca"].der)],
    )
    assert not pinned.predictions["openvpn3"].accepts  # CA errors are never overridden


def test_intermediate_chain(pki):
    result = ev(pki, "intermediate")
    assert result.trusted and result.clean
    assert len(result.path) == 3


def test_missing_eku(pki):
    result = ev(pki, "no_eku")
    assert result.codes() == {"PURPOSE"}
    pinned = ev(pki, "no_eku", pins=[fingerprint(pki.leaves["no_eku"].der)])
    assert not pinned.predictions["openvpn3"].accepts  # policy checks still apply


def test_verify_x509_name(pki):
    assert ev(pki, "valid", verify_x509_name=("vpn.lab.test", "name")).clean
    assert ev(pki, "valid", verify_x509_name=("vpn.", "name-prefix")).clean
    assert ev(pki, "valid", verify_x509_name=("O=Lab, CN=vpn.lab.test", "subject")).clean
    assert "NAME" in ev(pki, "valid", verify_x509_name=("other", "name")).codes()


def test_time_is_a_parameter(pki):
    leaf = describe(pki.leaves["expired"].cert)
    before_expiry = leaf.not_after - timedelta(hours=1)
    assert ev(pki, "expired", now=before_expiry).clean
