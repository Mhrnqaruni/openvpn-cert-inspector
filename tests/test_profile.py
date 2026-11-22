import pytest

from ovpncert.profile import Profile, ProfileError, Remote, normalize_fingerprint, parse_directives
from ovpncert.wire import PlainWrapper, TlsAuthWrapper, TlsCryptWrapper

FP = ":".join(["AB"] * 32)


def test_remotes_and_defaults(tmp_path):
    profile = Profile.from_text(
        "client\nremote a.example.org\nremote b.example.org 443 tcp\nport 1195\nproto udp4\n"
        "remote a.example.org 1195 udp\n",
        base_dir=tmp_path,
    )
    assert [r.label for r in profile.remotes] == ["a.example.org:1195/udp", "b.example.org:443/tcp"]
    assert profile.remotes[0].proto == "udp4"


def test_connection_blocks():
    text = (
        "client\n<connection>\nremote x.example.org 1195\nproto tcp-client\n</connection>\n"
        "<connection>\nremote y.example.org\n</connection>\n"
    )
    profile = Profile.from_text(text)
    assert [r.label for r in profile.remotes] == ["x.example.org:1195/tcp", "y.example.org:1194/udp"]


def test_inline_tls_auth_with_key_direction(pki):
    text = f"remote h\nauth SHA512\nkey-direction 1\n<tls-auth>\n{pki.static_key}</tls-auth>\n"
    profile = Profile.from_text(text)
    assert profile.protection == "tls-auth" and profile.key_direction == 1
    wrapper = profile.make_wrapper()
    assert isinstance(wrapper, TlsAuthWrapper) and wrapper.size == 64


def test_tls_auth_file_with_direction_argument(pki, tmp_path):
    (tmp_path / "ta.key").write_text(pki.static_key)
    (tmp_path / "ca.crt").write_text(pki.ca.cert_pem)
    profile = Profile.from_file(_write(tmp_path, "remote h\ntls-auth ta.key 0\nca ca.crt\n"))
    assert profile.key_direction == 0
    assert "BEGIN CERTIFICATE" in profile.ca_pem


def test_tls_auth_inline_marker(pki):
    text = f"remote h\ntls-auth [inline] 1\n<tls-auth>\n{pki.static_key}</tls-auth>\n"
    assert Profile.from_text(text).key_direction == 1


def test_tls_crypt_and_no_protection(pki):
    assert isinstance(
        Profile.from_text(f"remote h\n<tls-crypt>\n{pki.static_key}</tls-crypt>\n").make_wrapper(),
        TlsCryptWrapper,
    )
    assert isinstance(Profile.from_text("remote h\n").make_wrapper(), PlainWrapper)


def test_policy_options():
    text = (
        f"remote h\nremote-cert-tls server\nverify-x509-name vpn.example.org name\n"
        f"<peer-fingerprint>\n# comment\n{FP.lower()}\n</peer-fingerprint>\npeer-fingerprint {FP}\n"
    )
    profile = Profile.from_text(text)
    assert profile.remote_cert_tls == "server"
    assert profile.verify_x509_name == ("vpn.example.org", "name")
    assert profile.peer_fingerprints == [FP, FP]


def test_notes_for_unsupported_features():
    profile = Profile.from_text("remote h\nhttp-proxy proxy 8080\ntls-crypt-v2 client.key\n")
    assert len(profile.notes) == 2


def test_quotes_comments_and_escapes():
    directives = parse_directives('remote "my host" 1194 # comment\n; ignored\nca "C:\\\\keys\\\\ca.crt"\n')
    assert directives[0].args == ["my host", "1194"]
    assert directives[1].args == ["C:\\keys\\ca.crt"]


def test_errors(tmp_path):
    with pytest.raises(ProfileError):
        Profile.from_text("remote h\n<ca>\nunterminated\n")
    with pytest.raises(ProfileError):
        Profile.from_file(_write(tmp_path, "remote h\nca missing.crt\n"))
    with pytest.raises(ProfileError):
        Profile.from_text("remote h\nport abc\n")
    with pytest.raises(ProfileError):
        normalize_fingerprint("12:34")


def test_remote_spec_parsing():
    assert Remote.parse("vpn.example.org").label == "vpn.example.org:1194/udp"
    assert Remote.parse("vpn.example.org:443/tcp").label == "vpn.example.org:443/tcp"
    assert Remote.parse("[2001:db8::1]:1195").label == "[2001:db8::1]:1195/udp"
    assert normalize_fingerprint("ab" * 32) == FP


def _write(directory, text):
    path = directory / "client.ovpn"
    path.write_text(text)
    return path
