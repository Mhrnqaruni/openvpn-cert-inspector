from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lab.pki import make_ca, make_leaf, make_static_key, write_bundle  # noqa: E402


@pytest.fixture(scope="session")
def pki(tmp_path_factory):
    """One throw-away PKI with server certificates in every interesting state."""
    directory = tmp_path_factory.mktemp("pki")
    ca = make_ca("Lab CA")
    other_ca = make_ca("Other CA")
    old_ca = make_ca("Old CA", valid_from=timedelta(days=-4000), valid_to=timedelta(days=-10))
    intermediate = make_ca("Lab Intermediate", issuer=ca)
    leaves = {
        "valid": (make_leaf(ca, "vpn.lab.test"), []),
        "expired": (
            make_leaf(ca, "vpn.lab.test", valid_from=timedelta(days=-731), valid_to=timedelta(hours=-3)),
            [],
        ),
        "future": (
            make_leaf(ca, "vpn.lab.test", valid_from=timedelta(days=2), valid_to=timedelta(days=700)),
            [],
        ),
        "expiring": (make_leaf(ca, "vpn.lab.test", valid_to=timedelta(days=5)), []),
        "no_eku": (make_leaf(ca, "vpn.lab.test", eku=False), []),
        "rogue": (make_leaf(other_ca, "vpn.lab.test"), []),
        "old_ca": (make_leaf(old_ca, "vpn.lab.test", valid_to=timedelta(days=300)), []),
        "intermediate": (make_leaf(intermediate, "vpn.lab.test"), [intermediate]),
        "rsa": (make_leaf(ca, "vpn.lab.test", key_kind="rsa"), []),
    }
    files = {}
    for name, (leaf, chain) in leaves.items():
        files[name] = write_bundle(directory, name, leaf, chain)
    ca_file = directory / "ca.crt"
    ca_file.write_text(ca.cert_pem, encoding="ascii")
    old_ca_file = directory / "old-ca.crt"
    old_ca_file.write_text(old_ca.cert_pem, encoding="ascii")
    client = make_leaf(ca, "client1", role="client")
    return SimpleNamespace(
        dir=directory,
        ca=ca,
        other_ca=other_ca,
        old_ca=old_ca,
        intermediate=intermediate,
        leaves={name: leaf for name, (leaf, _chain) in leaves.items()},
        files=files,
        ca_file=ca_file,
        old_ca_file=old_ca_file,
        client=client,
        static_key=make_static_key(),
        other_static_key=make_static_key(),
    )


def profile_text(
    port: int,
    *,
    proto: str = "udp",
    ca_pem: str | None = None,
    tls_auth: str | None = None,
    key_direction: int | None = 1,
    auth: str = "SHA256",
    tls_crypt: str | None = None,
    extra: str = "",
) -> str:
    lines = ["client", "dev tun", f"proto {proto}", f"remote 127.0.0.1 {port}", "nobind", f"auth {auth}"]
    lines.append("remote-cert-tls server")
    if extra:
        lines.append(extra)
    if ca_pem:
        lines += ["<ca>", ca_pem.strip(), "</ca>"]
    if tls_auth:
        if key_direction is not None:
            lines.append(f"key-direction {key_direction}")
        lines += ["<tls-auth>", tls_auth.strip(), "</tls-auth>"]
    if tls_crypt:
        lines += ["<tls-crypt>", tls_crypt.strip(), "</tls-crypt>"]
    return "\n".join(lines) + "\n"


@pytest.fixture
def make_profile_text():
    return profile_text
