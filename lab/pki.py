"""Throw-away PKI for tests and the OpenVPN lab.

Generates CAs, server and client certificates with arbitrary validity windows
(already expired, not yet valid, ...) and OpenVPN static keys. Nothing here is
meant for production use.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

__all__ = ["Issued", "make_ca", "make_leaf", "make_static_key", "write_bundle"]


@dataclass
class Issued:
    cert: x509.Certificate
    key: object

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def key_pem(self) -> str:
        return self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    @property
    def der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)


def _key(kind: str):
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name: str, org: str = "Lab") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def make_ca(
    common_name: str = "Lab CA",
    *,
    valid_from: timedelta = timedelta(days=-365),
    valid_to: timedelta = timedelta(days=3650),
    issuer: Issued | None = None,
    key_kind: str = "ec",
    now: datetime | None = None,
) -> Issued:
    """A CA (self-signed, or an intermediate when ``issuer`` is given)."""
    now = now or datetime.now(timezone.utc)
    key = _key(key_kind)
    subject = _name(common_name)
    signer_key = issuer.key if issuer else key
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.cert.subject if issuer else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + valid_from)
        .not_valid_after(now + valid_to)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    return Issued(builder.sign(signer_key, hashes.SHA256()), key)


def make_leaf(
    ca: Issued,
    common_name: str,
    *,
    role: str = "server",
    valid_from: timedelta = timedelta(days=-30),
    valid_to: timedelta = timedelta(days=730),
    key_usage: bool = True,
    eku: bool = True,
    key_kind: str = "ec",
    now: datetime | None = None,
) -> Issued:
    """A server or client certificate signed by ``ca`` with a chosen validity window."""
    now = now or datetime.now(timezone.utc)
    key = _key(key_kind)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + valid_from)
        .not_valid_after(now + valid_to)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=key_kind == "rsa",
                data_encipherment=False,
                key_agreement=key_kind != "rsa",
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if eku:
        usage = ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
        builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
    return Issued(builder.sign(ca.key, hashes.SHA256()), key)


def make_static_key() -> str:
    """A fresh OpenVPN static key (same format as ``openvpn --genkey secret``)."""
    material = os.urandom(256)
    lines = [material[i : i + 16].hex() for i in range(0, 256, 16)]
    return (
        "-----BEGIN OpenVPN Static key V1-----\n"
        + "\n".join(lines)
        + "\n-----END OpenVPN Static key V1-----\n"
    )


def write_bundle(directory: Path, name: str, leaf: Issued, chain: list[Issued] = ()) -> tuple[Path, Path]:
    """Write ``<name>.crt`` (leaf + chain) and ``<name>.key``; return both paths."""
    directory.mkdir(parents=True, exist_ok=True)
    cert_path = directory / f"{name}.crt"
    key_path = directory / f"{name}.key"
    cert_path.write_text(leaf.cert_pem + "".join(c.cert_pem for c in chain), encoding="ascii")
    key_path.write_text(leaf.key_pem, encoding="ascii")
    return cert_path, key_path
