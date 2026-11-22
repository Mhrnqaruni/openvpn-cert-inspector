"""X.509 analysis of the chain an OpenVPN server presents.

Verification is split into the same checks an OpenVPN client performs:

1. **Chain checks** (done by the TLS library): a signature path from the leaf
   to a CA in the profile, and every certificate inside its validity window.
2. **Policy checks** (done by OpenVPN itself): ``remote-cert-tls`` key usage,
   ``verify-x509-name`` and ``peer-fingerprint``.

On top of the raw findings, :func:`predict` models how the two OpenVPN
implementations combine them, because they differ when ``peer-fingerprint`` is
present:

* **OpenVPN 3** (OpenVPN Connect, openvpn3-linux): an error on a CA or
  intermediate is final, but for the leaf a matching fingerprint replaces the
  TLS library's verdict, including "certificate has expired".
* **OpenVPN 2.x**: with a ``ca`` configured every TLS-library error is final.
  Only in fingerprint-only mode (no ``ca``) are those errors ignored and the
  fingerprint decides.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

__all__ = [
    "CertInfo",
    "ChainEvaluation",
    "Prediction",
    "Problem",
    "describe",
    "evaluate",
    "fingerprint",
    "load_pem_certificates",
    "oneline",
    "predict",
]

# Problems the TLS library (OpenSSL / mbedTLS) reports, as opposed to OpenVPN policy.
LIBRARY_CODES = frozenset(
    {"EXPIRED", "NOT_YET_VALID", "ISSUER_EXPIRED", "ISSUER_NOT_YET_VALID", "UNTRUSTED", "BAD_SIGNATURE"}
)
POLICY_CODES = frozenset({"PURPOSE", "NAME"})

_EKU_NAMES = {
    ExtendedKeyUsageOID.SERVER_AUTH: "TLS Web Server Authentication",
    ExtendedKeyUsageOID.CLIENT_AUTH: "TLS Web Client Authentication",
    ExtendedKeyUsageOID.CODE_SIGNING: "Code Signing",
    ExtendedKeyUsageOID.EMAIL_PROTECTION: "E-mail Protection",
    ExtendedKeyUsageOID.TIME_STAMPING: "Time Stamping",
    ExtendedKeyUsageOID.OCSP_SIGNING: "OCSP Signing",
}


def fingerprint(der: bytes) -> str:
    """SHA-256 fingerprint as ``AA:BB:...``, the format of ``peer-fingerprint``."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    return ":".join(f"{b:02X}" for b in digest.finalize())


def oneline(name: x509.Name) -> str:
    """Render a name in certificate order, e.g. ``O=Example, CN=vpn.example.org``."""
    parts = []
    for rdn in name.rdns:
        for attribute in rdn:
            parts.append(f"{attribute.rfc4514_attribute_name}={attribute.value}")
    return ", ".join(parts)


def load_pem_certificates(pem: str | None) -> list[x509.Certificate]:
    if not pem:
        return []
    return x509.load_pem_x509_certificates(pem.encode())


def _public_key(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size}"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {key.curve.name}"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA {key.key_size}"
    return type(key).__name__


def _extension(cert: x509.Certificate, kind):
    try:
        return cert.extensions.get_extension_for_class(kind).value
    except x509.ExtensionNotFound:
        return None


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    sha256: str
    public_key: str
    signature_algorithm: str
    key_usage: list[str]
    extended_key_usage: list[str]
    is_ca: bool
    self_issued: bool

    def days_left(self, now: datetime) -> float:
        return (self.not_after - now).total_seconds() / 86400


def describe(cert: x509.Certificate) -> CertInfo:
    key_usage = _extension(cert, x509.KeyUsage)
    ku_names: list[str] = []
    if key_usage is not None:
        for attr in (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
        ):
            if getattr(key_usage, attr):
                ku_names.append(attr)
    eku = _extension(cert, x509.ExtendedKeyUsage)
    eku_names = [_EKU_NAMES.get(oid, oid.dotted_string) for oid in eku] if eku is not None else []
    constraints = _extension(cert, x509.BasicConstraints)
    oid = cert.signature_algorithm_oid
    signature = getattr(oid, "_name", None) or oid.dotted_string  # e.g. sha256WithRSAEncryption
    return CertInfo(
        subject=oneline(cert.subject),
        issuer=oneline(cert.issuer),
        serial=f"{cert.serial_number:X}",
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        sha256=fingerprint(cert.public_bytes(Encoding.DER)),
        public_key=_public_key(cert),
        signature_algorithm=signature,
        key_usage=ku_names,
        extended_key_usage=eku_names,
        is_ca=bool(constraints and constraints.ca),
        self_issued=cert.subject == cert.issuer,
    )


_DER = Encoding.DER


@dataclass
class Problem:
    code: str
    depth: int
    message: str


@dataclass
class Prediction:
    accepts: bool
    reason: str


@dataclass
class ChainEvaluation:
    path: list[CertInfo]
    trusted: bool
    has_ca: bool
    problems: list[Problem] = field(default_factory=list)
    pin_match: bool | None = None
    untrusted_depth: int | None = None
    predictions: dict[str, Prediction] = field(default_factory=dict)

    @property
    def leaf(self) -> CertInfo:
        return self.path[0]

    def codes(self) -> set[str]:
        return {problem.code for problem in self.problems}

    @property
    def library_ok(self) -> bool:
        return not any(p.code in LIBRARY_CODES for p in self.problems)

    @property
    def clean(self) -> bool:
        return not self.problems


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool | None:
    """True if ``issuer`` signed ``cert``; False on a bad signature; None if unrelated."""
    if cert.issuer != issuer.subject:
        return None
    try:
        cert.verify_directly_issued_by(issuer)
    except InvalidSignature:
        return False
    except (ValueError, TypeError):
        return None
    return True


def _purpose_problem(cert: x509.Certificate, role: str) -> str | None:
    if _extension(cert, x509.KeyUsage) is None:
        return f"remote-cert-tls {role}: the certificate has no keyUsage extension"
    eku = _extension(cert, x509.ExtendedKeyUsage)
    wanted = ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
    if eku is None or wanted not in eku:
        return f"remote-cert-tls {role}: extendedKeyUsage lacks '{_EKU_NAMES[wanted]}'"
    return None


def _name_problem(cert: x509.Certificate, expected: str, kind: str) -> str | None:
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = str(names[0].value) if names else ""
    if kind == "name":
        ok = common_name == expected
    elif kind == "name-prefix":
        ok = common_name.startswith(expected)
    else:

        def normalise(value: str) -> str:
            return ",".join(part.strip() for part in value.replace("/", ",").split(",") if part.strip())

        ok = normalise(oneline(cert.subject)) == normalise(expected)
    if ok:
        return None
    return f"verify-x509-name {expected!r} ({kind}) does not match CN={common_name!r}"


def evaluate(
    chain_der: list[bytes],
    anchors: list[x509.Certificate],
    now: datetime | None = None,
    *,
    remote_cert_tls: str | None = None,
    verify_x509_name: tuple[str, str] | None = None,
    pins: list[str] | tuple[str, ...] = (),
) -> ChainEvaluation:
    """Evaluate a server chain (leaf first) against the profile's trust settings."""
    if not chain_der:
        raise ValueError("empty certificate chain")
    now = now or datetime.now(timezone.utc)
    certs = [x509.load_der_x509_certificate(der) for der in chain_der]
    leaf = certs[0]
    anchor_prints = {fingerprint(a.public_bytes(_DER)) for a in anchors}

    path = [leaf]
    problems: list[Problem] = []
    trusted = False
    bad_signature = False
    current = leaf
    for _ in range(8):
        if fingerprint(current.public_bytes(_DER)) in anchor_prints:
            trusted = True
            break
        issuer = None
        for candidate in anchors:
            verdict = _issued_by(current, candidate)
            if verdict:
                issuer = candidate
                trusted = True
                break
            bad_signature |= verdict is False
        if issuer is not None:
            path.append(issuer)
            break
        for candidate in certs[1:]:
            if any(candidate is p for p in path):
                continue
            verdict = _issued_by(current, candidate)
            if verdict:
                issuer = candidate
                break
            bad_signature |= verdict is False
        if issuer is None:
            break
        path.append(issuer)
        current = issuer

    untrusted_depth = None
    if not trusted:
        untrusted_depth = len(path) - 1
        if anchors:
            if bad_signature:
                problems.append(
                    Problem("BAD_SIGNATURE", untrusted_depth, "a certificate signature does not verify")
                )
            else:
                problems.append(
                    Problem(
                        "UNTRUSTED",
                        untrusted_depth,
                        "no signature path from the server certificate to a CA in the profile",
                    )
                )

    for depth, cert in enumerate(path):
        is_leaf = depth == 0
        label = "server certificate" if is_leaf else f"issuer at depth {depth}"
        if now < cert.not_valid_before_utc:
            problems.append(
                Problem(
                    "NOT_YET_VALID" if is_leaf else "ISSUER_NOT_YET_VALID",
                    depth,
                    f"{label} is not valid before {cert.not_valid_before_utc:%Y-%m-%d %H:%M:%S} UTC",
                )
            )
        if now > cert.not_valid_after_utc:
            problems.append(
                Problem(
                    "EXPIRED" if is_leaf else "ISSUER_EXPIRED",
                    depth,
                    f"{label} expired on {cert.not_valid_after_utc:%Y-%m-%d %H:%M:%S} UTC",
                )
            )

    if remote_cert_tls in ("server", "client"):
        message = _purpose_problem(leaf, remote_cert_tls)
        if message:
            problems.append(Problem("PURPOSE", 0, message))
    if verify_x509_name:
        message = _name_problem(leaf, *verify_x509_name)
        if message:
            problems.append(Problem("NAME", 0, message))

    pin_match = None
    if pins:
        pin_match = fingerprint(leaf.public_bytes(_DER)) in {p.upper() for p in pins}
        if not pin_match:
            problems.append(
                Problem("PIN_MISMATCH", 0, "server certificate does not match any peer-fingerprint")
            )

    evaluation = ChainEvaluation(
        path=[describe(c) for c in path],
        trusted=trusted,
        has_ca=bool(anchors),
        problems=problems,
        pin_match=pin_match,
        untrusted_depth=untrusted_depth,
    )
    evaluation.predictions = predict(evaluation, has_pins=bool(pins))
    return evaluation


def predict(evaluation: ChainEvaluation, *, has_pins: bool) -> dict[str, Prediction]:
    """Predict whether OpenVPN 3 and OpenVPN 2.x clients accept this server."""
    library = [p for p in evaluation.problems if p.code in LIBRARY_CODES]
    if not evaluation.has_ca and not evaluation.trusted and evaluation.untrusted_depth is not None:
        # Without a CA the TLS library still reports "unable to get issuer" (depth 0)
        # or "self-signed certificate in chain" (depth >= 1).
        library = [
            Problem("UNTRUSTED", evaluation.untrusted_depth, "no CA configured to verify the chain"),
            *library,
        ]
    policy = [p for p in evaluation.problems if p.code in POLICY_CODES]
    pin_problem = [p for p in evaluation.problems if p.code == "PIN_MISMATCH"]

    # OpenVPN 3: depth > 0 errors are final; a fingerprint match overrides depth 0.
    if not evaluation.has_ca and not has_pins:
        v3 = Prediction(False, "profile has neither a CA nor a peer-fingerprint")
    elif [p for p in library if p.depth > 0]:
        v3 = Prediction(False, next(p for p in library if p.depth > 0).message)
    elif has_pins:
        if pin_problem:
            v3 = Prediction(False, pin_problem[0].message)
        elif policy:
            v3 = Prediction(False, policy[0].message)
        elif library:
            v3 = Prediction(True, "fingerprint match overrides: " + "; ".join(p.message for p in library))
        else:
            v3 = Prediction(True, "chain valid and fingerprint matches")
    elif library or policy:
        v3 = Prediction(False, (library + policy)[0].message)
    else:
        v3 = Prediction(True, "chain valid")

    # OpenVPN 2.x: with a CA every library error is final; without one, the pin decides.
    if evaluation.has_ca:
        failures = library + policy + pin_problem
        v2 = Prediction(False, failures[0].message) if failures else Prediction(True, "chain valid")
    elif not has_pins:
        v2 = Prediction(False, "profile has neither a CA nor a peer-fingerprint")
    elif pin_problem or policy:
        v2 = Prediction(False, (pin_problem + policy)[0].message)
    else:
        v2 = Prediction(True, "fingerprint-only mode: TLS-library errors are ignored, fingerprint matches")
    return {"openvpn3": v3, "openvpn2": v2}
