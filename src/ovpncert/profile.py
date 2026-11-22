"""Parser for OpenVPN client profiles (``.ovpn`` / ``.conf``).

Only the options that matter for reaching the server and verifying its
certificate are interpreted: ``remote``/``proto``/``port``/``<connection>``,
``ca``, ``tls-auth``/``key-direction``/``auth``, ``tls-crypt``,
``remote-cert-tls``, ``verify-x509-name`` and ``peer-fingerprint``. Inline
blocks and file references (relative to the profile) are both supported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .statickey import StaticKey, StaticKeyError
from .wire import PlainWrapper, TlsAuthWrapper, TlsCryptWrapper, WireError, normalize_digest

__all__ = [
    "DEFAULT_PORT",
    "DEFAULT_PROTO",
    "Directive",
    "Profile",
    "ProfileError",
    "Remote",
    "normalize_fingerprint",
    "parse_directives",
]

DEFAULT_PORT = 1194
DEFAULT_PROTO = "udp"

_BLOCK_OPEN = re.compile(r"<([A-Za-z0-9_-]+)>")
_FINGERPRINT = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){31}$")


class ProfileError(ValueError):
    """The profile is malformed or references something that cannot be read."""


@dataclass
class Directive:
    name: str
    args: list[str]
    inline: str | None = None
    line: int = 0


def _split_args(line: str) -> list[str]:
    """Tokenise one config line the way OpenVPN does (quotes, escapes, comments)."""
    tokens: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    in_token = False
    i = 0
    while i < len(line):
        char = line[i]
        if quote is not None:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"' and i + 1 < len(line):
                i += 1
                buf.append(line[i])
            else:
                buf.append(char)
        elif char in "\"'":
            quote = char
            in_token = True
        elif char.isspace():
            if in_token:
                tokens.append("".join(buf))
                buf, in_token = [], False
        elif char in "#;" and not in_token:
            break
        elif char == "\\" and i + 1 < len(line):
            i += 1
            buf.append(line[i])
            in_token = True
        else:
            buf.append(char)
            in_token = True
        i += 1
    if in_token:
        tokens.append("".join(buf))
    return tokens


def parse_directives(text: str) -> list[Directive]:
    """Split a profile into directives, keeping ``<tag>`` blocks as inline text."""
    directives: list[Directive] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        index += 1
        if not stripped or stripped[0] in "#;":
            continue
        opening = _BLOCK_OPEN.fullmatch(stripped)
        if opening:
            tag = opening.group(1).lower()
            start = index
            body: list[str] = []
            while index < len(lines) and lines[index].strip().lower() != f"</{tag}>":
                body.append(lines[index])
                index += 1
            if index >= len(lines):
                raise ProfileError(f"line {start}: <{tag}> block is never closed")
            index += 1
            directives.append(Directive(tag, [], "\n".join(body) + "\n", start))
            continue
        tokens = _split_args(stripped)
        if tokens:
            directives.append(Directive(tokens[0].lower().lstrip("-"), tokens[1:], None, index))
    return directives


def normalize_fingerprint(value: str) -> str:
    """Return ``AA:BB:...`` (upper case) or raise ``ProfileError``."""
    candidate = value.strip()
    if ":" not in candidate and len(candidate) == 64:
        candidate = ":".join(candidate[i : i + 2] for i in range(0, 64, 2))
    if not _FINGERPRINT.match(candidate):
        raise ProfileError(f"not a SHA-256 fingerprint: {value!r}")
    return candidate.upper()


@dataclass(frozen=True)
class Remote:
    host: str
    port: int = DEFAULT_PORT
    proto: str = DEFAULT_PROTO

    @property
    def kind(self) -> str:
        return "tcp" if self.proto.lower().startswith("tcp") else "udp"

    @property
    def label(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}/{self.kind}"

    @classmethod
    def parse(cls, spec: str, default_port: int = DEFAULT_PORT, default_proto: str = DEFAULT_PROTO):
        """Parse ``HOST[:PORT][/PROTO]`` (IPv6 literals in brackets)."""
        value = spec.strip()
        proto = default_proto
        if "/" in value:
            value, proto = value.rsplit("/", 1)
        port = default_port
        if value.startswith("["):
            host, _, rest = value[1:].partition("]")
            if rest.startswith(":"):
                port = int(rest[1:])
        elif value.count(":") == 1:
            host, port_text = value.split(":")
            port = int(port_text)
        else:
            host = value
        if not host:
            raise ProfileError(f"invalid remote {spec!r}")
        return cls(host, port, proto)


@dataclass
class Profile:
    remotes: list[Remote]
    ca_pem: str | None = None
    tls_auth: StaticKey | None = None
    key_direction: int | None = None
    tls_crypt: StaticKey | None = None
    tls_crypt_v2: bool = False
    auth_digest: str = "SHA1"
    remote_cert_tls: str | None = None
    verify_x509_name: tuple[str, str] | None = None
    peer_fingerprints: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    path: Path | None = None
    text: str = ""

    @property
    def protection(self) -> str:
        if self.tls_crypt is not None:
            return "tls-crypt"
        if self.tls_auth is not None:
            return "tls-auth"
        if self.tls_crypt_v2:
            return "tls-crypt-v2"
        return "none"

    def make_wrapper(self):
        """Return a fresh packet wrapper (each probe needs its own replay counter)."""
        if self.tls_crypt is not None:
            return TlsCryptWrapper(self.tls_crypt)
        if self.tls_auth is not None:
            return TlsAuthWrapper(self.tls_auth, self.key_direction, self.auth_digest)
        return PlainWrapper()

    @classmethod
    def from_file(cls, path: str | Path) -> Profile:
        file_path = Path(path)
        try:
            text = file_path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            raise ProfileError(f"cannot read profile {file_path}: {exc.strerror}") from exc
        return cls.from_text(text, base_dir=file_path.parent, path=file_path)

    @classmethod
    def from_text(cls, text: str, base_dir: Path | None = None, path: Path | None = None):
        base = base_dir or Path.cwd()
        directives = parse_directives(text)
        profile = cls(remotes=[], path=path, text=text)

        global_defaults: dict[str, object] = {}
        pending: list[tuple[str, int | None, str | None, dict]] = []
        tls_auth_direction: int | None = None

        def read_file(name: str, option: str) -> str:
            file_path = Path(name)
            if not file_path.is_absolute():
                file_path = base / file_path
            try:
                return file_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ProfileError(f"--{option}: cannot read {file_path}: {exc.strerror}") from exc

        def load_key(d: Directive, option: str) -> StaticKey | None:
            source = d.inline
            if source is None and d.args and d.args[0] != "[inline]":
                source = read_file(d.args[0], option)
            if source is None:
                return None
            try:
                return StaticKey.parse(source)
            except StaticKeyError as exc:
                raise ProfileError(f"--{option}: {exc}") from exc

        def collect_remotes(items: list[Directive], scope: dict) -> None:
            for d in items:
                if d.name == "remote":
                    if not d.args:
                        raise ProfileError(f"line {d.line}: 'remote' needs a host")
                    port = int(d.args[1]) if len(d.args) > 1 else None
                    proto = d.args[2] if len(d.args) > 2 else None
                    pending.append((d.args[0], port, proto, scope))
                elif d.name in ("port", "rport", "proto") and d.args:
                    scope[d.name] = d.args[0]

        for d in directives:
            try:
                if d.name in ("remote", "port", "rport", "proto"):
                    collect_remotes([d], global_defaults)
                elif d.name == "connection" and d.inline is not None:
                    block: dict = {}
                    inner = parse_directives(d.inline)
                    for item in inner:
                        if item.name in ("port", "rport", "proto") and item.args:
                            block[item.name] = item.args[0]
                    collect_remotes([i for i in inner if i.name == "remote"], block)
                elif d.name == "ca":
                    if d.inline is not None:
                        profile.ca_pem = d.inline
                    elif d.args and d.args[0] != "[inline]":
                        profile.ca_pem = read_file(d.args[0], "ca")
                elif d.name == "tls-auth":
                    key = load_key(d, "tls-auth")
                    if key is not None:
                        profile.tls_auth = key
                    direction_args = d.args[1:] if d.args else []
                    if direction_args:
                        tls_auth_direction = int(direction_args[0])
                elif d.name == "key-direction" and d.args:
                    profile.key_direction = int(d.args[0])
                elif d.name == "tls-crypt":
                    key = load_key(d, "tls-crypt")
                    if key is not None:
                        profile.tls_crypt = key
                elif d.name == "tls-crypt-v2":
                    profile.tls_crypt_v2 = True
                elif d.name == "auth" and d.args:
                    profile.auth_digest = d.args[0]
                elif d.name == "remote-cert-tls" and d.args:
                    profile.remote_cert_tls = d.args[0].lower()
                elif d.name == "verify-x509-name" and d.args:
                    kind = d.args[1].lower() if len(d.args) > 1 else "subject"
                    profile.verify_x509_name = (d.args[0], kind)
                elif d.name == "peer-fingerprint":
                    values = (d.inline or "").splitlines() if d.inline is not None else d.args
                    for value in values:
                        value = value.strip()
                        if value and value[0] not in "#;":
                            profile.peer_fingerprints.append(normalize_fingerprint(value))
                elif d.name in ("http-proxy", "socks-proxy"):
                    profile.notes.append(f"'{d.name}' is ignored: the probe connects to the server directly")
            except ValueError as exc:
                if isinstance(exc, ProfileError):
                    raise
                raise ProfileError(f"line {d.line}: invalid '{d.name}' value: {exc}") from exc

        if tls_auth_direction is not None:
            profile.key_direction = tls_auth_direction
        if profile.tls_auth is not None:
            try:
                normalize_digest(profile.auth_digest)
            except WireError as exc:
                raise ProfileError(str(exc)) from exc
        if profile.tls_crypt_v2 and profile.tls_crypt is None and profile.tls_auth is None:
            profile.notes.append("tls-crypt-v2 is not supported yet; servers that require it will not answer")

        seen: set[tuple[str, int, str]] = set()
        for host, port, proto, scope in pending:
            port_value = (
                port
                or scope.get("rport")
                or scope.get("port")
                or global_defaults.get("rport")
                or global_defaults.get("port")
                or DEFAULT_PORT
            )
            try:
                resolved_port = int(port_value)
            except ValueError as exc:
                raise ProfileError(f"invalid port {port_value!r} for remote {host}") from exc
            if not 0 < resolved_port < 65536:
                raise ProfileError(f"port {resolved_port} for remote {host} is out of range")
            resolved_proto = str(proto or scope.get("proto") or global_defaults.get("proto") or DEFAULT_PROTO)
            remote = Remote(host, resolved_port, resolved_proto)
            identity = (remote.host.lower(), remote.port, remote.kind)
            if identity not in seen:
                seen.add(identity)
                profile.remotes.append(remote)
        return profile
