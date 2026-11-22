#!/usr/bin/env python3
"""Reproducible lab: real OpenVPN servers and clients versus ovpncert.

Runs on Linux with the ``openvpn`` binary and permission to create TUN devices
(root, or a container started with ``--cap-add NET_ADMIN --device /dev/net/tun``).

Group A - probe interoperability
    ovpncert retrieves the certificate from real OpenVPN servers over UDP and
    TCP with no protection, tls-auth (several digests and key directions) and
    tls-crypt; wrong keys must get no reply at all.
Group B - diagnosis
    One server per certificate state; ovpncert's root cause is compared with
    the state that was deployed.
Group C - client behaviour
    Real OpenVPN clients connect to a server whose certificate has expired,
    using CA-only, CA + pin and pin-only profiles (including the profiles
    written by ``ovpncert pin``). Each observation is compared with the
    prediction made by ovpncert's verification model.

Usage::

    python3 lab/run_lab.py --out results/          # OpenVPN 2.x client only
    python3 lab/run_lab.py --out results/ --openvpn3-client /usr/local/bin/ovpncli
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from lab.pki import Issued, make_ca, make_leaf, make_static_key, write_bundle  # noqa: E402
from ovpncert import __version__  # noqa: E402
from ovpncert.certs import fingerprint  # noqa: E402
from ovpncert.diagnose import diagnose  # noqa: E402
from ovpncert.inspector import ProbeOptions, inspect  # noqa: E402
from ovpncert.pin import pin_profile  # noqa: E402
from ovpncert.profile import Profile  # noqa: E402

V2_OK = ("Initialization Sequence Completed",)
V2_FAIL = (
    "VERIFY ERROR",
    "VERIFY EKU ERROR",
    "VERIFY KU ERROR",
    "certificate verify failed",
    "hash verification failed",
    "TLS Error: TLS handshake failed",
    "Exiting due to fatal error",
    "Options error",
)
V3_OK = ("Connected via", "EVENT: CONNECTED", "CONNECTED")
V3_FAIL = ("CERT_VERIFY_FAIL", "VERIFY FAIL", "TLS_VERSION_MIN", "HANDSHAKE_TIMEOUT", "TRANSPORT_ERROR")


@dataclass
class Case:
    group: str
    name: str
    expected: str
    observed: str = ""
    predicted: str | None = None
    ok: bool = False
    detail: str = ""
    seconds: float = 0.0


@dataclass
class Server:
    process: subprocess.Popen
    port: int
    proto: str
    log: Path


@dataclass
class Pki:
    ca: Issued
    other_ca: Issued
    old_ca: Issued
    intermediate: Issued
    client: Issued
    ta: str
    tc: str
    other_ta: str
    leaves: dict[str, tuple[Issued, list[Issued], Issued]] = field(default_factory=dict)


class Lab:
    def __init__(self, work: Path, openvpn: str, ovpncli: str | None) -> None:
        self.work = work
        self.openvpn = openvpn
        self.ovpncli = ovpncli
        self.port = 21000
        self.subnet = 20
        self.cases: list[Case] = []
        self.pki = self._make_pki()

    # -- set-up ----------------------------------------------------------------

    def _make_pki(self) -> Pki:
        ca = make_ca("Lab Root CA", key_kind="rsa")
        other_ca = make_ca("Unrelated CA")
        old_ca = make_ca("Retired CA", valid_from=timedelta(days=-4000), valid_to=timedelta(days=-2))
        intermediate = make_ca("Lab Issuing CA", issuer=ca)
        pki = Pki(
            ca=ca,
            other_ca=other_ca,
            old_ca=old_ca,
            intermediate=intermediate,
            client=make_leaf(ca, "lab-client", role="client"),
            ta=make_static_key(),
            tc=make_static_key(),
            other_ta=make_static_key(),
        )
        expired_window = {"valid_from": timedelta(days=-731), "valid_to": timedelta(hours=-3)}
        pki.leaves = {
            "valid": (make_leaf(ca, "vpn.lab.test", key_kind="rsa"), [], ca),
            "expired": (make_leaf(ca, "vpn.lab.test", key_kind="rsa", **expired_window), [], ca),
            "expired-other": (make_leaf(ca, "vpn.lab.test", **expired_window), [], ca),
            "future": (
                make_leaf(ca, "vpn.lab.test", valid_from=timedelta(days=3), valid_to=timedelta(days=700)),
                [],
                ca,
            ),
            "expiring": (make_leaf(ca, "vpn.lab.test", valid_to=timedelta(days=5)), [], ca),
            "rogue": (make_leaf(other_ca, "vpn.lab.test"), [], other_ca),
            "no-eku": (make_leaf(ca, "vpn.lab.test", eku=False), [], ca),
            "chain": (make_leaf(intermediate, "vpn.lab.test"), [intermediate], ca),
            "chain-expired": (make_leaf(intermediate, "vpn.lab.test", **expired_window), [intermediate], ca),
            "retired-ca": (make_leaf(old_ca, "vpn.lab.test", valid_to=timedelta(days=200)), [], old_ca),
        }
        for name, (leaf, chain, server_ca) in pki.leaves.items():
            write_bundle(self.work, name, leaf, chain)
            (self.work / f"{name}.ca").write_text(server_ca.cert_pem, encoding="ascii")
        (self.work / "ta.key").write_text(pki.ta, encoding="ascii")
        (self.work / "tc.key").write_text(pki.tc, encoding="ascii")
        return pki

    def _next(self) -> tuple[int, int]:
        self.port += 1
        self.subnet += 1
        return self.port, self.subnet

    def start_server(
        self,
        leaf: str,
        *,
        proto: str = "udp",
        protection: str = "tls-auth",
        digest: str = "SHA256",
        key_direction: int | None = 0,
    ) -> Server:
        port, subnet = self._next()
        lines = [
            f"port {port}",
            "proto udp4" if proto == "udp" else "proto tcp4-server",
            "local 127.0.0.1",
            "dev tun",
            "topology subnet",
            f"server 10.{subnet}.0.0 255.255.255.0",
            f"ca {self.work / (leaf + '.ca')}",
            f"cert {self.work / (leaf + '.crt')}",
            f"key {self.work / (leaf + '.key')}",
            "dh none",
            f"auth {digest}",
            "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
            "keepalive 10 60",
            "verb 3",
        ]
        if protection == "tls-auth":
            direction = "" if key_direction is None else f" {key_direction}"
            lines.append(f"tls-auth {self.work / 'ta.key'}{direction}")
        elif protection == "tls-crypt":
            lines.append(f"tls-crypt {self.work / 'tc.key'}")
        conf = self.work / f"server-{port}.conf"
        conf.write_text("\n".join(lines) + "\n", encoding="ascii")
        log = self.work / f"server-{port}.log"
        process = subprocess.Popen(
            [self.openvpn, "--config", str(conf)],
            stdout=log.open("w"),
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            text = log.read_text(errors="replace")
            if "Initialization Sequence Completed" in text:
                return Server(process, port, proto, log)
            if process.poll() is not None:
                break
            time.sleep(0.2)
        process.kill()
        raise RuntimeError(
            f"OpenVPN server for '{leaf}' did not start:\n{log.read_text(errors='replace')[-2000:]}"
        )

    @staticmethod
    def stop(server: Server) -> None:
        server.process.terminate()
        try:
            server.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.process.kill()

    def client_profile(
        self,
        server: Server,
        *,
        ca: str | None = "lab",
        pins: tuple[str, ...] = (),
        protection: str = "tls-auth",
        digest: str = "SHA256",
        key_direction: int | None = 1,
        ta: str | None = None,
    ) -> str:
        lines = [
            "client",
            "dev null",
            "proto udp4" if server.proto == "udp" else "proto tcp4-client",
            f"remote 127.0.0.1 {server.port}",
            "nobind",
            "remote-cert-tls server",
            f"auth {digest}",
            "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
            "verb 3",
        ]
        anchors = {"lab": self.pki.ca, "retired": self.pki.old_ca}
        if ca is not None:
            lines += ["<ca>", anchors[ca].cert_pem.strip(), "</ca>"]
        if pins:
            lines += ["<peer-fingerprint>", *pins, "</peer-fingerprint>"]
        lines += ["<cert>", self.pki.client.cert_pem.strip(), "</cert>"]
        lines += ["<key>", self.pki.client.key_pem.strip(), "</key>"]
        if protection == "tls-auth":
            if key_direction is not None:
                lines.append(f"key-direction {key_direction}")
            lines += ["<tls-auth>", (ta or self.pki.ta).strip(), "</tls-auth>"]
        elif protection == "tls-crypt":
            lines += ["<tls-crypt>", self.pki.tc.strip(), "</tls-crypt>"]
        return "\n".join(lines) + "\n"

    # -- clients -----------------------------------------------------------------

    def _run_client(
        self, command: list[str], ok_markers, fail_markers, timeout: float = 25
    ) -> tuple[str, str]:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        verdict, reason = "timeout", "no success or failure marker"
        deadline = time.monotonic() + timeout
        lines: list[str] = []
        try:
            while time.monotonic() < deadline:
                line = process.stdout.readline()
                if not line:
                    if process.poll() is not None:
                        break
                    continue
                lines.append(line.rstrip())
                if any(m in line for m in fail_markers):
                    verdict, reason = "rejected", line.strip()
                    break
                if any(m in line for m in ok_markers):
                    verdict, reason = "accepted", line.strip()
                    break
        finally:
            process.kill()
            process.wait()
        if verdict == "timeout":
            reason = " | ".join(lines[-3:]) or reason
        return verdict, reason[-220:]

    def openvpn2(self, profile_text: str) -> tuple[str, str]:
        path = self.work / f"client-{time.monotonic_ns()}.ovpn"
        path.write_text(profile_text, encoding="ascii")
        return self._run_client([self.openvpn, "--config", str(path)], V2_OK, V2_FAIL)

    def openvpn3(self, profile_text: str) -> tuple[str, str]:
        path = self.work / f"client3-{time.monotonic_ns()}.ovpn"
        path.write_text(profile_text.replace("dev null\n", ""), encoding="ascii")
        return self._run_client([self.ovpncli, str(path)], V3_OK, V3_FAIL)

    # -- helpers -----------------------------------------------------------------

    def probe(self, profile_text: str, reset_timeout: float = 5.0):
        profile = Profile.from_text(profile_text)
        return profile, inspect(profile, ProbeOptions(timeout=10, reset_timeout=reset_timeout))

    def record(self, case: Case, started: float) -> None:
        case.seconds = round(time.monotonic() - started, 2)
        case.ok = case.observed == case.expected and (case.predicted in (None, case.observed))
        self.cases.append(case)
        mark = "PASS" if case.ok else "FAIL"
        extra = f" (model: {case.predicted})" if case.predicted is not None else ""
        print(f"[{mark}] {case.group} {case.name}: expected {case.expected}, observed {case.observed}{extra}")
        if not case.ok:
            print(f"       {case.detail}")

    # -- experiments -----------------------------------------------------------

    def group_a(self) -> None:
        valid_fp = fingerprint(self.pki.leaves["valid"][0].der)
        matrix = [
            ("udp", "none", "SHA256", 0, 1, None),
            ("udp", "tls-auth", "SHA256", 0, 1, None),
            ("udp", "tls-auth", "SHA512", 0, 1, None),
            ("udp", "tls-auth", "SHA1", None, None, None),
            ("udp", "tls-crypt", "SHA256", 0, 1, None),
            ("tcp", "none", "SHA256", 0, 1, None),
            ("tcp", "tls-auth", "SHA256", 0, 1, None),
            ("tcp", "tls-crypt", "SHA256", 0, 1, None),
            ("udp", "tls-auth", "SHA256", 0, 1, "wrong-key"),
            ("udp", "tls-auth", "SHA256", 0, 0, "wrong-direction"),
        ]
        for proto, protection, digest, server_kd, client_kd, fault in matrix:
            label = f"{proto}/{protection}"
            if protection == "tls-auth":
                label += f" HMAC-{digest} " + ("bidirectional" if server_kd is None else f"kd {client_kd}")
            if fault:
                label += f" ({fault})"
            started = time.monotonic()
            server = self.start_server(
                "valid", proto=proto, protection=protection, digest=digest, key_direction=server_kd
            )
            try:
                text = self.client_profile(
                    server,
                    protection=protection,
                    digest=digest,
                    key_direction=client_kd,
                    ta=self.pki.other_ta if fault == "wrong-key" else None,
                )
                _profile, reports = self.probe(text, reset_timeout=3.0 if fault else 5.0)
            finally:
                self.stop(server)
            report = reports[0]
            if report.reachable:
                same = report.leaf.sha256 == valid_fp
                observed = "certificate" if same else "wrong certificate"
                hs = report.handshake
                detail = f"{hs.tls_version} {hs.cipher} {hs.elapsed_ms} ms"
            else:
                observed, detail = "no reply", report.failure
            self.record(
                Case("A", label, "no reply" if fault else "certificate", observed, None, False, detail),
                started,
            )

    def group_b(self) -> None:
        expected = {
            "valid": "CERTIFICATE_OK",
            "expired": "SERVER_CERT_EXPIRED",
            "future": "SERVER_CERT_NOT_YET_VALID",
            "expiring": "SERVER_CERT_EXPIRING",
            "rogue": "CA_MISMATCH",
            "no-eku": "SERVER_CERT_PURPOSE",
            "chain": "CERTIFICATE_OK",
            "retired-ca": "CA_EXPIRED",
        }
        for leaf, code in expected.items():
            started = time.monotonic()
            server = self.start_server(leaf)
            try:
                text = self.client_profile(server, ca="retired" if leaf == "retired-ca" else "lab")
                profile, reports = self.probe(text)
            finally:
                self.stop(server)
            result = diagnose(profile, reports)
            observed = result.primary.code
            self.record(
                Case("B", f"server certificate: {leaf}", code, observed, None, False, result.primary.title),
                started,
            )

    def _client_case(self, client: str, name: str, server: Server, text: str, expected: str) -> None:
        started = time.monotonic()
        _profile, reports = self.probe(text)
        prediction = None
        if reports[0].reachable:
            accepts = (
                reports[0].evaluation.predictions["openvpn3" if client == "OpenVPN 3" else "openvpn2"].accepts
            )
            prediction = "accepted" if accepts else "rejected"
        runner = self.openvpn3 if client == "OpenVPN 3" else self.openvpn2
        observed, reason = runner(text)
        self.record(Case("C", f"{client}: {name}", expected, observed, prediction, False, reason), started)

    def group_c(self) -> None:
        clients = ["OpenVPN 2"] + (["OpenVPN 3"] if self.ovpncli else [])
        expired_fp = fingerprint(self.pki.leaves["expired"][0].der)
        other_fp = fingerprint(self.pki.leaves["expired-other"][0].der)
        chain_fp = fingerprint(self.pki.leaves["chain-expired"][0].der)

        server = self.start_server("valid")
        try:
            for client in clients:
                self._client_case(
                    client, "valid certificate, CA only", server, self.client_profile(server), "accepted"
                )
        finally:
            self.stop(server)

        server = self.start_server("expired")
        try:
            base = self.client_profile(server)
            profile = Profile.from_text(base)
            reports = inspect(profile, ProbeOptions(timeout=10))
            pinned3 = pin_profile(profile, reports, "openvpn3").text
            pinned2 = pin_profile(profile, reports, "openvpn2").text
            expectations = {
                "OpenVPN 2": {
                    "expired, CA only": (base, "rejected"),
                    "expired, CA + pin": (self.client_profile(server, pins=(expired_fp,)), "rejected"),
                    "expired, pin only": (
                        self.client_profile(server, ca=None, pins=(expired_fp,)),
                        "accepted",
                    ),
                    "expired, pin only, wrong pin": (
                        self.client_profile(server, ca=None, pins=(other_fp,)),
                        "rejected",
                    ),
                    "expired, `ovpncert pin --client openvpn2`": (pinned2, "accepted"),
                    "expired, `ovpncert pin --client openvpn3`": (pinned3, "rejected"),
                },
                "OpenVPN 3": {
                    "expired, CA only": (base, "rejected"),
                    "expired, CA + pin": (self.client_profile(server, pins=(expired_fp,)), "accepted"),
                    "expired, pin only (leaf sent)": (
                        self.client_profile(server, ca=None, pins=(expired_fp,)),
                        "accepted",
                    ),
                    "expired, CA + wrong pin": (self.client_profile(server, pins=(other_fp,)), "rejected"),
                    "expired, `ovpncert pin --client openvpn3`": (pinned3, "accepted"),
                },
            }
            for client in clients:
                for name, (text, expected) in expectations[client].items():
                    self._client_case(client, name, server, text, expected)
        finally:
            self.stop(server)

        server = self.start_server("chain-expired")
        try:
            outcomes = {"OpenVPN 2": "accepted", "OpenVPN 3": "rejected"}
            for client in clients:
                self._client_case(
                    client,
                    "expired, pin only (chain sent)",
                    server,
                    self.client_profile(server, ca=None, pins=(chain_fp,)),
                    outcomes[client],
                )
        finally:
            self.stop(server)


def environment(openvpn: str, ovpncli: str | None) -> dict:
    version = subprocess.run([openvpn, "--version"], capture_output=True, text=True).stdout.splitlines()
    env = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "ovpncert": __version__,
        "openvpn": version[0] if version else "unknown",
        "python": platform.python_version(),
        "openssl": ssl.OPENSSL_VERSION,
        "platform": platform.platform(),
    }
    if ovpncli:
        env["openvpn3_client"] = ovpncli
    return env


def write_reports(out: Path, cases: list[Case], env: dict) -> None:
    out.mkdir(parents=True, exist_ok=True)
    data = {
        "environment": env,
        "passed": sum(c.ok for c in cases),
        "total": len(cases),
        "cases": [asdict(c) for c in cases],
    }
    (out / "lab-results.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Lab results",
        "",
        f"{data['passed']} of {data['total']} cases match the expected outcome.",
        "",
        "| Environment | |",
        "|---|---|",
        *[f"| {key} | {value} |" for key, value in env.items()],
        "",
        "| Group | Case | Expected | Observed | ovpncert model | Result |",
        "|---|---|---|---|---|---|",
    ]
    for case in cases:
        lines.append(
            f"| {case.group} | {case.name} | {case.expected} | {case.observed} | "
            f"{case.predicted or '-'} | {'pass' if case.ok else 'FAIL'} |"
        )
    (out / "lab-results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=ROOT / "results")
    parser.add_argument("--openvpn", default=shutil.which("openvpn") or "openvpn")
    parser.add_argument("--openvpn3-client", help="path to the OpenVPN 3 core test client (ovpncli)")
    parser.add_argument("--groups", default="ABC")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ovpncert-lab-") as tmp:
        lab = Lab(Path(tmp), args.openvpn, args.openvpn3_client)
        for group in args.groups:
            getattr(lab, f"group_{group.lower()}")()
        env = environment(args.openvpn, args.openvpn3_client)
    write_reports(args.out, lab.cases, env)
    failed = [c for c in lab.cases if not c.ok]
    print(f"\n{len(lab.cases) - len(failed)}/{len(lab.cases)} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
