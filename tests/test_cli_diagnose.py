import json
from datetime import datetime, timedelta, timezone

import pytest
from fakeserver import FakeOpenVPNServer

from ovpncert.cli import main
from ovpncert.clock import ClockCheck
from ovpncert.diagnose import diagnose, human_delta
from ovpncert.inspector import inspect
from ovpncert.logs import summarize
from ovpncert.profile import Profile
from ovpncert.statickey import StaticKey
from ovpncert.wire import TlsAuthWrapper


@pytest.fixture
def server_factory(pki):
    def start(name: str):
        cert, key = pki.files[name]
        wrapper = TlsAuthWrapper(StaticKey.parse(pki.static_key), 0, "SHA256")
        return FakeOpenVPNServer(cert, key, wrapper)

    return start


def write_profile(tmp_path, pki, port, make_profile_text):
    path = tmp_path / "client.ovpn"
    path.write_text(make_profile_text(port, ca_pem=pki.ca.cert_pem, tls_auth=pki.static_key))
    return path


def test_inspect_cli_text_and_exit_codes(tmp_path, pki, server_factory, make_profile_text, capsys):
    with server_factory("valid") as server:
        profile = write_profile(tmp_path, pki, server.port, make_profile_text)
        assert main(["inspect", str(profile), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "PASS" in out and "OpenVPN 3 (Connect): accepts" in out
    with server_factory("expired") as server:
        profile = write_profile(tmp_path, pki, server.port, make_profile_text)
        assert main(["inspect", str(profile), "--no-color"]) == 1
    assert "EXPIRED" in capsys.readouterr().out


def test_inspect_cli_json(tmp_path, pki, server_factory, make_profile_text, capsys):
    with server_factory("expired") as server:
        profile = write_profile(tmp_path, pki, server.port, make_profile_text)
        main(["inspect", str(profile), "--json"])
    data = json.loads(capsys.readouterr().out)
    remote = data["remotes"][0]
    assert remote["handshake"]["status"] == "ok"
    assert "BEGIN CERTIFICATE" in remote["handshake"]["chain_pem"][0]
    assert [p["code"] for p in remote["evaluation"]["problems"]] == ["EXPIRED"]
    assert remote["evaluation"]["predictions"]["openvpn3"]["accepts"] is False


def test_pin_cli_end_to_end(tmp_path, pki, server_factory, make_profile_text, capsys):
    with server_factory("expired") as server:
        profile = write_profile(tmp_path, pki, server.port, make_profile_text)
        assert main(["pin", str(profile), "--no-color"]) == 0
        pinned = tmp_path / "client.pinned-openvpn3.ovpn"
        assert pinned.exists()
        assert main(["pin", str(profile), "--no-color"]) == 3  # refuses to overwrite
        capsys.readouterr()
        assert main(["inspect", str(pinned), "--json"]) == 1  # still reported as expired...
    data = json.loads(capsys.readouterr().out)
    predictions = data["remotes"][0]["evaluation"]["predictions"]
    assert predictions["openvpn3"]["accepts"] is True  # ...but OpenVPN 3 accepts the pin


def test_check_cli_formats(tmp_path, pki, server_factory, make_profile_text, capsys):
    with server_factory("expiring") as server:
        profile = write_profile(tmp_path, pki, server.port, make_profile_text)
        assert main(["check", str(profile)]) == 2
        assert capsys.readouterr().out.startswith("OVPNCERT CRITICAL")
        assert main(["check", str(profile), "--critical", "1", "--format", "json"]) == 1
        assert json.loads(capsys.readouterr().out)["state"] == "WARNING"
        assert main(["check", str(profile), "--format", "prometheus"]) == 2
        assert "ovpncert_probe_success" in capsys.readouterr().out


def test_cli_without_profile(pki, capsys, tmp_path):
    ta = tmp_path / "ta.key"
    ta.write_text(pki.static_key)
    cert, key = pki.files["valid"]
    with FakeOpenVPNServer(cert, key, TlsAuthWrapper(StaticKey.parse(pki.static_key), 0, "SHA256")) as server:
        code = main(
            [
                "inspect",
                "--remote",
                f"127.0.0.1:{server.port}/udp",
                "--tls-auth",
                str(ta),
                "--key-direction",
                "1",
                "--auth",
                "SHA256",
                "--ca",
                str(pki.ca_file),
                "--no-color",
            ]
        )
    assert code == 0
    assert "vpn.lab.test" in capsys.readouterr().out


def test_cli_errors(capsys, tmp_path):
    assert main(["inspect"]) == 3
    assert main(["inspect", str(tmp_path / "missing.ovpn")]) == 3
    assert "error" in capsys.readouterr().err


def test_diagnose_expired_with_log(tmp_path, pki, server_factory, make_profile_text):
    with server_factory("expired") as server:
        profile = Profile.from_file(write_profile(tmp_path, pki, server.port, make_profile_text))
        now = datetime.now(timezone.utc)
        reports = inspect(profile, now=now)
    expiry_local = reports[0].leaf.not_after.astimezone().replace(tzinfo=None)
    log = (
        f"{(expiry_local - timedelta(minutes=6)):%Y-%m-%d %H:%M:%S} VERIFY OK: depth=0, CN=vpn\n"
        f"{(expiry_local + timedelta(minutes=8)):%Y-%m-%d %H:%M:%S} VERIFY ERROR: depth=0, "
        "error=certificate has expired: CN=vpn, serial=1\n"
    )
    result = diagnose(
        profile,
        reports,
        now=now,
        clock=ClockCheck(0.2, "ntp://test"),
        timeline=summarize(log),
        profile_name="client.ovpn",
    )
    assert result.primary.code == "SERVER_CERT_EXPIRED"
    assert result.primary.owner == "server operator"
    assert any("ovpncert pin client.ovpn" in a for a in result.primary.actions)
    timeline = next(f for f in result.findings if f.code == "LOG_TIMELINE")
    assert "consistent with the expiry" in timeline.detail


def test_diagnose_client_clock(tmp_path, pki, server_factory, make_profile_text):
    with server_factory("valid") as server:
        profile = Profile.from_file(write_profile(tmp_path, pki, server.port, make_profile_text))
        local_now = datetime.now(timezone.utc) + timedelta(days=900)  # clock far in the future
        reports = inspect(profile, now=local_now)
    offset = -timedelta(days=900).total_seconds()
    result = diagnose(profile, reports, now=local_now, clock=ClockCheck(offset, "ntp://test"))
    assert result.primary.code == "CLIENT_CLOCK"
    assert {f.code for f in result.findings} >= {"CLIENT_CLOCK", "CLOCK_SKEW"}


def test_diagnose_other_causes(tmp_path, pki, server_factory, make_profile_text):
    expected = {
        "rogue": "CA_MISMATCH",
        "no_eku": "SERVER_CERT_PURPOSE",
        "future": "SERVER_CERT_NOT_YET_VALID",
        "expiring": "SERVER_CERT_EXPIRING",
        "valid": "CERTIFICATE_OK",
    }
    for name, code in expected.items():
        with server_factory(name) as server:
            profile = Profile.from_file(write_profile(tmp_path, pki, server.port, make_profile_text))
            result = diagnose(profile, inspect(profile))
        assert result.primary.code == code, name


def test_diagnose_unreachable(pki, make_profile_text):
    profile = Profile.from_text(make_profile_text(9, ca_pem=pki.ca.cert_pem, tls_auth=pki.static_key))
    from ovpncert.inspector import ProbeOptions

    reports = inspect(profile, ProbeOptions(reset_timeout=1.0))
    result = diagnose(profile, reports)
    assert result.primary.code == "NO_RESPONSE" and result.unreachable


def test_human_delta():
    assert human_delta(30) == "30 seconds"
    assert human_delta(90) == "1.5 minutes"
    assert human_delta(3 * 86400) == "3 days"
