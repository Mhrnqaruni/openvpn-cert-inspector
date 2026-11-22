from datetime import datetime, timedelta, timezone

from ovpncert.handshake import HandshakeResult
from ovpncert.inspector import RemoteReport, reevaluate
from ovpncert.logs import summarize
from ovpncert.monitor import (
    CRITICAL,
    OK,
    UNKNOWN,
    WARNING,
    check_remote,
    format_json,
    format_nagios,
    format_prometheus,
    overall_state,
)
from ovpncert.pin import build_pinned_profile, pin_profile
from ovpncert.profile import Profile, Remote

NOW = datetime.now(timezone.utc)


def report_for(pki, name, profile, host="vpn1.lab.test"):
    chain = [pki.leaves[name].der] + ([pki.intermediate.der] if name == "intermediate" else [])
    report = RemoteReport(Remote(host), address="192.0.2.10", handshake=HandshakeResult("ok", chain=chain))
    report.evaluation = reevaluate(report, profile, NOW)
    return report


def make_profile(pki, extra="", ca=True, crlf=False):
    text = "client\nremote vpn1.lab.test\nremote-cert-tls server\n" + extra
    if ca:
        text += "<ca>\n" + pki.ca.cert_pem + "</ca>\n"
    text += "verb 3\n"
    if crlf:
        text = text.replace("\n", "\r\n")
    return Profile.from_text(text)


def test_pin_openvpn3_keeps_ca_and_adds_pin(pki):
    profile = make_profile(pki, crlf=True)
    result = pin_profile(profile, [report_for(pki, "expired", profile)], "openvpn3", NOW)
    assert result.ok
    assert "<ca>" in result.text and "<peer-fingerprint>" in result.text
    assert "\r\n" in result.text and result.text.index("<peer-fingerprint>") < result.text.index("<ca>")
    pinned = Profile.from_text(result.text)
    assert pinned.peer_fingerprints == [pki.leaves["expired"].cert_pem and result.candidates[0].fingerprint]
    re_report = report_for(pki, "expired", pinned)
    assert re_report.evaluation.predictions["openvpn3"].accepts
    assert not re_report.evaluation.predictions["openvpn2"].accepts


def test_pin_openvpn2_removes_ca(pki):
    profile = make_profile(pki, extra="ca /etc/openvpn/ca.crt\n".replace("ca /etc", "# ca /etc"))
    result = pin_profile(profile, [report_for(pki, "expired", profile)], "openvpn2", NOW)
    assert result.ok and "<ca>" not in result.text
    pinned = Profile.from_text(result.text)
    assert pinned.ca_pem is None
    assert report_for(pki, "expired", pinned).evaluation.predictions["openvpn2"].accepts


def test_pin_replaces_existing_pins(pki):
    profile = make_profile(pki, extra="peer-fingerprint " + ":".join(["00"] * 32) + "\n")
    text = pin_profile(profile, [report_for(pki, "expired", profile)], "openvpn3", NOW).text
    assert text.count("<peer-fingerprint>") == 1 and text.count("</peer-fingerprint>") == 1
    assert ":".join(["00"] * 32) not in text
    assert len(Profile.from_text(text).peer_fingerprints) == 1


def test_pin_refuses_untrusted_or_unhelpful(pki):
    profile = make_profile(pki)
    for name in ("rogue", "no_eku"):
        result = pin_profile(profile, [report_for(pki, name, profile)], "openvpn3", NOW)
        assert not result.ok and result.candidates[0].blocked
    no_ca = make_profile(pki, ca=False)
    assert not pin_profile(no_ca, [report_for(pki, "expired", no_ca)], "openvpn3", NOW).ok
    old = Profile.from_text("remote h\n<ca>\n" + pki.old_ca.cert_pem + "</ca>\n")
    assert not pin_profile(old, [report_for(pki, "old_ca", old)], "openvpn3", NOW).ok
    assert pin_profile(old, [report_for(pki, "old_ca", old)], "openvpn2", NOW).ok


def test_pin_notes_valid_certificate(pki):
    profile = make_profile(pki)
    result = pin_profile(profile, [report_for(pki, "valid", profile)], "openvpn3", NOW)
    assert result.ok and result.candidates[0].notes


def test_pin_requires_all_reachable_remotes_to_pass(pki):
    profile = make_profile(pki)
    reports = [report_for(pki, "expired", profile), report_for(pki, "rogue", profile, "vpn2.lab.test")]
    assert not pin_profile(profile, reports, "openvpn3", NOW).ok


def test_build_without_ca_block_appends(pki):
    text = build_pinned_profile("client\nremote h\n", [], "openvpn3", NOW)
    assert text.startswith("client\nremote h\n\n# --- Temporary")


def test_monitor_states(pki):
    profile = make_profile(pki)
    results = {
        name: check_remote(report_for(pki, name, profile), 30, 7, NOW)
        for name in ("valid", "expiring", "expired", "rogue")
    }
    assert results["valid"].state == OK
    assert results["expiring"].state == CRITICAL and "expires in" in results["expiring"].message
    assert results["expired"].state == CRITICAL and "expired" in results["expired"].message
    assert results["rogue"].state == CRITICAL
    assert check_remote(report_for(pki, "expiring", profile), 30, 2, NOW).state == WARNING
    unreachable = RemoteReport(Remote("down.lab.test"), error="cannot resolve")
    assert check_remote(unreachable, 30, 7, NOW).state == UNKNOWN
    assert overall_state([results["valid"], check_remote(unreachable, 30, 7, NOW)]) == UNKNOWN
    assert overall_state(list(results.values())) == CRITICAL


def test_monitor_formats(pki):
    profile = make_profile(pki)
    results = [check_remote(report_for(pki, n, profile), 30, 7, NOW) for n in ("valid", "expired")]
    nagios = format_nagios(results, 30, 7)
    assert nagios.startswith("OVPNCERT CRITICAL - ") and " | 'vpn1.lab.test:1194/udp'=" in nagios
    assert '"state": "CRITICAL"' in format_json(results)
    prom = format_prometheus(results)
    assert 'ovpncert_check_state{remote="vpn1.lab.test:1194/udp"} 2' in prom
    assert "# TYPE ovpncert_certificate_expiry_timestamp_seconds gauge" in prom


def test_monitor_counts_issuer_expiry(pki):
    profile = Profile.from_text("remote h\n<ca>\n" + pki.ca.cert_pem + "</ca>\n")
    short_ca_report = report_for(pki, "valid", profile)
    earliest = min(short_ca_report.evaluation.path, key=lambda c: c.not_after)
    result = check_remote(short_ca_report, 30, 7, NOW)
    assert result.not_after == earliest.not_after


CONNECT_LOG = (
    "⏎[Mar 14, 2026, 09:01:00] SSL Handshake: peer certificate: CN=vpn1, 2048 bit RSA"
    "⏎[Mar 14, 2026, 09:01:01] EVENT: CONNECTED user@vpn1:1194 (192.0.2.10) via /UDP"
    "⏎[Mar 14, 2026, 09:15:37] SSL Handshake: peer certificate: CN=vpn1, 2048 bit RSA"
    "⏎[Mar 14, 2026, 09:30:13] Transport Error: OpenSSLContext::SSL::read_cleartext: BIO_read "
    "failed, cap=2640 status=-1: error:0A000086:SSL routines::certificate verify failed"
    "⏎[Mar 14, 2026, 09:30:13] EVENT: CERT_VERIFY_FAIL certificate verify failed"
)

OPENVPN2_LOG = """2026-03-14 09:01:00 VERIFY OK: depth=1, O=Lab, CN=Lab CA
2026-03-14 09:01:00 VERIFY OK: depth=0, O=Lab, CN=vpn1
2026-03-14 09:01:02 Initialization Sequence Completed
2026-03-14 10:01:00 VERIFY ERROR: depth=0, error=certificate has expired: O=Lab, CN=vpn1, serial=1234
2026-03-14 10:01:00 OpenSSL: error:0A000086:SSL routines::certificate verify failed
"""


def test_connect_log_timeline():
    summary = summarize(CONNECT_LOG)
    assert summary.format == "openvpn-connect"
    assert summary.last_success == datetime(2026, 3, 14, 9, 15, 37)
    assert summary.first_failure == datetime(2026, 3, 14, 9, 30, 13)
    assert summary.failure_reason == "certificate verify failed"
    assert summary.interval_seconds == timedelta(minutes=14, seconds=37).total_seconds()


def test_openvpn2_log_timeline():
    summary = summarize(OPENVPN2_LOG)
    assert summary.format == "openvpn2"
    assert summary.last_success == datetime(2026, 3, 14, 9, 1, 2)
    assert summary.failure_reason == "certificate has expired"
