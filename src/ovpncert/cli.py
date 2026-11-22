"""Command-line interface: ``ovpncert inspect | diagnose | pin | check``."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .clock import check_clock
from .diagnose import diagnose
from .inspector import ProbeOptions, inspect
from .logs import summarize_file
from .monitor import check_remote, format_json, format_nagios, format_prometheus, overall_state
from .pin import CLIENTS, pin_profile
from .profile import Profile, ProfileError, Remote
from .report import (
    Style,
    color_enabled,
    diagnosis_json,
    inspect_json,
    render_diagnosis,
    render_inspect,
    render_pin,
)
from .statickey import StaticKey, StaticKeyError

__all__ = ["build_parser", "main"]

EXIT_OK, EXIT_PROBLEM, EXIT_UNREACHABLE, EXIT_ERROR = 0, 1, 2, 3


def _add_target_options(parser: argparse.ArgumentParser, profile_required: bool) -> None:
    parser.add_argument(
        "profile",
        nargs=None if profile_required else "?",
        type=Path,
        help="OpenVPN client profile (.ovpn/.conf)"
        + ("" if profile_required else " (optional with --remote)"),
    )
    group = parser.add_argument_group("target")
    group.add_argument(
        "--remote",
        action="append",
        metavar="HOST[:PORT][/PROTO]",
        help="probe this server instead of the profile's remotes (repeatable)",
    )
    group.add_argument("--ca", type=Path, help="CA certificate(s) in PEM (overrides the profile)")
    group.add_argument("--tls-auth", type=Path, metavar="KEY", help="tls-auth static key file")
    group.add_argument("--key-direction", type=int, choices=(0, 1), help="tls-auth key direction")
    group.add_argument("--auth", metavar="DIGEST", help="tls-auth HMAC digest, e.g. SHA256")
    group.add_argument("--tls-crypt", type=Path, metavar="KEY", help="tls-crypt static key file")
    group.add_argument(
        "--remote-cert-tls", choices=("server",), help="require serverAuth key usage (like OpenVPN)"
    )
    probe = parser.add_argument_group("probe")
    probe.add_argument("--timeout", type=float, default=15.0, help="TLS handshake timeout in seconds")
    probe.add_argument(
        "--legacy-tls", action="store_true", help="allow TLS 1.0/1.1 and weak ciphers (old servers)"
    )
    probe.add_argument("--no-color", action="store_true", help="disable coloured output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ovpncert",
        description=(
            "Inspect, diagnose and monitor the certificate of an OpenVPN server through a "
            "handshake-only probe. No credentials are sent."
        ),
    )
    parser.add_argument("--version", action="version", version=f"ovpncert {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_inspect = commands.add_parser("inspect", help="show and verify the certificate of every remote")
    _add_target_options(p_inspect, profile_required=False)
    p_inspect.add_argument("--json", action="store_true", help="machine-readable output")
    p_inspect.set_defaults(func=cmd_inspect)

    p_diag = commands.add_parser("diagnose", help="explain a certificate failure and who can fix it")
    _add_target_options(p_diag, profile_required=False)
    p_diag.add_argument("--log", type=Path, help="OpenVPN Connect or OpenVPN 2.x log to correlate")
    p_diag.add_argument("--no-clock-check", action="store_true", help="skip the NTP clock check")
    p_diag.add_argument("--time-server", action="append", metavar="HOST", help="NTP server (repeatable)")
    p_diag.add_argument("--warn-days", type=float, default=30, help="warn when expiry is closer (days)")
    p_diag.add_argument("--json", action="store_true", help="machine-readable output")
    p_diag.set_defaults(func=cmd_diagnose)

    p_pin = commands.add_parser("pin", help="write a temporary profile that pins the server certificate(s)")
    _add_target_options(p_pin, profile_required=True)
    p_pin.add_argument(
        "--client",
        choices=CLIENTS,
        default="openvpn3",
        help="client family (default openvpn3 = OpenVPN Connect; openvpn2 = OpenVPN 2.6+)",
    )
    p_pin.add_argument("-o", "--output", type=Path, help="output path (default: next to the profile)")
    p_pin.add_argument("--overwrite", action="store_true", help="replace an existing output file")
    p_pin.set_defaults(func=cmd_pin)

    p_check = commands.add_parser(
        "check", help="expiry check for monitoring (Nagios/Icinga exit codes, JSON, Prometheus)"
    )
    _add_target_options(p_check, profile_required=False)
    p_check.add_argument("--warning", type=float, default=30, metavar="DAYS", help="default 30")
    p_check.add_argument("--critical", type=float, default=7, metavar="DAYS", help="default 7")
    p_check.add_argument(
        "--format", choices=("nagios", "json", "prometheus"), default="nagios", help="output format"
    )
    p_check.set_defaults(func=cmd_check)
    return parser


def load_profile(args: argparse.Namespace) -> Profile:
    if args.profile is not None:
        profile = Profile.from_file(args.profile)
    elif args.remote:
        profile = Profile(remotes=[])
    else:
        raise ProfileError("give a profile or at least one --remote")
    if args.remote:
        profile.remotes = [Remote.parse(spec) for spec in args.remote]
    try:
        if args.ca is not None:
            profile.ca_pem = args.ca.read_text(encoding="utf-8", errors="replace")
        if args.tls_auth is not None:
            profile.tls_auth = StaticKey.from_file(args.tls_auth)
        if args.tls_crypt is not None:
            profile.tls_crypt = StaticKey.from_file(args.tls_crypt)
    except (OSError, StaticKeyError) as exc:
        raise ProfileError(str(exc)) from exc
    if args.key_direction is not None:
        profile.key_direction = args.key_direction
    if args.auth:
        profile.auth_digest = args.auth
    if args.remote_cert_tls:
        profile.remote_cert_tls = args.remote_cert_tls
    return profile


def _options(args: argparse.Namespace) -> ProbeOptions:
    return ProbeOptions(timeout=args.timeout, legacy_tls=args.legacy_tls)


def _style(args: argparse.Namespace) -> Style:
    return Style(enabled=not args.no_color and color_enabled(sys.stdout))


def cmd_inspect(args: argparse.Namespace) -> int:
    profile = load_profile(args)
    now = datetime.now(timezone.utc)
    reports = inspect(profile, _options(args), now)
    if args.json:
        print(json.dumps(inspect_json(profile, reports, now), indent=2))
    else:
        sys.stdout.write(render_inspect(profile, reports, now, _style(args)))
    if not any(r.reachable for r in reports):
        return EXIT_UNREACHABLE
    if any(r.reachable and not r.evaluation.clean for r in reports):
        return EXIT_PROBLEM
    return EXIT_OK


def cmd_diagnose(args: argparse.Namespace) -> int:
    profile = load_profile(args)
    now = datetime.now(timezone.utc)
    clock = None
    if not args.no_clock_check:
        clock = check_clock(args.time_server) if args.time_server else check_clock()
    timeline = summarize_file(args.log) if args.log else None
    reports = inspect(profile, _options(args), now)
    name = str(args.profile) if args.profile else "PROFILE"
    diagnosis = diagnose(
        profile,
        reports,
        now=now,
        clock=clock,
        timeline=timeline,
        warn_days=args.warn_days,
        profile_name=name,
    )
    if args.json:
        print(json.dumps(diagnosis_json(diagnosis), indent=2))
    else:
        sys.stdout.write(render_diagnosis(diagnosis, _style(args)))
    if diagnosis.unreachable:
        return EXIT_UNREACHABLE
    return EXIT_PROBLEM if diagnosis.problem_found else EXIT_OK


def cmd_pin(args: argparse.Namespace) -> int:
    profile = load_profile(args)
    now = datetime.now(timezone.utc)
    output = args.output or args.profile.with_name(f"{args.profile.stem}.pinned-{args.client}.ovpn")
    if output.resolve() == args.profile.resolve():
        raise ProfileError("refusing to overwrite the original profile")
    if output.exists() and not args.overwrite:
        raise ProfileError(f"{output} exists (use --overwrite)")
    reports = inspect(profile, _options(args), now)
    result = pin_profile(profile, reports, args.client, now)
    if result.ok:
        output.write_text(result.text, encoding="utf-8", newline="")
    sys.stdout.write(render_pin(result, output if result.ok else None, _style(args)))
    if not any(r.reachable for r in reports):
        return EXIT_UNREACHABLE
    return EXIT_OK if result.ok else EXIT_PROBLEM


def cmd_check(args: argparse.Namespace) -> int:
    profile = load_profile(args)
    now = datetime.now(timezone.utc)
    reports = inspect(profile, _options(args), now)
    results = [check_remote(r, args.warning, args.critical, now) for r in reports]
    if args.format == "json":
        print(format_json(results))
    elif args.format == "prometheus":
        sys.stdout.write(format_prometheus(results))
    else:
        print(format_nagios(results, args.warning, args.critical))
    return overall_state(results)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ProfileError as exc:
        print(f"ovpncert: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
