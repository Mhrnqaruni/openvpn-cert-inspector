# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-22

### Added

- Handshake-only OpenVPN control-channel client:
  - UDP and TCP; no protection, `tls-auth` (any `--auth` digest, key direction 0/1/none) and
    `tls-crypt`;
  - reliability layer with acknowledgements and retransmission;
  - certificate capture for TLS 1.3 (completed handshake) and TLS 1.2 (cleartext records, even if
    the server aborts).
- Profile parser:
  - `remote`, `<connection>` blocks, inline and file-based `ca` / `tls-auth` / `tls-crypt`;
  - `key-direction`, `auth`, `remote-cert-tls`, `verify-x509-name`, `peer-fingerprint`.
- Chain evaluation separating signature trust from validity periods, plus OpenVPN policy checks,
  with acceptance predictions for OpenVPN 3 and OpenVPN 2.x.
- `ovpncert inspect`: certificate details, verdict and client predictions per remote (text or
  JSON).
- `ovpncert diagnose`: root cause with owner and next steps, SNTP clock check, and log timeline
  correlation for OpenVPN Connect and OpenVPN 2.x logs.
- `ovpncert pin`: temporary `peer-fingerprint` profile for `openvpn3` (CA kept) or `openvpn2`
  (fingerprint-only), with safety gates.
- `ovpncert check`: expiry monitoring with Nagios/Icinga exit codes, JSON or Prometheus text
  format.
- Lab with real OpenVPN 2.6 servers and clients and the OpenVPN 3 core client, run in CI:
  29/29 and 22/22 cases.

[1.0.0]: https://github.com/Mhrnqaruni/openvpn-cert-inspector/releases/tag/v1.0.0
