# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/Mhrnqaruni/openvpn-cert-inspector/security/advisories/new)
rather than in a public issue. Expect an acknowledgement within a few days.

## Supported versions

Security fixes go into the latest release.

## Design properties relevant to security

- **Handshake only.** The probe sends a hard reset and a TLS handshake and
  stops. It never sends the key-method-2 message, credentials, client
  certificates or client options.
- **No TLS-layer trust shortcuts.** TLS verification is disabled only so that
  the chain can be captured. It is then evaluated in full by `ovpncert.certs`,
  and every finding is reported.
- **Key material stays local.** Static keys are read from your profile, used
  to authenticate the probe's packets, and never logged. `repr()` of a key is
  redacted, and JSON output contains certificates, never keys.
- **Pinning is gated.** `ovpncert pin` refuses certificates that do not chain
  to the CA in the original profile, certificates that would fail
  `remote-cert-tls` or `verify-x509-name`, and (for OpenVPN 3) chains whose CA
  is outside its validity period. Pinned profiles fail closed when the
  certificate changes.
- **Untrusted input.** Server responses and profiles are parsed defensively.
  Malformed packets are dropped like packets that fail authentication.

See [docs/responsible-use.md](docs/responsible-use.md) for guidance on probing
and pinning.
