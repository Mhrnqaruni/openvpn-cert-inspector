# Client compatibility: how OpenVPN 2.x and OpenVPN 3 treat `peer-fingerprint`

OpenVPN has two independent client implementations:

* **OpenVPN 2.x**: the community `openvpn` binary, also used by OpenVPN GUI,
  Tunnelblick, NetworkManager-openvpn and many routers.
* **OpenVPN 3**: a C++ core library used by OpenVPN Connect (Windows, macOS,
  iOS, Android) and openvpn3-linux.

Both accept the `peer-fingerprint` option introduced with OpenVPN 2.6. They
disagree, however, on what happens when a pinned certificate fails the TLS
library's checks, for instance because it has expired. This matters for anyone
who uses a pin to stay connected while an operator renews a certificate, and it
is why `ovpncert pin` writes a different profile per client family.

## Source analysis

### OpenVPN 3 (core 3.11.3, the version inside OpenVPN Connect 3.8)

[`openvpn/openssl/ssl/sslctx.hpp`, `verify_callback_client`](https://github.com/OpenVPN/openvpn3/blob/9d2da83c70334d390b8f1f23d1110dd1551bc756/openvpn/openssl/ssl/sslctx.hpp#L1881-L1936):

1. For any certificate other than the leaf (`depth != 0`), the OpenSSL verdict
   is returned unchanged
   ([L1918-L1921](https://github.com/OpenVPN/openvpn3/blob/9d2da83c70334d390b8f1f23d1110dd1551bc756/openvpn/openssl/ssl/sslctx.hpp#L1918-L1921)).
2. For the leaf, if fingerprints are configured, the verdict is **replaced** by
   the result of the fingerprint comparison
   ([L1930](https://github.com/OpenVPN/openvpn3/blob/9d2da83c70334d390b8f1f23d1110dd1551bc756/openvpn/openssl/ssl/sslctx.hpp#L1930)).
   An expired but pinned leaf is therefore accepted.
3. Key usage, extended key usage (`remote-cert-tls`), `verify-x509-name` and
   `tls-remote` are evaluated afterwards and can still reject the certificate.
4. With fingerprints configured, the CA becomes optional
   ([L557](https://github.com/OpenVPN/openvpn3/blob/9d2da83c70334d390b8f1f23d1110dd1551bc756/openvpn/openssl/ssl/sslctx.hpp#L557)).
   Without a CA, though, a server that sends its root or an intermediate
   produces an OpenSSL error at depth ≥ 1. Rule 1 makes that error final.

### OpenVPN 2.6

[`src/openvpn/ssl_verify_openssl.c`, `verify_callback`](https://github.com/OpenVPN/openvpn/blob/34b4d05091c2a1bd7ad203a0c12e963c01dedddf/src/openvpn/ssl_verify_openssl.c#L50-L103):

1. Any OpenSSL error is final unless `verify_hash_no_ca` is set
   ([L68](https://github.com/OpenVPN/openvpn/blob/34b4d05091c2a1bd7ad203a0c12e963c01dedddf/src/openvpn/ssl_verify_openssl.c#L68)).
2. `verify_hash_no_ca` is set only when `peer-fingerprint` is given and **no**
   `ca`/`capath` is configured
   ([`options.c` L3776-L3782](https://github.com/OpenVPN/openvpn/blob/34b4d05091c2a1bd7ad203a0c12e963c01dedddf/src/openvpn/options.c#L3776-L3782)).
3. The fingerprint itself is compared in `verify_cert`
   ([`ssl_verify.c` L678](https://github.com/OpenVPN/openvpn/blob/34b4d05091c2a1bd7ad203a0c12e963c01dedddf/src/openvpn/ssl_verify.c#L678)).
   When a CA is present, this is an additional check, not a replacement.

## Resulting behaviour

| Profile | Server sends | OpenVPN 2.6 | OpenVPN 3 |
|---|---|---|---|
| CA only, certificate expired | any | rejects | rejects |
| CA + pin, certificate expired | leaf | rejects | **accepts** |
| CA + pin, certificate expired | leaf + root | rejects | **accepts** |
| CA + pin, certificate expired | leaf + intermediate | rejects | **accepts** |
| pin only, certificate expired | leaf | **accepts** | **accepts** |
| pin only, certificate expired | leaf + root | **accepts** | rejects |
| pin only, certificate expired | leaf + intermediate | **accepts** | rejects |
| pin only, wrong fingerprint | leaf | rejects | rejects |
| CA + wrong pin | leaf | rejects | rejects |

Every row was observed with real clients (OpenVPN 2.6.19 and the OpenVPN 3
core 3.11.3 test client) against real OpenVPN servers, in the CI lab
([results/lab-openvpn2.md](../results/lab-openvpn2.md),
[results/lab-openvpn3.md](../results/lab-openvpn3.md)). In every row,
`ovpncert`'s prediction matched the observed outcome.

Two practical consequences:

* **No single profile works everywhere.** CA + pin is the robust choice for
  OpenVPN 3 and does nothing for OpenVPN 2.6. Pin-only works for OpenVPN 2.6
  but fails on OpenVPN 3 whenever the server sends more than its leaf
  certificate. OpenVPN 2.6 servers often do: OpenSSL completes the chain from
  the server's `ca` file when that CA also issued the server certificate.
  Hence `ovpncert pin --client openvpn3` (default) and `--client openvpn2`.
* **Pinning certificates you have not verified is dangerous with OpenVPN 3.**
  A pinned leaf whose only problem is an unknown issuer at depth 0 is accepted,
  so pinning whatever a server presents would accept an interception
  certificate. `ovpncert pin` therefore refuses to pin any certificate that does
  not chain to the CA in the original profile.
