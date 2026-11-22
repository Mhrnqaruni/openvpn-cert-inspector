# Related work

## Reading or monitoring a server certificate

| Tool / approach | What it does | OpenVPN server certificate? |
|---|---|---|
| [`openssl s_client`](https://docs.openssl.org/master/man1/openssl-s_client/), [testssl.sh](https://github.com/testssl/testssl.sh), [sslyze](https://github.com/nabla-c0d3/sslyze), [nmap `ssl-cert`](https://nmap.org/nsedoc/scripts/ssl-cert.html) | TLS handshake directly on a socket, optionally after STARTTLS | No. OpenVPN carries TLS inside its own control packets |
| [Prometheus blackbox_exporter](https://github.com/prometheus/blackbox_exporter), [check_ssl_cert](https://github.com/matteocorti/check_ssl_cert) | expiry monitoring over plain TLS, or of certificate files | Only when run on the VPN host against local files ([example](https://forum.netgate.com/topic/64449/monitor-openvpn-certificate-expiration-dates)) |
| OpenVPN community answers | a [forum question](https://forums.openvpn.net/viewtopic.php?p=110835) on checking a server's certificate expiry remotely got "log in to the server and read the file" | No remote method |
| OpenVPN client logs | report "certificate verify failed" after the fact; OpenVPN's own [troubleshooting article](https://support.openvpn.com/hc/en-us/articles/36141971457179-Access-Server-Peer-Certificate-Verification-Failure) lists expired CA, server or client certificates as causes | Symptom only |
| **ovpncert** | client side of the OpenVPN control channel up to the end of the TLS handshake, with the profile's `tls-auth`/`tls-crypt` key | **Yes**, remotely and without credentials |

## OpenVPN protocol and verification

- **`peer-fingerprint`** was introduced in OpenVPN 2.6. Its documentation
  presents it for small setups that do without a PKI
  ([example-fingerprint](https://sources.debian.org/src/openvpn/2.6.3-1%2Bdeb12u3/doc/man-sections/example-fingerprint.rst)).
  Using it to keep clients connected through an operator-side certificate
  expiry, and the different semantics of OpenVPN 2.6 and OpenVPN 3, are
  analysed in [compatibility.md](compatibility.md) from the source code of
  both implementations and confirmed in the lab.
- **Control-channel protection.** `tls-auth` and `tls-crypt` make a server
  ignore unauthenticated packets. That defeats generic scanners, and it is why
  the probe needs the profile's static key.

## Research

- D. Xue et al., *"OpenVPN is Open to VPN Fingerprinting"*, USENIX Security 2022
  ([paper](https://www.usenix.org/conference/usenixsecurity22/presentation/xue-diwen)).
  It shows that OpenVPN traffic and servers can be identified from protocol
  behaviour such as opcodes and acknowledgement patterns. Fingerprinting
  establishes *that* a server speaks OpenVPN. `ovpncert` goes one step
  further for servers you are entitled to use: it reads and verifies the
  certificate.
- M. E. Acer et al., *"Where the Wild Warnings Are: Root Causes of Chrome HTTPS
  Certificate Errors"*, ACM CCS 2017
  ([paper](https://dl.acm.org/doi/10.1145/3133956.3134007)). It found that a
  large share of certificate errors are caused on the client side, notably by
  wrong clocks. This motivates the NTP check in `ovpncert diagnose`.

## Certificate pinning

- RFC 7469, *Public Key Pinning Extension for HTTP*
  ([rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7469)), is the
  best-known pinning mechanism. It was later abandoned by browsers because a
  wrong pin locks users out. `ovpncert` limits that risk: pins are written
  only for certificates verified against the CA, and only as a temporary
  profile that fails closed on renewal.
- SSH host keys follow trust-on-first-use. A `peer-fingerprint` profile is
  similar, except that `ovpncert pin` verifies the certificate against your
  CA before trusting it, rather than trusting whatever the server presents
  first.
