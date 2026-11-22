# Related work

## Why certificate expiry needs monitoring

Expired certificates are a recurring cause of large outages:

- **Ericsson, December 2018.** An expired certificate in mobile-core software
  cut service for tens of millions of subscribers at O2 UK and SoftBank
  ([Ericsson](https://www.ericsson.com/en/press-releases/2018/12/update-on-software-issue-impacting-certain-customers),
  [The Register](https://www.theregister.com/2018/12/06/ericsson_o2_telefonica_uk_outage/)).
- **Microsoft Teams, February 2020.** An expired authentication certificate
  took the service down
  ([The Register](https://www.theregister.com/2020/02/03/teams_down/)).
- **Let's Encrypt, September 2021.** The expiry of the DST Root CA X3 root
  broke older clients across many providers
  ([Let's Encrypt](https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/)).
- **Cisco SD-WAN vEdge, May 2023.** A certificate expiry dropped the overlay
  tunnels of SD-WAN devices
  ([Cisco](https://www.cisco.com/c/en/us/support/docs/routers/sd-wan/220448-identify-vedge-certificate-expired-on-ma.html)).
- **Equifax, 2017.** An expired certificate on a traffic-inspection device
  meant encrypted traffic went unexamined for months. The breach was noticed
  only after it was renewed
  ([GAO-18-559](https://www.gao.gov/assets/gao-18-559.pdf)).

Private OpenVPN PKIs make expiry dates predictable. Easy-RSA, the usual tool,
has defaulted to 825-day certificates since version 3.0.7 and 3650-day CAs
([commit](https://github.com/OpenVPN/easy-rsa/commit/7f727b791b76147f97bfae2a152f57ad94240106),
[vars.example](https://github.com/OpenVPN/easy-rsa/blob/master/easyrsa3/vars.example)).
The public Web PKI is moving to much shorter lifetimes: CA/Browser Forum
ballot SC-081v3 caps them at 200 days from March 2026 and 47 days from March
2029
([ballot](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)).
That ballot does not cover private OpenVPN CAs. It does make automated
renewal and expiry monitoring the norm.

## Reading or monitoring a server certificate

| Tool / approach | What it does | OpenVPN server certificate? |
|---|---|---|
| [`openssl s_client`](https://docs.openssl.org/master/man1/openssl-s_client/), [testssl.sh](https://github.com/testssl/testssl.sh), [sslyze](https://github.com/nabla-c0d3/sslyze), [nmap `ssl-cert`](https://nmap.org/nsedoc/scripts/ssl-cert.html) | TLS handshake directly on a socket, optionally after STARTTLS | No. OpenVPN carries TLS inside its own control packets |
| [Prometheus blackbox_exporter](https://github.com/prometheus/blackbox_exporter), [check_ssl_cert](https://github.com/matteocorti/check_ssl_cert) | expiry monitoring over plain TLS, or of certificate files | Only when run on the VPN host against local files ([example](https://forum.netgate.com/topic/64449/monitor-openvpn-certificate-expiration-dates)) |
| [check_openvpn](https://github.com/liquidat/nagios-icinga-openvpn) (Nagios/Icinga) | liveness: sends a hard reset (optionally `tls-auth`-signed) and waits for the server's reply | No. Stops before the TLS handshake |
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
  ([paper](https://research.google.com/pubs/archive/46359.pdf)). In more than
  300 million Chrome certificate errors, over half had client-side or network
  causes. A wrong system clock caused 33.5% of the errors reported on
  Windows. This motivates the NTP check in `ovpncert diagnose`: a client
  whose clock is behind sees a freshly renewed certificate as "not yet
  valid", and one whose clock is ahead sees a valid certificate as expired.

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
