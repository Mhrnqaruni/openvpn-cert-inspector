# Lab results

29 of 29 cases match the expected outcome.

| Environment | |
|---|---|
| date | 2026-11-22 |
| ovpncert | 1.0.0 |
| openvpn | OpenVPN 2.6.19 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO] |
| python | 3.12.16 |
| openssl | OpenSSL 3.0.13 30 Jan 2024 |
| platform | Linux-7.0.0-1017-azure-x86_64-with-glibc2.39 |

| Group | Case | Expected | Observed | ovpncert model | Result |
|---|---|---|---|---|---|
| A | udp/none | certificate | certificate | - | pass |
| A | udp/tls-auth HMAC-SHA256 kd 1 | certificate | certificate | - | pass |
| A | udp/tls-auth HMAC-SHA512 kd 1 | certificate | certificate | - | pass |
| A | udp/tls-auth HMAC-SHA1 bidirectional | certificate | certificate | - | pass |
| A | udp/tls-crypt | certificate | certificate | - | pass |
| A | tcp/none | certificate | certificate | - | pass |
| A | tcp/tls-auth HMAC-SHA256 kd 1 | certificate | certificate | - | pass |
| A | tcp/tls-crypt | certificate | certificate | - | pass |
| A | udp/tls-auth HMAC-SHA256 kd 1 (wrong-key) | no reply | no reply | - | pass |
| A | udp/tls-auth HMAC-SHA256 kd 0 (wrong-direction) | no reply | no reply | - | pass |
| B | server certificate: valid | CERTIFICATE_OK | CERTIFICATE_OK | - | pass |
| B | server certificate: expired | SERVER_CERT_EXPIRED | SERVER_CERT_EXPIRED | - | pass |
| B | server certificate: future | SERVER_CERT_NOT_YET_VALID | SERVER_CERT_NOT_YET_VALID | - | pass |
| B | server certificate: expiring | SERVER_CERT_EXPIRING | SERVER_CERT_EXPIRING | - | pass |
| B | server certificate: rogue | CA_MISMATCH | CA_MISMATCH | - | pass |
| B | server certificate: no-eku | SERVER_CERT_PURPOSE | SERVER_CERT_PURPOSE | - | pass |
| B | server certificate: chain | CERTIFICATE_OK | CERTIFICATE_OK | - | pass |
| B | server certificate: retired-ca | CA_EXPIRED | CA_EXPIRED | - | pass |
| C | OpenVPN 2: valid certificate, CA only | accepted | accepted | accepted | pass |
| C | OpenVPN 2: expired, leaf sent; CA only | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf sent; CA + pin | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf sent; pin only | accepted | accepted | accepted | pass |
| C | OpenVPN 2: expired, leaf sent; pin only, wrong pin | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf sent; `ovpncert pin --client openvpn2` | accepted | accepted | accepted | pass |
| C | OpenVPN 2: expired, leaf sent; `ovpncert pin --client openvpn3` | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf + root sent; CA + pin | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf + root sent; pin only | accepted | accepted | accepted | pass |
| C | OpenVPN 2: expired, leaf + intermediate sent; CA + pin | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf + intermediate sent; pin only | accepted | accepted | accepted | pass |
