# Lab results

22 of 22 cases match the expected outcome.

| Environment | |
|---|---|
| date | 2026-11-22 |
| ovpncert | 1.0.0 |
| openvpn | OpenVPN 2.6.19 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO] |
| python | 3.12.16 |
| openssl | OpenSSL 3.0.13 30 Jan 2024 |
| platform | Linux-7.0.0-1017-azure-x86_64-with-glibc2.39 |
| openvpn3_client | /home/runner/ovpncli/ovpncli |

| Group | Case | Expected | Observed | ovpncert model | Result |
|---|---|---|---|---|---|
| C | OpenVPN 2: valid certificate, CA only | accepted | accepted | accepted | pass |
| C | OpenVPN 3: valid certificate, CA only | accepted | accepted | accepted | pass |
| C | OpenVPN 2: expired, leaf sent; CA only | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf sent; CA + pin | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf sent; pin only | accepted | accepted | accepted | pass |
| C | OpenVPN 2: expired, leaf sent; pin only, wrong pin | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf sent; `ovpncert pin --client openvpn2` | accepted | accepted | accepted | pass |
| C | OpenVPN 2: expired, leaf sent; `ovpncert pin --client openvpn3` | rejected | rejected | rejected | pass |
| C | OpenVPN 3: expired, leaf sent; CA only | rejected | rejected | rejected | pass |
| C | OpenVPN 3: expired, leaf sent; CA + pin | accepted | accepted | accepted | pass |
| C | OpenVPN 3: expired, leaf sent; pin only | accepted | accepted | accepted | pass |
| C | OpenVPN 3: expired, leaf sent; CA + wrong pin | rejected | rejected | rejected | pass |
| C | OpenVPN 3: expired, leaf sent; `ovpncert pin --client openvpn3` | accepted | accepted | accepted | pass |
| C | OpenVPN 3: expired, leaf sent; `ovpncert pin --client openvpn2` | accepted | accepted | accepted | pass |
| C | OpenVPN 2: expired, leaf + root sent; CA + pin | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf + root sent; pin only | accepted | accepted | accepted | pass |
| C | OpenVPN 3: expired, leaf + root sent; CA + pin | accepted | accepted | accepted | pass |
| C | OpenVPN 3: expired, leaf + root sent; pin only | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf + intermediate sent; CA + pin | rejected | rejected | rejected | pass |
| C | OpenVPN 2: expired, leaf + intermediate sent; pin only | accepted | accepted | accepted | pass |
| C | OpenVPN 3: expired, leaf + intermediate sent; CA + pin | accepted | accepted | accepted | pass |
| C | OpenVPN 3: expired, leaf + intermediate sent; pin only | rejected | rejected | rejected | pass |
