# Responsible use

`ovpncert` reads the same certificate any OpenVPN client receives when it
connects, and it can relax one specific check on your own client. Both deserve
some care.

## What the probe does on the network

* One hard reset and one TLS handshake per remote, then it stops. No
  username, password, client certificate or client option is sent, and no
  tunnel is created.
* For servers protected by `tls-auth` or `tls-crypt`, the static key from
  your client profile is used to authenticate the probe's packets, exactly as
  your VPN client does. Without that key the server does not answer.
* The server sees an aborted handshake from your address, as it would after a
  failed connection attempt.

Production servers may rate-limit or ignore bursts of handshakes from one
address. For monitoring, run checks minutes apart, not in a tight loop. Only
probe servers you are entitled to use or operate.

## When a pinned profile is appropriate

Use `ovpncert pin` only when all of these hold:

* the diagnosis is `SERVER_CERT_EXPIRED` (or not yet valid) and nothing else;
* the certificate is signed by the CA in the profile your operator gave you
  (`ovpncert pin` refuses otherwise);
* you need access before the operator can renew the certificate, and your
  organisation's policy allows you to adjust your own client profile.

Do **not** pin when the diagnosis is `CA_MISMATCH`, which means the
certificate does not chain to your CA. That is either a CA change you should
confirm with the operator, or an interception.

## What a pin relaxes, and what it does not

A `peer-fingerprint` pin binds the client to one exact certificate. An
attacker can copy a certificate, but cannot use it without the matching
private key, which the TLS handshake proves the server holds. The pin keeps
every other protection: the TLS handshake itself, `tls-auth`/`tls-crypt`, and
the `remote-cert-tls` key-usage check. Server-side authentication of your
credentials is unchanged. The only thing given up is the client-side check of
the certificate's validity period.

## Reverting

The pin matches only the certificate that was current when you created it.
When the operator renews it, the pinned profile stops connecting on its own:
it **fails closed**. Switch back to the original profile at that point and
delete the pinned copy. The field validation in [results.md](results.md) shows
this happening on a production service.

## Reporting

Tell the operator. They are usually the only ones who can fix the cause, and
an expired server certificate affects every user, not just you. `ovpncert
diagnose` prints the evidence an operator needs: the certificate subject,
serial number, expiry time and the verified chain.
