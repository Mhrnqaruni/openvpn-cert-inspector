"""Remote inspection, diagnosis and monitoring of OpenVPN server certificates.

The package speaks just enough of the OpenVPN control channel (hard reset, the
reliability layer and the TLS handshake carried inside ``P_CONTROL_V1``
packets) to read the certificate chain an OpenVPN server presents. It never
sends the key-method-2 message, so credentials and client options never leave
the machine.
"""

__all__ = ["__version__"]

__version__ = "1.0.0"
