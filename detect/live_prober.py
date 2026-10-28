"""Single-endpoint TLS metadata probing and static/live drift comparison."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class TLSObservation:
    host: str
    port: int
    key_type: str
    key_size: int
    cipher_suite: str
    tls_version: str


@dataclass(frozen=True)
class ConfigurationDrift:
    asset_id: str
    mismatches: tuple[str, ...]

    @property
    def has_drift(self) -> bool:
        return bool(self.mismatches)


def probe_tls_endpoint(
    host: str,
    port: int = 443,
    *,
    timeout: float = 5.0,
    server_hostname: str | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> TLSObservation:
    """Perform one TLS handshake and return peer key and negotiated cipher metadata."""
    if not host or not isinstance(host, str):
        raise ValueError("host must be a non-empty hostname")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535")
    if timeout <= 0:
        raise ValueError("timeout must be positive")

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
    except ImportError as error:
        raise RuntimeError("TLS public-key inspection requires the 'cryptography' package") from error

    context = ssl_context or ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=server_hostname or host) as tls_socket:
            certificate_der = tls_socket.getpeercert(binary_form=True)
            if not certificate_der:
                raise ssl.SSLError("TLS peer did not provide a certificate")
            public_key = x509.load_der_x509_certificate(certificate_der).public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                key_type = "RSA"
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                key_type = "ECDSA"
            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                key_type = "ED25519"
            elif isinstance(public_key, ed448.Ed448PublicKey):
                key_type = "ED448"
            else:
                key_type = public_key.__class__.__name__.replace("PublicKey", "").upper()
            cipher = tls_socket.cipher()
            if cipher is None:
                raise ssl.SSLError("TLS handshake did not negotiate a cipher suite")
            return TLSObservation(
                host=host,
                port=port,
                key_type=key_type,
                key_size=public_key.key_size,
                cipher_suite=cipher[0],
                tls_version=tls_socket.version() or "unknown",
            )


def compare_configuration_drift(
    static_finding: Any,
    live_observation: TLSObservation | Mapping[str, Any],
) -> ConfigurationDrift:
    """Compare a static Atlas finding with one live TLS observation."""
    static = (
        static_finding.to_scan_record()
        if hasattr(static_finding, "to_scan_record")
        else static_finding
    )
    live = (
        live_observation.__dict__
        if isinstance(live_observation, TLSObservation)
        else live_observation
    )
    mismatches = []

    static_type = str(static.get("key_type", "")).upper()
    live_type = str(live.get("key_type", "")).upper()
    normalize_type = {"ECC": "ECDSA", "EC": "ECDSA"}
    if normalize_type.get(static_type, static_type) != normalize_type.get(live_type, live_type):
        mismatches.append(f"key_type: static={static_type}, live={live_type}")

    static_size = static.get("key_size")
    live_size = live.get("key_size")
    if static_size is not None and live_size is not None and int(static_size) != int(live_size):
        mismatches.append(f"key_size: static={static_size}, live={live_size}")

    configured_suites = {
        str(suite).upper() for suite in static.get("cipher_suites", [])
    }
    negotiated_suite = str(live.get("cipher_suite", "")).upper()
    if configured_suites and negotiated_suite not in configured_suites:
        mismatches.append(
            f"cipher_suite: configured={','.join(sorted(configured_suites))}, "
            f"negotiated={negotiated_suite}"
        )

    return ConfigurationDrift(
        asset_id=str(static.get("asset_id", live.get("host", "unknown"))),
        mismatches=tuple(mismatches),
    )