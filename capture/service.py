"""Generate synthetic, offline TLS-like exchanges using a deliberately weak RSA key."""

from __future__ import annotations

import json
import math
import secrets
from pathlib import Path
from typing import Any

DEFAULT_KEY_BITS = 70
MIN_TOY_KEY_BITS = 64
MAX_TOY_KEY_BITS = 128
DEFAULT_SERVICE_ID = "atlas-toy-rsa-service"
DEFAULT_LABEL = "TOY ONLY: weak RSA stand-in; not a TLS implementation"
DEFAULT_MESSAGE = b"legacy"
CONTRACT_VERSION = "q-shield-capture/1"


def _is_probable_prime(candidate: int) -> bool:
    if candidate < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    odd_part = candidate - 1
    powers_of_two = 0
    while odd_part % 2 == 0:
        powers_of_two += 1
        odd_part //= 2
    for base in small_primes:
        if base >= candidate - 1:
            continue
        value = pow(base, odd_part, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(powers_of_two - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


class ToyTLSService:
    """Produce a synthetic handshake and textbook-RSA encrypted toy payload.

    This class does not bind a socket or implement TLS. Its handshake bytes are
    a labeled teaching artifact only and must not be used as a protocol.
    """

    def __init__(
        self,
        *,
        key_bits: int = DEFAULT_KEY_BITS,
        service_id: str = DEFAULT_SERVICE_ID,
        label: str = DEFAULT_LABEL,
    ) -> None:
        if isinstance(key_bits, bool) or not MIN_TOY_KEY_BITS <= key_bits <= MAX_TOY_KEY_BITS:
            raise ValueError(f"toy key_bits must be between {MIN_TOY_KEY_BITS} and {MAX_TOY_KEY_BITS}")
        if not service_id.strip():
            raise ValueError("service_id must not be empty")
        if not label.strip() or "TOY" not in label.upper():
            raise ValueError("label must clearly mark this as a toy service")

        prime_bits = (key_bits + 1) // 2
        public_exponent = 65537
        while True:
            prime_p = _generate_prime(prime_bits)
            prime_q = _generate_prime(prime_bits)
            if prime_p == prime_q:
                continue
            totient = (prime_p - 1) * (prime_q - 1)
            if math.gcd(public_exponent, totient) == 1:
                modulus = prime_p * prime_q
                if MIN_TOY_KEY_BITS <= modulus.bit_length() <= MAX_TOY_KEY_BITS:
                    break

        self.service_id = service_id
        self.label = label
        self.modulus = modulus
        self.public_exponent = public_exponent
        self._private_exponent = pow(public_exponent, -1, totient)

    def capture(self, plaintext: bytes = DEFAULT_MESSAGE) -> dict[str, Any]:
        """Return a contract-shaped capture; the plaintext is never stored."""
        if not isinstance(plaintext, bytes) or not plaintext:
            raise ValueError("plaintext must be non-empty bytes")
        message_value = int.from_bytes(plaintext, "big")
        if message_value >= self.modulus:
            raise ValueError("plaintext is too large for this toy RSA modulus")
        ciphertext = pow(message_value, self.public_exponent, self.modulus)
        key_bits = self.modulus.bit_length()
        modulus_bytes = (key_bits + 7) // 8
        handshake = (
            b"QSHIELD-TOY-HANDSHAKE/1\n"
            + f"service_id={self.service_id}\n".encode("utf-8")
            + f"rsa_bits={key_bits}\n".encode("ascii")
            + f"label={self.label}\n".encode("utf-8")
        )
        return {
            "contract": CONTRACT_VERSION,
            "service_id": self.service_id,
            "label": self.label,
            "protocol": "synthetic-tls-like-toy-only",
            "public_key": {
                "algorithm": "RSA",
                "modulus_hex": format(self.modulus, "x"),
                "public_exponent": self.public_exponent,
                "key_bits": key_bits,
            },
            "handshake_bytes_hex": handshake.hex(),
            "ciphertexts": [
                {
                    "record_id": "record-0001",
                    "encoding": "raw-rsa-fixed-width-big-endian",
                    "ciphertext_hex": ciphertext.to_bytes(modulus_bytes, "big").hex(),
                }
            ],
        }

    def decrypt_for_test(self, ciphertext_hex: str) -> bytes:
        """Decrypt only with this generated toy service's private key."""
        ciphertext = int.from_bytes(bytes.fromhex(ciphertext_hex), "big")
        message = pow(ciphertext, self._private_exponent, self.modulus)
        return message.to_bytes(max(1, (message.bit_length() + 7) // 8), "big")


def create_capture(
    plaintext: bytes = DEFAULT_MESSAGE,
    *,
    key_bits: int = DEFAULT_KEY_BITS,
    service_id: str = DEFAULT_SERVICE_ID,
) -> dict[str, Any]:
    """Create one ephemeral, offline toy exchange capture."""
    service = ToyTLSService(key_bits=key_bits, service_id=service_id)
    return service.capture(plaintext)


def dump_capture(
    capture: dict[str, Any],
    path: str | Path = "contracts/capture.json",
) -> Path:
    """Write a capture artifact as formatted JSON without adding plaintext."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(capture, indent=2) + "\n", encoding="utf-8")
    return destination