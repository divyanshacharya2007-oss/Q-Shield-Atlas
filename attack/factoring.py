"""Toy-key factorization and offline capture replay inspection.

This module intentionally refuses production-size moduli and never opens a
network connection. It is not a TLS attack tool.
"""

from __future__ import annotations

import json
import math
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from capture.service import CONTRACT_VERSION, MAX_TOY_KEY_BITS, MIN_TOY_KEY_BITS

MAX_RHO_ITERATIONS = 2_000_000
SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


@dataclass(frozen=True)
class OfflineReplayResult:
    """Inspection result for a captured record, never a network transmission."""

    capture_service_id: str
    target_service_id: str
    record_ids: tuple[str, ...]
    identity_matches: bool
    transmitted: bool = False


def _is_probable_prime(candidate: int) -> bool:
    if candidate < 2:
        return False
    for prime in SMALL_PRIMES:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    odd_part = candidate - 1
    powers_of_two = 0
    while odd_part % 2 == 0:
        powers_of_two += 1
        odd_part //= 2
    for base in SMALL_PRIMES:
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


def _pollard_rho_factor(number: int) -> int:
    for prime in SMALL_PRIMES:
        if number % prime == 0:
            return prime

    for _ in range(24):
        x = secrets.randbelow(number - 2) + 2
        y = x
        constant = secrets.randbelow(number - 1) + 1
        divisor = 1
        for _iteration in range(MAX_RHO_ITERATIONS):
            x = (x * x + constant) % number
            y = (y * y + constant) % number
            y = (y * y + constant) % number
            divisor = math.gcd(abs(x - y), number)
            if divisor == 1:
                continue
            if divisor != number:
                return divisor
            break
    raise ValueError("could not factor toy modulus within the bounded Pollard-rho budget")


def factor_toy_modulus(modulus: int) -> tuple[int, int]:
    """Factor a semiprime only when its modulus is in the 64–128-bit toy range."""
    if isinstance(modulus, bool) or not isinstance(modulus, int) or modulus <= 0:
        raise ValueError("modulus must be a positive integer")
    if not MIN_TOY_KEY_BITS <= modulus.bit_length() <= MAX_TOY_KEY_BITS:
        raise ValueError(
            f"refusing modulus outside toy range ({MIN_TOY_KEY_BITS}-{MAX_TOY_KEY_BITS} bits)"
        )
    factor = _pollard_rho_factor(modulus)
    other_factor = modulus // factor
    if factor * other_factor != modulus or not _is_probable_prime(factor) or not _is_probable_prime(other_factor):
        raise ValueError("capture modulus is not a two-prime toy RSA modulus")
    return tuple(sorted((factor, other_factor)))


def _load_capture(capture: Mapping[str, Any] | str | Path) -> dict[str, Any]:
    if isinstance(capture, (str, Path)):
        data = json.loads(Path(capture).read_text(encoding="utf-8"))
    elif isinstance(capture, Mapping):
        data = dict(capture)
    else:
        raise TypeError("capture must be a mapping or JSON file path")

    required = {
        "contract",
        "service_id",
        "label",
        "protocol",
        "public_key",
        "handshake_bytes_hex",
        "ciphertexts",
    }
    if set(data) != required:
        raise ValueError("capture does not match the q-shield-capture/1 contract fields")
    if data["contract"] != CONTRACT_VERSION or "toy" not in str(data["label"]).lower():
        raise ValueError("capture must use the explicitly labeled toy capture contract")
    if data["protocol"] != "synthetic-tls-like-toy-only":
        raise ValueError("only synthetic TLS-like toy captures are supported")
    public_key = data["public_key"]
    if set(public_key) != {"algorithm", "modulus_hex", "public_exponent", "key_bits"}:
        raise ValueError("capture public_key does not match the contract")
    modulus = int(public_key["modulus_hex"], 16)
    if public_key["algorithm"] != "RSA" or modulus.bit_length() != public_key["key_bits"]:
        raise ValueError("capture RSA key metadata is inconsistent")
    if not MIN_TOY_KEY_BITS <= modulus.bit_length() <= MAX_TOY_KEY_BITS:
        raise ValueError("capture modulus is outside the permitted toy range")
    if not isinstance(data["ciphertexts"], list) or not data["ciphertexts"]:
        raise ValueError("capture must contain at least one ciphertext record")
    return data


def factor_and_decrypt_capture(
    capture: Mapping[str, Any] | str | Path = "contracts/capture.json",
    *,
    evidence_path: str | Path = "contracts/attack-evidence.json",
) -> dict[str, Any]:
    """Factor a captured toy RSA modulus, decrypt records, and write evidence."""
    data = _load_capture(capture)
    public_key = data["public_key"]
    modulus = int(public_key["modulus_hex"], 16)
    public_exponent = int(public_key["public_exponent"])
    prime_p, prime_q = factor_toy_modulus(modulus)
    totient = (prime_p - 1) * (prime_q - 1)
    private_exponent = pow(public_exponent, -1, totient)
    plaintext_records = []

    for record in data["ciphertexts"]:
        if set(record) != {"record_id", "encoding", "ciphertext_hex"}:
            raise ValueError("ciphertext record does not match the capture contract")
        if record["encoding"] != "raw-rsa-fixed-width-big-endian":
            raise ValueError("unsupported toy ciphertext encoding")
        ciphertext = int.from_bytes(bytes.fromhex(record["ciphertext_hex"]), "big")
        if ciphertext >= modulus:
            raise ValueError("ciphertext integer must be less than the RSA modulus")
        plaintext_value = pow(ciphertext, private_exponent, modulus)
        plaintext = plaintext_value.to_bytes(max(1, (plaintext_value.bit_length() + 7) // 8), "big")
        plaintext_records.append(
            {
                "record_id": record["record_id"],
                "plaintext_hex": plaintext.hex(),
                "plaintext_utf8": plaintext.decode("utf-8", errors="replace"),
            }
        )

    evidence = {
        "contract": "q-shield-attack-evidence/1",
        "service_id": data["service_id"],
        "label": "TOY ONLY: classical factorization demonstration",
        "modulus_bits": modulus.bit_length(),
        "factors": [str(prime_p), str(prime_q)],
        "private_exponent": str(private_exponent),
        "decrypted_records": plaintext_records,
        "network_used": False,
    }
    destination = Path(evidence_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    return evidence


def replay_capture_offline(
    capture: Mapping[str, Any] | str | Path,
    *,
    target_service_id: str,
) -> OfflineReplayResult:
    """Inspect captured record identity for replay tests without transmitting it."""
    data = _load_capture(capture)
    if not target_service_id:
        raise ValueError("target_service_id must not be empty")
    return OfflineReplayResult(
        capture_service_id=data["service_id"],
        target_service_id=target_service_id,
        record_ids=tuple(record["record_id"] for record in data["ciphertexts"]),
        identity_matches=data["service_id"] == target_service_id,
    )