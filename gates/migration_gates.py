"""Transactional migration checks for synthetic hybrid-PQC service states.

All checks are local state validation. This module does not configure or probe
network services and does not implement a production TLS stack.
"""

from __future__ import annotations

import copy
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from attack.factoring import factor_and_decrypt_capture, replay_capture_offline

HYBRID_KEY_EXCHANGES = frozenset({"ML-KEM-768", "ML-KEM-1024"})
HYBRID_SIGNATURES = frozenset({"ML-DSA-65", "ML-DSA-87"})
SUPPORTED_TLS_VERSIONS = frozenset({"TLSv1.3"})
SUPPORTED_CIPHER_SUITES = frozenset(
    {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
)
LEGACY_ALGORITHMS = frozenset({"RSA", "ECDSA", "ECC"})


@dataclass(frozen=True)
class GateCheck:
    """Result of validating one synthetic hybrid handshake profile."""

    compatible: bool
    failures: tuple[str, ...] = ()


@dataclass
class ServiceState:
    """Local representation of one service's migration-relevant crypto state."""

    service_id: str
    key_exchange: str = "RSA"
    signature_algorithm: str = "RSA"
    tls_version: str = "TLSv1.2"
    cipher_suite: str = "TLS_AES_128_GCM_SHA256"
    migration_status: str = "LEGACY"
    generation: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_hybrid(self) -> bool:
        return (
            self.key_exchange in HYBRID_KEY_EXCHANGES
            and self.signature_algorithm in HYBRID_SIGNATURES
            and self.migration_status == "MIGRATED"
        )


@dataclass(frozen=True)
class MigrationWaveResult:
    wave_id: str
    status: str
    migrated_service_ids: tuple[str, ...]
    checks: Mapping[str, GateCheck]
    rolled_back: bool


@dataclass(frozen=True)
class AttackReplayVerification:
    service_id: str
    status: str
    attack_succeeded: bool
    explicit_failure_status: str | None
    details: str


def verify_hybrid_compatibility(
    service_profile: ServiceState | Mapping[str, Any],
    handshake: ServiceState | Mapping[str, Any] | None = None,
) -> GateCheck:
    """Require matching hybrid ML-KEM/ML-DSA state and a supported TLS 1.3 profile."""
    expected = _as_mapping(service_profile)
    observed = _as_mapping(handshake if handshake is not None else service_profile)
    failures = []

    for field_name in ("key_exchange", "signature_algorithm", "tls_version", "cipher_suite"):
        if field_name not in expected or field_name not in observed:
            failures.append(f"missing {field_name} in expected or observed handshake")

    expected_kex = str(expected.get("key_exchange", ""))
    observed_kex = str(observed.get("key_exchange", ""))
    if expected_kex not in HYBRID_KEY_EXCHANGES:
        failures.append(f"unsupported hybrid key exchange: {expected_kex or 'missing'}")
    if observed_kex != expected_kex:
        failures.append(f"key exchange mismatch: expected={expected_kex}, observed={observed_kex}")

    expected_signature = str(expected.get("signature_algorithm", ""))
    observed_signature = str(observed.get("signature_algorithm", ""))
    if expected_signature not in HYBRID_SIGNATURES:
        failures.append(f"unsupported hybrid signature: {expected_signature or 'missing'}")
    if observed_signature != expected_signature:
        failures.append(
            f"signature mismatch: expected={expected_signature}, observed={observed_signature}"
        )

    tls_version = str(observed.get("tls_version", ""))
    if tls_version not in SUPPORTED_TLS_VERSIONS:
        failures.append(f"unsupported TLS version: {tls_version or 'missing'}")
    cipher_suite = str(observed.get("cipher_suite", ""))
    if cipher_suite not in SUPPORTED_CIPHER_SUITES:
        failures.append(f"unsupported cipher suite: {cipher_suite or 'missing'}")
    return GateCheck(compatible=not failures, failures=tuple(failures))


class MigrationGateController:
    """Apply migration waves transactionally and restore state if any gate fails."""

    def __init__(self, services: Sequence[ServiceState]) -> None:
        self.services = {service.service_id: service for service in services}
        if len(self.services) != len(services):
            raise ValueError("service_id values must be unique")

    def migrate_wave(
        self,
        wave_id: str,
        service_ids: Sequence[str],
        *,
        handshakes: Mapping[str, ServiceState | Mapping[str, Any]] | None = None,
    ) -> MigrationWaveResult:
        if not wave_id.strip():
            raise ValueError("wave_id must not be empty")
        if not service_ids or len(set(service_ids)) != len(service_ids):
            raise ValueError("a migration wave needs unique service IDs")
        missing = [service_id for service_id in service_ids if service_id not in self.services]
        if missing:
            raise KeyError(f"unknown service IDs in wave: {', '.join(missing)}")

        snapshots = {service_id: copy.deepcopy(self.services[service_id]) for service_id in service_ids}
        checks: dict[str, GateCheck] = {}
        for service_id in service_ids:
            state = self.services[service_id]
            if state.migration_status != "LEGACY" or state.key_exchange not in LEGACY_ALGORITHMS:
                checks[service_id] = GateCheck(
                    compatible=False,
                    failures=("service is not in a migratable legacy state",),
                )
                continue

            state.key_exchange = "ML-KEM-768"
            state.signature_algorithm = "ML-DSA-65"
            state.tls_version = "TLSv1.3"
            state.cipher_suite = "TLS_AES_128_GCM_SHA256"
            state.migration_status = "MIGRATED"
            state.generation += 1
            observed = handshakes.get(service_id, state) if handshakes else state
            checks[service_id] = verify_hybrid_compatibility(state, observed)

        passed = all(check.compatible for check in checks.values())
        if not passed:
            for service_id, snapshot in snapshots.items():
                current = self.services[service_id]
                current.key_exchange = snapshot.key_exchange
                current.signature_algorithm = snapshot.signature_algorithm
                current.tls_version = snapshot.tls_version
                current.cipher_suite = snapshot.cipher_suite
                current.migration_status = snapshot.migration_status
                current.generation = snapshot.generation
                current.metadata = snapshot.metadata
            return MigrationWaveResult(
                wave_id=wave_id,
                status="ROLLED_BACK",
                migrated_service_ids=(),
                checks=checks,
                rolled_back=True,
            )

        return MigrationWaveResult(
            wave_id=wave_id,
            status="PASSED",
            migrated_service_ids=tuple(service_ids),
            checks=checks,
            rolled_back=False,
        )


def verify_classical_replay(
    capture: Mapping[str, Any] | str | Path,
    service_state: ServiceState,
) -> AttackReplayVerification:
    """Run the toy factoring check for legacy state; explicitly reject it for hybrid state."""
    replay = replay_capture_offline(capture, target_service_id=service_state.service_id)
    if not replay.identity_matches:
        return AttackReplayVerification(
            service_id=service_state.service_id,
            status="FAILED",
            attack_succeeded=False,
            explicit_failure_status="SERVICE_ID_MISMATCH",
            details="Captured service ID does not match the target service state.",
        )

    if service_state.is_hybrid:
        return AttackReplayVerification(
            service_id=service_state.service_id,
            status="FAILED",
            attack_succeeded=False,
            explicit_failure_status="REPLAY_REJECTED_HYBRID_STATE",
            details="The migrated state has no legacy RSA record-acceptance profile.",
        )
    if service_state.migration_status != "LEGACY":
        return AttackReplayVerification(
            service_id=service_state.service_id,
            status="FAILED",
            attack_succeeded=False,
            explicit_failure_status="SERVICE_STATE_NOT_VERIFIABLE",
            details="Service state is neither a recognized legacy nor hybrid state.",
        )

    with tempfile.TemporaryDirectory(prefix="qshield-toy-attack-") as temporary_directory:
        evidence = factor_and_decrypt_capture(
            capture,
            evidence_path=Path(temporary_directory) / "evidence.json",
        )
    decrypted = evidence.get("decrypted_records", [])
    if decrypted:
        return AttackReplayVerification(
            service_id=service_state.service_id,
            status="SUCCEEDED",
            attack_succeeded=True,
            explicit_failure_status=None,
            details=f"Toy RSA factoring decrypted {len(decrypted)} captured record(s).",
        )
    return AttackReplayVerification(
        service_id=service_state.service_id,
        status="FAILED",
        attack_succeeded=False,
        explicit_failure_status="NO_DECRYPTED_RECORDS",
        details="The toy capture contained no decryptable records.",
    )


def _as_mapping(value: ServiceState | Mapping[str, Any] | None) -> Mapping[str, Any]:
    if isinstance(value, ServiceState):
        return {
            "key_exchange": value.key_exchange,
            "signature_algorithm": value.signature_algorithm,
            "tls_version": value.tls_version,
            "cipher_suite": value.cipher_suite,
        }
    return value or {}