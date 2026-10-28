from capture.service import ToyTLSService
from gates.migration_gates import (
    MigrationGateController,
    ServiceState,
    verify_classical_replay,
    verify_hybrid_compatibility,
)


def test_wave_migration_passes_hybrid_protocol_verification():
    service = ServiceState(service_id="auth-service")
    controller = MigrationGateController([service])

    result = controller.migrate_wave("wave-1", ["auth-service"])

    assert result.status == "PASSED"
    assert result.rolled_back is False
    assert result.migrated_service_ids == ("auth-service",)
    assert result.checks["auth-service"].compatible is True
    assert service.is_hybrid
    assert service.key_exchange == "ML-KEM-768"
    assert service.signature_algorithm == "ML-DSA-65"
    assert verify_hybrid_compatibility(service).compatible is True


def test_failed_handshake_check_rolls_back_entire_wave():
    first = ServiceState(service_id="auth-service")
    second = ServiceState(service_id="payments-service", key_exchange="ECDSA")
    controller = MigrationGateController([first, second])
    incompatible_handshake = {
        "key_exchange": "ML-KEM-768",
        "signature_algorithm": "ML-DSA-65",
        "tls_version": "TLSv1.2",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
    }

    result = controller.migrate_wave(
        "wave-2",
        ["auth-service", "payments-service"],
        handshakes={"payments-service": incompatible_handshake},
    )

    assert result.status == "ROLLED_BACK"
    assert result.rolled_back is True
    assert result.migrated_service_ids == ()
    assert result.checks["payments-service"].compatible is False
    assert first.key_exchange == "RSA"
    assert first.migration_status == "LEGACY"
    assert first.generation == 0
    assert second.key_exchange == "ECDSA"
    assert second.migration_status == "LEGACY"
    assert second.generation == 0


def test_toy_classical_replay_succeeds_legacy_and_fails_hybrid_gate():
    capture = ToyTLSService(key_bits=64, service_id="legacy-api").capture(b"legacy")
    service = ServiceState(service_id="legacy-api")

    legacy_result = verify_classical_replay(capture, service)
    migration_result = MigrationGateController([service]).migrate_wave(
        "wave-3", ["legacy-api"]
    )
    hybrid_result = verify_classical_replay(capture, service)

    assert legacy_result.status == "SUCCEEDED"
    assert legacy_result.attack_succeeded is True
    assert legacy_result.explicit_failure_status is None
    assert migration_result.status == "PASSED"
    assert hybrid_result.status == "FAILED"
    assert hybrid_result.attack_succeeded is False
    assert hybrid_result.explicit_failure_status == "REPLAY_REJECTED_HYBRID_STATE"