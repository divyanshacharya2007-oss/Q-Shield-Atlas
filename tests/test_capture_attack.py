import json

import pytest

from attack.factoring import (
    factor_and_decrypt_capture,
    factor_toy_modulus,
    replay_capture_offline,
)
from capture.service import ToyTLSService, dump_capture


def test_toy_capture_records_handshake_key_and_ciphertext(tmp_path):
    service = ToyTLSService(key_bits=64, service_id="toy-auth-service")
    capture = service.capture(b"legacy")
    capture_path = dump_capture(capture, tmp_path / "capture.json")
    loaded = json.loads(capture_path.read_text(encoding="utf-8"))

    assert loaded["service_id"] == "toy-auth-service"
    assert "TOY" in loaded["label"]
    assert loaded["public_key"]["algorithm"] == "RSA"
    assert 64 <= loaded["public_key"]["key_bits"] <= 128
    assert bytes.fromhex(loaded["handshake_bytes_hex"]).startswith(
        b"QSHIELD-TOY-HANDSHAKE/1"
    )
    assert loaded["ciphertexts"][0]["ciphertext_hex"]
    assert "legacy" not in capture_path.read_text(encoding="utf-8")


def test_toy_modulus_factors_and_captured_traffic_decrypts(tmp_path):
    service = ToyTLSService(key_bits=64)
    capture = service.capture(b"legacy")
    capture_path = dump_capture(capture, tmp_path / "capture.json")

    modulus = int(capture["public_key"]["modulus_hex"], 16)
    prime_p, prime_q = factor_toy_modulus(modulus)
    evidence_path = tmp_path / "attack-evidence.json"
    evidence = factor_and_decrypt_capture(capture_path, evidence_path=evidence_path)
    saved_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

    assert prime_p * prime_q == modulus
    assert evidence["network_used"] is False
    assert evidence["modulus_bits"] <= 128
    assert bytes.fromhex(evidence["decrypted_records"][0]["plaintext_hex"]) == b"legacy"
    assert saved_evidence["service_id"] == capture["service_id"]


def test_replay_mode_is_offline_and_reports_service_identity():
    capture = ToyTLSService(key_bits=64, service_id="old-service").capture(b"record")

    matching = replay_capture_offline(capture, target_service_id="old-service")
    migrated = replay_capture_offline(capture, target_service_id="migrated-service")

    assert matching.identity_matches is True
    assert migrated.identity_matches is False
    assert matching.record_ids == ("record-0001",)
    assert matching.transmitted is False


@pytest.mark.parametrize("modulus", [15, 2**2048 - 159])
def test_factoring_rejects_non_toy_modulus(modulus):
    with pytest.raises(ValueError, match="toy range"):
        factor_toy_modulus(modulus)


def test_capture_service_rejects_production_sized_key():
    with pytest.raises(ValueError, match="toy key_bits"):
        ToyTLSService(key_bits=2048)