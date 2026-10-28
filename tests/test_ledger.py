import json

from ledger.merkle_ledger import ENTRY_FIELDS, MerkleLedger, hash_payload


def test_append_builds_signed_hash_chain_and_merkle_root(tmp_path):
    ledger_path = tmp_path / "migration-ledger.json"
    ledger = MerkleLedger(ledger_path)
    first = ledger.append(
        "migration_event",
        {"service_id": "auth", "from": "RSA", "to": "ML-KEM-768"},
        ts="2026-10-28T12:00:00Z",
    )
    second = ledger.append_run_manifest(
        inputs={"assets": ["auth"]},
        solver_output={"schedule": ["auth"]},
        job_id="job-42",
        ts="2026-10-28T12:01:00Z",
    )

    assert set(first) == ENTRY_FIELDS
    assert first["index"] == 0
    assert second["index"] == 1
    assert first["payload_hash"] == hash_payload(
        {"service_id": "auth", "from": "RSA", "to": "ML-KEM-768"}
    )
    assert second["prev_hash"] != "0" * 64
    assert second["sig_mldsa"]["status"] in {"ML-DSA", "FALLBACK_CLASSICAL"}
    assert ledger.verify_hash_chain()
    assert ledger.verify_signatures()
    assert ledger.verify_merkle()
    assert ledger.verify()
    assert ledger.verify_payload(0, {"service_id": "auth", "from": "RSA", "to": "ML-KEM-768"})

    persisted = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert [entry["index"] for entry in persisted] == [0, 1]
    assert (tmp_path / "migration-ledger.json.root").read_text(encoding="ascii").strip() == ledger.merkle_root


def test_signature_generation_and_verification_is_explicitly_labeled():
    ledger = MerkleLedger()
    entry = ledger.append("event", {"value": 7})

    assert entry["sig_mldsa"]["signature"]
    assert entry["sig_mldsa"]["public_key"]
    assert entry["sig_mldsa"]["status"] == ledger.signature_status
    if ledger.signature_status == "FALLBACK_CLASSICAL":
        assert entry["sig_mldsa"]["algorithm"] in {"ECDSA-SHA256", "ML-DSA-65"}
        assert "CLASSICAL" in ledger.signature_status
    assert ledger.verify_signatures()


def test_merkle_inclusion_proof_verifies_for_entry():
    ledger = MerkleLedger()
    ledger.append("event", {"value": "a"})
    ledger.append("event", {"value": "b"})
    ledger.append("event", {"value": "c"})
    root = ledger.merkle_root

    proof = ledger.inclusion_proof(2)

    assert ledger.verify_inclusion(2, proof, root)
    assert not ledger.verify_inclusion(2, proof, "0" * 64)


def test_historical_payload_hash_tamper_fails_merkle_chain_and_signature_checks():
    ledger = MerkleLedger()
    ledger.append("event", {"value": "original"})
    ledger.append("event", {"value": "subsequent"})
    anchored_root = ledger.merkle_root

    ledger.entries[0]["payload_hash"] = hash_payload({"value": "tampered"})

    assert ledger.verify_merkle(anchored_root) is False
    assert ledger.verify_hash_chain() is False
    assert ledger.verify_signatures() is False
    assert ledger.verify(anchored_root) is False
    assert ledger.verify_payload(0, {"value": "original"}) is False