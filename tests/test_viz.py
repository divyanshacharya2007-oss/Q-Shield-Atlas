import json
from pathlib import Path

from jsonschema import validate

from ledger.merkle_ledger import MerkleLedger
from viz.export import export_results

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "contracts" / "results.schema.json"


def test_export_results_aggregates_pipeline_and_validates_contract(tmp_path):
    assets = [
        {
            "asset_id": "auth",
            "domain": "auth.example.test",
            "key_type": "RSA",
            "key_size": 2048,
            "tls_version": "TLSv1.2",
            "shelf_life_years": 3.0,
            "effort_weeks": 2.0,
            "risk_weight": 7.0,
            "vulnerable": True,
            "dependencies": [],
            "evidence": [{"file": "auth/settings.py", "line": 12}],
            "cipher_suites": ["TLS_AES_128_GCM_SHA256"],
        },
        {
            "asset_id": "payments",
            "domain": "payments.example.test",
            "key_type": "ECDSA",
            "key_size": 256,
            "tls_version": "TLSv1.2",
            "shelf_life_years": 3.0,
            "effort_weeks": 2.0,
            "risk_weight": 7.0,
            "vulnerable": True,
            "dependencies": [],
            "evidence": [{"file": "payments/tls.yaml", "line": 2}],
            "cipher_suites": [],
        },
    ]
    schedule_result = {
        "optimized": {"objective": 0.9, "schedule": [{"asset_id": "auth", "start_week": 0}]},
        "fcfs": {"objective": 1.8, "schedule": [{"asset_id": "auth", "start_week": 0}]},
        "greedy": {"objective": 1.2, "schedule": [{"asset_id": "auth", "start_week": 0}]},
        "exposure_years_avoided_vs_fcfs": 0.9,
        "exposure_years_avoided_vs_greedy": 0.3,
    }
    waves = [
        {
            "wave_id": "wave-1",
            "status": "PASSED",
            "migrated_service_ids": ["auth"],
            "rolled_back": False,
            "checks": {"auth": {"compatible": True, "failures": []}},
        }
    ]
    factoring = {
        "contract": "q-shield-attack-evidence/1",
        "service_id": "legacy-toy",
        "decrypted_records": [{"record_id": "record-1"}],
        "network_used": False,
    }
    ledger = MerkleLedger()
    ledger.append("migration_event", {"service_id": "auth"})
    qaoa = {
        "label": "Measured cross-check only, no claim of quantum advantage.",
        "backend": "local-statevector",
        "backend_status": "MEASURED",
        "approximation_ratio": 0.95,
        "optimal_bitstring_probability": 0.25,
        "job_ids": ["qaoa-job-1"],
    }
    output_path = tmp_path / "results.json"

    results = export_results(
        output_path,
        assets=assets,
        schedule_result=schedule_result,
        wave_results=waves,
        factoring_evidence=factoring,
        ledger=ledger,
        qaoa_result=qaoa,
        generated_at="2026-10-28T12:00:00Z",
    )
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    persisted = json.loads(output_path.read_text(encoding="utf-8"))
    validate(instance=persisted, schema=schema)

    assert results == persisted
    assert {asset["asset_id"] for asset in persisted["asset_inventory"]["assets"]} == {
        "auth",
        "payments",
    }
    auth = next(asset for asset in persisted["asset_inventory"]["assets"] if asset["asset_id"] == "auth")
    assert auth["migrated"] is True
    assert auth["remaining_exposure_years"] == 0
    assert persisted["schedule"]["status"] == "COMPLETED"
    assert persisted["schedule"]["baselines"]["fcfs"]["objective"] == 1.8
    assert persisted["schedule"]["baselines"]["greedy"]["objective"] == 1.2
    assert persisted["schedule"]["exposure_years_avoided"] == {"fcfs": 0.9, "greedy": 0.3}
    assert persisted["waves"][0]["wave_id"] == "wave-1"
    assert persisted["classical_factoring"]["evidence"]["service_id"] == "legacy-toy"
    assert persisted["ledger"]["merkle_root"] == ledger.merkle_root
    assert persisted["ledger"]["signature_status"] == ledger.signature_status
    assert persisted["qaoa"]["result"]["approximation_ratio"] == 0.95
    assert persisted["qaoa"]["result"]["job_ids"] == ["qaoa-job-1"]


def test_empty_pipeline_export_is_schema_valid(tmp_path):
    output_path = tmp_path / "results.json"

    export_results(output_path, generated_at="2026-10-28T00:00:00Z")

    validate(
        instance=json.loads(output_path.read_text(encoding="utf-8")),
        schema=json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
    )