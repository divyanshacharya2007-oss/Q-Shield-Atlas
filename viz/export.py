"""Aggregate Q-Shield Atlas pipeline outputs into the visualizer contract."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

RESULTS_CONTRACT = "q-shield-atlas-results/1"
RESULTS_LABEL = "Q-Shield Atlas pipeline results"


def _plain(value: Any) -> Any:
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list, set)):
        return [_plain(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "item") and callable(value.item):
        return value.item()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"cannot serialize pipeline value of type {type(value).__name__}")


def _read_json_or_value(value: Any) -> Any:
    if isinstance(value, (str, Path)):
        path = Path(value)
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    return _plain(value)


def _plan_data(plan: Any) -> dict[str, Any]:
    plain = _plain(plan)
    if not isinstance(plain, Mapping):
        raise TypeError("schedule plan must serialize to an object")
    return {
        "objective": float(plain.get("objective", 0.0)),
        "schedule": list(plain.get("schedule", [])),
    }


def _schedule_data(schedule_result: Any, provider: str | None) -> dict[str, Any]:
    if schedule_result is None:
        return {
            "status": "NOT_RUN",
            "provider": None,
            "optimized": {"objective": None, "schedule": []},
            "baselines": {
                "fcfs": {"objective": None, "schedule": []},
                "greedy": {"objective": None, "schedule": []},
            },
            "exposure_years_avoided": {"fcfs": None, "greedy": None},
        }

    plain = _plain(schedule_result)
    if not isinstance(plain, Mapping):
        raise TypeError("schedule_result must serialize to an object")
    optimized = _plan_data(plain.get("optimized", {}))
    fcfs = _plan_data(plain.get("fcfs", {}))
    greedy = _plan_data(plain.get("greedy", {}))
    return {
        "status": "COMPLETED",
        "provider": provider or "QpiAI Opt MILP",
        "optimized": optimized,
        "baselines": {"fcfs": fcfs, "greedy": greedy},
        "exposure_years_avoided": {
            "fcfs": float(plain.get("exposure_years_avoided_vs_fcfs", fcfs["objective"] - optimized["objective"])),
            "greedy": float(plain.get("exposure_years_avoided_vs_greedy", greedy["objective"] - optimized["objective"])),
        },
    }


def _wave_data(wave_results: Any) -> list[dict[str, Any]]:
    if wave_results is None:
        return []
    plain = _plain(wave_results)
    if isinstance(plain, Mapping):
        plain = plain.get("waves", [plain])
    if not isinstance(plain, list):
        raise TypeError("wave_results must be a sequence or a mapping containing waves")
    waves = []
    for wave in plain:
        if not isinstance(wave, Mapping):
            raise TypeError("each wave result must serialize to an object")
        checks = wave.get("checks", {})
        waves.append(
            {
                "wave_id": str(wave.get("wave_id", f"wave-{len(waves) + 1}")),
                "status": str(wave.get("status", "UNKNOWN")),
                "migrated_service_ids": list(wave.get("migrated_service_ids", [])),
                "rolled_back": bool(wave.get("rolled_back", False)),
                "checks": checks,
            }
        )
    return waves


def _gate_migrated_ids(waves: Sequence[Mapping[str, Any]]) -> set[str]:
    migrated: set[str] = set()
    for wave in waves:
        if wave.get("status") == "PASSED" and not wave.get("rolled_back"):
            migrated.update(map(str, wave.get("migrated_service_ids", [])))
    return migrated


def build_results(
    *,
    assets: Sequence[Mapping[str, Any]] | None = None,
    repository_path: str | Path | None = None,
    schedule_result: Any = None,
    wave_results: Any = None,
    factoring_evidence: Any = None,
    ledger: Any = None,
    ledger_tamper_check: Any = None,
    qaoa_result: Any = None,
    detection: Mapping[str, Any] | None = None,
    schedule_provider: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build the complete versioned JSON result document from completed stages."""
    if assets is None and repository_path is not None:
        from data_ingest.dataset_loader import load_repository_assets

        assets = load_repository_assets(str(repository_path))
    assets = list(assets or [])
    waves = _wave_data(wave_results)
    migrated_ids = _gate_migrated_ids(waves)

    inventory = []
    for asset in assets:
        item = _plain(asset)
        if not isinstance(item, Mapping):
            raise TypeError("each asset must be a mapping")
        record = dict(item)
        asset_id = str(record.get("asset_id", ""))
        state = str(record.get("migration_status", "")).upper()
        migrated = state in {"MIGRATED", "HYBRID", "COMPLETED"} or asset_id in migrated_ids
        shelf_life = record.get("shelf_life_years", 0)
        record["remaining_exposure_years"] = 0.0 if migrated else float(
            record.get("remaining_exposure_years", shelf_life or 0)
        )
        record["migration_status"] = "MIGRATED" if migrated else record.get(
            "migration_status", "LEGACY"
        )
        record["migrated"] = migrated
        inventory.append(record)

    if factoring_evidence is None:
        default_evidence = Path("contracts/attack-evidence.json")
        factoring_evidence = default_evidence if default_evidence.exists() else None
    evidence_value = _read_json_or_value(factoring_evidence) if factoring_evidence is not None else None
    factoring = {
        "status": "COMPLETED" if evidence_value is not None else "NOT_RUN",
        "evidence": evidence_value,
    }

    if ledger is None:
        ledger_path = Path("contracts/ledger.json")
        if ledger_path.is_file():
            try:
                from ledger.merkle_ledger import MerkleLedger

                ledger = MerkleLedger(ledger_path)
            except (ImportError, OSError, ValueError, json.JSONDecodeError):
                ledger = None
    if ledger is None:
        ledger_data: dict[str, Any] = {
            "status": "NOT_RUN",
            "merkle_root": None,
            "signature_status": None,
            "signature_algorithm": None,
        }
    else:
        ledger_data = {
            "status": "COMPLETED",
            "merkle_root": str(getattr(ledger, "merkle_root", "")),
            "signature_status": str(getattr(ledger, "signature_status", "UNKNOWN")),
            "signature_algorithm": str(getattr(ledger, "signature_algorithm", "UNKNOWN")),
            "tamper_check": _plain(ledger_tamper_check) if ledger_tamper_check is not None else {"status": "NOT_RUN"},
        }
    if ledger is None:
        ledger_data["tamper_check"] = _plain(ledger_tamper_check) if ledger_tamper_check is not None else {"status": "NOT_RUN"}

    if qaoa_result is None:
        qaoa = {"status": "NOT_RUN", "result": None}
    else:
        qaoa = {"status": "COMPLETED", "result": _plain(qaoa_result)}

    detection_data = {
        "static_status": "COMPLETED" if assets else "EMPTY",
        "static_findings": _plain((detection or {}).get("static_findings", [])),
        "live_status": str((detection or {}).get("live_status", "NOT_RUN")),
        "live_observations": _plain((detection or {}).get("live_observations", [])),
        "drifts": _plain((detection or {}).get("drifts", [])),
    }

    return {
        "contract": RESULTS_CONTRACT,
        "label": RESULTS_LABEL,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "detection": detection_data,
        "asset_inventory": {"status": "COMPLETED" if inventory else "EMPTY", "assets": inventory},
        "schedule": _schedule_data(schedule_result, schedule_provider),
        "waves": waves,
        "classical_factoring": factoring,
        "ledger": ledger_data,
        "qaoa": qaoa,
    }


def export_results(
    output_path: str | Path = "contracts/results.json",
    **pipeline_data: Any,
) -> dict[str, Any]:
    """Generate and persist the results document consumed by the visualization."""
    results = build_results(**pipeline_data)
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return results


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Export Q-Shield Atlas pipeline results")
    parser.add_argument("--repository", default="tests/fixtures/fake_repo")
    parser.add_argument("--output", default="contracts/results.json")
    arguments = parser.parse_args()
    export_results(output_path=arguments.output, repository_path=arguments.repository)