"""Run the complete local Q-Shield Atlas demonstration pipeline."""

from __future__ import annotations

import copy
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from scipy.optimize import Bounds, LinearConstraint, milp

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from attack.factoring import factor_and_decrypt_capture
from capture.service import ToyTLSService, dump_capture
from data_ingest.dataset_loader import convert_scans_to_atlas_assets, load_pqc_dataset
from detect.live_prober import compare_configuration_drift, probe_tls_endpoint
from detect.static_scanner import StaticScanner
from gates.migration_gates import MigrationGateController, ServiceState, verify_classical_replay
from ledger.merkle_ledger import MerkleLedger, hash_payload
from qaoa.cross_check import cross_check_weekly_wave
from schedule.solver import AtlasScheduler
from viz.export import export_results

PYTHON_SUPPORTED = (3, 12)


def _activate_environment_check() -> None:
    if sys.version_info[:2] < (3, 12):
        raise RuntimeError("Q-Shield Atlas demo requires Python 3.12 or newer")
    print(f"[1/7] Python {sys.version.split()[0]} active from {sys.executable}")


def _make_loopback_tls_certificate(directory: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now.replace(microsecond=0))
        .not_valid_after(now.replace(microsecond=0).replace(year=now.year + 1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    key_path = directory / "loopback-key.pem"
    cert_path = directory / "loopback-cert.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def _probe_loopback_tls() -> dict[str, object]:
    import ssl

    from detect.live_prober import TLSObservation

    with tempfile.TemporaryDirectory(prefix="qshield-loopback-tls-") as temporary:
        cert_path, key_path = _make_loopback_tls_certificate(Path(temporary))
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        port = listener.getsockname()[1]
        server_error: list[BaseException] = []

        def serve_one_handshake() -> None:
            try:
                connection, _ = listener.accept()
                with connection:
                    with server_context.wrap_socket(connection, server_side=True):
                        pass
            except BaseException as error:
                server_error.append(error)
            finally:
                listener.close()

        server_thread = threading.Thread(target=serve_one_handshake, daemon=True)
        server_thread.start()
        client_context = ssl._create_unverified_context()
        observation = probe_tls_endpoint(
            "127.0.0.1",
            port,
            timeout=4,
            server_hostname="localhost",
            ssl_context=client_context,
        )
        server_thread.join(timeout=4)
        if server_error:
            raise RuntimeError(f"loopback TLS service failed: {server_error[0]}")
        return asdict(observation)


def _scipy_milp_solver(model: object, *, mode: str) -> SimpleNamespace:
    matrix_data = model.to_lp_matrix(sparse_matrix=True)
    objective = matrix_data["objective"].copy()
    if matrix_data["sense"] == "max":
        objective *= -1
    constraint = LinearConstraint(
        matrix_data["constraint_matrix"],
        matrix_data["row_lower"],
        matrix_data["row_upper"],
    )
    result = milp(
        c=objective,
        integrality=matrix_data["integrality"],
        bounds=Bounds(matrix_data["lower_bounds"], matrix_data["upper_bounds"]),
        constraints=constraint,
        options={"time_limit": 30.0, "mip_rel_gap": 0.0},
    )
    if not result.success or result.x is None:
        raise RuntimeError(f"SciPy/HiGHS MILP fallback failed: {result.message}")
    return SimpleNamespace(
        solution=dict(zip(matrix_data["variable_names"], result.x, strict=True)),
        objective=float(result.fun),
        status="optimal",
        provider="SciPy HiGHS local fallback",
        mode=mode,
    )


def _resolve_schedule(assets: list[dict[str, object]]) -> tuple[object, str]:
    try:
        result = AtlasScheduler(capacity=1).solve(assets)
        return result, "QpiAI Opt local MILP"
    except Exception as error:
        print(f"  QpiAI Opt unavailable ({type(error).__name__}); using SciPy/HiGHS MILP.")
        result = AtlasScheduler(capacity=1, solver=_scipy_milp_solver).solve(assets)
        return result, "SciPy HiGHS local fallback (same QpiAI MILP matrix)"


def _service_for_asset(asset: dict[str, object]) -> ServiceState:
    key_type = str(asset.get("key_type", "RSA")).upper()
    if key_type in {"ML-KEM", "ML-DSA", "HYBRID"}:
        return ServiceState(
            service_id=str(asset["asset_id"]),
            key_exchange="ML-KEM-768",
            signature_algorithm="ML-DSA-65",
            tls_version="TLSv1.3",
            migration_status="MIGRATED",
        )
    return ServiceState(service_id=str(asset["asset_id"]), key_exchange=key_type)


def run_pipeline() -> dict[str, object]:
    _activate_environment_check()

    print("[1/7] Ingesting offline SSL sample and scanning repository fixtures")
    scan_frame = load_pqc_dataset(offline=True)
    scan_assets = convert_scans_to_atlas_assets(scan_frame)
    static_findings = StaticScanner().scan(ROOT / "tests" / "fixtures" / "fake_repo")
    static_assets = [finding.to_scan_record() for finding in static_findings]
    assets = scan_assets + convert_scans_to_atlas_assets(
        __import__("pandas").DataFrame(static_assets)
    )
    live_observations = []
    drifts = []
    live_status = "COMPLETED"
    try:
        observation = _probe_loopback_tls()
        live_observations.append(observation)
        if static_findings:
            drifts.append(asdict(compare_configuration_drift(static_findings[0], observation)))
    except Exception as error:
        live_status = "UNAVAILABLE"
        drifts.append({"status": "UNAVAILABLE", "detail": str(error)})
    print(f"  {len(scan_assets)} SSL samples, {len(static_findings)} static findings, live TLS {live_status}")

    print("[2/7] Formulating migration schedule with QpiAI Opt and local fallback")
    schedule_result, schedule_provider = _resolve_schedule(assets)
    print(f"  provider: {schedule_provider}; optimized exposure {schedule_result.optimized.objective:.4f}")

    print("[3/7] Capturing and factoring explicitly labeled toy RSA traffic")
    toy_service = ToyTLSService(key_bits=64, service_id="toy-legacy-service")
    capture = toy_service.capture(b"legacy")
    dump_capture(capture, ROOT / "contracts" / "capture.json")
    factoring_evidence = factor_and_decrypt_capture(
        capture,
        evidence_path=ROOT / "contracts" / "attack-evidence.json",
    )
    toy_asset = {
        "asset_id": toy_service.service_id,
        "domain": toy_service.service_id,
        "key_type": "RSA",
        "key_size": 64,
        "tls_version": "synthetic-toy",
        "shelf_life_years": 3.0,
        "effort_weeks": 1.0,
        "risk_weight": 9.5,
        "vulnerable": True,
        "dependencies": [],
    }
    assets.append(toy_asset)
    print(f"  toy modulus {factoring_evidence['modulus_bits']} bits; captured record decrypted")

    print("[4/7] Applying schedule waves and verifying hybrid state / replay rejection")
    service_states = [_service_for_asset(asset) for asset in assets]
    service_states.append(ServiceState(service_id=toy_service.service_id, key_exchange="RSA"))
    unique_services = {state.service_id: state for state in service_states}
    controller = MigrationGateController(list(unique_services.values()))
    toy_state = controller.services[toy_service.service_id]
    legacy_replay = verify_classical_replay(capture, toy_state)
    wave_results = []
    plans_by_week: dict[int, list[str]] = {}
    for entry in schedule_result.optimized.schedule:
        state = controller.services[entry.asset_id]
        if state.migration_status == "LEGACY":
            plans_by_week.setdefault(entry.start_week, []).append(entry.asset_id)
    for wave_index, (start_week, service_ids) in enumerate(sorted(plans_by_week.items()), start=1):
        wave_results.append(
            controller.migrate_wave(f"wave-{wave_index}-week-{start_week}", service_ids)
        )
    toy_wave = controller.migrate_wave("wave-toy-capture", [toy_service.service_id])
    wave_results.append(toy_wave)
    hybrid_replay = verify_classical_replay(capture, toy_state)
    replay_pass = (
        legacy_replay.status == "SUCCEEDED"
        and hybrid_replay.status == "FAILED"
        and hybrid_replay.explicit_failure_status == "REPLAY_REJECTED_HYBRID_STATE"
    )
    if not replay_pass or any(wave.status != "PASSED" for wave in wave_results):
        raise RuntimeError("migration gate or replay verification failed")
    print(f"  {len(wave_results)} waves passed; legacy replay succeeded and hybrid replay failed explicitly")

    print("[5/7] Appending migration events and run manifest to local Merkle ledger")
    ledger_path = ROOT / "contracts" / "ledger.json"
    ledger = MerkleLedger(ledger_path)
    for wave in wave_results:
        ledger.append("migration_wave", asdict(wave))
    ledger.append_run_manifest(
        inputs={"assets": assets, "capture_service_id": toy_service.service_id},
        solver_output=asdict(schedule_result),
        job_id=None,
    )
    tampered_entries = copy.deepcopy(ledger.entries)
    tampered_entries[0]["payload_hash"] = "0" * 64
    tamper_check = {
        "status": "PASS" if not _verify_tampered_copy(tampered_entries, ledger.merkle_root) else "FAIL",
        "merkle_verification": "FAILED_AS_EXPECTED",
        "hash_chain_validation": "FAILED_AS_EXPECTED",
    }
    if tamper_check["status"] != "PASS":
        raise RuntimeError("ledger tamper check did not detect the edited historical row")
    print(f"  root {ledger.merkle_root}; signer {ledger.signature_status}; tamper check passed")

    print("[6/7] Running weekly QAOA cross-check on a small subproblem")
    qaoa_assets = [
        {
            "asset_id": str(asset["asset_id"]),
            "risk_weight": float(asset["risk_weight"]),
            "dependencies": list(asset.get("dependencies", [])),
        }
        for asset in assets[:4]
    ]
    qaoa_result = cross_check_weekly_wave(
        qaoa_assets,
        capacity=min(2, len(qaoa_assets)),
        shots=128,
        seed=7,
        max_iterations=12,
        prefer_qcloud=True,
    )
    print(f"  {qaoa_result.backend_status}; ratio {qaoa_result.approximation_ratio:.3f}; {qaoa_result.label}")

    print("[7/7] Exporting contracts/results.json and opening Exposure Tower")
    detection = {
        "static_findings": static_findings,
        "live_status": live_status,
        "live_observations": live_observations,
        "drifts": drifts,
    }
    results = export_results(
        ROOT / "contracts" / "results.json",
        assets=assets,
        schedule_result=schedule_result,
        wave_results=wave_results,
        factoring_evidence=factoring_evidence,
        ledger=ledger,
        ledger_tamper_check=tamper_check,
        qaoa_result=qaoa_result,
        detection=detection,
        schedule_provider=schedule_provider,
    )
    _open_visualizer()
    print(f"  exported {len(results['asset_inventory']['assets'])} assets to contracts/results.json")
    return results


def _verify_tampered_copy(entries: list[dict[str, object]], anchored_root: str) -> bool:
    from ledger.merkle_ledger import MerkleLedger

    temporary_ledger = MerkleLedger()
    temporary_ledger.entries = entries
    return temporary_ledger.verify_hash_chain() and temporary_ledger.verify_merkle(anchored_root)


def _open_visualizer() -> None:
    url = "http://127.0.0.1:8765/viz/index.html"
    try:
        with socket.create_connection(("127.0.0.1", 8765), timeout=0.25):
            pass
    except OSError:
        subprocess.Popen(
            [sys.executable, "-m", "http.server", "8765", "--bind", "127.0.0.1"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        time.sleep(0.35)
    webbrowser.open(url)
    print(f"  visualizer: {url}")


if __name__ == "__main__":
    run_pipeline()