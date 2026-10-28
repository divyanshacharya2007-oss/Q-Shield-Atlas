import pandas as pd
from typing import List, Dict, Any

DATASET_NAME = "Q-GRID/pqc-ssl-scans"

def load_pqc_dataset(limit: int = 50, *, offline: bool = False) -> pd.DataFrame:
    """Loads scan records from Hugging Face dataset or falls back to local sample."""
    if offline:
        return _sample_scans()
    try:
        from datasets import load_dataset
        print(f"[data_ingest] Fetching '{DATASET_NAME}' from Hugging Face...")
        ds = load_dataset(DATASET_NAME, split=f"train[:{limit}]")
        return ds.to_pandas()
    except Exception as err:
        print(f"[data_ingest] Offline/Fallback mode ({err}). Using standard scan table.")
        return _sample_scans()


def _sample_scans() -> pd.DataFrame:
    return pd.DataFrame([
            {"domain": "auth.bank.internal", "key_type": "RSA", "key_size": 2048, "tls_version": "TLSv1.2"},
            {"domain": "payments.bank.internal", "key_type": "ECDSA", "key_size": 256, "tls_version": "TLSv1.2"},
            {"domain": "crypto.bank.internal", "key_type": "RSA", "key_size": 1024, "tls_version": "TLSv1.1"},
            {"domain": "api.bank.internal", "key_type": "ML-KEM", "key_size": 768, "tls_version": "TLSv1.3"}
        ])

def convert_scans_to_atlas_assets(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Converts raw SSL scan rows into standard Q-Shield Atlas Asset objects."""
    assets = []
    for idx, row in df.iterrows():
        key_type = str(row.get("key_type", "RSA")).upper()
        key_size = int(row.get("key_size", 2048)) if pd.notnull(row.get("key_size")) else 2048
        domain = str(row.get("domain", f"target-{idx:03d}.internal"))

        is_vulnerable = key_type in ["RSA", "ECDSA", "ECC"] and key_size <= 2048

        asset = {
            "asset_id": str(row.get("asset_id", f"asset-{idx:03d}")),
            "domain": domain,
            "key_type": key_type,
            "key_size": key_size,
            "tls_version": row.get("tls_version", "TLSv1.2"),
            "shelf_life_years": 3.0 if is_vulnerable else 10.0,
            "effort_weeks": 2.0 if key_size <= 2048 else 4.0,
            "risk_weight": 9.5 if key_size <= 1024 else (7.0 if is_vulnerable else 1.0),
            "vulnerable": is_vulnerable,
            "dependencies": row.get("dependencies", []),
            "evidence": row.get("evidence", []),
            "cipher_suites": row.get("cipher_suites", []),
        }
        assets.append(asset)
    return assets


def load_repository_assets(repository_path: str) -> List[Dict[str, Any]]:
    """Scan a repository and convert its findings to Atlas assets."""
    from detect.static_scanner import scan_repository

    findings = scan_repository(repository_path)
    return convert_scans_to_atlas_assets(
        pd.DataFrame([finding.to_scan_record() for finding in findings])
    )