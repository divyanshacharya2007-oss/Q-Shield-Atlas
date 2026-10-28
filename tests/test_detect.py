from pathlib import Path
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from data_ingest.dataset_loader import load_repository_assets
from detect.live_prober import TLSObservation, compare_configuration_drift
from detect.static_scanner import StaticScanner

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "fake_repo"


def test_static_scanner_collects_rsa_and_ecc_evidence():
    findings = StaticScanner().scan(FIXTURE_REPO)
    by_domain = {finding.domain: finding for finding in findings}

    assert set(by_domain) == {"auth-service", "payments-service"}
    auth = by_domain["auth-service"]
    assert auth.key_type == "RSA"
    assert auth.key_size == 2048
    assert any(
        item.file == "auth-service/app.py" and item.line == 3
        for item in auth.evidence
    )
    assert any(item.file.endswith("server.crt") for item in auth.evidence)
    payments = by_domain["payments-service"]
    assert payments.key_type == "ECDSA"
    assert payments.key_size == 256
    assert any(item.file == "payments-service/client.go" and item.line == 3 for item in payments.evidence)


def test_live_handshake_comparison_reports_key_and_cipher_drift():
    static = {
        "asset_id": "auth-service",
        "key_type": "RSA",
        "key_size": 2048,
        "cipher_suites": ["TLS_AES_128_GCM_SHA256"],
    }
    live = TLSObservation(
        host="auth.example.test",
        port=443,
        key_type="ECDSA",
        key_size=256,
        cipher_suite="TLS_AES_256_GCM_SHA384",
        tls_version="TLSv1.3",
    )

    drift = compare_configuration_drift(static, live)

    assert drift.has_drift
    assert len(drift.mismatches) == 3
    assert any("key_type" in mismatch for mismatch in drift.mismatches)
    assert any("key_size" in mismatch for mismatch in drift.mismatches)
    assert any("cipher_suite" in mismatch for mismatch in drift.mismatches)


def test_dataset_loader_converts_static_findings_to_atlas_assets():
    assets = load_repository_assets(str(FIXTURE_REPO))
    by_domain = {asset["domain"]: asset for asset in assets}

    assert set(by_domain) == {"auth-service", "payments-service"}
    assert by_domain["auth-service"]["asset_id"] == "repo-auth-service"
    assert by_domain["auth-service"]["key_type"] == "RSA"
    assert by_domain["auth-service"]["key_size"] == 2048
    assert by_domain["auth-service"]["vulnerable"] is True
    assert by_domain["auth-service"]["evidence"]
    assert by_domain["auth-service"]["cipher_suites"] == ["TLS_AES_128_GCM_SHA256"]


def test_scanner_rejects_non_directory_path(tmp_path):
    with pytest.raises(NotADirectoryError):
        StaticScanner().scan(tmp_path / "missing")


def test_static_scanner_extracts_key_from_pem_certificate(tmp_path):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2035, 1, 1, tzinfo=timezone.utc))
        .sign(private_key, hashes.SHA256())
    )
    cert_path = tmp_path / "service" / "server.pem"
    cert_path.parent.mkdir()
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    finding = StaticScanner().scan(tmp_path)[0]

    assert finding.key_type == "RSA"
    assert finding.key_size == 2048
    assert finding.evidence[0].file == "service/server.pem"
    assert finding.evidence[0].line == 1