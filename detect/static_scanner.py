"""Read-only scanner for RSA/ECC use in source, configuration, and certificates."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 2_000_000
SKIP_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
}
TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".conf",
    ".config",
    ".crt",
    ".csr",
    ".go",
    ".h",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".key",
    ".kt",
    ".pem",
    ".php",
    ".properties",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".tf",
    ".toml",
    ".ts",
    ".yaml",
    ".yml",
    ".xml",
}
RSA_PATTERN = re.compile(
    r"\bRSA(?:ENCRYPTION|[-_ ](?:PUBLIC|PRIVATE|KEY|ENCRYPTION))?\b", re.I
)
ECC_PATTERN = re.compile(
    r"\b(?:ECDSA|ECDH|ECC|EC[-_ ](?:PUBLIC|PRIVATE|KEY|PARAMETERS)|"
    r"ELLIPTIC[- ]CURVE|SECP(?:\d+[RK]?)|PRIME256V1|ED25519|ED448)\b",
    re.I,
)
KEY_SIZE_PATTERN = re.compile(
    r"(?:key[_ -]?size|rsa[_ -]?bits|public-key|public key size)"
    r"\s*[:=]?\s*\(?\s*(\d{3,5})\s*(?:bit)?",
    re.I,
)
PEM_PATTERN = re.compile(r"-----BEGIN CERTIFICATE-----")
CIPHER_PATTERN = re.compile(r"\b(?:TLS|SSL)_[A-Z0-9_]+\b")
CERT_SUFFIXES = {".cer", ".crt", ".der", ".pem"}


@dataclass(frozen=True)
class Evidence:
    """A cryptographic finding tied to an exact repository line."""

    file: str
    line: int
    match: str
    key_type: str
    key_size: int | None = None

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class StaticFinding:
    """Repository-level key inventory grouped by microservice directory."""

    asset_id: str
    domain: str
    key_type: str
    key_size: int | None
    evidence: list[Evidence] = field(default_factory=list)
    cipher_suites: list[str] = field(default_factory=list)

    def to_scan_record(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "domain": self.domain,
            "key_type": self.key_type,
            "key_size": self.key_size,
            "evidence": [
                {
                    "file": item.file,
                    "line": item.line,
                    "match": item.match,
                    "key_type": item.key_type,
                    "key_size": item.key_size,
                }
                for item in self.evidence
            ],
            "cipher_suites": self.cipher_suites,
        }


def _service_name(repository: Path, file_path: Path) -> str:
    relative = file_path.relative_to(repository)
    return relative.parts[0] if len(relative.parts) > 1 else repository.name


def _certificate_public_key(content: bytes) -> tuple[str, int] | None:
    if not PEM_PATTERN.search(content.decode("ascii", errors="ignore")):
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

        certificate = x509.load_pem_x509_certificate(content)
        public_key = certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            return "RSA", public_key.key_size
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return "ECDSA", public_key.key_size
        if isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            return public_key.__class__.__name__.replace("PublicKey", "").upper(), public_key.key_size
    except (ImportError, ValueError, TypeError):
        return None
    return None


class StaticScanner:
    """Scan bounded text files and certificates without executing repository code."""

    def __init__(self, *, max_file_bytes: int = MAX_FILE_BYTES) -> None:
        if max_file_bytes < 1:
            raise ValueError("max_file_bytes must be positive")
        self.max_file_bytes = max_file_bytes

    def scan(self, repository_path: str | Path) -> list[StaticFinding]:
        repository = Path(repository_path).resolve()
        if not repository.is_dir():
            raise NotADirectoryError(repository)

        grouped: dict[str, StaticFinding] = {}
        for file_path in sorted(repository.rglob("*")):
            if not file_path.is_file() or any(
                part in SKIP_DIRECTORIES for part in file_path.relative_to(repository).parts
            ):
                continue
            if file_path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                if file_path.stat().st_size > self.max_file_bytes:
                    continue
                content = file_path.read_bytes()
                text = content.decode("utf-8", errors="ignore")
            except OSError:
                continue

            relative_path = file_path.relative_to(repository).as_posix()
            key = _certificate_public_key(content) if file_path.suffix.lower() in CERT_SUFFIXES else None
            lines = text.splitlines()
            file_key_sizes = {
                int(match.group(1))
                for line in lines
                if (match := KEY_SIZE_PATTERN.search(line)) is not None
            }
            file_key_size = next(iter(file_key_sizes)) if len(file_key_sizes) == 1 else None
            finding = grouped.get(_service_name(repository, file_path))
            for line_number, line in enumerate(lines, start=1):
                rsa_match = RSA_PATTERN.search(line)
                ecc_match = ECC_PATTERN.search(line)
                key_type = "RSA" if rsa_match else "ECDSA" if ecc_match else None
                if key is not None and line_number == 1:
                    key_type = key[0]
                if key_type is None:
                    continue

                size_match = KEY_SIZE_PATTERN.search(line)
                key_size = (
                    int(size_match.group(1))
                    if size_match
                    else file_key_size
                    if key_type is not None
                    else None
                )
                if key is not None:
                    key_type, key_size = key
                if finding is None:
                    service = _service_name(repository, file_path)
                    finding = StaticFinding(
                        asset_id=f"repo-{re.sub(r'[^a-zA-Z0-9_-]+', '-', service).strip('-')}",
                        domain=service,
                        key_type=key_type,
                        key_size=key_size,
                    )
                    grouped[service] = finding
                if key_type == "RSA" or finding.key_type not in {"RSA", "ECDSA"}:
                    finding.key_type = key_type
                if key_size is not None and (finding.key_size is None or key_size > finding.key_size):
                    finding.key_size = key_size
                finding.evidence.append(
                    Evidence(
                        file=relative_path,
                        line=line_number,
                        match=line.strip()[:240],
                        key_type=key_type,
                        key_size=key_size,
                    )
                )

            if finding is not None:
                finding.cipher_suites = sorted(
                    set(finding.cipher_suites).union(CIPHER_PATTERN.findall(text))
                )

        return sorted(grouped.values(), key=lambda item: item.asset_id)


def scan_repository(repository_path: str | Path) -> list[StaticFinding]:
    """Convenience wrapper returning all repository findings."""
    return StaticScanner().scan(repository_path)