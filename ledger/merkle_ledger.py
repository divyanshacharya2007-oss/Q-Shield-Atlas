"""SHA-256 append-only ledger with signed entries and Merkle-root anchoring."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ENTRY_FIELDS = frozenset({"index", "type", "payload_hash", "prev_hash", "sig_mldsa", "ts"})
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def canonical_json(value: Any) -> bytes:
    """Serialize JSON deterministically for hashing and signature inputs."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def hash_payload(payload: Any) -> str:
    """Return the SHA-256 digest of a canonical JSON value."""
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def _entry_hash(entry: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(entry)).hexdigest()


def _signing_bytes(entry: Mapping[str, Any]) -> bytes:
    return canonical_json({key: entry[key] for key in ("index", "type", "payload_hash", "prev_hash", "ts")})


def _public_key_der_b64(public_key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(encoded).decode("ascii")


class _Signer:
    def __init__(self) -> None:
        self.algorithm, self.status = "ECDSA-SHA256", "FALLBACK_CLASSICAL"
        self._private_key: Any = None
        self._oqs_signer: Any = None
        self._openssl_private_pem: bytes | None = None
        self._openssl_public_pem: bytes | None = None
        self._initialize()

    def _initialize(self) -> None:
        if self._try_cryptography_mldsa():
            return
        if self._try_oqs():
            return
        if self._try_openssl_mldsa():
            return

        from cryptography.hazmat.primitives.asymmetric import ec

        self._private_key = ec.generate_private_key(ec.SECP256R1())
        self.algorithm = "ECDSA-SHA256"
        self.status = "FALLBACK_CLASSICAL"

    def _try_cryptography_mldsa(self) -> bool:
        try:
            from cryptography.hazmat.primitives.asymmetric import ml_dsa

            key_type = getattr(ml_dsa, "MLDSA65PrivateKey", None)
            if key_type is None:
                return False
            self._private_key = key_type.generate()
            self.algorithm = "ML-DSA-65"
            self.status = "ML-DSA"
            return True
        except (ImportError, AttributeError, NotImplementedError, ValueError):
            return False

    def _try_oqs(self) -> bool:
        if importlib.util.find_spec("oqs") is None:
            return False
        try:
            import oqs

            signer = oqs.Signature("ML-DSA-65")
            signer.generate_keypair()
            self._oqs_signer = signer
            self.algorithm = "ML-DSA-65"
            self.status = "ML-DSA"
            return True
        except (ImportError, AttributeError, OSError, RuntimeError, ValueError):
            return False

    def _try_openssl_mldsa(self) -> bool:
        executable = shutil.which("openssl")
        if executable is None:
            return False
        try:
            version = subprocess.run(
                [executable, "version"], capture_output=True, text=True, timeout=3, check=True
            ).stdout
            version_parts = version.split()
            version_number = version_parts[1].split(".") if len(version_parts) > 1 else []
            if not version_number or tuple(int(part) for part in version_number[:2]) < (3, 5):
                return False
            with tempfile.TemporaryDirectory(prefix="qshield-mldsa-") as temporary:
                private_path = Path(temporary) / "private.pem"
                public_path = Path(temporary) / "public.pem"
                generated = subprocess.run(
                    [executable, "genpkey", "-algorithm", "ML-DSA-65", "-out", str(private_path)],
                    capture_output=True,
                    timeout=5,
                )
                if generated.returncode != 0:
                    return False
                exported = subprocess.run(
                    [executable, "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
                    capture_output=True,
                    timeout=5,
                )
                if exported.returncode != 0:
                    return False
                self._openssl_private_pem = private_path.read_bytes()
                self._openssl_public_pem = public_path.read_bytes()
            self.algorithm = "ML-DSA-65"
            self.status = "ML-DSA"
            return True
        except (OSError, subprocess.SubprocessError, ValueError):
            return False

    def sign(self, message: bytes) -> dict[str, str]:
        if self.status == "ML-DSA" and self._oqs_signer is not None:
            signature = self._oqs_signer.sign(message)
            public_key = self._oqs_signer.export_public_key()
            public_encoding = "raw"
        elif self.status == "ML-DSA" and self._openssl_private_pem is not None:
            signature = self._openssl_sign(message)
            public_key = self._openssl_public_pem or b""
            public_encoding = "pem"
        elif self.status == "ML-DSA":
            from cryptography.hazmat.primitives import serialization

            public_key = self._private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            signature = self._private_key.sign(message)
            public_encoding = "raw"
        else:
            from cryptography.hazmat.primitives import hashes

            public_key = _public_key_der_b64(self._private_key.public_key()).encode("ascii")
            signature = self._private_key.sign(
                message,
                __import__("cryptography.hazmat.primitives.asymmetric.ec", fromlist=["ec"]).ECDSA(
                    hashes.SHA256()
                ),
            )
            public_encoding = "der-base64"

        return {
            "algorithm": self.algorithm,
            "status": self.status,
            "public_key_encoding": public_encoding,
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }

    def _openssl_sign(self, message: bytes) -> bytes:
        executable = shutil.which("openssl")
        if executable is None or self._openssl_private_pem is None:
            raise RuntimeError("OpenSSL ML-DSA backend is no longer available")
        with tempfile.TemporaryDirectory(prefix="qshield-sign-") as temporary:
            key_path = Path(temporary) / "private.pem"
            message_path = Path(temporary) / "message.bin"
            signature_path = Path(temporary) / "signature.bin"
            key_path.write_bytes(self._openssl_private_pem)
            message_path.write_bytes(message)
            subprocess.run(
                [executable, "pkeyutl", "-sign", "-inkey", str(key_path), "-in", str(message_path), "-out", str(signature_path)],
                capture_output=True,
                timeout=5,
                check=True,
            )
            return signature_path.read_bytes()


def _verify_signature(signature_record: Mapping[str, str], message: bytes) -> bool:
    try:
        algorithm = signature_record["algorithm"]
        public_encoding = signature_record["public_key_encoding"]
        public_bytes = base64.b64decode(signature_record["public_key"], validate=True)
        signature = base64.b64decode(signature_record["signature"], validate=True)
        if public_encoding == "pem":
            executable = shutil.which("openssl")
            if executable is None:
                return False
            with tempfile.TemporaryDirectory(prefix="qshield-verify-") as temporary:
                public_path = Path(temporary) / "public.pem"
                message_path = Path(temporary) / "message.bin"
                signature_path = Path(temporary) / "signature.bin"
                public_path.write_bytes(public_bytes)
                message_path.write_bytes(message)
                signature_path.write_bytes(signature)
                result = subprocess.run(
                    [executable, "pkeyutl", "-verify", "-pubin", "-inkey", str(public_path), "-in", str(message_path), "-sigfile", str(signature_path)],
                    capture_output=True,
                    timeout=5,
                )
                return result.returncode == 0
        if algorithm == "ML-DSA-65":
            if public_encoding == "raw":
                if importlib.util.find_spec("oqs") is not None:
                    import oqs

                    with oqs.Signature("ML-DSA-65") as verifier:
                        return bool(verifier.verify(message, signature, public_bytes))
                from cryptography.hazmat.primitives.asymmetric import ml_dsa

                key_type = getattr(ml_dsa, "MLDSA65PublicKey", None)
                if key_type is not None:
                    key_type.from_public_bytes(public_bytes).verify(signature, message)
                    return True
                return False
        if algorithm == "ECDSA-SHA256" and public_encoding == "der-base64":
            from cryptography.hazmat.primitives import hashes, serialization

            public_key = serialization.load_der_public_key(base64.b64decode(public_bytes))
            from cryptography.hazmat.primitives.asymmetric import ec

            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
    except (ValueError, TypeError, KeyError, ImportError, OSError, RuntimeError, subprocess.SubprocessError):
        return False
    except Exception:
        return False
    return False


def _merkle_root(entry_hashes: list[bytes]) -> bytes:
    if not entry_hashes:
        return bytes.fromhex(EMPTY_ROOT)
    level = entry_hashes
    while len(level) > 1:
        if len(level) % 2:
            level = [*level, level[-1]]
        level = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0]


class MerkleLedger:
    """Append-only SHA-256 Merkle log with signed, hash-chained JSON entries."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.root_path = self.path.with_suffix(self.path.suffix + ".root") if self.path else None
        self.entries: list[dict[str, Any]] = []
        self._signer = _Signer()
        if self.path is not None and self.path.exists():
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(loaded, list):
                raise ValueError("ledger file must contain a JSON array of entries")
            self.entries = loaded
        self._anchored_root = (
            self.root_path.read_text(encoding="ascii").strip()
            if self.root_path is not None and self.root_path.exists()
            else self.merkle_root
        )

    @property
    def signature_status(self) -> str:
        return self._signer.status

    @property
    def signature_algorithm(self) -> str:
        return self._signer.algorithm

    @property
    def merkle_root(self) -> str:
        hashes = [bytes.fromhex(_entry_hash(entry)) for entry in self.entries]
        return _merkle_root(hashes).hex()

    def append(self, entry_type: str, payload: Any, *, ts: str | None = None) -> dict[str, Any]:
        if not isinstance(entry_type, str) or not entry_type.strip():
            raise ValueError("entry type must be a non-empty string")
        timestamp = ts or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        if not isinstance(timestamp, str) or not timestamp.strip():
            raise ValueError("ts must be a non-empty ISO-8601 timestamp string")
        prev_hash = _entry_hash(self.entries[-1]) if self.entries else "0" * 64
        entry: dict[str, Any] = {
            "index": len(self.entries),
            "type": entry_type,
            "payload_hash": hash_payload(payload),
            "prev_hash": prev_hash,
            "sig_mldsa": {},
            "ts": timestamp,
        }
        entry["sig_mldsa"] = self._signer.sign(_signing_bytes(entry))
        if set(entry) != ENTRY_FIELDS:
            raise AssertionError("ledger entry schema mismatch")
        self.entries.append(entry)
        self._persist()
        return json.loads(json.dumps(entry))

    def append_run_manifest(
        self,
        *,
        inputs: Any,
        solver_output: Any,
        job_id: str | None,
        ts: str | None = None,
    ) -> dict[str, Any]:
        timestamp = ts or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        payload = {
            "input_hash": hash_payload(inputs),
            "solver_output_hash": hash_payload(solver_output),
            "job_id_hash": hash_payload(job_id),
            "timestamp_hash": hash_payload(timestamp),
        }
        return self.append("run_manifest", payload, ts=timestamp)

    def verify_hash_chain(self) -> bool:
        previous_hash = "0" * 64
        for index, entry in enumerate(self.entries):
            if set(entry) != ENTRY_FIELDS or entry.get("index") != index:
                return False
            if entry.get("prev_hash") != previous_hash:
                return False
            previous_hash = _entry_hash(entry)
        return True

    def verify_signatures(self) -> bool:
        for entry in self.entries:
            if set(entry) != ENTRY_FIELDS or not isinstance(entry.get("sig_mldsa"), dict):
                return False
            status = entry["sig_mldsa"].get("status")
            if status not in {"ML-DSA", "FALLBACK_CLASSICAL"}:
                return False
            if not _verify_signature(entry["sig_mldsa"], _signing_bytes(entry)):
                return False
        return True

    def verify_merkle(self, expected_root: str | None = None) -> bool:
        anchor = expected_root if expected_root is not None else self._anchored_root
        if not isinstance(anchor, str) or len(anchor) != 64:
            return False
        try:
            bytes.fromhex(anchor)
        except ValueError:
            return False
        return self.merkle_root == anchor

    def verify(self, expected_root: str | None = None) -> bool:
        return (
            self.verify_hash_chain()
            and self.verify_signatures()
            and self.verify_merkle(expected_root)
        )

    def verify_payload(self, index: int, payload: Any) -> bool:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self.entries):
            return False
        return self.entries[index].get("payload_hash") == hash_payload(payload)

    def inclusion_proof(self, index: int) -> list[tuple[str, str]]:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(self.entries):
            raise IndexError("ledger entry index is out of range")
        level = [bytes.fromhex(_entry_hash(entry)) for entry in self.entries]
        proof = []
        position = index
        while len(level) > 1:
            if len(level) % 2:
                level = [*level, level[-1]]
            sibling_position = position - 1 if position % 2 else position + 1
            proof.append(("left" if position % 2 else "right", level[sibling_position].hex()))
            level = [
                hashlib.sha256(level[offset] + level[offset + 1]).digest()
                for offset in range(0, len(level), 2)
            ]
            position //= 2
        return proof

    def verify_inclusion(self, index: int, proof: list[tuple[str, str]], root: str) -> bool:
        if not 0 <= index < len(self.entries):
            return False
        current = bytes.fromhex(_entry_hash(self.entries[index]))
        try:
            for side, sibling_hex in proof:
                sibling = bytes.fromhex(sibling_hex)
                if side == "left":
                    current = hashlib.sha256(sibling + current).digest()
                elif side == "right":
                    current = hashlib.sha256(current + sibling).digest()
                else:
                    return False
            return current.hex() == root
        except ValueError:
            return False

    def _persist(self) -> None:
        self._anchored_root = self.merkle_root
        if self.path is None or self.root_path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.entries, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        self.root_path.write_text(self._anchored_root + "\n", encoding="ascii")