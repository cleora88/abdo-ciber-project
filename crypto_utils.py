"""Cryptographic integrity helpers for generated SOC reports."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path


DEFAULT_SECRET_KEY = "change-this-demo-secret-key-for-bank-soc-project"
SECRET_KEY = os.getenv("BANK_SOC_HMAC_SECRET", DEFAULT_SECRET_KEY)


def calculate_sha256(file_path: str | Path) -> str:
    """Return the SHA-256 digest of a report file."""
    path = Path(file_path)
    sha256 = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_hmac_signature(report_hash: str, secret_key: str = SECRET_KEY) -> str:
    """Sign a report hash with HMAC-SHA256."""
    return hmac.new(
        secret_key.encode("utf-8"),
        report_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_report_integrity(
    report_path: str | Path,
    expected_hash: str,
    expected_signature: str,
    secret_key: str = SECRET_KEY,
) -> dict:
    """Verify that a saved report still matches its hash and HMAC signature."""
    current_hash = calculate_sha256(report_path)
    current_signature = generate_hmac_signature(current_hash, secret_key)
    hash_valid = hmac.compare_digest(current_hash, expected_hash)
    signature_valid = hmac.compare_digest(current_signature, expected_signature)

    return {
        "report_path": str(report_path),
        "current_hash": current_hash,
        "expected_hash": expected_hash,
        "current_signature": current_signature,
        "expected_signature": expected_signature,
        "hash_valid": hash_valid,
        "signature_valid": signature_valid,
        "is_valid": hash_valid and signature_valid,
    }
