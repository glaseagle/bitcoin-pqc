"""
Encrypted key storage using AES-256-GCM + PBKDF2-HMAC-SHA256.

File format (JSON):
  {
    "version": 1,
    "kdf": "pbkdf2-sha256",
    "iterations": 600000,        # OWASP 2023 minimum for PBKDF2-SHA256
    "salt": "<hex>",             # 32 bytes
    "nonce": "<hex>",            # 12 bytes (GCM standard)
    "ciphertext": "<hex>",       # encrypted payload
    "tag": "<hex>"               # 16-byte GCM authentication tag (appended by AESGCM)
  }

The plaintext payload is the UTF-8 encoding of the JSON produced by
PQKeyPair.to_dict() / HybridKeyPair.to_dict().
"""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import DecryptionError, StorageError

_KDF_ITERATIONS = 600_000
_SALT_LEN = 32
_NONCE_LEN = 12
_FILE_VERSION = 1
_AAD = b"bitcoin-pqc-v1"   # additional authenticated data


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_key_data(plaintext: dict, passphrase: str) -> dict:
    """Encrypt a key dict with a passphrase. Returns a serialisable envelope."""
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key = _derive_key(passphrase, salt, _KDF_ITERATIONS)
    aesgcm = AESGCM(key)
    payload = json.dumps(plaintext, separators=(",", ":")).encode("utf-8")
    # AESGCM.encrypt appends the 16-byte tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, payload, _AAD)
    return {
        "version": _FILE_VERSION,
        "kdf": "pbkdf2-sha256",
        "iterations": _KDF_ITERATIONS,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ct_with_tag.hex(),
    }


def decrypt_key_data(envelope: dict, passphrase: str) -> dict:
    """Decrypt an envelope produced by encrypt_key_data. Raises DecryptionError on failure."""
    if envelope.get("version") != _FILE_VERSION:
        raise StorageError(f"Unknown key file version: {envelope.get('version')}")
    try:
        salt = bytes.fromhex(envelope["salt"])
        nonce = bytes.fromhex(envelope["nonce"])
        ct_with_tag = bytes.fromhex(envelope["ciphertext"])
        iterations = int(envelope["iterations"])
    except (KeyError, ValueError) as exc:
        raise StorageError(f"Malformed key file: {exc}") from exc

    key = _derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, _AAD)
    except Exception as exc:
        raise DecryptionError("Wrong passphrase or corrupted key file.") from exc

    return json.loads(plaintext.decode("utf-8"))


def save_encrypted(path: str, key_dict: dict, passphrase: str) -> None:
    """Write an encrypted key file to disk."""
    envelope = encrypt_key_data(key_dict, passphrase)
    try:
        with open(path, "w") as f:
            json.dump(envelope, f, indent=2)
    except OSError as exc:
        raise StorageError(f"Failed to write key file '{path}': {exc}") from exc


def load_encrypted(path: str, passphrase: str) -> dict:
    """Read and decrypt a key file from disk."""
    try:
        with open(path) as f:
            envelope = json.load(f)
    except FileNotFoundError as exc:
        raise StorageError(f"Key file not found: '{path}'") from exc
    except json.JSONDecodeError as exc:
        raise StorageError(f"Key file is not valid JSON: {exc}") from exc
    return decrypt_key_data(envelope, passphrase)
