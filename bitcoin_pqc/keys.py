"""
Key management: ML-DSA (post-quantum) and hybrid ECDSA + ML-DSA.

Two key types are provided:

  PQKeyPair     — pure ML-DSA key pair (post-quantum only).
  HybridKeyPair — secp256k1 ECDSA key + ML-DSA key, both required to sign/verify.
                  Analogous to Apple PQ3 / Signal PQXDH's hybrid approach:
                  a classical break does not compromise quantum security and vice versa.

Storage
-------
Keys can be saved in two formats:
  - Plaintext JSON  (.save() / .load())             — for testing only
  - AES-256-GCM encrypted JSON (.save_encrypted() / .load_encrypted())  — for production
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import coincurve
from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5

from .exceptions import (
    InvalidKeyError,
    SignatureError,
    VerificationError,
    StorageError,
)
from .secure import save_encrypted, load_encrypted


class SecurityLevel(Enum):
    """ML-DSA parameter sets (NIST FIPS 204)."""
    ML_DSA_44 = "ML-DSA-44"   # NIST Level 2
    ML_DSA_65 = "ML-DSA-65"   # NIST Level 3  ← recommended
    ML_DSA_87 = "ML-DSA-87"   # NIST Level 5


_DILITHIUM = {
    SecurityLevel.ML_DSA_44: Dilithium2,
    SecurityLevel.ML_DSA_65: Dilithium3,
    SecurityLevel.ML_DSA_87: Dilithium5,
}

_PUBKEY_SIZES = {
    SecurityLevel.ML_DSA_44: 1312,
    SecurityLevel.ML_DSA_65: 1952,
    SecurityLevel.ML_DSA_87: 2592,
}


# ---------------------------------------------------------------------------
# Pure ML-DSA key pair
# ---------------------------------------------------------------------------

@dataclass
class PQKeyPair:
    """ML-DSA key pair. Use HybridKeyPair for production signing."""

    public_key: bytes
    secret_key: bytes
    level: SecurityLevel

    def __post_init__(self) -> None:
        expected = _PUBKEY_SIZES[self.level]
        if len(self.public_key) != expected:
            raise InvalidKeyError(
                f"Public key length {len(self.public_key)} does not match "
                f"{self.level.value} (expected {expected})"
            )

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls, level: SecurityLevel = SecurityLevel.ML_DSA_65) -> "PQKeyPair":
        """Generate a fresh ML-DSA key pair."""
        pk, sk = _DILITHIUM[level].keygen()
        return cls(public_key=pk, secret_key=sk, level=level)

    # ------------------------------------------------------------------
    # Sign / verify
    # ------------------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """Return a detached ML-DSA signature over message."""
        if not isinstance(message, (bytes, bytearray)):
            raise SignatureError("message must be bytes")
        try:
            return _DILITHIUM[self.level].sign(self.secret_key, message)
        except Exception as exc:
            raise SignatureError(f"ML-DSA signing failed: {exc}") from exc

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a detached ML-DSA signature. Returns True/False (never raises)."""
        return verify_mldsa(self.public_key, message, signature, self.level)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def pubkey_hash(self) -> bytes:
        """RIPEMD160(SHA256(public_key)) — used in address derivation."""
        sha = hashlib.sha256(self.public_key).digest()
        r = hashlib.new("ripemd160")
        r.update(sha)
        return r.digest()

    # ------------------------------------------------------------------
    # Serialisation — plaintext
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "type": "pq",
            "level": self.level.value,
            "public_key": self.public_key.hex(),
            "secret_key": self.secret_key.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PQKeyPair":
        try:
            return cls(
                public_key=bytes.fromhex(data["public_key"]),
                secret_key=bytes.fromhex(data["secret_key"]),
                level=SecurityLevel(data["level"]),
            )
        except (KeyError, ValueError) as exc:
            raise InvalidKeyError(f"Malformed key dict: {exc}") from exc

    def save(self, path: str) -> None:
        """Save plaintext key (testing only — use save_encrypted for production)."""
        try:
            with open(path, "w") as f:
                json.dump(self.to_dict(), f, indent=2)
        except OSError as exc:
            raise StorageError(str(exc)) from exc

    @classmethod
    def load(cls, path: str) -> "PQKeyPair":
        try:
            with open(path) as f:
                return cls.from_dict(json.load(f))
        except FileNotFoundError as exc:
            raise StorageError(f"Key file not found: '{path}'") from exc

    def save_encrypted(self, path: str, passphrase: str) -> None:
        """Encrypt and save key with AES-256-GCM."""
        save_encrypted(path, self.to_dict(), passphrase)

    @classmethod
    def load_encrypted(cls, path: str, passphrase: str) -> "PQKeyPair":
        """Decrypt and load an encrypted key file."""
        return cls.from_dict(load_encrypted(path, passphrase))

    def __repr__(self) -> str:
        return f"PQKeyPair(level={self.level.value}, hash={self.pubkey_hash.hex()[:12]}…)"

    def __del__(self) -> None:
        # Best-effort zero of secret key bytes in CPython
        try:
            if self.secret_key:
                mv = memoryview(bytearray(self.secret_key))
                mv[:] = bytes(len(self.secret_key))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Hybrid ECDSA + ML-DSA key pair
# ---------------------------------------------------------------------------

@dataclass
class HybridKeyPair:
    """
    Hybrid secp256k1 ECDSA + ML-DSA key pair.

    Both signatures are required to unlock a P2HPQ output.
    Neither a classical break (breaking ECDSA) nor a quantum break
    (breaking ML-DSA) alone compromises security — both must fail simultaneously.

    This mirrors the construction used in Apple PQ3 and Signal PQXDH.
    """

    ecdsa_private_key: bytes    # 32-byte secp256k1 scalar
    ecdsa_public_key: bytes     # 33-byte compressed public key
    pq_keypair: PQKeyPair

    def __post_init__(self) -> None:
        if len(self.ecdsa_private_key) != 32:
            raise InvalidKeyError("ECDSA private key must be 32 bytes")
        if len(self.ecdsa_public_key) != 33:
            raise InvalidKeyError("ECDSA public key must be 33 bytes (compressed)")

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls, level: SecurityLevel = SecurityLevel.ML_DSA_65) -> "HybridKeyPair":
        """Generate a fresh hybrid key pair."""
        ecdsa_sk = coincurve.PrivateKey()
        pq = PQKeyPair.generate(level)
        return cls(
            ecdsa_private_key=ecdsa_sk.secret,
            ecdsa_public_key=ecdsa_sk.public_key.format(compressed=True),
            pq_keypair=pq,
        )

    # ------------------------------------------------------------------
    # Sign / verify
    # ------------------------------------------------------------------

    def sign(self, message: bytes) -> "HybridSignature":
        """
        Sign message with both ECDSA and ML-DSA.

        The message is double-SHA256 hashed (Bitcoin convention) before
        ECDSA signing.  ML-DSA signs the raw message bytes.
        """
        if not isinstance(message, (bytes, bytearray)):
            raise SignatureError("message must be bytes")

        # ECDSA: sign SHA256(SHA256(message))
        msg_hash = hashlib.sha256(hashlib.sha256(message).digest()).digest()
        try:
            sk = coincurve.PrivateKey(self.ecdsa_private_key)
            ecdsa_sig = sk.sign(msg_hash, hasher=None)
        except Exception as exc:
            raise SignatureError(f"ECDSA signing failed: {exc}") from exc

        # ML-DSA: sign raw message
        mldsa_sig = self.pq_keypair.sign(message)

        return HybridSignature(
            ecdsa_sig=ecdsa_sig,
            mldsa_sig=mldsa_sig,
            ecdsa_pubkey=self.ecdsa_public_key,
            mldsa_pubkey=self.pq_keypair.public_key,
            level=self.pq_keypair.level,
        )

    def verify(self, message: bytes, sig: "HybridSignature") -> bool:
        """Verify that both ECDSA and ML-DSA signatures are valid."""
        return sig.verify(message)

    # ------------------------------------------------------------------
    # Address helpers
    # ------------------------------------------------------------------

    @property
    def pubkey_hash(self) -> bytes:
        """
        RIPEMD160(SHA256(ecdsa_pubkey || mldsa_pubkey)) — 20-byte combined hash.
        Both keys contribute to the address commitment.
        """
        combined = self.ecdsa_public_key + self.pq_keypair.public_key
        sha = hashlib.sha256(combined).digest()
        r = hashlib.new("ripemd160")
        r.update(sha)
        return r.digest()

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "type": "hybrid",
            "ecdsa_private_key": self.ecdsa_private_key.hex(),
            "ecdsa_public_key": self.ecdsa_public_key.hex(),
            "pq": self.pq_keypair.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HybridKeyPair":
        try:
            pq = PQKeyPair.from_dict(data["pq"])
            return cls(
                ecdsa_private_key=bytes.fromhex(data["ecdsa_private_key"]),
                ecdsa_public_key=bytes.fromhex(data["ecdsa_public_key"]),
                pq_keypair=pq,
            )
        except (KeyError, ValueError) as exc:
            raise InvalidKeyError(f"Malformed hybrid key dict: {exc}") from exc

    def save_encrypted(self, path: str, passphrase: str) -> None:
        """Encrypt and save with AES-256-GCM + PBKDF2 (600k iterations)."""
        save_encrypted(path, self.to_dict(), passphrase)

    @classmethod
    def load_encrypted(cls, path: str, passphrase: str) -> "HybridKeyPair":
        return cls.from_dict(load_encrypted(path, passphrase))

    def save(self, path: str) -> None:
        """Plaintext save — testing only."""
        try:
            with open(path, "w") as f:
                json.dump(self.to_dict(), f, indent=2)
        except OSError as exc:
            raise StorageError(str(exc)) from exc

    @classmethod
    def load(cls, path: str) -> "HybridKeyPair":
        try:
            with open(path) as f:
                return cls.from_dict(json.load(f))
        except FileNotFoundError as exc:
            raise StorageError(f"Key file not found: '{path}'") from exc

    def __repr__(self) -> str:
        return (
            f"HybridKeyPair(level={self.pq_keypair.level.value}, "
            f"hash={self.pubkey_hash.hex()[:12]}…)"
        )

    def __del__(self) -> None:
        try:
            if self.ecdsa_private_key:
                mv = memoryview(bytearray(self.ecdsa_private_key))
                mv[:] = bytes(len(self.ecdsa_private_key))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HybridSignature
# ---------------------------------------------------------------------------

@dataclass
class HybridSignature:
    """A combined ECDSA + ML-DSA signature."""

    ecdsa_sig: bytes
    mldsa_sig: bytes
    ecdsa_pubkey: bytes
    mldsa_pubkey: bytes
    level: SecurityLevel

    def verify(self, message: bytes) -> bool:
        """Return True only if BOTH signatures are valid."""
        return _verify_ecdsa(self.ecdsa_pubkey, message, self.ecdsa_sig) and \
               verify_mldsa(self.mldsa_pubkey, message, self.mldsa_sig, self.level)

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "ecdsa_sig": self.ecdsa_sig.hex(),
            "mldsa_sig": self.mldsa_sig.hex(),
            "ecdsa_pubkey": self.ecdsa_pubkey.hex(),
            "mldsa_pubkey": self.mldsa_pubkey.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HybridSignature":
        return cls(
            ecdsa_sig=bytes.fromhex(data["ecdsa_sig"]),
            mldsa_sig=bytes.fromhex(data["mldsa_sig"]),
            ecdsa_pubkey=bytes.fromhex(data["ecdsa_pubkey"]),
            mldsa_pubkey=bytes.fromhex(data["mldsa_pubkey"]),
            level=SecurityLevel(data["level"]),
        )

    def serialise(self) -> bytes:
        """Pack into bytes for scriptSig embedding."""
        parts = []
        for field in (self.ecdsa_sig, self.ecdsa_pubkey, self.mldsa_sig, self.mldsa_pubkey):
            length = len(field).to_bytes(2, "big")
            parts.append(length + field)
        return b"".join(parts)

    @classmethod
    def deserialise(cls, data: bytes, level: SecurityLevel) -> "HybridSignature":
        """Unpack bytes produced by serialise()."""
        offset = 0
        fields = []
        for _ in range(4):
            if offset + 2 > len(data):
                raise ValueError("Truncated hybrid signature")
            length = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2
            fields.append(data[offset:offset + length])
            offset += length
        ecdsa_sig, ecdsa_pubkey, mldsa_sig, mldsa_pubkey = fields
        return cls(ecdsa_sig=ecdsa_sig, mldsa_sig=mldsa_sig,
                   ecdsa_pubkey=ecdsa_pubkey, mldsa_pubkey=mldsa_pubkey, level=level)


# ---------------------------------------------------------------------------
# Standalone verification helpers
# ---------------------------------------------------------------------------

def verify_mldsa(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    level: SecurityLevel = SecurityLevel.ML_DSA_65,
) -> bool:
    """Verify an ML-DSA signature. Returns True/False, never raises."""
    if not public_key or not signature:
        return False
    try:
        return _DILITHIUM[level].verify(public_key, message, signature)
    except Exception:
        return False


def _verify_ecdsa(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a secp256k1 ECDSA signature over SHA256(SHA256(message))."""
    if not public_key or not signature:
        return False
    msg_hash = hashlib.sha256(hashlib.sha256(message).digest()).digest()
    try:
        pk = coincurve.PublicKey(public_key)
        return pk.verify(signature, msg_hash, hasher=None)
    except Exception:
        return False
