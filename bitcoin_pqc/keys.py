"""
Post-quantum key pair generation using ML-DSA (CRYSTALS-Dilithium).

ML-DSA is NIST FIPS 204 (2024), standardised as the primary post-quantum
digital signature algorithm. Three security levels are provided:

  ML-DSA-44  (Dilithium2)  — NIST Level 2  (~AES-128 security)
  ML-DSA-65  (Dilithium3)  — NIST Level 3  (~AES-192 security)  ← recommended
  ML-DSA-87  (Dilithium5)  — NIST Level 5  (~AES-256 security)

Public key sizes are larger than secp256k1 (1312–2592 bytes vs 33 bytes),
so this scheme targets a new SegWit-v2 / Taproot-extension output type
(P2PQH — Pay to Post-Quantum Hash) rather than a direct ECDSA replacement
inside existing script types.
"""

from __future__ import annotations

import os
import json
import hashlib
from enum import Enum
from dataclasses import dataclass

from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5


class SecurityLevel(Enum):
    """ML-DSA security parameter sets."""
    ML_DSA_44 = "ML-DSA-44"   # NIST Level 2
    ML_DSA_65 = "ML-DSA-65"   # NIST Level 3 (recommended)
    ML_DSA_87 = "ML-DSA-87"   # NIST Level 5


_IMPL = {
    SecurityLevel.ML_DSA_44: Dilithium2,
    SecurityLevel.ML_DSA_65: Dilithium3,
    SecurityLevel.ML_DSA_87: Dilithium5,
}

# Expected public key sizes per level (bytes)
_PUBKEY_SIZES = {
    SecurityLevel.ML_DSA_44: 1312,
    SecurityLevel.ML_DSA_65: 1952,
    SecurityLevel.ML_DSA_87: 2592,
}

# Expected signature sizes per level (bytes)
_SIG_SIZES = {
    SecurityLevel.ML_DSA_44: 2420,
    SecurityLevel.ML_DSA_65: 3293,
    SecurityLevel.ML_DSA_87: 4595,
}


@dataclass
class PQKeyPair:
    """A post-quantum key pair (public + secret key) for a given security level."""

    public_key: bytes
    secret_key: bytes
    level: SecurityLevel

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls, level: SecurityLevel = SecurityLevel.ML_DSA_65) -> "PQKeyPair":
        """Generate a fresh ML-DSA key pair at the requested security level."""
        impl = _IMPL[level]
        pk, sk = impl.keygen()
        return cls(public_key=pk, secret_key=sk, level=level)

    @classmethod
    def from_secret_key(cls, secret_key: bytes, level: SecurityLevel = SecurityLevel.ML_DSA_65) -> "PQKeyPair":
        """Reconstruct a key pair from a stored secret key (re-derives public key)."""
        impl = _IMPL[level]
        # dilithium-py stores the public key inside the secret key bytes;
        # derive it by signing a dummy message and extracting pk.
        # Simpler: store pk alongside sk (standard practice).
        raise NotImplementedError(
            "Pass both public_key and secret_key directly: "
            "PQKeyPair(public_key=pk, secret_key=sk, level=level)"
        )

    # ------------------------------------------------------------------
    # Signing / verification
    # ------------------------------------------------------------------

    def sign(self, message: bytes) -> bytes:
        """Sign arbitrary bytes. Returns a detached ML-DSA signature."""
        impl = _IMPL[self.level]
        return impl.sign(self.secret_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a detached ML-DSA signature against this key pair's public key."""
        return verify_with_pubkey(self.public_key, message, signature, self.level)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "public_key": self.public_key.hex(),
            "secret_key": self.secret_key.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PQKeyPair":
        level = SecurityLevel(data["level"])
        return cls(
            public_key=bytes.fromhex(data["public_key"]),
            secret_key=bytes.fromhex(data["secret_key"]),
            level=level,
        )

    def save(self, path: str) -> None:
        """Persist key pair to a JSON file. Keep secret_key safe."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "PQKeyPair":
        with open(path) as f:
            return cls.from_dict(json.load(f))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def pubkey_hash(self) -> bytes:
        """RIPEMD-160(SHA-256(public_key)) — used in P2PQH address derivation."""
        sha = hashlib.sha256(self.public_key).digest()
        r = hashlib.new("ripemd160")
        r.update(sha)
        return r.digest()

    def __repr__(self) -> str:
        return (
            f"PQKeyPair(level={self.level.value}, "
            f"pubkey_hash={self.pubkey_hash.hex()[:16]}...)"
        )


def verify_with_pubkey(
    public_key: bytes,
    message: bytes,
    signature: bytes,
    level: SecurityLevel = SecurityLevel.ML_DSA_65,
) -> bool:
    """Verify an ML-DSA signature given only the public key (no secret key needed)."""
    impl = _IMPL[level]
    try:
        return impl.verify(public_key, message, signature)
    except Exception:
        return False
