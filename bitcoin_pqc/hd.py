"""
HD (Hierarchical Deterministic) key derivation for post-quantum keys.

Derives ML-DSA key pairs deterministically from a BIP-39 seed or any
high-entropy master secret using HKDF-SHA512 with a Bitcoin-PQC domain
separator.

Derivation path notation mirrors BIP-32:
  m / purpose' / account' / index

Where:
  purpose = 444  (proposed, "PQC")
  account = user-defined account index
  index   = per-address key index

Each level mixes in the path component so child keys are independent.

NOTE: Unlike BIP-32 (which derives ECDSA keys), there is no "hardened vs
      normal" child distinction for ML-DSA because ML-DSA has no public-key
      homomorphism to exploit. All derivations are effectively hardened.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .keys import PQKeyPair, SecurityLevel
from .exceptions import DerivationError

_DOMAIN = b"bitcoin-pqc-hd-v1"
_PURPOSE = 444


def _hkdf_expand(ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA512 expand step — produces deterministic pseudo-random bytes."""
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(ikm)


_DILITHIUM_IMPL = {
    SecurityLevel.ML_DSA_44: None,
    SecurityLevel.ML_DSA_65: None,
    SecurityLevel.ML_DSA_87: None,
}


def _get_impl(level: SecurityLevel):
    from dilithium_py.dilithium import Dilithium2, Dilithium3, Dilithium5
    return {
        SecurityLevel.ML_DSA_44: Dilithium2,
        SecurityLevel.ML_DSA_65: Dilithium3,
        SecurityLevel.ML_DSA_87: Dilithium5,
    }[level]


def _derive_seed_at_path(
    master_seed: bytes,
    purpose: int,
    account: int,
    index: int,
) -> bytes:
    """Derive a deterministic seed for a specific path using chained HKDF."""
    if len(master_seed) < 16:
        raise DerivationError("Master seed must be at least 16 bytes.")

    # Chain HKDF through each path level so keys at different paths are independent
    info_root    = _DOMAIN + b"/root"
    info_purpose = _DOMAIN + b"/purpose/" + struct.pack(">I", purpose)
    info_account = _DOMAIN + b"/account/" + struct.pack(">I", account)
    info_index   = _DOMAIN + b"/index/"   + struct.pack(">I", index)

    k = _hkdf_expand(master_seed, info_root, 64)
    k = _hkdf_expand(k, info_purpose, 64)
    k = _hkdf_expand(k, info_account, 64)
    k = _hkdf_expand(k, info_index, 64)
    return k


def derive_keypair(
    master_seed: bytes,
    account: int = 0,
    index: int = 0,
    level: SecurityLevel = SecurityLevel.ML_DSA_65,
    purpose: int = _PURPOSE,
) -> PQKeyPair:
    """
    Derive a deterministic ML-DSA key pair from a master seed and path.

    Args:
        master_seed: High-entropy bytes (e.g. BIP-39 seed, 64 bytes recommended).
        account:     Account index (analogous to BIP-44 account).
        index:       Address index within the account.
        level:       ML-DSA security level.
        purpose:     BIP-43 purpose field (default 444 for PQC).

    Returns:
        A PQKeyPair deterministically bound to the given path.
    """
    child_seed = _derive_seed_at_path(master_seed, purpose, account, index)

    # dilithium-py exposes set_drbg_seed() for deterministic key generation.
    # We use the first 48 bytes of the derived child seed as the DRBG seed
    # (dilithium-py's AES-CTR DRBG expects exactly 48 bytes).
    impl = _get_impl(level)
    drbg_seed = child_seed[:48]

    # Save original random_bytes, switch to seeded DRBG, keygen, restore.
    _original_random_bytes = impl.random_bytes
    impl.set_drbg_seed(drbg_seed)
    try:
        pk, sk = impl.keygen()
    finally:
        impl.random_bytes = _original_random_bytes

    return PQKeyPair(public_key=pk, secret_key=sk, level=level)


def seed_from_mnemonic(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Derive a 64-byte seed from a BIP-39 mnemonic phrase.

    Uses PBKDF2-HMAC-SHA512 with 2048 iterations (BIP-39 standard).
    No wordlist validation is performed — any space-separated string is accepted.
    """
    mnemonic_bytes = mnemonic.encode("utf-8")
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic_bytes, salt, 2048)
