"""
bitcoin-pqc: Post-Quantum Cryptography for Bitcoin

Key types:
  PQKeyPair       — pure ML-DSA (CRYSTALS-Dilithium, NIST FIPS 204)
  HybridKeyPair   — secp256k1 ECDSA + ML-DSA, both required to verify

Address types:
  P2PQH  — Pay to Post-Quantum Hash  (pure ML-DSA)
  P2HPQ  — Pay to Hybrid PQ Hash     (ECDSA + ML-DSA, recommended for production)
"""

from .keys import PQKeyPair, HybridKeyPair, HybridSignature, SecurityLevel, verify_mldsa
from .address import (
    pubkey_to_address,
    hybrid_pubkeys_to_address,
    address_to_script_pubkey,
    is_hybrid_address,
)
from .transaction import PQTransaction, sign_transaction, verify_transaction
from .exceptions import (
    BitcoinPQCError,
    InvalidKeyError,
    SignatureError,
    VerificationError,
    InvalidSignatureError,
    AddressError,
    BadChecksumError,
    TransactionError,
    StorageError,
    DecryptionError,
    DerivationError,
)

__version__ = "0.2.0"
__all__ = [
    "PQKeyPair", "HybridKeyPair", "HybridSignature", "SecurityLevel", "verify_mldsa",
    "pubkey_to_address", "hybrid_pubkeys_to_address", "address_to_script_pubkey", "is_hybrid_address",
    "PQTransaction", "sign_transaction", "verify_transaction",
    "BitcoinPQCError", "InvalidKeyError", "SignatureError", "VerificationError",
    "InvalidSignatureError", "AddressError", "BadChecksumError", "TransactionError",
    "StorageError", "DecryptionError", "DerivationError",
]
