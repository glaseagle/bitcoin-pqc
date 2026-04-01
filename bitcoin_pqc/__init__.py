"""
bitcoin-pqc: Post-Quantum Cryptography for Bitcoin

Implements ML-DSA (CRYSTALS-Dilithium) based key generation, address derivation,
and transaction signing as a drop-in research replacement for Bitcoin's ECDSA scheme.
"""

from .keys import PQKeyPair, SecurityLevel
from .address import pubkey_to_address, address_to_script_pubkey
from .transaction import PQTransaction, sign_transaction, verify_transaction

__version__ = "0.1.0"
__all__ = [
    "PQKeyPair",
    "SecurityLevel",
    "pubkey_to_address",
    "address_to_script_pubkey",
    "PQTransaction",
    "sign_transaction",
    "verify_transaction",
]
