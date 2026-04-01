"""
ECDSA → ML-DSA migration helpers.

Bitcoin wallets currently use secp256k1 ECDSA.  Migrating to post-quantum
signatures requires:

  1. Generating a new ML-DSA key pair.
  2. Deriving a new P2PQH address from it.
  3. Spending all funds from legacy addresses to the new P2PQH address
     *while quantum computers are still too small to break ECDSA*.
     (The migration window is finite — once CRQCs appear, unspent
      P2PKH outputs become vulnerable before they can be moved.)
  4. Publishing the ML-DSA public key on-chain so full nodes can verify.

This module provides a MigrationPlan dataclass that captures the above,
and a helper to estimate the cost (in vbytes / sats) of a migration TX.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .keys import PQKeyPair, SecurityLevel
from .address import pubkey_to_address


# Approximate witness sizes (bytes) at ML-DSA-65
_MLDSA65_SIG_BYTES = 3293
_MLDSA65_PK_BYTES  = 1952

# Legacy P2PKH scriptSig size (bytes, typical)
_ECDSA_SCRIPTSIG_BYTES = 107

# Output script sizes
_P2PKH_SCRIPT_BYTES   = 25
_P2PQH_SCRIPT_BYTES   = 23   # same structure, different opcodes
_TX_OVERHEAD_BYTES    = 10   # version + locktime + varint counts


@dataclass
class MigrationPlan:
    """
    Summary of a key migration from one or more legacy addresses to a new P2PQH address.
    """
    legacy_addresses: List[str]
    new_keypair: PQKeyPair
    new_address: str
    estimated_input_count: int
    estimated_tx_size_bytes: int
    security_level: SecurityLevel

    @classmethod
    def create(
        cls,
        legacy_addresses: List[str],
        level: SecurityLevel = SecurityLevel.ML_DSA_65,
    ) -> "MigrationPlan":
        kp = PQKeyPair.generate(level)
        addr = pubkey_to_address(kp.public_key)
        n = len(legacy_addresses)

        # Rough size estimate:
        #   inputs:  n × (41 overhead + ECDSA scriptSig)
        #   outputs: 1 × P2PQH output
        #   overhead: fixed
        input_bytes = n * (41 + _ECDSA_SCRIPTSIG_BYTES)
        output_bytes = 8 + 1 + _P2PQH_SCRIPT_BYTES   # value + varint + script
        estimated_size = _TX_OVERHEAD_BYTES + input_bytes + output_bytes

        return cls(
            legacy_addresses=legacy_addresses,
            new_keypair=kp,
            new_address=addr,
            estimated_input_count=n,
            estimated_tx_size_bytes=estimated_size,
            security_level=level,
        )

    def summary(self) -> str:
        lines = [
            "=== Migration Plan ===",
            f"Security level     : {self.security_level.value}",
            f"Legacy inputs      : {self.estimated_input_count}",
            f"New P2PQH address  : {self.new_address}",
            f"Estimated TX size  : {self.estimated_tx_size_bytes:,} bytes",
            f"  (vs legacy only  : ~{10 + self.estimated_input_count * (41 + _ECDSA_SCRIPTSIG_BYTES) + 8 + 1 + _P2PKH_SCRIPT_BYTES:,} bytes for P2PKH→P2PKH)",
            "",
            "New key pair pubkey hash:",
            f"  {self.new_keypair.pubkey_hash.hex()}",
            "",
            "Steps:",
            "  1. Back up new_keypair.secret_key securely.",
            "  2. Construct a transaction spending legacy UTXOs → new_address.",
            "  3. Sign with legacy ECDSA keys (use your existing wallet).",
            "  4. Broadcast before any quantum adversary can break your ECDSA keys.",
            "  5. Future spends from new_address use ML-DSA signing (this library).",
        ]
        return "\n".join(lines)


def compare_signature_sizes() -> str:
    """Return a human-readable table comparing signature/key sizes."""
    rows = [
        ("Algorithm",       "Public Key", "Signature", "Total witness"),
        ("-" * 20,          "-" * 11,    "-" * 10,    "-" * 14),
        ("secp256k1 ECDSA", "33 B",      "72 B",      "107 B"),
        ("ML-DSA-44",       "1,312 B",   "2,420 B",   "3,732 B"),
        ("ML-DSA-65",       "1,952 B",   "3,293 B",   "5,245 B"),
        ("ML-DSA-87",       "2,592 B",   "4,595 B",   "7,187 B"),
        ("SPHINCS+-128s",   "32 B",      "7,856 B",   "7,888 B"),
        ("Falcon-512",      "897 B",     "666 B",     "1,563 B"),
    ]
    col_widths = [max(len(r[i]) for r in rows) for i in range(4)]
    lines = []
    for row in rows:
        lines.append("  ".join(cell.ljust(col_widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines)
