#!/usr/bin/env python3
"""
bitcoin-pqc demo — generate keys, derive address, sign & verify a transaction.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bitcoin_pqc import PQKeyPair, SecurityLevel, pubkey_to_address, sign_transaction, verify_transaction
from bitcoin_pqc.transaction import PQTransaction
from bitcoin_pqc.migration import MigrationPlan, compare_signature_sizes

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"


def section(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 60}{RESET}")


def main() -> None:
    # ------------------------------------------------------------------
    section("1. Key Generation  (ML-DSA-65 / Dilithium3)")
    # ------------------------------------------------------------------
    print("Generating key pair...")
    kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
    print(f"  Public key  : {len(kp.public_key):,} bytes")
    print(f"  Secret key  : {len(kp.secret_key):,} bytes")
    print(f"  Pubkey hash : {kp.pubkey_hash.hex()}")

    # ------------------------------------------------------------------
    section("2. P2PQH Address Derivation")
    # ------------------------------------------------------------------
    addr = pubkey_to_address(kp.public_key)
    addr_testnet = pubkey_to_address(kp.public_key, testnet=True)
    print(f"  Mainnet address : {addr}")
    print(f"  Testnet address : {addr_testnet}")

    # ------------------------------------------------------------------
    section("3. Build & Sign a Transaction")
    # ------------------------------------------------------------------
    # Simulate spending a UTXO to the new P2PQH address
    dummy_txid = "a" * 64   # placeholder TXID
    tx = PQTransaction()
    tx.add_input(dummy_txid, 0)
    tx.add_output(49_900_000, addr)   # 0.499 BTC (minus fee)

    print(f"  Sighash : {tx.sighash().hex()}")
    print(f"  Signing with ML-DSA-65...")

    sign_transaction(tx, [kp])

    sig_size = len(tx.inputs[0].script_sig)
    print(f"  scriptSig size : {sig_size:,} bytes")
    print(f"  Raw TX size    : {len(tx.serialise()):,} bytes")
    print(f"  TXID           : {tx.txid()}")

    # ------------------------------------------------------------------
    section("4. Signature Verification")
    # ------------------------------------------------------------------
    valid = verify_transaction(tx)
    status = f"{GREEN}VALID{RESET}" if valid else "\033[31mINVALID\033[0m"
    print(f"  Verification result : {status}")

    # Tamper test
    original_value = tx.outputs[0].value
    tx.outputs[0].value = 50_000_000   # attacker changes output value
    tampered = verify_transaction(tx)
    tamper_status = f"{GREEN}REJECTED (correct){RESET}" if not tampered else "\033[31mACCEPTED (bad!)\033[0m"
    print(f"  Tampered TX result  : {tamper_status}")
    tx.outputs[0].value = original_value  # restore

    # ------------------------------------------------------------------
    section("5. Signature / Key Size Comparison")
    # ------------------------------------------------------------------
    print(compare_signature_sizes())

    # ------------------------------------------------------------------
    section("6. Migration Plan")
    # ------------------------------------------------------------------
    plan = MigrationPlan.create(
        legacy_addresses=["1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf", "1HLoD9E4SDFFPDiYfNYnkBLQ85Y51J3Zb1"],
        level=SecurityLevel.ML_DSA_65,
    )
    print(plan.summary())

    print(f"\n{GREEN}Demo complete.{RESET}\n")


if __name__ == "__main__":
    main()
