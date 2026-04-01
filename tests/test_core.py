"""Tests for bitcoin-pqc v0.2.0"""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from bitcoin_pqc.keys import PQKeyPair, HybridKeyPair, HybridSignature, SecurityLevel, verify_mldsa
from bitcoin_pqc.address import (
    pubkey_to_address, hybrid_pubkeys_to_address, address_to_pubkey_hash,
    address_to_script_pubkey, is_hybrid_address, b58check_encode, b58check_decode,
    MAINNET_P2PQH, MAINNET_P2HPQ,
)
from bitcoin_pqc.transaction import PQTransaction, sign_transaction, verify_transaction
from bitcoin_pqc.secure import encrypt_key_data, decrypt_key_data
from bitcoin_pqc.hd import derive_keypair, seed_from_mnemonic
from bitcoin_pqc.exceptions import (
    InvalidKeyError, BadChecksumError, DecryptionError, TransactionError, DerivationError
)
from bitcoin_pqc.migration import MigrationPlan, compare_signature_sizes


# ---------------------------------------------------------------------------
# PQKeyPair
# ---------------------------------------------------------------------------

class TestPQKeyPair(unittest.TestCase):
    def setUp(self):
        self.kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)

    def test_keygen_sizes(self):
        self.assertEqual(len(self.kp.public_key), 1952)
        self.assertGreater(len(self.kp.secret_key), 0)

    def test_invalid_pubkey_length_raises(self):
        with self.assertRaises(InvalidKeyError):
            PQKeyPair(public_key=b"\x00" * 10, secret_key=b"\x00" * 32, level=SecurityLevel.ML_DSA_65)

    def test_sign_verify_roundtrip(self):
        msg = b"hello post-quantum world"
        sig = self.kp.sign(msg)
        self.assertTrue(self.kp.verify(msg, sig))

    def test_verify_wrong_message(self):
        sig = self.kp.sign(b"correct")
        self.assertFalse(self.kp.verify(b"wrong", sig))

    def test_verify_wrong_key(self):
        other = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        sig = self.kp.sign(b"msg")
        self.assertFalse(other.verify(b"msg", sig))

    def test_verify_truncated_signature(self):
        sig = self.kp.sign(b"msg")
        self.assertFalse(self.kp.verify(b"msg", sig[:100]))

    def test_all_security_levels(self):
        for level in SecurityLevel:
            kp = PQKeyPair.generate(level)
            msg = b"level test"
            self.assertTrue(kp.verify(msg, kp.sign(msg)))

    def test_pubkey_hash_is_20_bytes(self):
        self.assertEqual(len(self.kp.pubkey_hash), 20)

    def test_dict_roundtrip(self):
        d = self.kp.to_dict()
        kp2 = PQKeyPair.from_dict(d)
        self.assertEqual(self.kp.public_key, kp2.public_key)
        self.assertEqual(self.kp.secret_key, kp2.secret_key)

    def test_save_load_plaintext(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            self.kp.save(path)
            kp2 = PQKeyPair.load(path)
            self.assertEqual(self.kp.public_key, kp2.public_key)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# HybridKeyPair
# ---------------------------------------------------------------------------

class TestHybridKeyPair(unittest.TestCase):
    def setUp(self):
        self.kp = HybridKeyPair.generate(SecurityLevel.ML_DSA_65)

    def test_keygen_sizes(self):
        self.assertEqual(len(self.kp.ecdsa_public_key), 33)
        self.assertEqual(len(self.kp.ecdsa_private_key), 32)
        self.assertEqual(len(self.kp.pq_keypair.public_key), 1952)

    def test_sign_verify_roundtrip(self):
        msg = b"hybrid message"
        sig = self.kp.sign(msg)
        self.assertIsInstance(sig, HybridSignature)
        self.assertTrue(sig.verify(msg))

    def test_verify_fails_wrong_message(self):
        sig = self.kp.sign(b"real")
        self.assertFalse(sig.verify(b"fake"))

    def test_verify_fails_tampered_ecdsa_sig(self):
        sig = self.kp.sign(b"msg")
        tampered = HybridSignature(
            ecdsa_sig=bytes(len(sig.ecdsa_sig)),
            mldsa_sig=sig.mldsa_sig,
            ecdsa_pubkey=sig.ecdsa_pubkey,
            mldsa_pubkey=sig.mldsa_pubkey,
            level=sig.level,
        )
        self.assertFalse(tampered.verify(b"msg"))

    def test_verify_fails_tampered_mldsa_sig(self):
        sig = self.kp.sign(b"msg")
        tampered = HybridSignature(
            ecdsa_sig=sig.ecdsa_sig,
            mldsa_sig=bytes(len(sig.mldsa_sig)),
            ecdsa_pubkey=sig.ecdsa_pubkey,
            mldsa_pubkey=sig.mldsa_pubkey,
            level=sig.level,
        )
        self.assertFalse(tampered.verify(b"msg"))

    def test_hybrid_signature_serialise_roundtrip(self):
        msg = b"serialise me"
        sig = self.kp.sign(msg)
        raw = sig.serialise()
        sig2 = HybridSignature.deserialise(raw, SecurityLevel.ML_DSA_65)
        self.assertTrue(sig2.verify(msg))

    def test_pubkey_hash_is_20_bytes(self):
        self.assertEqual(len(self.kp.pubkey_hash), 20)

    def test_dict_roundtrip(self):
        d = self.kp.to_dict()
        kp2 = HybridKeyPair.from_dict(d)
        self.assertEqual(self.kp.ecdsa_public_key, kp2.ecdsa_public_key)
        self.assertEqual(self.kp.pq_keypair.public_key, kp2.pq_keypair.public_key)


# ---------------------------------------------------------------------------
# Encrypted storage
# ---------------------------------------------------------------------------

class TestEncryptedStorage(unittest.TestCase):
    def test_pq_key_encrypt_decrypt(self):
        kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        with tempfile.NamedTemporaryFile(suffix=".enc.json", delete=False) as f:
            path = f.name
        try:
            kp.save_encrypted(path, "correct-horse-battery")
            kp2 = PQKeyPair.load_encrypted(path, "correct-horse-battery")
            self.assertEqual(kp.public_key, kp2.public_key)
            self.assertEqual(kp.secret_key, kp2.secret_key)
        finally:
            os.unlink(path)

    def test_wrong_passphrase_raises(self):
        kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        with tempfile.NamedTemporaryFile(suffix=".enc.json", delete=False) as f:
            path = f.name
        try:
            kp.save_encrypted(path, "correct")
            with self.assertRaises(DecryptionError):
                PQKeyPair.load_encrypted(path, "wrong")
        finally:
            os.unlink(path)

    def test_hybrid_key_encrypt_decrypt(self):
        kp = HybridKeyPair.generate(SecurityLevel.ML_DSA_65)
        with tempfile.NamedTemporaryFile(suffix=".enc.json", delete=False) as f:
            path = f.name
        try:
            kp.save_encrypted(path, "passphrase123")
            kp2 = HybridKeyPair.load_encrypted(path, "passphrase123")
            self.assertEqual(kp.ecdsa_public_key, kp2.ecdsa_public_key)
            self.assertEqual(kp.pq_keypair.public_key, kp2.pq_keypair.public_key)
        finally:
            os.unlink(path)

    def test_envelope_is_opaque(self):
        """Encrypted file must not contain any readable key material."""
        kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        with tempfile.NamedTemporaryFile(suffix=".enc.json", delete=False, mode="w") as f:
            path = f.name
        try:
            kp.save_encrypted(path, "pw")
            with open(path) as f:
                content = f.read()
            self.assertNotIn(kp.public_key.hex()[:16], content)
            self.assertNotIn(kp.secret_key.hex()[:16], content)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Address
# ---------------------------------------------------------------------------

class TestAddress(unittest.TestCase):
    def setUp(self):
        self.pq = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        self.hybrid = HybridKeyPair.generate(SecurityLevel.ML_DSA_65)

    def test_p2pqh_address(self):
        addr = pubkey_to_address(self.pq.public_key)
        self.assertIsInstance(addr, str)
        self.assertGreater(len(addr), 0)

    def test_p2hpq_address(self):
        addr = hybrid_pubkeys_to_address(self.hybrid.ecdsa_public_key, self.hybrid.pq_keypair.public_key)
        self.assertIsInstance(addr, str)

    def test_p2pqh_is_not_hybrid(self):
        addr = pubkey_to_address(self.pq.public_key)
        self.assertFalse(is_hybrid_address(addr))

    def test_p2hpq_is_hybrid(self):
        addr = hybrid_pubkeys_to_address(self.hybrid.ecdsa_public_key, self.hybrid.pq_keypair.public_key)
        self.assertTrue(is_hybrid_address(addr))

    def test_mainnet_testnet_differ(self):
        a1 = pubkey_to_address(self.pq.public_key, testnet=False)
        a2 = pubkey_to_address(self.pq.public_key, testnet=True)
        self.assertNotEqual(a1, a2)

    def test_script_pubkey_p2pqh(self):
        addr = pubkey_to_address(self.pq.public_key)
        script = address_to_script_pubkey(addr)
        self.assertEqual(len(script), 24)
        self.assertEqual(script[0], 0xc0)   # OP_PQH
        self.assertEqual(script[1], 0x14)   # push 20 bytes
        self.assertEqual(script[22], 0x88)  # OP_EQUALVERIFY
        self.assertEqual(script[23], 0xc1)  # OP_PQCHECKSIG

    def test_script_pubkey_p2hpq(self):
        addr = hybrid_pubkeys_to_address(self.hybrid.ecdsa_public_key, self.hybrid.pq_keypair.public_key)
        script = address_to_script_pubkey(addr)
        self.assertEqual(script[23], 0xc2)  # OP_HPQCHECKSIG

    def test_b58check_roundtrip(self):
        payload = b"\xde\xad\xbe\xef" * 5
        encoded = b58check_encode(0x30, payload)
        version, decoded = b58check_decode(encoded)
        self.assertEqual(version, 0x30)
        self.assertEqual(decoded, payload)

    def test_bad_checksum_raises(self):
        addr = pubkey_to_address(self.pq.public_key)
        with self.assertRaises(BadChecksumError):
            b58check_decode(addr[:-1] + ("1" if addr[-1] != "1" else "2"))


# ---------------------------------------------------------------------------
# Transaction — pure PQ
# ---------------------------------------------------------------------------

class TestPQTransaction(unittest.TestCase):
    def setUp(self):
        self.kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        self.addr = pubkey_to_address(self.kp.public_key)

    def _tx(self) -> PQTransaction:
        tx = PQTransaction()
        tx.add_input("a" * 64, 0)
        tx.add_output(49_000_000, self.addr)
        return tx

    def test_sign_and_verify(self):
        tx = self._tx()
        sign_transaction(tx, [self.kp])
        self.assertTrue(verify_transaction(tx))

    def test_verify_fails_after_tamper(self):
        tx = self._tx()
        sign_transaction(tx, [self.kp])
        tx.outputs[0].value += 1
        self.assertFalse(verify_transaction(tx))

    def test_txid_is_64_hex(self):
        tx = self._tx()
        sign_transaction(tx, [self.kp])
        txid = tx.txid()
        self.assertEqual(len(txid), 64)
        int(txid, 16)

    def test_invalid_txid_raises(self):
        tx = PQTransaction()
        with self.assertRaises(TransactionError):
            tx.add_input("tooshort", 0)

    def test_negative_output_raises(self):
        with self.assertRaises(TransactionError):
            TxOutput = __import__("bitcoin_pqc.transaction", fromlist=["TxOutput"]).TxOutput
            TxOutput(value=-1, script_pubkey=b"\x00")

    def test_multi_input(self):
        kp2 = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        tx = PQTransaction()
        tx.add_input("a" * 64, 0)
        tx.add_input("b" * 64, 1)
        tx.add_output(10_000_000, self.addr)
        sign_transaction(tx, [self.kp, kp2])
        self.assertTrue(verify_transaction(tx))

    def test_sighash_changes_with_value(self):
        tx1 = self._tx()
        tx2 = self._tx()
        tx2.outputs[0].value = 1
        self.assertNotEqual(tx1.sighash(), tx2.sighash())


# ---------------------------------------------------------------------------
# Transaction — hybrid
# ---------------------------------------------------------------------------

class TestHybridTransaction(unittest.TestCase):
    def setUp(self):
        self.kp = HybridKeyPair.generate(SecurityLevel.ML_DSA_65)
        self.addr = hybrid_pubkeys_to_address(self.kp.ecdsa_public_key, self.kp.pq_keypair.public_key)

    def _tx(self) -> PQTransaction:
        tx = PQTransaction()
        tx.add_input("c" * 64, 0)
        tx.add_output(49_000_000, self.addr)
        return tx

    def test_sign_and_verify(self):
        tx = self._tx()
        sign_transaction(tx, [self.kp])
        self.assertTrue(verify_transaction(tx))

    def test_verify_fails_tamper(self):
        tx = self._tx()
        sign_transaction(tx, [self.kp])
        tx.outputs[0].value += 1
        self.assertFalse(verify_transaction(tx))


# ---------------------------------------------------------------------------
# HD derivation
# ---------------------------------------------------------------------------

class TestHDDerivation(unittest.TestCase):
    SEED = bytes.fromhex("000102030405060708090a0b0c0d0e0f" * 4)

    def test_deterministic(self):
        kp1 = derive_keypair(self.SEED, account=0, index=0)
        kp2 = derive_keypair(self.SEED, account=0, index=0)
        self.assertEqual(kp1.public_key, kp2.public_key)

    def test_different_index_gives_different_key(self):
        kp0 = derive_keypair(self.SEED, account=0, index=0)
        kp1 = derive_keypair(self.SEED, account=0, index=1)
        self.assertNotEqual(kp0.public_key, kp1.public_key)

    def test_different_account_gives_different_key(self):
        kp0 = derive_keypair(self.SEED, account=0, index=0)
        kp1 = derive_keypair(self.SEED, account=1, index=0)
        self.assertNotEqual(kp0.public_key, kp1.public_key)

    def test_derived_key_can_sign_verify(self):
        kp = derive_keypair(self.SEED, account=0, index=5)
        msg = b"hd derived key test"
        self.assertTrue(kp.verify(msg, kp.sign(msg)))

    def test_seed_too_short_raises(self):
        with self.assertRaises(DerivationError):
            derive_keypair(b"tooshort", account=0, index=0)

    def test_mnemonic_to_seed(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        seed = seed_from_mnemonic(mnemonic)
        self.assertEqual(len(seed), 64)
        # Deterministic
        self.assertEqual(seed, seed_from_mnemonic(mnemonic))

    def test_mnemonic_passphrase_changes_seed(self):
        mnemonic = "abandon " * 11 + "about"
        s1 = seed_from_mnemonic(mnemonic, "")
        s2 = seed_from_mnemonic(mnemonic, "extra")
        self.assertNotEqual(s1, s2)


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------

class TestMigration(unittest.TestCase):
    def test_migration_plan_creates(self):
        plan = MigrationPlan.create(["1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"])
        self.assertIsInstance(plan.new_address, str)
        self.assertGreater(plan.estimated_tx_size_bytes, 0)

    def test_compare_sizes_returns_string(self):
        result = compare_signature_sizes()
        self.assertIn("ECDSA", result)
        self.assertIn("ML-DSA", result)


if __name__ == "__main__":
    unittest.main()
