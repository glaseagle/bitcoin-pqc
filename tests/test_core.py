"""Core tests for bitcoin-pqc."""

import sys
import os
import hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from bitcoin_pqc.keys import PQKeyPair, SecurityLevel, verify_with_pubkey
from bitcoin_pqc.address import (
    pubkey_to_address,
    address_to_pubkey_hash,
    address_to_script_pubkey,
    b58check_encode,
    b58check_decode,
    MAINNET_P2PQH_VERSION,
)
from bitcoin_pqc.transaction import PQTransaction, sign_transaction, verify_transaction


class TestKeys(unittest.TestCase):
    def setUp(self):
        self.kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)

    def test_keygen_sizes(self):
        self.assertEqual(len(self.kp.public_key), 1952)
        self.assertGreater(len(self.kp.secret_key), 0)

    def test_sign_verify_roundtrip(self):
        msg = b"test message"
        sig = self.kp.sign(msg)
        self.assertTrue(self.kp.verify(msg, sig))

    def test_verify_wrong_message(self):
        msg = b"test message"
        sig = self.kp.sign(msg)
        self.assertFalse(self.kp.verify(b"wrong message", sig))

    def test_verify_wrong_key(self):
        msg = b"test message"
        sig = self.kp.sign(msg)
        other = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        self.assertFalse(other.verify(msg, sig))

    def test_pubkey_hash_length(self):
        self.assertEqual(len(self.kp.pubkey_hash), 20)

    def test_all_security_levels(self):
        for level in SecurityLevel:
            kp = PQKeyPair.generate(level)
            msg = b"hello pqc"
            sig = kp.sign(msg)
            self.assertTrue(kp.verify(msg, sig))

    def test_serialisation_roundtrip(self):
        d = self.kp.to_dict()
        kp2 = PQKeyPair.from_dict(d)
        self.assertEqual(self.kp.public_key, kp2.public_key)
        self.assertEqual(self.kp.secret_key, kp2.secret_key)
        self.assertEqual(self.kp.level, kp2.level)


class TestAddress(unittest.TestCase):
    def setUp(self):
        self.kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)

    def test_address_is_string(self):
        addr = pubkey_to_address(self.kp.public_key)
        self.assertIsInstance(addr, str)
        self.assertGreater(len(addr), 0)

    def test_address_decode_roundtrip(self):
        addr = pubkey_to_address(self.kp.public_key)
        pubkey_hash = address_to_pubkey_hash(addr)
        self.assertEqual(pubkey_hash, self.kp.pubkey_hash)

    def test_script_pubkey_length(self):
        addr = pubkey_to_address(self.kp.public_key)
        script = address_to_script_pubkey(addr)
        # OP_PQH(1) + push20(1) + hash(20) + OP_EQUALVERIFY(1) + OP_PQCHECKSIG(1) = 24
        self.assertEqual(len(script), 24)

    def test_script_pubkey_structure(self):
        addr = pubkey_to_address(self.kp.public_key)
        script = address_to_script_pubkey(addr)
        self.assertEqual(script[0], 0xc0)   # OP_PQH
        self.assertEqual(script[1], 0x14)   # push 20 bytes
        self.assertEqual(script[22], 0x88)  # OP_EQUALVERIFY
        self.assertEqual(script[23], 0xc1)  # OP_PQCHECKSIG

    def test_b58check_roundtrip(self):
        payload = b"\xde\xad\xbe\xef" * 5
        encoded = b58check_encode(0x30, payload)
        version, decoded = b58check_decode(encoded)
        self.assertEqual(version, 0x30)
        self.assertEqual(decoded, payload)

    def test_mainnet_testnet_differ(self):
        a1 = pubkey_to_address(self.kp.public_key, testnet=False)
        a2 = pubkey_to_address(self.kp.public_key, testnet=True)
        self.assertNotEqual(a1, a2)


class TestTransaction(unittest.TestCase):
    def setUp(self):
        self.kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        self.addr = pubkey_to_address(self.kp.public_key)

    def _make_tx(self) -> PQTransaction:
        tx = PQTransaction()
        tx.add_input("a" * 64, 0)
        tx.add_output(49_000_000, self.addr)
        return tx

    def test_sign_and_verify(self):
        tx = self._make_tx()
        sign_transaction(tx, [self.kp])
        self.assertTrue(verify_transaction(tx))

    def test_verify_fails_after_tamper(self):
        tx = self._make_tx()
        sign_transaction(tx, [self.kp])
        tx.outputs[0].value += 1
        self.assertFalse(verify_transaction(tx))

    def test_txid_is_hex_string(self):
        tx = self._make_tx()
        sign_transaction(tx, [self.kp])
        txid = tx.txid()
        self.assertEqual(len(txid), 64)
        int(txid, 16)   # raises if not valid hex

    def test_sighash_changes_with_output(self):
        tx1 = self._make_tx()
        tx2 = self._make_tx()
        tx2.outputs[0].value = 1
        self.assertNotEqual(tx1.sighash(), tx2.sighash())

    def test_multi_input_requires_matching_keypairs(self):
        kp2 = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
        tx = PQTransaction()
        tx.add_input("a" * 64, 0)
        tx.add_input("b" * 64, 1)
        tx.add_output(10_000_000, self.addr)
        sign_transaction(tx, [self.kp, kp2])
        self.assertTrue(verify_transaction(tx))


if __name__ == "__main__":
    unittest.main()
