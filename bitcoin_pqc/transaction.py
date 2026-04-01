"""
Post-quantum transaction construction, signing, and verification.

A PQTransaction mirrors Bitcoin's raw transaction structure with one key
difference in the witness / scriptSig field: instead of a DER-encoded ECDSA
signature + compressed pubkey (typically ~107 bytes), the unlocking data is:

  <ml_dsa_signature>  <ml_dsa_public_key>

Sizes at ML-DSA-65:
  Signature : 3293 bytes
  Public key: 1952 bytes
  Total      : 5245 bytes  (vs ~107 bytes for ECDSA)

This is intentionally large — the trade-off is quantum resistance.  Future
work includes aggregated/batch verification and Winternitz OTS for cases
where smaller proofs are critical.

Transaction serialisation follows Bitcoin's little-endian conventions.
The sighash (message signed) is SHA-256(SHA-256(serialised_tx_body)).
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Optional

from .keys import PQKeyPair, SecurityLevel, verify_with_pubkey
from .address import address_to_script_pubkey


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TxInput:
    prev_txid: bytes        # 32 bytes, little-endian
    prev_index: int         # uint32
    script_sig: bytes = b"" # empty for unsigned; filled with PQ witness on sign
    sequence: int = 0xFFFFFFFF

    def serialise(self) -> bytes:
        return (
            self.prev_txid[::-1]           # stored big-endian → flip to LE
            + struct.pack("<I", self.prev_index)
            + _varint(len(self.script_sig))
            + self.script_sig
            + struct.pack("<I", self.sequence)
        )


@dataclass
class TxOutput:
    value: int              # satoshis (uint64)
    script_pubkey: bytes    # locking script

    def serialise(self) -> bytes:
        return (
            struct.pack("<Q", self.value)
            + _varint(len(self.script_pubkey))
            + self.script_pubkey
        )


@dataclass
class PQTransaction:
    version: int = 2
    inputs: List[TxInput] = field(default_factory=list)
    outputs: List[TxOutput] = field(default_factory=list)
    locktime: int = 0

    # ------------------------------------------------------------------
    # Convenience builders
    # ------------------------------------------------------------------

    def add_input(
        self,
        prev_txid: str | bytes,
        prev_index: int,
        sequence: int = 0xFFFFFFFF,
    ) -> "PQTransaction":
        if isinstance(prev_txid, str):
            prev_txid = bytes.fromhex(prev_txid)
        self.inputs.append(TxInput(prev_txid=prev_txid, prev_index=prev_index, sequence=sequence))
        return self

    def add_output(self, value: int, address: str) -> "PQTransaction":
        script = address_to_script_pubkey(address)
        self.outputs.append(TxOutput(value=value, script_pubkey=script))
        return self

    def add_output_script(self, value: int, script_pubkey: bytes) -> "PQTransaction":
        self.outputs.append(TxOutput(value=value, script_pubkey=script_pubkey))
        return self

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def serialise(self, signing: bool = False) -> bytes:
        """Full transaction serialisation.  signing=True omits scriptSigs."""
        parts = [struct.pack("<I", self.version)]
        parts.append(_varint(len(self.inputs)))
        for inp in self.inputs:
            if signing:
                # Empty scriptSig for sighash computation
                bare = TxInput(
                    prev_txid=inp.prev_txid,
                    prev_index=inp.prev_index,
                    script_sig=b"",
                    sequence=inp.sequence,
                )
                parts.append(bare.serialise())
            else:
                parts.append(inp.serialise())
        parts.append(_varint(len(self.outputs)))
        for out in self.outputs:
            parts.append(out.serialise())
        parts.append(struct.pack("<I", self.locktime))
        return b"".join(parts)

    def txid(self) -> str:
        """TXID = hex(SHA256(SHA256(serialised_tx)))[::-1]"""
        raw = self.serialise()
        h = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
        return h[::-1].hex()

    def sighash(self) -> bytes:
        """The message that gets signed: SHA256(SHA256(tx_body_without_sigs))."""
        raw = self.serialise(signing=True)
        return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------

def sign_transaction(tx: PQTransaction, keypairs: List[PQKeyPair]) -> PQTransaction:
    """
    Sign each input with the corresponding keypair.

    keypairs[i] signs inputs[i].  Pass a single-element list to sign all
    inputs with the same key (unusual but valid for testing).
    """
    if len(keypairs) == 1:
        keypairs = keypairs * len(tx.inputs)
    if len(keypairs) != len(tx.inputs):
        raise ValueError(
            f"Need one keypair per input: {len(tx.inputs)} inputs, "
            f"{len(keypairs)} keypairs"
        )

    msg = tx.sighash()

    for inp, kp in zip(tx.inputs, keypairs):
        sig = kp.sign(msg)
        # scriptSig = <varint sig_len> <sig> <varint pubkey_len> <pubkey>
        inp.script_sig = (
            _varint(len(sig)) + sig
            + _varint(len(kp.public_key)) + kp.public_key
        )

    return tx


def verify_transaction(tx: PQTransaction, level: SecurityLevel = SecurityLevel.ML_DSA_65) -> bool:
    """
    Verify all input signatures in a signed transaction.

    Extracts the ML-DSA public key and signature from each scriptSig,
    then checks against the transaction sighash.
    """
    msg = tx.sighash()

    for i, inp in enumerate(tx.inputs):
        try:
            sig, pubkey = _parse_script_sig(inp.script_sig)
        except Exception as e:
            raise ValueError(f"Input {i}: failed to parse scriptSig: {e}") from e

        if not verify_with_pubkey(pubkey, msg, sig, level):
            return False

    return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _varint(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Return (value, new_offset)."""
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    elif first == 0xFD:
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    elif first == 0xFE:
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    else:
        return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9


def _parse_script_sig(script_sig: bytes) -> tuple[bytes, bytes]:
    """Extract (signature, public_key) from a P2PQH scriptSig."""
    offset = 0
    sig_len, offset = _read_varint(script_sig, offset)
    sig = script_sig[offset: offset + sig_len]
    offset += sig_len
    pk_len, offset = _read_varint(script_sig, offset)
    pubkey = script_sig[offset: offset + pk_len]
    return sig, pubkey
