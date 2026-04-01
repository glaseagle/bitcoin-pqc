"""
Transaction construction, signing, and verification.

Supports both P2PQH (pure ML-DSA) and P2HPQ (hybrid ECDSA + ML-DSA) inputs.

scriptSig format
----------------
P2PQH (pure PQ):
  <varint sig_len> <mldsa_sig> <varint pk_len> <mldsa_pubkey>

P2HPQ (hybrid):
  <varint data_len> <hybrid_serialised>
  where hybrid_serialised = HybridSignature.serialise() —
    2B ecdsa_sig_len | ecdsa_sig | 2B ecdsa_pk_len | ecdsa_pk |
    2B mldsa_sig_len | mldsa_sig | 2B mldsa_pk_len | mldsa_pk

Sighash
-------
SHA256(SHA256(serialised_tx_body_with_empty_scriptsigs))
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import List, Union

from .keys import PQKeyPair, HybridKeyPair, HybridSignature, SecurityLevel, verify_mldsa, _verify_ecdsa
from .address import address_to_script_pubkey, is_hybrid_address
from .exceptions import TransactionError, ScriptSigParseError


KeyType = Union[PQKeyPair, HybridKeyPair]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TxInput:
    prev_txid: bytes
    prev_index: int
    script_sig: bytes = b""
    sequence: int = 0xFFFFFFFF
    _is_hybrid: bool = False

    def serialise(self, empty_script: bool = False) -> bytes:
        script = b"" if empty_script else self.script_sig
        return (
            self.prev_txid[::-1]
            + struct.pack("<I", self.prev_index)
            + _varint(len(script))
            + script
            + struct.pack("<I", self.sequence)
        )


@dataclass
class TxOutput:
    value: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        if self.value < 0:
            raise TransactionError("Output value cannot be negative")
        if self.value > 21_000_000 * 100_000_000:
            raise TransactionError("Output value exceeds maximum Bitcoin supply")

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
    # Builders
    # ------------------------------------------------------------------

    def add_input(
        self,
        prev_txid: Union[str, bytes],
        prev_index: int,
        sequence: int = 0xFFFFFFFF,
    ) -> "PQTransaction":
        if isinstance(prev_txid, str):
            if len(prev_txid) != 64:
                raise TransactionError("TXID must be 64 hex characters")
            prev_txid = bytes.fromhex(prev_txid)
        if len(prev_txid) != 32:
            raise TransactionError("TXID must be 32 bytes")
        if not 0 <= prev_index <= 0xFFFFFFFF:
            raise TransactionError("Output index out of range")
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
        if not self.inputs:
            raise TransactionError("Transaction has no inputs")
        if not self.outputs:
            raise TransactionError("Transaction has no outputs")
        parts = [struct.pack("<I", self.version)]
        parts.append(_varint(len(self.inputs)))
        for inp in self.inputs:
            parts.append(inp.serialise(empty_script=signing))
        parts.append(_varint(len(self.outputs)))
        for out in self.outputs:
            parts.append(out.serialise())
        parts.append(struct.pack("<I", self.locktime))
        return b"".join(parts)

    def sighash(self) -> bytes:
        raw = self.serialise(signing=True)
        return hashlib.sha256(hashlib.sha256(raw).digest()).digest()

    def txid(self) -> str:
        raw = self.serialise()
        h = hashlib.sha256(hashlib.sha256(raw).digest()).digest()
        return h[::-1].hex()

    def total_output_value(self) -> int:
        return sum(o.value for o in self.outputs)

    def weight(self) -> int:
        """Approximate transaction weight (vbytes ≈ weight / 4)."""
        return len(self.serialise())


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------

def sign_transaction(tx: PQTransaction, keypairs: List[KeyType]) -> PQTransaction:
    """
    Sign all inputs.  Pass one keypair per input, or a single-element list
    to use the same key for all inputs.

    Accepts PQKeyPair (pure ML-DSA) or HybridKeyPair (ECDSA + ML-DSA).
    """
    if not keypairs:
        raise TransactionError("No keypairs provided")
    if len(keypairs) == 1:
        keypairs = keypairs * len(tx.inputs)
    if len(keypairs) != len(tx.inputs):
        raise TransactionError(
            f"{len(tx.inputs)} inputs but {len(keypairs)} keypairs provided"
        )

    msg = tx.sighash()

    for inp, kp in zip(tx.inputs, keypairs):
        if isinstance(kp, HybridKeyPair):
            sig = kp.sign(msg)
            serialised = sig.serialise()
            inp.script_sig = _varint(len(serialised)) + serialised
            inp._is_hybrid = True
        elif isinstance(kp, PQKeyPair):
            sig = kp.sign(msg)
            inp.script_sig = _varint(len(sig)) + sig + _varint(len(kp.public_key)) + kp.public_key
            inp._is_hybrid = False
        else:
            raise TransactionError(f"Unknown keypair type: {type(kp)}")

    return tx


def verify_transaction(
    tx: PQTransaction,
    level: SecurityLevel = SecurityLevel.ML_DSA_65,
) -> bool:
    """
    Verify all input signatures.

    For hybrid inputs, BOTH ECDSA and ML-DSA must be valid.
    For pure PQ inputs, ML-DSA must be valid.
    """
    if not tx.inputs:
        raise TransactionError("Transaction has no inputs")

    msg = tx.sighash()

    for i, inp in enumerate(tx.inputs):
        if not inp.script_sig:
            raise TransactionError(f"Input {i} has no scriptSig (unsigned)")
        try:
            if inp._is_hybrid:
                sig = _parse_hybrid_scriptsig(inp.script_sig, level)
                if not sig.verify(msg):
                    return False
            else:
                mldsa_sig, mldsa_pk = _parse_pq_scriptsig(inp.script_sig)
                if not verify_mldsa(mldsa_pk, msg, mldsa_sig, level):
                    return False
        except ScriptSigParseError as exc:
            raise TransactionError(f"Input {i}: {exc}") from exc

    return True


# ---------------------------------------------------------------------------
# Helpers
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
    if offset >= len(data):
        raise ScriptSigParseError("Unexpected end of data reading varint")
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    elif first == 0xFD:
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    elif first == 0xFE:
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    else:
        return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9


def _parse_pq_scriptsig(script_sig: bytes) -> tuple[bytes, bytes]:
    try:
        offset = 0
        sig_len, offset = _read_varint(script_sig, offset)
        sig = script_sig[offset: offset + sig_len]
        offset += sig_len
        pk_len, offset = _read_varint(script_sig, offset)
        pk = script_sig[offset: offset + pk_len]
        return sig, pk
    except Exception as exc:
        raise ScriptSigParseError(f"Failed to parse P2PQH scriptSig: {exc}") from exc


def _parse_hybrid_scriptsig(script_sig: bytes, level: SecurityLevel) -> HybridSignature:
    try:
        data_len, offset = _read_varint(script_sig, 0)
        payload = script_sig[offset: offset + data_len]
        return HybridSignature.deserialise(payload, level)
    except Exception as exc:
        raise ScriptSigParseError(f"Failed to parse P2HPQ scriptSig: {exc}") from exc
