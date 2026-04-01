"""
P2PQH — Pay to Post-Quantum Hash address scheme.

Address format (analogous to P2PKH / P2WPKH):

  P2PQH address = Base58Check( version_byte || RIPEMD160(SHA256(ml_dsa_pubkey)) )

Version bytes (proposed, not yet assigned by Bitcoin Core):
  0x30  mainnet P2PQH    →  addresses starting with "Q"
  0x6f  testnet P2PQH    →  addresses starting with "q" (or numeric)

Script pubkey (analogous to P2PKH locking script):
  OP_PQH <20-byte pubkey hash> OP_EQUALVERIFY OP_PQCHECKSIG
  (opcodes 0xc0, 0xc1 proposed — not yet allocated)

For practical testing the library encodes addresses as standard Base58Check
and emits human-readable script representations.
"""

from __future__ import annotations

import hashlib
import struct


# ---------------------------------------------------------------------------
# Base58 / Base58Check
# ---------------------------------------------------------------------------

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(data: bytes) -> str:
    """Encode bytes to Base58."""
    n = int.from_bytes(data, "big")
    result = []
    while n:
        n, remainder = divmod(n, 58)
        result.append(_BASE58_ALPHABET[remainder])
    # Leading zero bytes → leading '1' characters
    for byte in data:
        if byte == 0:
            result.append(_BASE58_ALPHABET[0])
        else:
            break
    return bytes(reversed(result)).decode("ascii")


def _b58decode(s: str) -> bytes:
    """Decode a Base58 string to bytes."""
    n = 0
    for char in s:
        n = n * 58 + _BASE58_ALPHABET.index(char.encode())
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    # Restore leading zeros
    pad = 0
    for char in s:
        if char == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + result


def _checksum(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def b58check_encode(version: int, payload: bytes) -> str:
    prefix = bytes([version]) + payload
    return _b58encode(prefix + _checksum(prefix))


def b58check_decode(address: str) -> tuple[int, bytes]:
    """Return (version_byte, payload) or raise ValueError on bad checksum."""
    raw = _b58decode(address)
    if len(raw) < 5:
        raise ValueError("Address too short")
    payload, check = raw[:-4], raw[-4:]
    if _checksum(payload) != check:
        raise ValueError("Bad checksum")
    return payload[0], payload[1:]


# ---------------------------------------------------------------------------
# P2PQH address derivation
# ---------------------------------------------------------------------------

MAINNET_P2PQH_VERSION = 0x30   # proposed
TESTNET_P2PQH_VERSION = 0x6F   # proposed (same as testnet P2PKH for convenience)


def pubkey_to_address(
    public_key: bytes,
    testnet: bool = False,
) -> str:
    """
    Derive a P2PQH address from a raw ML-DSA public key.

    Steps:
      1. SHA-256(pubkey)
      2. RIPEMD-160 of step 1         → 20-byte pubkey hash
      3. Base58Check with version byte → P2PQH address string
    """
    sha = hashlib.sha256(public_key).digest()
    r = hashlib.new("ripemd160")
    r.update(sha)
    pubkey_hash = r.digest()

    version = TESTNET_P2PQH_VERSION if testnet else MAINNET_P2PQH_VERSION
    return b58check_encode(version, pubkey_hash)


def address_to_pubkey_hash(address: str) -> bytes:
    """Decode a P2PQH address to its 20-byte pubkey hash."""
    version, pubkey_hash = b58check_decode(address)
    if version not in (MAINNET_P2PQH_VERSION, TESTNET_P2PQH_VERSION):
        raise ValueError(f"Unknown address version byte: 0x{version:02x}")
    if len(pubkey_hash) != 20:
        raise ValueError("Expected 20-byte pubkey hash")
    return pubkey_hash


def address_to_script_pubkey(address: str) -> bytes:
    """
    Return the P2PQH locking script (scriptPubKey) for a given address.

    Proposed opcodes:
      0xc0  OP_PQH            (hash top-of-stack PQ pubkey, push result)
      0x88  OP_EQUALVERIFY    (existing opcode reused)
      0xc1  OP_PQCHECKSIG     (verify ML-DSA signature)

    Encoded as: OP_PQH <push 20 bytes> <pubkey_hash> OP_EQUALVERIFY OP_PQCHECKSIG
    """
    pubkey_hash = address_to_pubkey_hash(address)
    return bytes([0xc0, 0x14]) + pubkey_hash + bytes([0x88, 0xc1])


def script_pubkey_repr(script: bytes) -> str:
    """Human-readable disassembly of a P2PQH scriptPubKey."""
    if len(script) == 23 and script[0] == 0xc0 and script[1] == 0x14:
        hash_hex = script[2:22].hex()
        return f"OP_PQH OP_DATA_20 {hash_hex} OP_EQUALVERIFY OP_PQCHECKSIG"
    return script.hex()
