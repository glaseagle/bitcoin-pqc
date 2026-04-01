"""
Address derivation for P2PQH (pure ML-DSA) and P2HPQ (Hybrid ECDSA+ML-DSA).

  P2PQH  — Pay to Post-Quantum Hash
            Commitment: RIPEMD160(SHA256(mldsa_pubkey))
            Version:    0x30 mainnet / 0x6F testnet

  P2HPQ  — Pay to Hybrid Post-Quantum Hash
            Commitment: RIPEMD160(SHA256(ecdsa_pubkey || mldsa_pubkey))
            Version:    0x31 mainnet / 0x70 testnet

Both use standard Base58Check encoding.

Proposed locking scripts:

  P2PQH:
    OP_PQH <20> <hash> OP_EQUALVERIFY OP_PQCHECKSIG
    (0xc0  0x14  <20B>  0x88           0xc1)

  P2HPQ:
    OP_PQH <20> <hash> OP_EQUALVERIFY OP_HPQCHECKSIG
    (0xc0  0x14  <20B>  0x88           0xc2)
    OP_HPQCHECKSIG verifies BOTH ECDSA and ML-DSA signatures.
"""

from __future__ import annotations

import hashlib

from .exceptions import BadChecksumError, UnknownVersionError, AddressError

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

MAINNET_P2PQH  = 0x30
TESTNET_P2PQH  = 0x6F
MAINNET_P2HPQ  = 0x31
TESTNET_P2HPQ  = 0x70

_KNOWN_VERSIONS = {MAINNET_P2PQH, TESTNET_P2PQH, MAINNET_P2HPQ, TESTNET_P2HPQ}


# ---------------------------------------------------------------------------
# Base58Check
# ---------------------------------------------------------------------------

def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    result = []
    while n:
        n, r = divmod(n, 58)
        result.append(_BASE58_ALPHABET[r])
    for byte in data:
        if byte == 0:
            result.append(_BASE58_ALPHABET[0])
        else:
            break
    return bytes(reversed(result)).decode("ascii")


def _b58decode(s: str) -> bytes:
    n = 0
    for char in s:
        idx = _BASE58_ALPHABET.find(char.encode())
        if idx == -1:
            raise AddressError(f"Invalid Base58 character: '{char}'")
        n = n * 58 + idx
    result = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + result


def _checksum(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def b58check_encode(version: int, payload: bytes) -> str:
    if not 0 <= version <= 255:
        raise AddressError(f"Version byte out of range: {version}")
    prefix = bytes([version]) + payload
    return _b58encode(prefix + _checksum(prefix))


def b58check_decode(address: str) -> tuple[int, bytes]:
    if not address:
        raise AddressError("Empty address string")
    raw = _b58decode(address)
    if len(raw) < 5:
        raise AddressError(f"Address too short ({len(raw)} bytes)")
    payload, check = raw[:-4], raw[-4:]
    if _checksum(payload) != check:
        raise BadChecksumError(f"Checksum mismatch for address '{address}'")
    return payload[0], payload[1:]


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def _hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    r = hashlib.new("ripemd160")
    r.update(sha)
    return r.digest()


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------

def pubkey_to_address(public_key: bytes, testnet: bool = False) -> str:
    """P2PQH address from a raw ML-DSA public key."""
    if not public_key:
        raise AddressError("public_key must be non-empty")
    version = TESTNET_P2PQH if testnet else MAINNET_P2PQH
    return b58check_encode(version, _hash160(public_key))


def hybrid_pubkeys_to_address(
    ecdsa_pubkey: bytes,
    mldsa_pubkey: bytes,
    testnet: bool = False,
) -> str:
    """P2HPQ address from a combined ECDSA + ML-DSA public key pair."""
    if not ecdsa_pubkey or not mldsa_pubkey:
        raise AddressError("Both ecdsa_pubkey and mldsa_pubkey must be non-empty")
    version = TESTNET_P2HPQ if testnet else MAINNET_P2HPQ
    combined = ecdsa_pubkey + mldsa_pubkey
    return b58check_encode(version, _hash160(combined))


def address_to_pubkey_hash(address: str) -> tuple[bytes, int]:
    """Decode any P2PQH or P2HPQ address to (pubkey_hash, version)."""
    version, pubkey_hash = b58check_decode(address)
    if version not in _KNOWN_VERSIONS:
        raise UnknownVersionError(f"Unknown address version byte: 0x{version:02x}")
    if len(pubkey_hash) != 20:
        raise AddressError(f"Expected 20-byte hash, got {len(pubkey_hash)}")
    return pubkey_hash, version


def address_to_script_pubkey(address: str) -> bytes:
    """
    Return the locking script (scriptPubKey) for a P2PQH or P2HPQ address.

    P2PQH: OP_PQH(0xc0) push20(0x14) <hash> OP_EQUALVERIFY(0x88) OP_PQCHECKSIG(0xc1)
    P2HPQ: OP_PQH(0xc0) push20(0x14) <hash> OP_EQUALVERIFY(0x88) OP_HPQCHECKSIG(0xc2)
    """
    pubkey_hash, version = address_to_pubkey_hash(address)
    if version in (MAINNET_P2HPQ, TESTNET_P2HPQ):
        checksig_op = 0xc2   # OP_HPQCHECKSIG — verifies both ECDSA + ML-DSA
    else:
        checksig_op = 0xc1   # OP_PQCHECKSIG  — verifies ML-DSA only
    return bytes([0xc0, 0x14]) + pubkey_hash + bytes([0x88, checksig_op])


def is_hybrid_address(address: str) -> bool:
    """Return True if address is P2HPQ (hybrid), False if P2PQH (pure PQ)."""
    _, version = address_to_pubkey_hash(address)
    return version in (MAINNET_P2HPQ, TESTNET_P2HPQ)


def script_pubkey_repr(script: bytes) -> str:
    """Human-readable disassembly of a P2PQH or P2HPQ scriptPubKey."""
    if len(script) == 24 and script[0] == 0xc0 and script[1] == 0x14:
        hash_hex = script[2:22].hex()
        op = "OP_HPQCHECKSIG" if script[23] == 0xc2 else "OP_PQCHECKSIG"
        return f"OP_PQH OP_DATA_20 {hash_hex} OP_EQUALVERIFY {op}"
    return script.hex()
