#!/usr/bin/env python3
"""
bitcoin-pqc CLI

Commands:
  keygen    Generate a new key pair (pure PQ or hybrid)
  address   Derive address from a key file
  sign      Sign a message with a key
  verify    Verify a signed message
  info      Print key file metadata (no secrets)
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from .keys import PQKeyPair, HybridKeyPair, SecurityLevel, HybridSignature
from .address import pubkey_to_address, hybrid_pubkeys_to_address
from .hd import derive_keypair, seed_from_mnemonic
from .exceptions import BitcoinPQCError


def _level(s: str) -> SecurityLevel:
    mapping = {
        "44": SecurityLevel.ML_DSA_44,
        "65": SecurityLevel.ML_DSA_65,
        "87": SecurityLevel.ML_DSA_87,
    }
    if s not in mapping:
        raise argparse.ArgumentTypeError(f"Security level must be 44, 65, or 87 (got '{s}')")
    return mapping[s]


def _get_passphrase(prompt: str = "Passphrase: ", confirm: bool = False) -> str:
    pw = getpass.getpass(prompt)
    if confirm:
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw != pw2:
            print("Error: passphrases do not match.", file=sys.stderr)
            sys.exit(1)
    return pw


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------

def cmd_keygen(args: argparse.Namespace) -> None:
    level = args.level

    if args.mnemonic:
        mnemonic = input("Enter BIP-39 mnemonic: ").strip()
        seed = seed_from_mnemonic(mnemonic, args.mnemonic_passphrase or "")
        print(f"Deriving key at m/444'/{args.account}'/{args.index}'…", file=sys.stderr)
        kp = derive_keypair(seed, account=args.account, index=args.index, level=level)
        if args.hybrid:
            print("Warning: --mnemonic with --hybrid derives only the PQ component.", file=sys.stderr)
            key = kp
        else:
            key = kp
    elif args.hybrid:
        key = HybridKeyPair.generate(level)
    else:
        key = PQKeyPair.generate(level)

    if args.output:
        passphrase = _get_passphrase("Encryption passphrase: ", confirm=True)
        key.save_encrypted(args.output, passphrase)
        print(f"Encrypted key saved to {args.output}")
    else:
        print(json.dumps(key.to_dict(), indent=2))

    # Print address to stderr so it's always visible
    if isinstance(key, HybridKeyPair):
        addr = hybrid_pubkeys_to_address(key.ecdsa_public_key, key.pq_keypair.public_key, testnet=args.testnet)
        print(f"P2HPQ address: {addr}", file=sys.stderr)
    else:
        addr = pubkey_to_address(key.public_key, testnet=args.testnet)
        print(f"P2PQH address: {addr}", file=sys.stderr)


# ---------------------------------------------------------------------------
# address
# ---------------------------------------------------------------------------

def cmd_address(args: argparse.Namespace) -> None:
    passphrase = _get_passphrase() if args.encrypted else None
    try:
        if passphrase:
            try:
                key = HybridKeyPair.load_encrypted(args.keyfile, passphrase)
            except Exception:
                key = PQKeyPair.load_encrypted(args.keyfile, passphrase)
        else:
            try:
                key = HybridKeyPair.load(args.keyfile)
            except Exception:
                key = PQKeyPair.load(args.keyfile)
    except BitcoinPQCError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if isinstance(key, HybridKeyPair):
        addr = hybrid_pubkeys_to_address(key.ecdsa_public_key, key.pq_keypair.public_key, testnet=args.testnet)
        print(f"Type:    P2HPQ (hybrid ECDSA + ML-DSA)")
    else:
        addr = pubkey_to_address(key.public_key, testnet=args.testnet)
        print(f"Type:    P2PQH (pure ML-DSA)")
    print(f"Address: {addr}")
    print(f"Network: {'testnet' if args.testnet else 'mainnet'}")


# ---------------------------------------------------------------------------
# sign
# ---------------------------------------------------------------------------

def cmd_sign(args: argparse.Namespace) -> None:
    passphrase = _get_passphrase() if args.encrypted else None
    try:
        if passphrase:
            try:
                key = HybridKeyPair.load_encrypted(args.keyfile, passphrase)
            except Exception:
                key = PQKeyPair.load_encrypted(args.keyfile, passphrase)
        else:
            try:
                key = HybridKeyPair.load(args.keyfile)
            except Exception:
                key = PQKeyPair.load(args.keyfile)
    except BitcoinPQCError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    message = args.message.encode("utf-8") if args.message else sys.stdin.buffer.read()

    try:
        if isinstance(key, HybridKeyPair):
            sig = key.sign(message)
            result = sig.to_dict()
        else:
            sig_bytes = key.sign(message)
            result = {
                "type": "pq",
                "level": key.level.value,
                "mldsa_pubkey": key.public_key.hex(),
                "mldsa_sig": sig_bytes.hex(),
            }
    except BitcoinPQCError as exc:
        print(f"Signing error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

def cmd_verify(args: argparse.Namespace) -> None:
    try:
        with open(args.sigfile) as f:
            sig_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"Error reading signature file: {exc}", file=sys.stderr)
        sys.exit(1)

    message = args.message.encode("utf-8") if args.message else sys.stdin.buffer.read()

    from .keys import SecurityLevel, verify_mldsa
    try:
        if sig_data.get("type") == "pq" or "mldsa_sig" in sig_data and "ecdsa_sig" not in sig_data:
            level = SecurityLevel(sig_data["level"])
            pubkey = bytes.fromhex(sig_data["mldsa_pubkey"])
            sig = bytes.fromhex(sig_data["mldsa_sig"])
            valid = verify_mldsa(pubkey, message, sig, level)
        else:
            hs = HybridSignature.from_dict(sig_data)
            valid = hs.verify(message)
    except Exception as exc:
        print(f"Verification error: {exc}", file=sys.stderr)
        sys.exit(1)

    if valid:
        print("✓ Signature valid")
    else:
        print("✗ Signature INVALID", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

def cmd_info(args: argparse.Namespace) -> None:
    passphrase = _get_passphrase() if args.encrypted else None
    try:
        if passphrase:
            try:
                key = HybridKeyPair.load_encrypted(args.keyfile, passphrase)
            except Exception:
                key = PQKeyPair.load_encrypted(args.keyfile, passphrase)
        else:
            try:
                key = HybridKeyPair.load(args.keyfile)
            except Exception:
                key = PQKeyPair.load(args.keyfile)
    except BitcoinPQCError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if isinstance(key, HybridKeyPair):
        print(f"Type         : HybridKeyPair (ECDSA + ML-DSA)")
        print(f"Level        : {key.pq_keypair.level.value}")
        print(f"ECDSA pubkey : {key.ecdsa_public_key.hex()}")
        print(f"PQ pubkey    : {key.pq_keypair.public_key.hex()[:64]}…")
        print(f"Pubkey hash  : {key.pubkey_hash.hex()}")
        addr_main = hybrid_pubkeys_to_address(key.ecdsa_public_key, key.pq_keypair.public_key)
        addr_test = hybrid_pubkeys_to_address(key.ecdsa_public_key, key.pq_keypair.public_key, testnet=True)
    else:
        print(f"Type         : PQKeyPair (ML-DSA only)")
        print(f"Level        : {key.level.value}")
        print(f"PQ pubkey    : {key.public_key.hex()[:64]}…")
        print(f"Pubkey hash  : {key.pubkey_hash.hex()}")
        addr_main = pubkey_to_address(key.public_key)
        addr_test = pubkey_to_address(key.public_key, testnet=True)

    print(f"Mainnet addr : {addr_main}")
    print(f"Testnet addr : {addr_test}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bitcoin-pqc",
        description="Post-quantum cryptography toolkit for Bitcoin",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # keygen
    p_kg = sub.add_parser("keygen", help="Generate a new key pair")
    p_kg.add_argument("--hybrid", action="store_true", help="Generate hybrid ECDSA + ML-DSA key")
    p_kg.add_argument("--level", type=_level, default=SecurityLevel.ML_DSA_65, metavar="44|65|87")
    p_kg.add_argument("--output", "-o", metavar="FILE", help="Save encrypted key to FILE")
    p_kg.add_argument("--testnet", action="store_true")
    p_kg.add_argument("--mnemonic", action="store_true", help="Derive from BIP-39 mnemonic")
    p_kg.add_argument("--mnemonic-passphrase", default="", metavar="PASSPHRASE")
    p_kg.add_argument("--account", type=int, default=0)
    p_kg.add_argument("--index", type=int, default=0)

    # address
    p_addr = sub.add_parser("address", help="Print address for a key file")
    p_addr.add_argument("keyfile")
    p_addr.add_argument("--encrypted", "-e", action="store_true")
    p_addr.add_argument("--testnet", action="store_true")

    # sign
    p_sign = sub.add_parser("sign", help="Sign a message")
    p_sign.add_argument("keyfile")
    p_sign.add_argument("--message", "-m", help="Message string (omit to read from stdin)")
    p_sign.add_argument("--encrypted", "-e", action="store_true")

    # verify
    p_ver = sub.add_parser("verify", help="Verify a signature")
    p_ver.add_argument("sigfile", help="JSON signature file produced by 'sign'")
    p_ver.add_argument("--message", "-m", help="Message string (omit to read from stdin)")

    # info
    p_info = sub.add_parser("info", help="Display key file metadata")
    p_info.add_argument("keyfile")
    p_info.add_argument("--encrypted", "-e", action="store_true")

    args = parser.parse_args()

    dispatch = {
        "keygen": cmd_keygen,
        "address": cmd_address,
        "sign": cmd_sign,
        "verify": cmd_verify,
        "info": cmd_info,
    }

    try:
        dispatch[args.command](args)
    except BitcoinPQCError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
