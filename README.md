# bitcoin-pqc

Post-quantum cryptography for Bitcoin. Implements hybrid **ECDSA + ML-DSA (CRYSTALS-Dilithium)** signing, two new address types, HD key derivation from BIP-39 mnemonics, and AES-256-GCM encrypted key storage.

Includes a draft BIP proposal for **P2PQH** and **P2HPQ** output types.

---

## The approach

Bitcoin's ECDSA over secp256k1 is broken by Shor's algorithm on a sufficiently large quantum computer. The question is when, not if.

This library uses the same hybrid strategy as **Apple PQ3** and **Signal PQXDH**: run a classical and a post-quantum algorithm in parallel, and require *both* to verify. A quantum break alone doesn't compromise security. Neither does a classical break. An attacker has to break both simultaneously.

The post-quantum algorithm is **ML-DSA** (CRYSTALS-Dilithium, [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)).

---

## Features

| | |
|---|---|
| **Hybrid signing** | secp256k1 ECDSA + ML-DSA — both must verify to spend |
| **Pure PQ signing** | ML-DSA only, for fully post-quantum outputs |
| **Two address types** | P2PQH (pure PQ) and P2HPQ (hybrid) |
| **HD key derivation** | Deterministic PQ keys from a BIP-39 mnemonic via HKDF |
| **Encrypted storage** | AES-256-GCM + PBKDF2 (600k iterations) |
| **Transaction engine** | Build, sign, verify, compute TXID |
| **CLI** | keygen, address, sign, verify, info |
| **BIP draft** | Full specification with proposed opcodes |

---

## Install

```bash
git clone https://github.com/glaseagle/bitcoin-pqc
cd bitcoin-pqc
pip install dilithium-py coincurve cryptography pycryptodome
```

---

## Quick start

### Generate a hybrid key

```python
from bitcoin_pqc import HybridKeyPair, SecurityLevel, hybrid_pubkeys_to_address

kp = HybridKeyPair.generate(SecurityLevel.ML_DSA_65)
addr = hybrid_pubkeys_to_address(kp.ecdsa_public_key, kp.pq_keypair.public_key)
print(addr)
```

### Save encrypted / load

```python
kp.save_encrypted("my_key.enc.json", passphrase="correct-horse-battery")
kp2 = HybridKeyPair.load_encrypted("my_key.enc.json", passphrase="correct-horse-battery")
```

### Derive from a BIP-39 mnemonic

```python
from bitcoin_pqc.hd import derive_keypair, seed_from_mnemonic

seed = seed_from_mnemonic("abandon abandon ... about")
kp = derive_keypair(seed, account=0, index=0)   # deterministic, same seed → same key
```

### Sign and verify a transaction

```python
from bitcoin_pqc.transaction import PQTransaction
from bitcoin_pqc import sign_transaction, verify_transaction

tx = PQTransaction()
tx.add_input("a" * 64, 0)
tx.add_output(49_900_000, addr)

sign_transaction(tx, [kp])
print(verify_transaction(tx))   # True
print(tx.txid())
```

---

## CLI

```bash
# Generate a hybrid key pair, save encrypted
python -m bitcoin_pqc.cli keygen --hybrid --output key.enc.json

# Print address for a key file
python -m bitcoin_pqc.cli address key.enc.json --encrypted

# Sign a message
python -m bitcoin_pqc.cli sign key.enc.json --message "hello" --encrypted > sig.json

# Verify a signature
python -m bitcoin_pqc.cli verify sig.json --message "hello"

# Print key metadata (no secrets shown)
python -m bitcoin_pqc.cli info key.enc.json --encrypted
```

---

## Address types

### P2HPQ — Pay to Hybrid Post-Quantum Hash (recommended)

```
address  = Base58Check( 0x31 || RIPEMD160(SHA256(ecdsa_pubkey || mldsa_pubkey)) )
scriptPubKey = OP_PQH <20> <hash> OP_EQUALVERIFY OP_HPQCHECKSIG
scriptSig    = <ecdsa_sig> <ecdsa_pubkey> <mldsa_sig> <mldsa_pubkey>
```

Spending requires valid ECDSA **and** valid ML-DSA signatures. Either algorithm alone is not sufficient.

### P2PQH — Pay to Post-Quantum Hash (pure PQ)

```
address  = Base58Check( 0x30 || RIPEMD160(SHA256(mldsa_pubkey)) )
scriptPubKey = OP_PQH <20> <hash> OP_EQUALVERIFY OP_PQCHECKSIG
scriptSig    = <mldsa_sig> <mldsa_pubkey>
```

ML-DSA only. Fully quantum-resistant but drops classical ECDSA protection.

---

## Key storage

Key files are AES-256-GCM encrypted with a passphrase-derived key (PBKDF2-SHA256, 600,000 iterations). The file contains only: KDF parameters, salt, nonce, and opaque ciphertext. No readable key material is present.

```json
{
  "version": 1,
  "kdf": "pbkdf2-sha256",
  "iterations": 600000,
  "salt": "...",
  "nonce": "...",
  "ciphertext": "..."
}
```

---

## HD derivation

PQ keys are derived deterministically from a master seed using chained HKDF-SHA512 with a `bitcoin-pqc-hd-v1` domain separator, then fed into dilithium-py's AES-256-CTR DRBG for key generation. Path notation: `m / 444' / account' / index`.

Same seed + same path = same key pair, every time.

---

## Security levels

| Level | Parameter set | Public key | Signature | NIST level |
|---|---|---|---|---|
| `ML_DSA_44` | Dilithium2 | 1,312 B | 2,420 B | 2 |
| `ML_DSA_65` | Dilithium3 | 1,952 B | 3,293 B | 3 ← recommended |
| `ML_DSA_87` | Dilithium5 | 2,592 B | 4,595 B | 5 |

---

## Witness size vs ECDSA

| Scheme | Public key | Signature | Total |
|---|---|---|---|
| secp256k1 ECDSA | 33 B | 72 B | 107 B |
| ML-DSA-65 (pure PQ) | 1,952 B | 3,293 B | 5,245 B |
| Hybrid (ECDSA + ML-DSA-65) | 1,985 B | 3,365 B | 5,350 B |
| Falcon-512 (future) | 897 B | 666 B | 1,563 B |

Hybrid adds ~105 bytes over pure ML-DSA. The size increase over ECDSA (~50×) is the cost of quantum resistance with current NIST algorithms.

---

## vs Apple PQ3 / Signal

| | Apple PQ3 | Signal PQXDH | bitcoin-pqc |
|---|---|---|---|
| Algorithm | ML-KEM-1024 | ML-KEM-1024 | ML-DSA-65 |
| Type | Key encapsulation | Key encapsulation | Digital signature |
| Hybrid with | X25519 | X25519 | secp256k1 ECDSA |
| Protects | Message confidentiality | Message confidentiality | Spending authorisation |
| NIST standard | FIPS 203 | FIPS 203 | FIPS 204 |

Apple and Signal use ML-KEM (Kyber) because they need to protect encryption keys. Bitcoin needs signatures to authorise spending, which requires ML-DSA (Dilithium). Both are from the CRYSTALS suite, built on the same lattice math.

---

## Run tests

```bash
python -m unittest discover tests/ -v
# 49 tests, all passing
```

---

## BIP draft

[BIP-DRAFT.md](BIP-DRAFT.md) — full specification covering P2PQH and P2HPQ output types, proposed opcode assignments (`OP_PQH` 0xc0, `OP_PQCHECKSIG` 0xc1, `OP_HPQCHECKSIG` 0xc2), sighash construction, and security analysis.

---

## Status

Research / proof-of-concept. The cryptography is real and all tests pass end-to-end. These transactions cannot be broadcast to the live Bitcoin network — that requires a soft fork to add the new opcodes. Intended to inform discussion around a post-quantum Bitcoin upgrade path.

---

## Dependencies

| Package | Purpose |
|---|---|
| `dilithium-py` | ML-DSA (CRYSTALS-Dilithium) implementation |
| `coincurve` | secp256k1 ECDSA (hybrid signing) |
| `cryptography` | AES-256-GCM, PBKDF2, HKDF |
| `pycryptodome` | AES-CTR DRBG (for HD deterministic keygen) |

---

## License

MIT
