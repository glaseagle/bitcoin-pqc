# bitcoin-pqc

Post-quantum cryptography for Bitcoin — a Python implementation of **ML-DSA (CRYSTALS-Dilithium)** based key generation, address derivation, transaction signing, and verification.

Includes a draft BIP proposal for **P2PQH (Pay to Post-Quantum Hash)**, a new output type analogous to P2PKH but quantum-resistant.

---

## Why

Bitcoin's ECDSA / secp256k1 is broken by Shor's algorithm on a sufficiently large quantum computer. This library provides a concrete, runnable proof-of-concept for what a post-quantum upgrade path could look like, using [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA, formerly CRYSTALS-Dilithium) as the signature scheme.

---

## Quick start

```bash
git clone https://github.com/glaseagle/bitcoin-pqc
cd bitcoin-pqc
pip install dilithium-py
python examples/demo.py
```

---

## What's inside

| Module | Description |
|--------|-------------|
| `bitcoin_pqc/keys.py` | ML-DSA key pair generation, signing, verification |
| `bitcoin_pqc/address.py` | P2PQH address derivation (Base58Check) and script encoding |
| `bitcoin_pqc/transaction.py` | Transaction construction, signing, and verification |
| `bitcoin_pqc/migration.py` | ECDSA → ML-DSA migration planning helpers |
| `BIP-DRAFT.md` | Full BIP-style specification for P2PQH |

---

## Usage

### Generate a key pair

```python
from bitcoin_pqc import PQKeyPair, SecurityLevel

kp = PQKeyPair.generate(SecurityLevel.ML_DSA_65)
print(f"Public key  : {len(kp.public_key)} bytes")
print(f"Pubkey hash : {kp.pubkey_hash.hex()}")
```

### Derive a P2PQH address

```python
from bitcoin_pqc import pubkey_to_address

addr = pubkey_to_address(kp.public_key)
print(addr)  # e.g. QmXk...
```

### Sign and verify a transaction

```python
from bitcoin_pqc.transaction import PQTransaction
from bitcoin_pqc import sign_transaction, verify_transaction

tx = PQTransaction()
tx.add_input("a" * 64, 0)          # prev txid, output index
tx.add_output(49_900_000, addr)     # satoshis, destination

sign_transaction(tx, [kp])
print(verify_transaction(tx))       # True
print(tx.txid())
```

### Save / load keys

```python
kp.save("my_pq_key.json")
kp2 = PQKeyPair.load("my_pq_key.json")
```

---

## Security levels

| Level | Parameter set | Public key | Signature | NIST level |
|-------|--------------|-----------|-----------|------------|
| `ML_DSA_44` | Dilithium2 | 1,312 B | 2,420 B | 2 |
| `ML_DSA_65` | Dilithium3 | 1,952 B | 3,293 B | 3 ← recommended |
| `ML_DSA_87` | Dilithium5 | 2,592 B | 4,595 B | 5 |

---

## Size trade-offs vs ECDSA

| Scheme | Public key | Signature | Total witness |
|--------|-----------|-----------|---------------|
| secp256k1 ECDSA | 33 B | 72 B | 107 B |
| ML-DSA-44 | 1,312 B | 2,420 B | 3,732 B |
| ML-DSA-65 | 1,952 B | 3,293 B | 5,245 B |
| ML-DSA-87 | 2,592 B | 4,595 B | 7,187 B |
| Falcon-512 | 897 B | 666 B | 1,563 B |

---

## Run the demo

```
python examples/demo.py
```

Output includes key generation, address derivation, a signed transaction, verification (including tamper detection), size comparisons, and a migration plan.

---

## Run tests

```bash
python -m pytest tests/ -v
# or
python -m unittest discover tests/
```

---

## BIP Draft

See [BIP-DRAFT.md](BIP-DRAFT.md) for the full specification of the proposed P2PQH output type, including script encoding, sighash construction, proposed opcodes, and security analysis.

---

## Requirements

- Python ≥ 3.9
- [dilithium-py](https://github.com/GiacomoPope/dilithium-py) ≥ 1.4.0

```bash
pip install dilithium-py
```

---

## Status

Research / proof-of-concept. Not for production use. Intended to inform discussion around post-quantum Bitcoin upgrades.

---

## License

MIT
