# BIP Draft: Post-Quantum Signatures for Bitcoin (P2PQH)

```
BIP:     TBD
Title:   Pay to Post-Quantum Hash (P2PQH) using ML-DSA
Author:  [author]
Status:  Draft
Type:    Standards Track
Created: 2026-03-31
```

---

## Abstract

This BIP defines a new output type, **Pay to Post-Quantum Hash (P2PQH)**, that uses
**ML-DSA** (CRYSTALS-Dilithium, NIST FIPS 204) instead of ECDSA for transaction
authorization. P2PQH outputs are quantum-resistant: a cryptographically relevant
quantum computer (CRQC) cannot forge signatures or recover private keys from
public keys exposed in spent outputs.

---

## Motivation

Bitcoin's current signature scheme — ECDSA over secp256k1 — is broken by
Shor's algorithm running on a sufficiently large quantum computer.
Estimates for when CRQCs may become practical range from 10–20 years, but
the migration window is shorter: any UTXO whose public key is already on-chain
(P2PKH, P2WPKH after first spend, Taproot key-path spends) is vulnerable
the moment a CRQC exists.

A forward-compatible output type that uses a NIST-standardised post-quantum
signature algorithm allows wallet authors and exchanges to begin migrating funds
before quantum adversaries become practical.

---

## Specification

### Signature Algorithm

**ML-DSA-65** (parameter set corresponding to Dilithium3, NIST security level 3,
roughly equivalent to AES-192) is the default. ML-DSA-44 and ML-DSA-87 are
also valid.

| Parameter Set | PK size  | Sig size | NIST Level |
|---------------|----------|----------|------------|
| ML-DSA-44     | 1,312 B  | 2,420 B  | 2          |
| ML-DSA-65     | 1,952 B  | 3,293 B  | 3          |
| ML-DSA-87     | 2,592 B  | 4,595 B  | 5          |

### Address Format

```
P2PQH address = Base58Check( 0x30 || RIPEMD160(SHA256(ml_dsa_pubkey)) )
```

- Version byte `0x30` (mainnet).  Testnet uses `0x6F`.
- The 20-byte hash commitment hides the full public key until first spend,
  preserving quantum safety for unspent outputs.

### Locking Script (scriptPubKey)

```
OP_PQH <20> <pubkey_hash> OP_EQUALVERIFY OP_PQCHECKSIG
```

Proposed new opcodes:

| Opcode           | Byte | Description                                                  |
|------------------|------|--------------------------------------------------------------|
| `OP_PQH`         | 0xc0 | Pop a PQ public key, push RIPEMD160(SHA256(key))             |
| `OP_PQCHECKSIG`  | 0xc1 | Pop sig + pubkey, verify ML-DSA sig against sighash; push 1/0|

### Unlocking Script (scriptSig)

```
<ml_dsa_signature>  <ml_dsa_public_key>
```

Items are length-prefixed with standard Bitcoin varint encoding.

### Sighash

```
sighash = SHA256(SHA256( serialised_tx_without_scriptsigs ))
```

Identical to legacy sighash SIGHASH_ALL, applied to the full transaction body
with all scriptSigs set to empty for the pre-image.

### Signature Encoding

Raw ML-DSA signature bytes are pushed directly; no DER encoding is used.

---

## Security Considerations

### Quantum Safety of Unspent Outputs

An unspent P2PQH output reveals only a 20-byte hash of the public key.  A CRQC
cannot reverse RIPEMD160∘SHA256 to recover the public key, so unspent outputs
are safe even after large quantum computers exist.

After the first spend (when the public key is revealed in scriptSig), the output
is consumed — the revealed public key is no longer controlling any funds.

### Classical Security

ML-DSA-65 provides roughly 128 bits of classical security against forgery
(EUF-CMA). It is not known to be vulnerable to any classical attack faster
than generic.

### Migration Window

Legacy P2PKH / P2WPKH outputs whose public keys are already on-chain are
vulnerable once CRQCs appear.  Wallets should sweep such outputs to P2PQH
addresses proactively.

### Witness Size Impact

ML-DSA signatures are ~45× larger than ECDSA signatures. At ML-DSA-65, each
input witness is approximately 5,245 bytes. This increases transaction fees and
block space consumption. Future optimisations (Falcon-512 at 1,563 bytes total,
or aggregated signatures) can reduce this overhead.

---

## Compatibility

- Nodes that do not implement this BIP treat P2PQH outputs as `anyone-can-spend`
  (unrecognised script type), consistent with existing behaviour for non-standard
  scripts. Activation via a soft-fork (similar to SegWit) is recommended to add
  consensus-level enforcement.
- No changes to P2PKH, P2WPKH, P2TR, or any existing output type.

---

## Reference Implementation

https://github.com/glaseagle/bitcoin-pqc

---

## Acknowledgements

- CRYSTALS-Dilithium team (Ducas et al.)
- NIST Post-Quantum Cryptography Standardisation project
- Bitcoin Core developers for BIP infrastructure
