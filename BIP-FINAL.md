```
BIP: XXX
Layer: Consensus (soft fork)
Title: Post-Quantum Output Types using ML-DSA (SegWit version 2)
Author: [author]
Comments-Summary: No comments yet
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-XXX
Status: Draft
Type: Standards Track
Created: 2026-04-01
License: BSD-2-Clause
Post-History: https://github.com/glaseagle/bitcoin-pqc
```

---

## Abstract

This BIP defines two new output types using SegWit version 2 that replace ECDSA with post-quantum signature schemes standardised by NIST:

- **P2PQH** (Pay to Post-Quantum Hash) — ML-DSA only
- **P2HPQ** (Pay to Hybrid Post-Quantum Hash) — secp256k1 ECDSA **and** ML-DSA, both required

Both output types commit to a 20-byte hash of the authorising public key(s). Spending reveals the full key(s) and signatures. The cryptographic scheme is **ML-DSA** (CRYSTALS-Dilithium, NIST FIPS 204, 2024), at security level ML-DSA-65 (NIST Level 3, ~AES-192 classical security).

---

## Motivation

Bitcoin's ECDSA over secp256k1 is vulnerable to Shor's algorithm on a cryptographically relevant quantum computer (CRQC). Current estimates for CRQC availability range from 10 to 20 years, but the threat manifests earlier:

1. **Harvest now, decrypt later** does not apply to Bitcoin signatures (signatures are ephemeral, not encrypted data), but:
2. **Exposed public keys** on-chain — P2PKH outputs after first spend, all P2PK outputs, most Taproot key-path spends — are vulnerable the moment a CRQC exists. Funds cannot be moved faster than a CRQC can forge the authorising signature.

The migration window is finite. Activating post-quantum output types now allows wallet authors, exchanges, and custodians to migrate funds to quantum-safe addresses while ECDSA remains secure.

### Why hybrid (P2HPQ)?

During the transition period, neither algorithm family should be trusted unconditionally:

- ML-DSA is new. Implementation flaws or unforeseen weaknesses are possible.
- ECDSA is well-understood but quantum-vulnerable.

Requiring both (as Apple PQ3 and Signal PQXDH do for messaging) means an attacker must break both simultaneously. A pure-PQ output (P2PQH) is provided for deployments that accept the trade-off of dropping ECDSA entirely.

### Why ML-DSA?

- NIST FIPS 204 (August 2024) — final standard, not draft.
- Lattice-based (Module-LWE), with 15+ years of public cryptanalysis.
- Deterministic signing (unlike ECDSA, no per-signature randomness required).
- Constant-time implementations are well-understood.
- Falcon-512 (NIST FIPS 206) produces smaller signatures (666 B vs 3,293 B) but requires floating-point Gaussian sampling, making constant-time implementation significantly harder. A future BIP may add Falcon support once constant-time implementations are more widely audited.

---

## Specification

### Notation

- `||` — byte concatenation
- `H(x)` — SHA-256(x)
- `H2(x)` — SHA-256(SHA-256(x))
- `HASH160(x)` — RIPEMD-160(SHA-256(x))
- `LE32(n)` — 32-bit little-endian encoding of integer n
- `LE64(n)` — 64-bit little-endian encoding of integer n
- All multi-byte integers are little-endian unless stated otherwise

### ML-DSA parameters

This BIP mandates **ML-DSA-65** (Dilithium3) exclusively. Higher security levels (ML-DSA-87) produce larger witnesses with limited practical benefit. Lower levels (ML-DSA-44) are excluded to ensure long-term security margin.

| Parameter | Value |
|-----------|-------|
| q         | 8,380,417 |
| n         | 256 |
| k         | 6 |
| l         | 5 |
| η         | 4 |
| d         | 13 |
| τ         | 49 |
| γ₁        | 2¹⁹ |
| γ₂        | (q−1)/32 |
| β         | 196 |
| ω         | 55 |
| λ         | 256 |
| Public key size  | 1,952 bytes |
| Secret key size  | 4,000 bytes |
| Signature size   | 3,293 bytes |

All values as specified in NIST FIPS 204, Table 2, parameter set ML-DSA-65.

### SegWit version 2

P2PQH and P2HPQ outputs use **witness version 2**, encoded as:

```
scriptPubKey = OP_2 <2-byte witness program>
```

The 2-byte witness program encodes both the output type and the 20-byte pubkey hash:

```
witness_program[0]    = type byte: 0x01 (P2PQH) or 0x02 (P2HPQ)
witness_program[1..20] = HASH160(pubkey_material)  [20 bytes, see below]
```

Total scriptPubKey length: 23 bytes. This is non-standard under current rules; the soft fork makes it standard and consensus-enforced.

**Why SegWit v2 and not Tapscript?**
Tapscript (BIP 342) uses `OP_SUCCESSx` for future opcode assignments, but those assignments require a Taproot commitment. Routing PQ outputs through Taproot would add unnecessary complexity (key tweaking, Merkle path) and prevent the 20-byte hash commitment that hides the PQ public key before first spend. SegWit v2 provides a clean namespace with the same malleability fixes as SegWit v1.

### Address encoding

P2PQH and P2HPQ addresses use **Bech32m** (BIP 350) with the existing `bc` human-readable part and witness version 2.

```
P2PQH address = bech32m("bc", 2, 0x01 || HASH160(mldsa_pubkey))
P2HPQ address = bech32m("bc", 2, 0x02 || HASH160(ecdsa_pubkey || mldsa_pubkey))
```

Testnet uses `tb` as the human-readable part.

### Pubkey commitments

**P2PQH:**
```
pubkey_material  = mldsa_pubkey              (1,952 bytes)
commitment       = HASH160(mldsa_pubkey)     (20 bytes)
```

**P2HPQ:**
```
pubkey_material  = ecdsa_pubkey || mldsa_pubkey    (33 + 1,952 = 1,985 bytes)
commitment       = HASH160(ecdsa_pubkey || mldsa_pubkey)  (20 bytes)
```

The 20-byte hash hides the full public key until the first spend, preserving quantum safety for unspent outputs. After a spend, the output is consumed — the revealed public key no longer controls funds.

### Witness structure

Witnesses are structured as a stack of items, consistent with SegWit conventions.

**P2PQH witness (2 stack items):**
```
stack[0] = mldsa_signature    (3,293 bytes)
stack[1] = mldsa_pubkey       (1,952 bytes)
```

**P2HPQ witness (4 stack items):**
```
stack[0] = ecdsa_signature    (≤72 bytes, DER-encoded)
stack[1] = ecdsa_pubkey       (33 bytes, compressed)
stack[2] = mldsa_signature    (3,293 bytes)
stack[3] = mldsa_pubkey       (1,952 bytes)
```

### Sighash

The message signed by both ECDSA and ML-DSA is:

```
sighash = H2(
    LE32(nVersion)    ||
    hashPrevouts      ||
    hashSequences     ||
    outpoint          ||
    LE64(amount)      ||
    LE32(nSequence)   ||
    hashOutputs       ||
    LE32(nLocktime)   ||
    sighash_type      ||
    witness_program
)
```

Where:

- `hashPrevouts` = H2(concatenation of all outpoints in the transaction)
- `hashSequences` = H2(concatenation of all nSequence fields)
- `hashOutputs` = H2(concatenation of all serialised outputs)
- `outpoint` = txid (32 bytes, LE) || vout (4 bytes, LE) of the input being signed
- `amount` = value of the UTXO being spent (satoshis)
- `witness_program` = the full 21-byte witness program (type byte + 20-byte hash)
- `sighash_type` = 1 byte, currently only `0x01` (SIGHASH_ALL) is defined

This construction commits to all transaction data relevant to the input being signed, preventing transaction malleability and cross-input signature replay.

### Signature encoding

**ML-DSA signature:** Raw bytes as specified in FIPS 204 §7.3 (ML-DSA.Sign output). No additional encoding. Length must be exactly 3,293 bytes.

**ECDSA signature (P2HPQ only):** DER-encoded, with the sighash type byte appended (as in existing P2WPKH). Length must be 71–73 bytes. Only `SIGHASH_ALL` (0x01) is defined for this BIP.

### Validation rules

Nodes enforce the following for inputs spending P2PQH or P2HPQ outputs:

**Common:**
1. The witness program type byte must be 0x01 (P2PQH) or 0x02 (P2HPQ).
2. The commitment in the witness program must equal `HASH160(pubkey_material)` as defined above.

**P2PQH:**
3. Witness stack must have exactly 2 items.
4. `stack[1]` (mldsa_pubkey) must be exactly 1,952 bytes.
5. `stack[0]` (mldsa_signature) must be exactly 3,293 bytes.
6. `ML-DSA.Verify(mldsa_pubkey, sighash, mldsa_signature)` must return 1.

**P2HPQ:**
3. Witness stack must have exactly 4 items.
4. `stack[3]` (mldsa_pubkey) must be exactly 1,952 bytes.
5. `stack[2]` (mldsa_signature) must be exactly 3,293 bytes.
6. `stack[1]` (ecdsa_pubkey) must be exactly 33 bytes (compressed, 0x02 or 0x03 prefix).
7. `stack[0]` (ecdsa_signature) must be 71–73 bytes, DER-encoded, with sighash type byte.
8. `ML-DSA.Verify(mldsa_pubkey, sighash, mldsa_signature)` must return 1.
9. `secp256k1.Verify(ecdsa_pubkey, H2(sighash), ecdsa_signature[:-1])` must return 1.
   (The sighash type byte is stripped before ECDSA verification.)
10. Both verifications must pass. Failure of either is script failure.

### Weight / virtual size

To avoid economically discouraging quantum-resistant outputs, this BIP defines a **witness discount** for ML-DSA witness data:

- ML-DSA signature bytes (3,293 bytes per input): weight factor **1** (same as existing SegWit witness data)
- ML-DSA public key bytes (1,952 bytes per input): weight factor **1**

This is identical to the existing SegWit witness discount (witness data counts at 1/4 weight vs non-witness data). No additional discount beyond what SegWit already provides is proposed, to avoid creating perverse incentives.

Virtual size of a typical 1-input, 2-output P2HPQ transaction:
```
Non-witness:  10 (overhead) + 41 (input) + 2×31 (outputs) = 113 bytes → 452 weight
Witness:      4 (stack items) + 33 + 72 + 1952 + 3293 = 5,354 bytes → 5,354 weight
Total weight: 5,806 → ~1,452 vbytes
```

Compare to P2WPKH: ~110 vbytes. The ~13× size increase is the cost of quantum resistance with ML-DSA-65.

### Script failure conditions

The following conditions cause script failure (the transaction is invalid):

- Witness stack has wrong number of items
- Public key is wrong length
- Signature is wrong length
- Commitment mismatch (revealed key doesn't hash to the committed value)
- ML-DSA verification failure
- ECDSA verification failure (P2HPQ only)
- Any sighash type byte other than 0x01

### Standardness

Transactions spending P2PQH and P2HPQ outputs are **standard** after this BIP activates. The existing `IsStandard()` checks are extended to permit:

- Witness version 2 output scripts of length 23 bytes
- Witness stacks of 2 items (P2PQH) or 4 items (P2HPQ) within weight limits

Maximum witness item sizes: 3,293 bytes (ML-DSA signature), 1,952 bytes (ML-DSA pubkey). These exceed the current 520-byte push limit, which is extended for SegWit v2 inputs only.

---

## Activation

Activation follows the **Speedy Trial** mechanism (as used for Taproot, BIP 341):

- Signal: bit 2 of `nVersion` (unused since Taproot used bit 2; adjust as needed)
- Start time: TBD (first retarget period after community consensus)
- Timeout: 1 year after start
- Threshold: 90% of blocks in a 2,016-block retarget period
- Minimum activation height: 6 retarget periods after lock-in (~12 weeks)

---

## Rationale

### Why not add opcodes to Tapscript?

BIP 342 defines `OP_SUCCESSx` opcodes that script within Taproot leaves can use for future upgrades. This was considered and rejected for three reasons:

1. ML-DSA public keys (1,952 bytes) would require non-standard push sizes in existing Tapscript, complicating implementation.
2. Taproot key-path spends expose the internal key on-chain. For a PQ upgrade, we specifically want to avoid on-chain key exposure until first spend.
3. A clean SegWit v2 namespace is simpler to implement, audit, and reason about than Tapscript extensions.

### Why HASH160 (20 bytes) and not SHA256 (32 bytes)?

20-byte commitments are used for consistency with existing P2PKH/P2WPKH address types. The 20-byte HASH160 is not a quantum vulnerability: it commits to the public key before spend, and the quantum attack target is the public key (Shor's algorithm), not the hash preimage (which requires a different, much harder attack). Post-spend, the UTXO is consumed.

If the output is never spent (e.g., dust), a 20-byte preimage attack would require ~2⁸⁰ operations classically — acceptable for the threat model.

### Why is ML-DSA-44 excluded?

ML-DSA-44 provides NIST Level 2 security (~AES-128). Given that Bitcoin UTXOs may remain unspent for decades, and quantum computing capabilities may improve faster than expected, Level 3 (ML-DSA-65, ~AES-192) provides a more comfortable margin. The additional 640 bytes per witness is acceptable.

### Why is Falcon-512 not included?

Falcon-512 (FIPS 206) produces significantly smaller signatures (666 bytes vs 3,293 bytes) but its signing algorithm requires sampling from a discrete Gaussian distribution over a lattice, which is notoriously difficult to implement in constant time. Multiple side-channel vulnerabilities have been demonstrated in Falcon implementations. Until robust, widely-audited constant-time implementations exist for all common platforms, Falcon is excluded. A follow-on BIP may add Falcon once that bar is met.

---

## Test vectors

### ML-DSA-65 key pair

```
seed (32 bytes):
  000102030405060708090a0b0c0d0e0f
  101112131415161718191a1b1c1d1e1f

public_key (first 64 bytes of 1,952):
  [see reference implementation KAT vectors, NIST PQC submission round 3]

sighash (32 bytes):
  e3b0c44298fc1c149afbf4c8996fb924
  27ae41e4649b934ca495991b7852b855
```

Full KAT vectors are provided in the accompanying `test/data/mldsa65_kat.bin` file (NIST format), consistent with the FIPS 204 reference implementation test vectors.

### P2PQH address derivation

```
mldsa_pubkey: [1,952-byte key from KAT vector #1]
SHA256(mldsa_pubkey):
  [32-byte intermediate hash]
RIPEMD160(SHA256(mldsa_pubkey)):
  [20-byte pubkey hash]
witness_program:
  01 || [20-byte pubkey hash]
bech32m address (mainnet):
  bc1z[...]
```

### Transaction sighash

```
nVersion:      02000000
hashPrevouts:  [32 bytes]
hashSequences: [32 bytes]
outpoint:      [36 bytes]
amount:        [8 bytes, satoshis]
nSequence:     [4 bytes]
hashOutputs:   [32 bytes]
nLocktime:     [4 bytes]
sighash_type:  01
witness_program: 01[20-byte hash]

sighash = H2(above concatenation)
```

---

## Backwards compatibility

- Nodes that do not implement this BIP see witness version 2 outputs as **anyone-can-spend** under BIP 141 rule §6 ("unknown witness versions"). This is the same mechanism used for Taproot's initial deployment.
- After activation, upgraded nodes enforce the new rules. Old nodes continue to accept the transactions (they see valid-looking SegWit v2 inputs) but do not enforce PQ signature validity. This is the standard soft-fork safety property.
- No changes to P2PKH, P2WPKH, P2SH, P2WSH, P2TR, or any existing output type.

---

## Security

### Quantum security of unspent outputs

An unspent P2PQH or P2HPQ output reveals only `HASH160(pubkey_material)`. A CRQC cannot reverse RIPEMD-160∘SHA-256 to recover the public key — hash preimage attacks are not accelerated by Grover's algorithm enough to threaten 160-bit hashes in practice (Grover provides ~2⁸⁰ query complexity, not polynomial time).

### Classical security

ML-DSA-65 provides EUF-CMA security under the Module-LWE and Module-SIS hardness assumptions. The best known classical attacks require exponential time. Security reduction to the underlying problems is proven in the CRYSTALS-Dilithium paper.

### Hybrid security (P2HPQ)

The P2HPQ scheme is secure if at least one of ECDSA or ML-DSA is secure. Formally: an adversary that can forge a P2HPQ spending witness must forge both an ECDSA signature and an ML-DSA signature on the same sighash. No known attack achieves this without breaking both independently.

### Implementation requirements

ML-DSA implementations used in consensus validation MUST be constant-time with respect to all secret data. Variable-time implementations risk side-channel attacks in signing (not verification), but constant-time verification is still required to prevent timing-based validity oracles.

The reference implementation in `src/crypto/mldsa/` accompanying this BIP is written to be constant-time on platforms that compile with standard C11 without optimisations that eliminate data-dependent branches. Implementors MUST validate constant-time behaviour on their target platform.

---

## Reference implementation

https://github.com/glaseagle/bitcoin-pqc (Python prototype)

The Bitcoin Core C++ implementation is provided in the `core/src/` directory of the above repository. It includes:

- `src/crypto/mldsa/` — self-contained ML-DSA-65 implementation (no external dependencies)
- `src/script/interpreter_pqc.cpp` — consensus-critical opcode handlers
- `src/script/script_pqc.h` — constants and type definitions
- `src/policy/policy_pqc.cpp` — standardness rules
- `src/test/mldsa_tests.cpp` — unit tests against NIST KAT vectors
- `src/test/script_pqc_tests.cpp` — script validation tests

---

## Acknowledgements

- CRYSTALS-Dilithium team: Léo Ducas, Eike Kiltz, Tancrède Lepoint, Vadim Lyubashevsky, Peter Schwabe, Gregor Seiler, Damien Stehlé
- NIST Post-Quantum Cryptography Standardisation project
- Bitcoin Core developers for the BIP infrastructure and SegWit/Taproot precedents (BIP 141, 340, 341, 342)

---

## Copyright

This BIP is licensed under the BSD 2-Clause licence.
