BIP: (to be assigned)
Layer: Consensus (soft fork)
Title: Post-Quantum Hybrid Signatures for Bitcoin (P2PQH and P2HPQ)
Author: Michael Culleton <michaelculleton@mac.com>
Comments-Summary: No comments yet
Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-???
Status: Draft
Type: Standards Track
Created: 2026-04-04
License: BSD-2-Clause
Post-History: (to be added after mailing list post)
Requires: 141 (SegWit), 173 (bech32)

## Abstract

This BIP defines two new SegWit version 2 output types that replace or augment secp256k1 ECDSA with the NIST-standardized post-quantum signature scheme ML-DSA-65:

- **P2PQH** (Pay to Post-Quantum Hash), which requires ML-DSA only.
- **P2HPQ** (Pay to Hybrid Post-Quantum Hash), which requires both secp256k1 ECDSA and ML-DSA.

Both output types commit to a 20-byte hash of the authorizing public key material and reveal the full public key material only when spent. The scheme uses ML-DSA-65 (CRYSTALS-Dilithium / NIST FIPS 204) at NIST Level 3 security.

## Motivation

Bitcoin's existing secp256k1 ECDSA signatures are vulnerable to Shor's algorithm on a cryptographically relevant quantum computer. The main risk is not encrypted historical data but on-chain public key exposure: once a spend reveals a public key, a sufficiently capable quantum adversary can attempt to forge an authorizing signature before funds are moved again. Some output types already expose keys on-chain immediately, and P2PKH-style constructions expose them at first spend.

Adding post-quantum output types before a cryptographically relevant quantum computer exists creates a migration path while ECDSA remains operationally secure. Wallets, exchanges, and custodians can move funds into outputs whose public keys remain hidden behind a hash commitment until spend.

The hybrid construction is included because transition risk is two-sided. ECDSA is mature but quantum-vulnerable. ML-DSA is standardized and well studied, but newer in deployed Bitcoin systems. Requiring both signatures means an attacker must break both schemes at once. A pure post-quantum form is still provided for users who want to eliminate ECDSA dependence entirely.

ML-DSA-65 is selected because it is standardized in NIST FIPS 204, lattice-based, deterministic to sign, and more practical to implement in constant time than Falcon. ML-DSA-44 is excluded to preserve a larger long-term security margin for UTXOs that may remain unspent for decades.

## Specification

### Output types and witness program

This BIP defines two new output types under **witness version 2**:

- `0x01`: **P2PQH**
- `0x02`: **P2HPQ**

The witness program is **21 bytes** long and is encoded in `scriptPubKey` as:

```text
scriptPubKey = OP_2 <21-byte witness program>
```

The witness program layout is:

```text
witness_program[0]     = type byte: 0x01 (P2PQH) or 0x02 (P2HPQ)
witness_program[1..20] = HASH160(pubkey_material)
```

For P2PQH:

```text
pubkey_material = mldsa_pubkey
commitment      = HASH160(mldsa_pubkey)
```

For P2HPQ:

```text
pubkey_material = ecdsa_pubkey || mldsa_pubkey
commitment      = HASH160(ecdsa_pubkey || mldsa_pubkey)
```

The source draft defines these semantics as new SegWit v2 output types with type-byte dispatch. It does not rely on Tapscript, and its consensus rules are expressed in witness-program validation terms.

### ML-DSA parameters

This BIP mandates **ML-DSA-65** exclusively. The parameter set is the FIPS 204 ML-DSA-65 profile:

| Parameter | Value |
|-----------|-------|
| q | 8,380,417 |
| n | 256 |
| k | 6 |
| l | 5 |
| eta | 4 |
| d | 13 |
| tau | 49 |
| gamma1 | 2^19 |
| gamma2 | (q-1)/32 |
| beta | 196 |
| omega | 55 |
| lambda | 256 |
| Public key size | 1,952 bytes |
| Secret key size | 4,000 bytes |
| Signature size | 3,293 bytes |

### Address encoding

Addresses use **Bech32m** with witness version 2. Mainnet uses HRP `bc`; testnet uses `tb`.

```text
P2PQH address = bech32m("bc", 2, 0x01 || HASH160(mldsa_pubkey))
P2HPQ address = bech32m("bc", 2, 0x02 || HASH160(ecdsa_pubkey || mldsa_pubkey))
```

### Witness stack layout

**P2PQH witness** has exactly 2 stack items:

```text
stack[0] = mldsa_signature    (3,293 bytes)
stack[1] = mldsa_pubkey       (1,952 bytes)
```

**P2HPQ witness** has exactly 4 stack items:

```text
stack[0] = ecdsa_signature    (DER-encoded, with sighash byte)
stack[1] = ecdsa_pubkey       (33 bytes, compressed)
stack[2] = mldsa_signature    (3,293 bytes)
stack[3] = mldsa_pubkey       (1,952 bytes)
```

### Signature encoding and sighash

The message signed by both schemes is:

```text
sighash = H2(
    LE32(nVersion) ||
    hashPrevouts   ||
    hashSequences  ||
    outpoint       ||
    LE64(amount)   ||
    LE32(nSequence)||
    hashOutputs    ||
    LE32(nLocktime)||
    sighash_type   ||
    witness_program
)
```

Where:

- `hashPrevouts` is `H2` over all transaction outpoints.
- `hashSequences` is `H2` over all input `nSequence` values.
- `hashOutputs` is `H2` over all serialized outputs.
- `outpoint` is the input's `txid || vout`.
- `amount` is the spent UTXO value.
- `witness_program` is the full 21-byte witness program.
- Only `SIGHASH_ALL` (`0x01`) is defined.

The ML-DSA signature is raw FIPS 204 output and must be exactly 3,293 bytes. The P2HPQ ECDSA signature is DER-encoded with the sighash byte appended and must be 71 to 73 bytes including that trailing sighash byte.

### Validation rules

For all spends:

1. The witness version must be 2.
2. The witness program type byte must be `0x01` or `0x02`.
3. The 20-byte commitment in the witness program must equal `HASH160(pubkey_material)` for the revealed public key material.
4. Any sighash type byte other than `0x01` causes failure.

For **P2PQH** spends:

1. The witness stack must contain exactly 2 items.
2. `mldsa_pubkey` must be exactly 1,952 bytes.
3. `mldsa_signature` must be exactly 3,293 bytes.
4. `ML-DSA.Verify(mldsa_pubkey, sighash, mldsa_signature)` must return success.

For **P2HPQ** spends:

1. The witness stack must contain exactly 4 items.
2. `mldsa_pubkey` must be exactly 1,952 bytes.
3. `mldsa_signature` must be exactly 3,293 bytes.
4. `ecdsa_pubkey` must be exactly 33 bytes and compressed (`0x02` or `0x03` prefix).
5. `ecdsa_signature` must be DER-encoded, 71 to 73 bytes, with sighash byte appended.
6. `ML-DSA.Verify(mldsa_pubkey, sighash, mldsa_signature)` must return success.
7. `secp256k1.Verify(ecdsa_pubkey, H2(sighash), ecdsa_signature[:-1])` must return success.
8. Both verifications are required; failure of either causes script failure.

Script failure conditions therefore include wrong witness-item count, wrong public key length, wrong signature length, commitment mismatch, ML-DSA verification failure, ECDSA verification failure in P2HPQ, and undefined sighash types.

### Standardness and size

After activation, standard relay policy is extended to permit witness version 2 output scripts of length 23 bytes and witness stacks matching the layouts above. The existing 520-byte push limit is extended for SegWit v2 inputs so ML-DSA public keys and signatures can be carried in the witness.

A typical 1-input, 2-output P2HPQ transaction is approximately 5,806 weight units, or about 1,452 vbytes, compared with about 110 vbytes for P2WPKH. The size increase is the cost of ML-DSA-65-based quantum resistance.

## Rationale

The draft chooses a new SegWit v2 namespace rather than a Tapscript extension for three reasons. First, ML-DSA public keys are much larger than current script push conventions and are simpler to handle in a dedicated witness-program design. Second, Taproot key-path constructions expose a key on-chain, while these output types aim to hide authorizing public key material until spend. Third, a standalone witness-program design is easier to implement, audit, and reason about than extending Tapscript semantics.

The commitment remains `HASH160` for consistency with existing address formats and because the relevant quantum attack target is the public key, not the 20-byte hash preimage. For unspent outputs, revealing only `HASH160(pubkey_material)` preserves the intended protection. ML-DSA-65 is preferred over ML-DSA-44 for additional long-term margin, and Falcon is excluded because constant-time implementations remain substantially harder and have seen side-channel concerns.

## Backwards Compatibility

This proposal is a soft fork. Pre-upgrade nodes treat witness version 2 outputs as unknown witness programs under BIP 141 and therefore do not enforce the new signature rules. Upgraded nodes begin enforcing the P2PQH and P2HPQ validation rules only after activation. Existing output types such as P2PKH, P2WPKH, P2SH, P2WSH, and P2TR remain unchanged.

## Security Analysis

An unspent P2PQH or P2HPQ output reveals only `HASH160(pubkey_material)`. Recovering the hidden public key from that hash would require a hash preimage attack rather than a Shor-style discrete log attack. Grover-style speedups still leave this at roughly 2^80 query complexity for a 160-bit hash, which is not considered practical for the threat model.

ML-DSA-65 targets EUF-CMA security under Module-LWE and Module-SIS assumptions. The hybrid P2HPQ construction is intended to remain secure so long as at least one of ECDSA or ML-DSA remains unbroken, because a valid spend requires both signatures over the same transaction digest.

Consensus implementations must verify signatures correctly and handle large witness items safely. Constant-time ML-DSA implementations are required, especially for any signing path, and the reference implementation accompanying the draft is designed accordingly.

## Activation

Activation follows the **Speedy Trial** model used for Taproot:

- Signaling bit: bit 2 of `nVersion` (subject to final deployment selection)
- Start time: TBD
- Timeout: 1 year after start
- Threshold: 90% of blocks in a 2,016-block retarget period
- Minimum activation height: 6 retarget periods after lock-in, approximately 12 weeks

## Test Vectors

### Test Vector 1: ML-DSA-65 seed and sighash

```text
seed (32 bytes):
000102030405060708090a0b0c0d0e0f
101112131415161718191a1b1c1d1e1f

sighash (32 bytes):
e3b0c44298fc1c149afbf4c8996fb924
27ae41e4649b934ca495991b7852b855
```

The source draft points to full ML-DSA-65 KAT material in the accompanying reference implementation test data.

### Test Vector 2: P2PQH address derivation

```text
mldsa_pubkey: [1,952-byte key from KAT vector #1]
SHA256(mldsa_pubkey): [32-byte intermediate hash]
RIPEMD160(SHA256(mldsa_pubkey)): [20-byte pubkey hash]
witness_program: 01 || [20-byte pubkey hash]
bech32m address (mainnet): bc1z[...]
```

### Test Vector 3: Transaction sighash layout

```text
nVersion:         02000000
hashPrevouts:     [32 bytes]
hashSequences:    [32 bytes]
outpoint:         [36 bytes]
amount:           [8 bytes]
nSequence:        [4 bytes]
hashOutputs:      [32 bytes]
nLocktime:        [4 bytes]
sighash_type:     01
witness_program:  01[20-byte hash]

sighash = H2(above concatenation)
```

## Reference Implementation

- https://github.com/glaseagle/bitcoin-pqc
- https://github.com/glaseagle/bitcoin/tree/pqc-softfork

The prototype repository contains a Python implementation and the Bitcoin Core integration branch contains the consensus, policy, and test changes for ML-DSA-based validation.

## Copyright

This BIP is licensed under the BSD 2-Clause license.
