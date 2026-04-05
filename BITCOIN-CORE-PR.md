# [RFC] BIP-PQC: SegWit v2 post-quantum output types (P2PQH + P2HPQ)

## Summary
This concept PR implements the current Draft BIP for SegWit v2 post-quantum outputs, introducing two new witness version 2 output types: P2PQH (pure ML-DSA-65) and P2HPQ (hybrid secp256k1 ECDSA + ML-DSA-65). The implementation adds a new `witness_v2_pqc` `TxoutType`, consensus validation for 21-byte PQC witness programs, and relay policy for the corresponding witness stacks, while leaving existing script and policy paths unchanged. The underlying post-quantum primitive is NIST FIPS 204 ML-DSA-65, implemented as a self-contained library under `src/crypto/mldsa/`. This is an RFC / concept PR intended to solicit design and review feedback; it is not being proposed for near-term merge, though signet and testnet4 deployment parameters are included to make the codepath testable.

## Motivation
Bitcoin's existing signature security depends primarily on secp256k1 ECDSA and Schnorr, both of which become forgeable in the presence of a cryptographically relevant quantum computer via Shor's algorithm once the authorizing public key is exposed. NIST finalized FIPS 204 in August 2024, standardizing ML-DSA and making a final, non-draft post-quantum signature scheme available for serious integration work. This branch explores a migration path that preserves hash-based key hiding prior to spend while also evaluating a hybrid construction: P2HPQ requires both classical and post-quantum signatures so that security does not rest entirely on either a quantum-vulnerable legacy scheme or a newly standardized PQ scheme.

## Changes

### New files
- `src/crypto/mldsa/` — self-contained ML-DSA-65 implementation (NIST FIPS 204), ~2,300 lines, no external crypto dependency
- `src/script/script_pqc.h` — SegWit v2 PQC constants: `SEGWIT_VERSION_PQC = 2`, 21-byte witness program layout, type discriminators `0xc0` (P2PQH) and `0xc2` (P2HPQ), witness stack indices, size/weight helpers
- `src/script/interpreter_pqc.h/cpp` — consensus bridge: `PQCTxContext`, `VerifyPQCWitnessProgram`, `VerifyP2PQH`, `VerifyP2HPQ`, PQC sighash construction
- `src/policy/policy_pqc.h/cpp` — standardness checks and weight helpers for `witness_v2_pqc`
- `src/test/mldsa_kat_test.cpp` — 6 Boost unit tests (size constants, determinism, roundtrip, wrong key/message/tampered sig)
- `src/test/fuzz/mldsa.cpp` / `pqc_script.cpp` — fuzz targets for ML-DSA and PQC script paths
- `src/bench/mldsa.cpp` — KeyGen, Sign, Verify, Verify-fail benchmarks
- `test/functional/feature_pqc.py` — output recognition, mempool standardness, witness/vsize policy

### Modified files (additive only)
- `src/script/solver.h/cpp` — `TxoutType::WITNESS_V2_PQC`, detection before unknown-witness fallback
- `src/script/interpreter.cpp` — `witversion == 2` dispatch into `VerifyPQCWitnessProgram`
- `src/policy/policy.cpp` — `IsStandard()` / `AreInputsStandard()` branches for `WITNESS_V2_PQC`
- `src/consensus/params.h` — `DEPLOYMENT_PQC` in versionbits enum
- `src/deploymentinfo.cpp` — `"pqc"` deployment metadata
- `src/kernel/chainparams.cpp` — signet + testnet4 activation: bit 2, 2025-06-01 start, 2026-06-01 timeout, 90% / 2016 blocks

## How to review

```bash
git clone https://github.com/glaseagle/bitcoin
git checkout pqc-softfork
cmake -B build -DBUILD_TESTS=ON -DBUILD_BENCH=ON -DENABLE_IPC=OFF
cmake --build build --parallel 8
./build/bin/test_bitcoin --run_test=mldsa_kat_tests
./build/bin/bench_bitcoin -filter=MLDSA
```

Suggested review order:
1. `src/script/script_pqc.h` — script surface and witness program layout
2. `src/script/interpreter_pqc.h/cpp` — consensus rules (start here for cryptographic review)
3. `src/script/interpreter.cpp` — integration point (additive v2 branch only)
4. `src/policy/policy_pqc.h/cpp` + `src/policy/policy.cpp` — relay policy
5. `src/script/solver.h/cpp` — type classification
6. `src/crypto/mldsa/` — crypto implementation (self-contained, audit independently)
7. Tests and benches

Points worth special attention:
- 21-byte witness program: `[type_byte || HASH160(commitment)]` hides large PQ pubkey until spend
- Sighash appends a one-byte type discriminator; currently only `0x00` accepted — review against BIP draft `SIGHASH_ALL` semantics
- All modified files are additive-only; existing v0/v1/Taproot paths are unaffected

## Known issues / TODOs
- Witness size ~50× larger than ECDSA P2WPKH even with SegWit discounting
- Falcon-512 (NIST FIPS 206) would be ~3.4× more compact — open design question
- Wallet signing not yet wired (consensus + policy layer only)
- NIST byte-level KAT vectors still needed (current tests are roundtrip, not conformance)
- `getdeploymentinfo` RPC needs "pqc" status string entry

## Benchmarks

| Operation | Time |
|-----------|------|
| ML-DSA-65 KeyGen | ~56ms |
| ML-DSA-65 Sign | ~2.3ms |
| ML-DSA-65 Verify | ~1.5ms |
| Secp256k1 Verify (reference) | ~0.05ms |

## Links
- Python reference impl: https://github.com/glaseagle/bitcoin-pqc
- BIP draft: (link after bitcoin/bips PR is opened)
