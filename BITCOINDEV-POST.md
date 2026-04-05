Subject: [BIP Proposal] Post-Quantum Hybrid Signatures for Bitcoin (P2PQH + P2HPQ)

To: bitcoindev@googlegroups.com

---

I'd like to propose a draft BIP for two new SegWit v2 output types that give Bitcoin users a path to quantum-resistant spending. P2PQH (Pay to Post-Quantum Hash) requires ML-DSA-65 only; P2HPQ (Pay to Hybrid Post-Quantum Hash) requires both secp256k1 ECDSA and ML-DSA-65, with both signatures verified independently. Unspent outputs commit only to a 20-byte HASH160 of the public key material; the full keys are revealed only at spend.

NIST finalised ML-DSA as FIPS 204 in August 2024, providing a stable standard rather than a moving draft. Bitcoin UTXOs can sit unspent for decades. Existing exposed public keys — P2PKH outputs after first spend, all P2PK outputs, many Taproot key-path spends — become vulnerable the moment a cryptographically relevant quantum computer exists. The window to migrate is finite.


## Technical Summary

Both types use **witness version 2**. The 23-byte scriptPubKey is:

    OP_2 <type_byte || HASH160(pubkey_material)>

`0x01` = P2PQH, `0x02` = P2HPQ. P2PQH witness: `mldsa_sig` (3,293 B) + `mldsa_pubkey` (1,952 B). P2HPQ witness: `ecdsa_sig` (≤72 B) + `ecdsa_pubkey` (33 B) + `mldsa_sig` (3,293 B) + `mldsa_pubkey` (1,952 B). Failure of either verification fails the script.

The sighash is a double-SHA256 of: `nVersion`, `hashPrevouts`, `hashSequences`, outpoint, amount, `nSequence`, `hashOutputs`, `nLocktime`, sighash type, and the full 21-byte witness program. Only `SIGHASH_ALL` is defined.

Activation: **Speedy Trial**, bit 2 of `nVersion`, 90% threshold, start time TBD, one-year timeout, minimum activation height six retarget periods after lock-in.


## Known Limitations

**Witness size.** Raw witness bytes: ~5,350 B (hybrid) vs 107 B for P2WPKH — roughly 50x larger. In vbytes a 1-in/2-out P2HPQ transaction is ~1,452 vbytes vs ~110 for P2WPKH. This has real fee and block-space implications.

**Falcon-512** (FIPS 206) would reduce witness to ~1,563 B total, but constant-time Gaussian sampling is hard to implement correctly and several side-channel attacks have been demonstrated. Excluded here; a follow-on BIP may add it when audited implementations mature.

**Existing UTXOs.** Only new output types are defined. Migration of existing P2PKH, P2WPKH, or P2TR funds is left to users and wallets.

**Commitment size.** HASH160 (20 bytes) is used for consistency with existing types. Whether SHA256 (32 bytes) would be more appropriate is an open question.

**Timeline.** Activation parameters are TBD. This is a research proposal, not an activation campaign.


## Reference Implementations

- Python prototype, 49 tests passing: https://github.com/glaseagle/bitcoin-pqc
- Bitcoin Core C++ soft-fork branch: https://github.com/glaseagle/bitcoin/tree/pqc-softfork
  — `bitcoind` builds clean; 6/6 NIST KAT vectors pass; ML-DSA verify ~1.5 ms per input


## Questions for Reviewers

1. **Algorithm.** ML-DSA-65 or Falcon-512 (or defer Falcon to a later BIP)?
2. **Scope.** Both P2PQH and P2HPQ, or only the hybrid type?
3. **Witness weight.** Is ~13x vbyte overhead acceptable, or does it need a larger witness discount before this is viable?
4. **Timing.** Appropriate to discuss activation parameters now, or premature?


## Close

Posted for technical review. I expect iteration on the sighash construction, weight policy, commitment size, and deployment mechanism. All critical feedback is welcome.

[author]
