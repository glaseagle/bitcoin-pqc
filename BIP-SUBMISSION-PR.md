## BIP-PQC: Post-Quantum Hybrid Signatures (P2PQH + P2HPQ)

This PR submits a Draft BIP that introduces two new SegWit v2 output types for Bitcoin: P2PQH (ML-DSA only) and P2HPQ (hybrid secp256k1 ECDSA + ML-DSA). Both constructions commit to a 20-byte HASH160 of the authorizing public key material and reveal the full keys only when the output is spent, preserving quantum resistance for unspent outputs while fitting into Bitcoin's existing witness-program model.

The proposal uses ML-DSA-65 as the post-quantum signature scheme and defines witness layout, sighash construction, validation rules, relay-policy implications, Bech32m address encoding under witness version 2, and a Speedy Trial activation path. The hybrid form is intended for transition-period deployments that want protection against both a future quantum break of ECDSA and potential implementation or cryptanalytic surprises in newer post-quantum code.

This submission also documents the practical tradeoff clearly: witness size increases materially. A typical spend is approximately 5 KB of witness data, compared with roughly 107 bytes for a conventional ECDSA P2WPKH witness. That overhead is the main cost of getting hidden-until-spend post-quantum or hybrid authorization semantics with ML-DSA-65.

Reference implementations and prototype code:

- https://github.com/glaseagle/bitcoin-pqc
- https://github.com/glaseagle/bitcoin/tree/pqc-softfork

This BIP is being submitted in **Draft** status and is seeking BIP number assignment and initial review from the `bitcoin/bips` maintainers and broader community.

### Benchmarks

| Operation | Approx. time |
|-----------|---------------|
| KeyGen | ~56 ms |
| Sign | ~2 ms |
| Verify | ~1.5 ms |
