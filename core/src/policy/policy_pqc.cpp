// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Standardness (policy) rules for PQC output types.
//
// These rules are NOT consensus — they live in the mempool relay layer.
// A transaction may be valid by consensus yet still be non-standard (e.g.,
// too large a witness, unknown sighash type).  Non-standard transactions are
// not relayed by default nodes but can still be mined.
//
// Integration point in Bitcoin Core:
//   src/policy/policy.cpp :: IsStandard() / AreInputsStandard()
//
//   In IsStandard(), after the existing SegWit v0/v1 branches:
//
//       case TxoutType::WITNESS_V2_PQC:
//           return IsStandardPQCOutput(spk, reason);
//
//   In AreInputsStandard():
//       if (IsPQCInput(txin)) return IsStandardPQCInput(txin, reason);

#include "policy_pqc.h"
#include "../script/script_pqc.h"

#include <cassert>
#include <string>

// ---------------------------------------------------------------------------
// Output standardness
// ---------------------------------------------------------------------------

/**
 * IsStandardPQCOutput — check that a scriptPubKey creating a PQC output
 * meets relay policy.
 *
 * Rules:
 *   1. Must be exactly 23 bytes (OP_2 + push21 + 21-byte program)
 *   2. Type byte must be PQC_TYPE_PURE (0xc0) or PQC_TYPE_HYBRID (0xc2)
 *   3. No other constraints on the hash160 itself — any 20-byte value is
 *      relayable.  Consensus already enforces the commitment check.
 *
 * @param spk    The scriptPubKey bytes
 * @param reason Out-parameter: human-readable rejection reason
 * @return true if output meets policy
 */
bool IsStandardPQCOutput(std::span<const uint8_t> spk, std::string& reason)
{
    if (!IsP2PQCScript(spk)) {
        reason = "pqc-bad-script";
        return false;
    }
    // Type byte already validated by IsP2PQCScript
    return true;
}

// ---------------------------------------------------------------------------
// Input standardness
// ---------------------------------------------------------------------------

/**
 * IsStandardPQCInput — check that the witness stack for a PQC input meets
 * relay policy.
 *
 * Rules for P2PQH inputs:
 *   - Exactly 2 witness items
 *   - Item 0 (mldsa_sig || sighash_type): exactly PQC_MLDSA_SIG_BYTES + 1 bytes
 *   - Item 1 (mldsa_pk): exactly PQC_MLDSA_PUBKEY_BYTES bytes
 *   - sighash_type == 0x00 (SIGHASH_ALL)
 *   - scriptSig must be empty (SegWit rule)
 *
 * Rules for P2HPQ inputs:
 *   - Exactly 4 witness items
 *   - Item 0 (ecdsa_sig || sighash_type): PQC_ECDSA_SIG_MIN+1 .. PQC_ECDSA_SIG_MAX+1 bytes
 *   - Item 1 (ecdsa_pk): exactly 33 bytes, first byte ∈ {0x02, 0x03}
 *   - Item 2 (mldsa_sig || sighash_type): exactly PQC_MLDSA_SIG_BYTES + 1 bytes
 *   - Item 3 (mldsa_pk): exactly PQC_MLDSA_PUBKEY_BYTES bytes
 *   - Both sighash_type bytes must be identical
 *   - sighash_type == 0x00 (SIGHASH_ALL)
 *   - scriptSig must be empty
 *
 * @param type_byte  PQC_TYPE_PURE or PQC_TYPE_HYBRID (from the scriptPubKey)
 * @param witness    Deserialized witness stack
 * @param scriptsig  The scriptSig bytes (must be empty)
 * @param reason     Out-parameter: human-readable rejection reason
 * @return true if input meets policy
 */
bool IsStandardPQCInput(
    uint8_t type_byte,
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t> scriptsig,
    std::string& reason)
{
    // SegWit rule: scriptSig must be empty
    if (!scriptsig.empty()) {
        reason = "pqc-nonempty-scriptsig";
        return false;
    }

    if (type_byte == PQC_TYPE_PURE) {
        // P2PQH
        if (witness.size() != PQC_WIT_P2PQH_ITEMS) {
            reason = "pqc-wrong-witness-items";
            return false;
        }

        // mldsa_sig size check
        constexpr size_t SIG_WIRE = PQC_MLDSA_SIG_BYTES + 1;
        if (witness[PQC_WIT_MLDSA_SIG].size() != SIG_WIRE) {
            reason = "pqc-bad-sig-size";
            return false;
        }

        // sighash_type
        if (witness[PQC_WIT_MLDSA_SIG].back() != 0x00) {
            reason = "pqc-nonstandard-sighash";
            return false;
        }

        // mldsa_pk size check
        if (witness[PQC_WIT_MLDSA_PK].size() != PQC_MLDSA_PUBKEY_BYTES) {
            reason = "pqc-bad-pubkey-size";
            return false;
        }

        return true;
    }

    if (type_byte == PQC_TYPE_HYBRID) {
        // P2HPQ
        if (witness.size() != PQC_WIT_P2HPQ_ITEMS) {
            reason = "pqc-wrong-witness-items";
            return false;
        }

        // ecdsa_sig size: 71–73 bytes (DER + sighash_type)
        size_t ecdsa_sig_sz = witness[HPQ_WIT_ECDSA_SIG].size();
        if (ecdsa_sig_sz < PQC_ECDSA_SIG_MIN + 1 || ecdsa_sig_sz > PQC_ECDSA_SIG_MAX + 1) {
            reason = "pqc-bad-ecdsa-sig-size";
            return false;
        }

        // ecdsa_pk: 33 bytes, compressed
        if (witness[HPQ_WIT_ECDSA_PK].size() != PQC_ECDSA_PUBKEY_BYTES) {
            reason = "pqc-bad-ecdsa-pubkey-size";
            return false;
        }
        uint8_t pk_prefix = witness[HPQ_WIT_ECDSA_PK][0];
        if (pk_prefix != 0x02 && pk_prefix != 0x03) {
            reason = "pqc-uncompressed-ecdsa-pubkey";
            return false;
        }

        // mldsa_sig size
        constexpr size_t MLDSA_WIRE = PQC_MLDSA_SIG_BYTES + 1;
        if (witness[HPQ_WIT_MLDSA_SIG].size() != MLDSA_WIRE) {
            reason = "pqc-bad-mldsa-sig-size";
            return false;
        }

        // mldsa_pk size
        if (witness[HPQ_WIT_MLDSA_PK].size() != PQC_MLDSA_PUBKEY_BYTES) {
            reason = "pqc-bad-mldsa-pubkey-size";
            return false;
        }

        // sighash_type: both must match and be SIGHASH_ALL
        uint8_t ecdsa_sht  = witness[HPQ_WIT_ECDSA_SIG].back();
        uint8_t mldsa_sht  = witness[HPQ_WIT_MLDSA_SIG].back();
        if (ecdsa_sht != mldsa_sht) {
            reason = "pqc-sighash-mismatch";
            return false;
        }
        if (ecdsa_sht != 0x00) {
            reason = "pqc-nonstandard-sighash";
            return false;
        }

        return true;
    }

    reason = "pqc-unknown-type";
    return false;
}

// ---------------------------------------------------------------------------
// Weight / virtual size helpers (for fee estimation)
// ---------------------------------------------------------------------------

/**
 * GetPQCInputWeight — return the weight of a PQC input.
 *
 * Weight = base_weight + witness_weight
 *   base_weight  = (outpoint + scriptSig varint + nSequence) × 4
 *                = (32+4 + 1 + 4) × 4 = 164 wu
 *   witness_weight (discounted ÷4 applied post-hoc by Bitcoin Core)
 *     P2PQH: 1 (stack item count) + 3 (varint) + PQC_MLDSA_SIG_BYTES+1
 *                                 + 3 (varint) + PQC_MLDSA_PUBKEY_BYTES
 *     P2HPQ: 1 + varints + ECDSA_SIG + ECDSA_PK + MLDSA_SIG + MLDSA_PK
 *
 * These are maximum estimates; actual ECDSA sig may be 70–72 bytes.
 */
size_t GetPQCInputWeight(uint8_t type_byte)
{
    constexpr size_t BASE_WEIGHT = (32 + 4 + 1 + 4) * 4; // 164

    if (type_byte == PQC_TYPE_PURE) {
        // witness bytes (not yet divided by 4 — Bitcoin Core does that)
        size_t wit = 1 /* item count */
                   + 3 /* varint for sig */ + PQC_MLDSA_SIG_BYTES + 1
                   + 3 /* varint for pk  */ + PQC_MLDSA_PUBKEY_BYTES;
        return BASE_WEIGHT + wit;
    }

    if (type_byte == PQC_TYPE_HYBRID) {
        size_t wit = 1 /* item count */
                   + 1 + PQC_ECDSA_SIG_MAX + 1    // ecdsa sig
                   + 1 + PQC_ECDSA_PUBKEY_BYTES    // ecdsa pk
                   + 3 + PQC_MLDSA_SIG_BYTES + 1   // mldsa sig
                   + 3 + PQC_MLDSA_PUBKEY_BYTES;   // mldsa pk
        return BASE_WEIGHT + wit;
    }

    return 0;
}

/**
 * GetPQCOutputWeight — return the weight of a PQC output's scriptPubKey.
 *
 * All PQC scriptPubKeys are 23 bytes, so weight = 23 × 4 = 92 wu,
 * plus 8 bytes for the value field = 100 wu total per output.
 * (This matches SegWit v0/v1 P2WPKH outputs.)
 */
size_t GetPQCOutputWeight()
{
    constexpr size_t VALUE_BYTES    = 8;
    constexpr size_t VARINT_BYTES   = 1; // scriptPubKey length < 0xfd
    constexpr size_t SCRIPT_BYTES   = 2 + PQC_WITNESS_PROGRAM_SIZE; // 23
    return (VALUE_BYTES + VARINT_BYTES + SCRIPT_BYTES) * 4; // 128 wu
}
