// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Script constants and helpers for post-quantum output types.
//
// This file defines the new opcodes and witness-program constants introduced
// by the SegWit-v2 PQC soft fork (BIP-PQC).  It must be included wherever
// script construction or parsing touches P2PQH / P2HPQ outputs.

#ifndef BITCOIN_SCRIPT_SCRIPT_PQC_H
#define BITCOIN_SCRIPT_SCRIPT_PQC_H

#include <cstdint>
#include <cstddef>
#include <span>
#include <vector>

// ---------------------------------------------------------------------------
// Witness version
// ---------------------------------------------------------------------------

/** SegWit version used by both P2PQH and P2HPQ. */
static constexpr uint8_t SEGWIT_VERSION_PQC = 2;

// ---------------------------------------------------------------------------
// Opcodes
// ---------------------------------------------------------------------------

/**
 * OP_PQH (0xc0) — Push the post-quantum type discriminator byte.
 *
 * In a P2PQH scriptPubKey:   OP_2 <21-byte witness program>
 * The 21-byte witness program is:  [type_byte || HASH160(mldsa_pk)]
 * where type_byte = OP_PQH for pure ML-DSA, OP_HPQCHECKSIG for hybrid.
 *
 * These constants are NOT executed by the script engine directly; they
 * serve as the type discriminator embedded in the witness program.
 */
static constexpr uint8_t OP_PQH           = 0xc0;   // P2PQH type byte
static constexpr uint8_t OP_PQCHECKSIG    = 0xc1;   // reserved / legacy v0.1
static constexpr uint8_t OP_HPQCHECKSIG   = 0xc2;   // P2HPQ type byte

// Friendly names for the type discriminator
static constexpr uint8_t PQC_TYPE_PURE    = OP_PQH;          // ML-DSA only
static constexpr uint8_t PQC_TYPE_HYBRID  = OP_HPQCHECKSIG;  // ECDSA + ML-DSA

// ---------------------------------------------------------------------------
// Witness program layout
// ---------------------------------------------------------------------------

/**
 * A SegWit-v2 PQC witness program is exactly 21 bytes:
 *   [0]     type byte  (PQC_TYPE_PURE or PQC_TYPE_HYBRID)
 *   [1..20] HASH160 of the key material
 *
 * For P2PQH:  HASH160(mldsa_pubkey)
 * For P2HPQ:  HASH160(ecdsa_pubkey || mldsa_pubkey)
 */
static constexpr size_t PQC_WITNESS_PROGRAM_SIZE = 21;
static constexpr size_t PQC_HASH160_SIZE         = 20;
static constexpr size_t PQC_TYPE_OFFSET          = 0;
static constexpr size_t PQC_HASH_OFFSET          = 1;

// ---------------------------------------------------------------------------
// scriptPubKey construction helpers
// ---------------------------------------------------------------------------

/**
 * Build the 4-byte scriptPubKey for a SegWit v2 PQC output:
 *
 *   OP_2  OP_PUSHDATA(21)  <21-byte witness program>
 *
 * This is a native SegWit scriptPubKey; total length = 23 bytes.
 */
inline std::vector<uint8_t> BuildPQCScriptPubKey(
    uint8_t                          type_byte,
    std::span<const uint8_t, PQC_HASH160_SIZE> hash160)
{
    std::vector<uint8_t> spk;
    spk.reserve(2 + PQC_WITNESS_PROGRAM_SIZE);
    spk.push_back(0x52);                         // OP_2
    spk.push_back(static_cast<uint8_t>(PQC_WITNESS_PROGRAM_SIZE)); // push 21 bytes
    spk.push_back(type_byte);
    spk.insert(spk.end(), hash160.begin(), hash160.end());
    return spk;
}

// ---------------------------------------------------------------------------
// Witness stack layout
// ---------------------------------------------------------------------------

/**
 * P2PQH witness stack (2 items):
 *   [0] mldsa_signature  (3,293 bytes)
 *   [1] mldsa_pubkey     (1,952 bytes)
 *
 * P2HPQ witness stack (4 items):
 *   [0] ecdsa_signature  (71–72 bytes, DER)
 *   [1] ecdsa_pubkey     (33 bytes, compressed)
 *   [2] mldsa_signature  (3,293 bytes)
 *   [3] mldsa_pubkey     (1,952 bytes)
 */

// Witness stack item indices — P2PQH
static constexpr int PQC_WIT_MLDSA_SIG = 0;
static constexpr int PQC_WIT_MLDSA_PK  = 1;
static constexpr int PQC_WIT_P2PQH_ITEMS = 2;

// Witness stack item indices — P2HPQ
static constexpr int HPQ_WIT_ECDSA_SIG  = 0;
static constexpr int HPQ_WIT_ECDSA_PK   = 1;
static constexpr int HPQ_WIT_MLDSA_SIG  = 2;
static constexpr int HPQ_WIT_MLDSA_PK   = 3;
static constexpr int PQC_WIT_P2HPQ_ITEMS = 4;

// ---------------------------------------------------------------------------
// Key / signature size constraints for stack item validation
// ---------------------------------------------------------------------------

static constexpr size_t PQC_MLDSA_PUBKEY_BYTES = 1952;
static constexpr size_t PQC_MLDSA_SIG_BYTES    = 3293;
static constexpr size_t PQC_ECDSA_PUBKEY_BYTES = 33;    // compressed
static constexpr size_t PQC_ECDSA_SIG_MIN      = 70;    // DER min
static constexpr size_t PQC_ECDSA_SIG_MAX      = 72;    // DER max

// ---------------------------------------------------------------------------
// Helper predicates
// ---------------------------------------------------------------------------

/** True if spk is a SegWit v2 PQC scriptPubKey (length 23, correct prefix). */
inline bool IsP2PQCScript(std::span<const uint8_t> spk)
{
    if (spk.size() != 2 + PQC_WITNESS_PROGRAM_SIZE) return false;
    if (spk[0] != 0x52) return false;  // OP_2
    if (spk[1] != static_cast<uint8_t>(PQC_WITNESS_PROGRAM_SIZE)) return false;
    uint8_t t = spk[2];
    return t == PQC_TYPE_PURE || t == PQC_TYPE_HYBRID;
}

/** Returns the type byte from a PQC scriptPubKey.  Caller must call
 *  IsP2PQCScript() first. */
inline uint8_t GetPQCType(std::span<const uint8_t> spk)
{
    return spk[2];
}

/** Extract the 20-byte hash160 from a PQC scriptPubKey. */
inline std::span<const uint8_t, PQC_HASH160_SIZE>
GetPQCHash160(std::span<const uint8_t> spk)
{
    // spk[3..22]
    return std::span<const uint8_t, PQC_HASH160_SIZE>{spk.data() + 3, PQC_HASH160_SIZE};
}

// ---------------------------------------------------------------------------
// Weight constants (for fee estimation)
// ---------------------------------------------------------------------------

/**
 * Weight of the witness stack data alone (not the scriptPubKey or input).
 *
 * FIPS 204 sizes:
 *   P2PQH witness:  3293 + 1952 = 5245 bytes of stack data
 *                   + 2 items × varint = +2 bytes
 *                   + stack item count varint = +1 byte
 *   P2HPQ witness:  72 + 33 + 3293 + 1952 = 5350 bytes
 *                   + 4 items × varint = +4 bytes
 *                   + stack item count varint = +1 byte
 *
 * Witness data is discounted at 1/4 weight vs base data.
 */
static constexpr size_t PQC_P2PQH_WITNESS_VSIZE =
    (PQC_MLDSA_SIG_BYTES + PQC_MLDSA_PUBKEY_BYTES + 2 + 1 + 3) / 4;  // +3 for rounding

static constexpr size_t PQC_P2HPQ_WITNESS_VSIZE =
    (PQC_ECDSA_SIG_MAX + PQC_ECDSA_PUBKEY_BYTES +
     PQC_MLDSA_SIG_BYTES + PQC_MLDSA_PUBKEY_BYTES + 4 + 1 + 3) / 4;

#endif // BITCOIN_SCRIPT_SCRIPT_PQC_H
