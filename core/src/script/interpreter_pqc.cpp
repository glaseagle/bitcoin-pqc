// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Consensus-critical script interpreter extension for PQC output types.
//
// This file contains VerifyP2PQH() and VerifyP2HPQ(), called from the
// SegWit v2 branch of Bitcoin Core's VerifyScript() / EvalScript().
//
// Integration point in Bitcoin Core:
//   src/script/interpreter.cpp :: VerifyWitnessProgram()
//
//   case 2:   // SegWit version 2 — PQC
//       return VerifyPQCWitnessProgram(witness, program, tx, nIn, amount, flags, serror);
//
// This file is intentionally standalone so it can be reviewed and audited
// independently of the main interpreter.  It has no global state.

#include "interpreter_pqc.h"
#include "script_pqc.h"
#include "../crypto/mldsa/mldsa.h"

#include <cassert>
#include <cstring>

// ---------------------------------------------------------------------------
// Forward declarations for Bitcoin Core primitives used here.
// These are provided by the main Bitcoin Core build; stubs are supplied in
// the test harness (see test/script_pqc_tests.cpp).
// ---------------------------------------------------------------------------

// Hash160 = RIPEMD160(SHA256(data))
extern std::array<uint8_t, 20> Hash160(std::span<const uint8_t> data);

// secp256k1 ECDSA verification (Bitcoin Core's existing implementation).
// Returns true iff sig is a valid DER signature for hash under pubkey.
extern bool ECDSAVerify(
    std::span<const uint8_t> sig,
    std::span<const uint8_t> hash,   // 32-byte sighash
    std::span<const uint8_t> pubkey  // 33-byte compressed
);

// Compute the BIP-PQC sighash for a given output.
// Defined in sighash_pqc.cpp.
extern std::array<uint8_t, 32> ComputePQCSigHash(
    const PQCTxContext& ctx,
    uint8_t sighash_type);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace {

/**
 * Validate that a witness stack item has an exact expected size.
 * Returns false (sets serror) if the size is wrong.
 */
static bool CheckItemSize(
    std::span<const uint8_t> item,
    size_t expected,
    ScriptError* serror,
    ScriptError code)
{
    if (item.size() != expected) {
        if (serror) *serror = code;
        return false;
    }
    return true;
}

/**
 * Extract the sighash type byte from the last byte of an ML-DSA signature.
 *
 * Per BIP-PQC §Sighash, the sighash_type is appended to the 3,293-byte
 * canonical ML-DSA signature, making the on-chain item 3,294 bytes.
 * sighash_type == 0x00 means SIGHASH_ALL (the only type defined in v1).
 */
static bool ParseMLDSASig(
    std::span<const uint8_t> raw,       // 3294 bytes (sig || sighash_type)
    std::span<const uint8_t, PQC_MLDSA_SIG_BYTES>& sig_out,
    uint8_t& sighash_type_out,
    ScriptError* serror)
{
    constexpr size_t WIRE_SIZE = PQC_MLDSA_SIG_BYTES + 1;
    if (raw.size() != WIRE_SIZE) {
        if (serror) *serror = SCRIPT_ERR_PQC_BAD_SIG_SIZE;
        return false;
    }
    sig_out = std::span<const uint8_t, PQC_MLDSA_SIG_BYTES>{raw.data(), PQC_MLDSA_SIG_BYTES};
    sighash_type_out = raw[PQC_MLDSA_SIG_BYTES];
    if (sighash_type_out != 0x00) {
        // Only SIGHASH_ALL defined for v1
        if (serror) *serror = SCRIPT_ERR_PQC_UNKNOWN_SIGHASH;
        return false;
    }
    return true;
}

/**
 * Parse an ECDSA DER signature with appended sighash type byte.
 * DER-encoded ECDSA signatures for secp256k1 are 70–72 bytes;
 * the Bitcoin wire format appends one sighash_type byte → 71–73 bytes.
 */
static bool ParseECDSASig(
    std::span<const uint8_t> raw,
    std::span<const uint8_t>& der_sig_out,
    uint8_t& sighash_type_out,
    ScriptError* serror)
{
    if (raw.size() < PQC_ECDSA_SIG_MIN + 1 || raw.size() > PQC_ECDSA_SIG_MAX + 1) {
        if (serror) *serror = SCRIPT_ERR_PQC_BAD_SIG_SIZE;
        return false;
    }
    sighash_type_out = raw.back();
    if (sighash_type_out != 0x00) {
        if (serror) *serror = SCRIPT_ERR_PQC_UNKNOWN_SIGHASH;
        return false;
    }
    der_sig_out = raw.subspan(0, raw.size() - 1);
    return true;
}

} // namespace

// ---------------------------------------------------------------------------
// P2PQH — pure ML-DSA
// ---------------------------------------------------------------------------

/**
 * Verify a P2PQH witness.
 *
 * Witness stack (2 items, bottom to top):
 *   [0] mldsa_sig || sighash_type  (3,294 bytes)
 *   [1] mldsa_pubkey               (1,952 bytes)
 *
 * Witness program (21 bytes):
 *   type_byte=0xc0 || HASH160(mldsa_pubkey)
 *
 * Verification:
 *   1. Item count == 2
 *   2. mldsa_pubkey is 1,952 bytes
 *   3. HASH160(mldsa_pubkey) == witness_program[1..20]
 *   4. Parse mldsa_sig, extract sighash_type
 *   5. Compute sighash H2(tx fields || witness_program)
 *   6. MLDSA_Verify(sig, sighash, pubkey) == true
 */
bool VerifyP2PQH(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t, PQC_WITNESS_PROGRAM_SIZE> program,
    const PQCTxContext& ctx,
    ScriptError* serror)
{
    // 1. Witness item count
    if (witness.size() != PQC_WIT_P2PQH_ITEMS) {
        if (serror) *serror = SCRIPT_ERR_PQC_WRONG_WITNESS_ITEMS;
        return false;
    }

    std::span<const uint8_t> raw_sig{witness[PQC_WIT_MLDSA_SIG]};
    std::span<const uint8_t> raw_pk {witness[PQC_WIT_MLDSA_PK]};

    // 2. Public key size
    if (!CheckItemSize(raw_pk, PQC_MLDSA_PUBKEY_BYTES,
                       serror, SCRIPT_ERR_PQC_BAD_PUBKEY_SIZE)) {
        return false;
    }

    // 3. Commitment check: HASH160(pk) must match witness program bytes [1..20]
    auto h160 = Hash160(raw_pk);
    auto prog_hash = program.subspan<PQC_HASH_OFFSET, PQC_HASH160_SIZE>();
    if (std::memcmp(h160.data(), prog_hash.data(), PQC_HASH160_SIZE) != 0) {
        if (serror) *serror = SCRIPT_ERR_PQC_PUBKEY_MISMATCH;
        return false;
    }

    // 4. Parse signature + sighash type
    std::span<const uint8_t, PQC_MLDSA_SIG_BYTES> mldsa_sig;
    uint8_t sighash_type{};
    if (!ParseMLDSASig(raw_sig, mldsa_sig, sighash_type, serror)) {
        return false;
    }

    // 5. Compute sighash
    // The message signed is SHA-256(SHA-256(BIP-PQC sighash preimage)).
    // ComputePQCSigHash embeds the witness program (type || hash160) so that
    // the signature commits to the output type.
    auto sighash = ComputePQCSigHash(ctx, sighash_type);

    // 6. ML-DSA signature verification
    MLDSAPublicKey pk_arr;
    std::copy(raw_pk.begin(), raw_pk.end(), pk_arr.begin());

    MLDSASignature sig_arr;
    std::copy(mldsa_sig.begin(), mldsa_sig.end(), sig_arr.begin());

    if (!MLDSA_Verify(sig_arr, sighash.data(), sighash.size(), pk_arr)) {
        if (serror) *serror = SCRIPT_ERR_PQC_SIG_INVALID;
        return false;
    }

    if (serror) *serror = SCRIPT_ERR_OK;
    return true;
}

// ---------------------------------------------------------------------------
// P2HPQ — hybrid ECDSA + ML-DSA
// ---------------------------------------------------------------------------

/**
 * Verify a P2HPQ witness.
 *
 * Witness stack (4 items):
 *   [0] ecdsa_sig || sighash_type  (71–73 bytes)
 *   [1] ecdsa_pubkey               (33 bytes, compressed)
 *   [2] mldsa_sig || sighash_type  (3,294 bytes)
 *   [3] mldsa_pubkey               (1,952 bytes)
 *
 * Witness program (21 bytes):
 *   type_byte=0xc2 || HASH160(ecdsa_pubkey || mldsa_pubkey)
 *
 * Verification:
 *   1. Item count == 4
 *   2. ecdsa_pubkey is 33 bytes; mldsa_pubkey is 1,952 bytes
 *   3. HASH160(ecdsa_pk || mldsa_pk) == witness_program[1..20]
 *   4. Parse both signatures
 *   5. Compute sighash
 *   6. Both ECDSA and ML-DSA must verify — if either fails, reject
 *
 * The hybrid requirement means an attacker must break BOTH classical and
 * post-quantum assumptions to forge a signature.
 */
bool VerifyP2HPQ(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t, PQC_WITNESS_PROGRAM_SIZE> program,
    const PQCTxContext& ctx,
    ScriptError* serror)
{
    // 1. Witness item count
    if (witness.size() != PQC_WIT_P2HPQ_ITEMS) {
        if (serror) *serror = SCRIPT_ERR_PQC_WRONG_WITNESS_ITEMS;
        return false;
    }

    std::span<const uint8_t> raw_ecdsa_sig{witness[HPQ_WIT_ECDSA_SIG]};
    std::span<const uint8_t> raw_ecdsa_pk {witness[HPQ_WIT_ECDSA_PK]};
    std::span<const uint8_t> raw_mldsa_sig{witness[HPQ_WIT_MLDSA_SIG]};
    std::span<const uint8_t> raw_mldsa_pk {witness[HPQ_WIT_MLDSA_PK]};

    // 2. Key size checks
    if (!CheckItemSize(raw_ecdsa_pk, PQC_ECDSA_PUBKEY_BYTES,
                       serror, SCRIPT_ERR_PQC_BAD_PUBKEY_SIZE)) {
        return false;
    }
    if (!CheckItemSize(raw_mldsa_pk, PQC_MLDSA_PUBKEY_BYTES,
                       serror, SCRIPT_ERR_PQC_BAD_PUBKEY_SIZE)) {
        return false;
    }

    // 3. Commitment check: HASH160(ecdsa_pk || mldsa_pk) == program[1..20]
    {
        std::vector<uint8_t> combined;
        combined.reserve(raw_ecdsa_pk.size() + raw_mldsa_pk.size());
        combined.insert(combined.end(), raw_ecdsa_pk.begin(), raw_ecdsa_pk.end());
        combined.insert(combined.end(), raw_mldsa_pk.begin(), raw_mldsa_pk.end());
        auto h160 = Hash160(combined);
        auto prog_hash = program.subspan<PQC_HASH_OFFSET, PQC_HASH160_SIZE>();
        if (std::memcmp(h160.data(), prog_hash.data(), PQC_HASH160_SIZE) != 0) {
            if (serror) *serror = SCRIPT_ERR_PQC_PUBKEY_MISMATCH;
            return false;
        }
    }

    // 4. Parse signatures
    std::span<const uint8_t> ecdsa_der;
    uint8_t ecdsa_sighash_type{};
    if (!ParseECDSASig(raw_ecdsa_sig, ecdsa_der, ecdsa_sighash_type, serror)) {
        return false;
    }

    std::span<const uint8_t, PQC_MLDSA_SIG_BYTES> mldsa_sig;
    uint8_t mldsa_sighash_type{};
    if (!ParseMLDSASig(raw_mldsa_sig, mldsa_sig, mldsa_sighash_type, serror)) {
        return false;
    }

    // Both sighash types must agree
    if (ecdsa_sighash_type != mldsa_sighash_type) {
        if (serror) *serror = SCRIPT_ERR_PQC_SIGHASH_MISMATCH;
        return false;
    }

    // 5. Compute sighash (same preimage for both signature systems)
    auto sighash = ComputePQCSigHash(ctx, ecdsa_sighash_type);

    // 6a. ECDSA verification
    if (!ECDSAVerify(ecdsa_der, sighash, raw_ecdsa_pk)) {
        if (serror) *serror = SCRIPT_ERR_PQC_SIG_INVALID;
        return false;
    }

    // 6b. ML-DSA verification
    MLDSAPublicKey pk_arr;
    std::copy(raw_mldsa_pk.begin(), raw_mldsa_pk.end(), pk_arr.begin());

    MLDSASignature sig_arr;
    std::copy(mldsa_sig.begin(), mldsa_sig.end(), sig_arr.begin());

    if (!MLDSA_Verify(sig_arr, sighash.data(), sighash.size(), pk_arr)) {
        if (serror) *serror = SCRIPT_ERR_PQC_SIG_INVALID;
        return false;
    }

    if (serror) *serror = SCRIPT_ERR_OK;
    return true;
}

// ---------------------------------------------------------------------------
// Top-level dispatcher — called from VerifyWitnessProgram()
// ---------------------------------------------------------------------------

/**
 * Verify a SegWit v2 PQC witness program.
 *
 * @param witness  Deserialized witness stack
 * @param program  Raw 21-byte witness program (type || hash160)
 * @param ctx      Transaction context for sighash computation
 * @param serror   Out-parameter for error code (may be nullptr)
 * @return true iff the witness is valid
 */
bool VerifyPQCWitnessProgram(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t> program_raw,
    const PQCTxContext& ctx,
    ScriptError* serror)
{
    // Program must be exactly 21 bytes
    if (program_raw.size() != PQC_WITNESS_PROGRAM_SIZE) {
        if (serror) *serror = SCRIPT_ERR_PQC_BAD_PROGRAM_SIZE;
        return false;
    }

    std::span<const uint8_t, PQC_WITNESS_PROGRAM_SIZE> program{
        program_raw.data(), PQC_WITNESS_PROGRAM_SIZE
    };

    uint8_t type_byte = program[PQC_TYPE_OFFSET];

    switch (type_byte) {
    case PQC_TYPE_PURE:
        return VerifyP2PQH(witness, program, ctx, serror);

    case PQC_TYPE_HYBRID:
        return VerifyP2HPQ(witness, program, ctx, serror);

    default:
        // Unknown PQC sub-type — reject rather than ANYONECANSPEND.
        // Future soft forks may define new type bytes; current nodes
        // must reject to maintain tightness of the rule set.
        if (serror) *serror = SCRIPT_ERR_PQC_UNKNOWN_TYPE;
        return false;
    }
}
