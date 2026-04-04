// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Interface for the SegWit v2 PQC witness program interpreter.
//
// Include this from interpreter.cpp at the SegWit v2 dispatch point.

#ifndef BITCOIN_SCRIPT_INTERPRETER_PQC_H
#define BITCOIN_SCRIPT_INTERPRETER_PQC_H

#include <cstdint>
#include <span>
#include <vector>

// ---------------------------------------------------------------------------
// ScriptError codes (extends Bitcoin Core's ScriptError enum)
// ---------------------------------------------------------------------------

// These values must be appended to the existing ScriptError enum in
// src/script/script_error.h.  They are defined here for standalone
// compilation of interpreter_pqc.cpp.

enum ScriptError {
    SCRIPT_ERR_OK = 0,

    // PQC-specific errors (values above existing ScriptError max)
    SCRIPT_ERR_PQC_BAD_PROGRAM_SIZE    = 0x80,
    SCRIPT_ERR_PQC_WRONG_WITNESS_ITEMS = 0x81,
    SCRIPT_ERR_PQC_BAD_PUBKEY_SIZE     = 0x82,
    SCRIPT_ERR_PQC_PUBKEY_MISMATCH     = 0x83,
    SCRIPT_ERR_PQC_BAD_SIG_SIZE        = 0x84,
    SCRIPT_ERR_PQC_UNKNOWN_SIGHASH     = 0x85,
    SCRIPT_ERR_PQC_SIGHASH_MISMATCH    = 0x86,
    SCRIPT_ERR_PQC_SIG_INVALID         = 0x87,
    SCRIPT_ERR_PQC_UNKNOWN_TYPE        = 0x88,
};

// ---------------------------------------------------------------------------
// Transaction context for sighash computation
// ---------------------------------------------------------------------------

/**
 * Minimal set of fields needed to compute the BIP-PQC sighash.
 * In production, this would be derived from CMutableTransaction + CTxIn.
 */
struct PQCTxContext {
    uint32_t nVersion;
    uint32_t nLocktime;

    // The input being signed
    uint32_t nIn;           // input index
    uint64_t amount;        // in satoshis
    uint32_t nSequence;

    // Prevout
    uint8_t  prevout_hash[32];
    uint32_t prevout_n;

    // Serialized outputs (for hashOutputs)
    std::vector<uint8_t> outputs_serialized;

    // The 21-byte witness program of the output being spent
    uint8_t  witness_program[21];
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Top-level entry point for SegWit v2 PQC witness verification.
 * Called from VerifyWitnessProgram() in interpreter.cpp.
 */
bool VerifyPQCWitnessProgram(
    const std::vector<std::vector<uint8_t>>& witness,
    std::span<const uint8_t>                 program,
    const PQCTxContext&                      ctx,
    ScriptError*                             serror);

/**
 * Verify a P2PQH (pure ML-DSA) witness.
 * Public so it can be tested directly.
 */
bool VerifyP2PQH(
    const std::vector<std::vector<uint8_t>>&              witness,
    std::span<const uint8_t, 21>                          program,
    const PQCTxContext&                                   ctx,
    ScriptError*                                          serror);

/**
 * Verify a P2HPQ (hybrid ECDSA + ML-DSA) witness.
 * Public so it can be tested directly.
 */
bool VerifyP2HPQ(
    const std::vector<std::vector<uint8_t>>&              witness,
    std::span<const uint8_t, 21>                          program,
    const PQCTxContext&                                   ctx,
    ScriptError*                                          serror);

#endif // BITCOIN_SCRIPT_INTERPRETER_PQC_H
