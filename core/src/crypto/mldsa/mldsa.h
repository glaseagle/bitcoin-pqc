// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ML-DSA-65 (CRYSTALS-Dilithium3) — public API.
// NIST FIPS 204, August 2024.
//
// This header is the only interface that consensus and wallet code should use.
// Internal polynomial/NTT routines are in mldsa_poly.h.

#ifndef BITCOIN_CRYPTO_MLDSA_H
#define BITCOIN_CRYPTO_MLDSA_H

#include <stdint.h>
#include <stddef.h>
#include <span>
#include <array>

#include "mldsa_params.h"

// Key and signature sizes (FIPS 204 Table 2, ML-DSA-65)
// sk = 2*32 + 64 + L*128 + K*128 + K*416 = 64+64+640+768+2496 = 4032 bytes
static constexpr size_t MLDSA_PUBKEY_SIZE  = MLDSA_PUBLICKEYBYTES;
static constexpr size_t MLDSA_SECKEY_SIZE  = MLDSA_SECRETKEYBYTES;
static constexpr size_t MLDSA_SIG_SIZE     = MLDSA_SIGNBYTES;

using MLDSAPublicKey  = std::array<uint8_t, MLDSA_PUBKEY_SIZE>;
using MLDSASecretKey  = std::array<uint8_t, MLDSA_SECKEY_SIZE>;
using MLDSASignature  = std::array<uint8_t, MLDSA_SIG_SIZE>;

/**
 * Generate an ML-DSA-65 key pair.
 *
 * @param[out] pk   Public key (1,952 bytes)
 * @param[out] sk   Secret key (4,000 bytes)
 * @param[in]  seed Optional 32-byte seed for deterministic generation.
 *                  If nullptr, os-level randomness is used (GetStrongRandBytes).
 * @return true on success, false on internal error.
 *
 * NOTE: The secret key contains the full key material including t0.
 *       Store it encrypted; never expose it over any network interface.
 */
[[nodiscard]] bool MLDSA_KeyGen(
    MLDSAPublicKey& pk,
    MLDSASecretKey& sk,
    const uint8_t seed[32] = nullptr);

/**
 * Sign a message with ML-DSA-65.
 *
 * @param[out] sig      Signature (3,293 bytes)
 * @param[in]  msg      Message bytes (any length)
 * @param[in]  msg_len  Length of message
 * @param[in]  sk       Secret key (4,000 bytes)
 * @return true on success.
 *
 * ML-DSA signing is deterministic by default (FIPS 204 hedged mode uses
 * a 32-byte random value rnd; we use all-zero rnd for determinism).
 * Pass rnd != nullptr for hedged (randomised) signing.
 */
[[nodiscard]] bool MLDSA_Sign(
    MLDSASignature& sig,
    const uint8_t* msg,
    size_t msg_len,
    const MLDSASecretKey& sk,
    const uint8_t rnd[32] = nullptr);

/**
 * Verify an ML-DSA-65 signature.
 *
 * @param[in] sig      Signature (3,293 bytes)
 * @param[in] msg      Message bytes
 * @param[in] msg_len  Length of message
 * @param[in] pk       Public key (1,952 bytes)
 * @return true if the signature is valid, false otherwise.
 *
 * This function is safe to call with untrusted inputs. It will return false
 * (not throw or crash) on any malformed input. Constant-time with respect to
 * all secret data.
 */
[[nodiscard]] bool MLDSA_Verify(
    const MLDSASignature& sig,
    const uint8_t* msg,
    size_t msg_len,
    const MLDSAPublicKey& pk);

/**
 * Convenience overloads for span-based callers (consensus code).
 */
[[nodiscard]] bool MLDSA_Verify(
    std::span<const uint8_t, MLDSA_SIG_SIZE>    sig,
    std::span<const uint8_t>                     msg,
    std::span<const uint8_t, MLDSA_PUBKEY_SIZE>  pk);

#endif // BITCOIN_CRYPTO_MLDSA_H
