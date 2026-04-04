// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// ML-DSA-65 (CRYSTALS-Dilithium3) parameter set.
// NIST FIPS 204, August 2024, Table 2.

#ifndef BITCOIN_CRYPTO_MLDSA_PARAMS_H
#define BITCOIN_CRYPTO_MLDSA_PARAMS_H

#include <stdint.h>

// Ring dimension
#define MLDSA_N       256
// Prime modulus q = 2^23 - 2^13 + 1
#define MLDSA_Q       8380417
// Number of bits dropped from t
#define MLDSA_D       13
// Weight of c in signing
#define MLDSA_TAU     49
// Collision strength of commitment
#define MLDSA_LAMBDA  256
// Dimensions of A
#define MLDSA_K       6
#define MLDSA_L       5
// Bound on secret key coefficients
#define MLDSA_ETA     4
// Low-order rounding range
#define MLDSA_GAMMA1  (1 << 19)
#define MLDSA_GAMMA2  ((MLDSA_Q - 1) / 32)
// β = τ·η
#define MLDSA_BETA    196
// Maximum number of 1s in hint h
#define MLDSA_OMEGA   55

// Derived sizes (bytes)
#define MLDSA_SEEDBYTES       32
#define MLDSA_CRHBYTES        64
#define MLDSA_TRBYTES         64
#define MLDSA_RNDBYTES        32

// Polynomial pack sizes
#define MLDSA_POLYT1_PACKEDBYTES   320
#define MLDSA_POLYT0_PACKEDBYTES   416
#define MLDSA_POLYVECH_PACKEDBYTES (MLDSA_OMEGA + MLDSA_K)
#define MLDSA_POLYZ_PACKEDBYTES    640
#define MLDSA_POLYW1_PACKEDBYTES   192
#define MLDSA_POLYETA_PACKEDBYTES  128

// Key / signature sizes
#define MLDSA_PUBLICKEYBYTES  (MLDSA_SEEDBYTES + MLDSA_K * MLDSA_POLYT1_PACKEDBYTES)
#define MLDSA_SECRETKEYBYTES  (2*MLDSA_SEEDBYTES + MLDSA_TRBYTES \
                               + MLDSA_L * MLDSA_POLYETA_PACKEDBYTES \
                               + MLDSA_K * MLDSA_POLYETA_PACKEDBYTES \
                               + MLDSA_K * MLDSA_POLYT0_PACKEDBYTES)
#define MLDSA_SIGNBYTES       (MLDSA_LAMBDA/4 \
                               + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES \
                               + MLDSA_POLYVECH_PACKEDBYTES)

// Verify these match FIPS 204 Table 2
static_assert(MLDSA_PUBLICKEYBYTES == 1952, "Public key size mismatch");
static_assert(MLDSA_SIGNBYTES == 3293,      "Signature size mismatch");

// Montgomery reduction constant: 2^32 mod q
#define MLDSA_MONT  (-4186625)
// q^{-1} mod 2^32
#define MLDSA_QINV  58728449

#endif // BITCOIN_CRYPTO_MLDSA_PARAMS_H
