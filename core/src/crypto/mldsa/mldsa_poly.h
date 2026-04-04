// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license.
//
// Polynomial types and operations for ML-DSA-65.
// Polynomials are elements of Z_q[X]/(X^256 + 1).

#ifndef BITCOIN_CRYPTO_MLDSA_POLY_H
#define BITCOIN_CRYPTO_MLDSA_POLY_H

#include <stdint.h>
#include <stddef.h>
#include "mldsa_params.h"

typedef struct {
    int32_t coeffs[MLDSA_N];
} mldsa_poly;

// Vectors of polynomials
typedef struct { mldsa_poly vec[MLDSA_L]; } mldsa_polyvecl;
typedef struct { mldsa_poly vec[MLDSA_K]; } mldsa_polyveck;

// ---- Reduction ----
int32_t mldsa_montgomery_reduce(int64_t a);
int32_t mldsa_reduce32(int32_t a);
int32_t mldsa_caddq(int32_t a);
int32_t mldsa_freeze(int32_t a);

// ---- NTT ----
void mldsa_ntt(int32_t a[MLDSA_N]);
void mldsa_invntt_tomont(int32_t a[MLDSA_N]);

// ---- Polynomial arithmetic ----
void mldsa_poly_reduce(mldsa_poly *a);
void mldsa_poly_caddq(mldsa_poly *a);
void mldsa_poly_add(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b);
void mldsa_poly_sub(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b);
void mldsa_poly_shiftl(mldsa_poly *a);
void mldsa_poly_ntt(mldsa_poly *a);
void mldsa_poly_invntt_tomont(mldsa_poly *a);
void mldsa_poly_pointwise_montgomery(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b);
void mldsa_poly_power2round(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a);
void mldsa_poly_decompose(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a);
uint32_t mldsa_poly_make_hint(mldsa_poly *h, const mldsa_poly *a0, const mldsa_poly *a1);
void mldsa_poly_use_hint(mldsa_poly *b, const mldsa_poly *a, const mldsa_poly *h);
int mldsa_poly_chknorm(const mldsa_poly *a, int32_t b);
void mldsa_poly_uniform(mldsa_poly *a, const uint8_t seed[MLDSA_SEEDBYTES], uint16_t nonce);
void mldsa_poly_uniform_eta(mldsa_poly *a, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);
void mldsa_poly_uniform_gamma1(mldsa_poly *a, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);
void mldsa_poly_challenge(mldsa_poly *c, const uint8_t seed[MLDSA_LAMBDA/8]);

// ---- Packing ----
void mldsa_poly_pack_t1(uint8_t *r, const mldsa_poly *a);
void mldsa_poly_unpack_t1(mldsa_poly *r, const uint8_t *a);
void mldsa_poly_pack_t0(uint8_t *r, const mldsa_poly *a);
void mldsa_poly_unpack_t0(mldsa_poly *r, const uint8_t *a);
void mldsa_poly_pack_eta(uint8_t *r, const mldsa_poly *a);
void mldsa_poly_unpack_eta(mldsa_poly *r, const uint8_t *a);
void mldsa_poly_pack_z(uint8_t *r, const mldsa_poly *a);
void mldsa_poly_unpack_z(mldsa_poly *r, const uint8_t *a);
void mldsa_poly_pack_w1(uint8_t *r, const mldsa_poly *a);

// ---- Vector operations ----
void mldsa_polyvecl_uniform_eta(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);
void mldsa_polyveck_uniform_eta(mldsa_polyveck *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);
void mldsa_polyvecl_uniform_gamma1(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce);
void mldsa_polyvecl_ntt(mldsa_polyvecl *v);
void mldsa_polyveck_ntt(mldsa_polyveck *v);
void mldsa_polyvecl_invntt_tomont(mldsa_polyvecl *v);
void mldsa_polyveck_invntt_tomont(mldsa_polyveck *v);
void mldsa_polyveck_pointwise_poly_montgomery(mldsa_polyveck *r, const mldsa_poly *a, const mldsa_polyveck *v);
void mldsa_polyvecl_pointwise_acc_montgomery(mldsa_poly *w, const mldsa_polyvecl *u, const mldsa_polyvecl *v);
void mldsa_polyveck_add(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v);
void mldsa_polyveck_sub(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v);
void mldsa_polyveck_shiftl(mldsa_polyveck *v);
void mldsa_polyveck_reduce(mldsa_polyveck *v);
void mldsa_polyveck_caddq(mldsa_polyveck *v);
void mldsa_polyveck_power2round(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v);
void mldsa_polyveck_decompose(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v);
uint32_t mldsa_polyveck_make_hint(mldsa_polyveck *h, const mldsa_polyveck *v0, const mldsa_polyveck *v1);
void mldsa_polyveck_use_hint(mldsa_polyveck *w, const mldsa_polyveck *v, const mldsa_polyveck *h);
int mldsa_polyvecl_chknorm(const mldsa_polyvecl *v, int32_t b);
int mldsa_polyveck_chknorm(const mldsa_polyveck *v, int32_t b);
void mldsa_polyveck_pack_w1(uint8_t r[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES], const mldsa_polyveck *v);

// Matrix-vector multiplication: w = A*v (all in NTT domain)
void mldsa_polyvec_matrix_expand(mldsa_polyvecl mat[MLDSA_K], const uint8_t rho[MLDSA_SEEDBYTES]);
void mldsa_polyvec_matrix_pointwise_montgomery(mldsa_polyveck *t, const mldsa_polyvecl mat[MLDSA_K], const mldsa_polyvecl *v);

#endif // BITCOIN_CRYPTO_MLDSA_POLY_H
