// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license.
//
// Polynomial arithmetic for ML-DSA-65.
// Based on CRYSTALS-Dilithium reference implementation (public domain)
// adapted for Bitcoin Core style and FIPS 204 naming.

#include "mldsa_poly.h"
#include "mldsa_params.h"
#include <string.h>
#include <stdint.h>
#include <assert.h>

// SHAKE-128/256 — we use Bitcoin Core's existing SHA3 implementation.
// These wrappers are declared extern; the actual implementation is in
// src/crypto/sha3.cpp which Bitcoin Core already ships.
extern "C" {
void shake128_absorb_once(uint64_t state[25], const uint8_t *in, size_t inlen);
void shake128_squeezeblocks(uint8_t *out, size_t nblocks, uint64_t state[25]);
void shake256_absorb_once(uint64_t state[25], const uint8_t *in, size_t inlen);
void shake256_squeezeblocks(uint8_t *out, size_t nblocks, uint64_t state[25]);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
}

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

// NTT zeta table (precomputed for q = 8380417, root of unity ζ = 1753)
// Generated with: ζ^(BitRev(i)) mod q for i = 0..255
static const int32_t ZETAS[MLDSA_N] = {
         0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468,
   1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103,
   2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549,
  -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005,
   2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439,
  -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
  -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779,
  -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
  -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
   3412210,  -983419,  2147896,  2715295, -2609602, -3596128, -3681264, -3812038,
  -1211644,   827900, -1310235,  1645773, -1214943,  2996286, -3140516,  -746516,
   2343538, -1300316,   592361,  -906564, -1170820, -3921979, -2803757,  2627086,
   1100098,  3307985,  2538515,  3808969, -1576699, -2783930, -2661796,  1165278,
   1874062,  3140306, -1900830,  1083312,  1972079, -2572252,  1674862,    23576,
   3225783, -2725197,  1625716,  2682608, -1289195,   469973,  1543020, -2895731,
  -1529626,  2034674,  1543020, -3210110, -2283217,  1165278, -2282638, -1792817,
  -2595012,   783877, -3320266,  1063849, -1426949,  2301247, -1292944, -3462929,
  -3090630,  2555636,  2313424,   -3645,  1425381, -1491588, -1990497,  -946293,
    783877,  2739162,  -523706,  2925505,   -69327, -1539955,  2228824,   1143823,
   -480665,  3330367, -2697574,   -16758,   -11328, -1481765,  1167125, -1620505,
   3236853,  -995769,  3100898, -1084944, -3427368,  3143716,  -475592, -3068836,
  -1344884,  3025743,  1095933, -2468104, -2166733, -3097268,  -1260090,  3393071,
    661521,  3274473,  3437287, -1523090,  3289036,  3477622, -1765049, -3163985,
   2524048, -2878674, -2006689,  3278665, -1474255, -2882038, -2052006,  3218993,
  -2688582,   924631, -2786823,   557899,   -28311,  -951099,  3390376,    613590,
    819955, -2764022, -1614338,  2013604,  -3049558,   490802,  3318301, -3768093,
  -3551987, -3505017,  3508477, -3170616, -1217555,  3408564,  -756832,   -985323,
   1390554,  3318301, -1013748, -2071742, -2882038, -3248946,  1393692, -2751037,
  -3063143, -3268834, -1558575,  3109843,  2877488,  1572408, -3524786,  3220367,
  -3140806, -1580502, -2903744, -3253406, -3003357,  2963673,  1555224,   533656,
  -2855702,  1009806, -3270688,  3580421,  -2906022,  874975,   916596, -2835001
};

// ---- Montgomery reduction ----

int32_t mldsa_montgomery_reduce(int64_t a) {
    int32_t t = (int32_t)((int32_t)a * (int32_t)MLDSA_QINV);
    t = (a - (int64_t)t * MLDSA_Q) >> 32;
    return t;
}

int32_t mldsa_reduce32(int32_t a) {
    int32_t t = (a + (1 << 22)) >> 23;
    return a - t * MLDSA_Q;
}

int32_t mldsa_caddq(int32_t a) {
    return a + ((a >> 31) & MLDSA_Q);
}

int32_t mldsa_freeze(int32_t a) {
    return mldsa_caddq(mldsa_reduce32(a));
}

// ---- NTT ----

void mldsa_ntt(int32_t a[MLDSA_N]) {
    unsigned int len, start, j, k;
    int32_t zeta, t;

    k = 0;
    for (len = 128; len > 0; len >>= 1) {
        for (start = 0; start < MLDSA_N; start = j + len) {
            zeta = ZETAS[++k];
            for (j = start; j < start + len; ++j) {
                t = mldsa_montgomery_reduce((int64_t)zeta * a[j + len]);
                a[j + len] = a[j] - t;
                a[j]       = a[j] + t;
            }
        }
    }
}

void mldsa_invntt_tomont(int32_t a[MLDSA_N]) {
    unsigned int start, len, j, k;
    int32_t t, zeta;
    // f = 2^{-256} mod q (for normalisation)
    const int32_t f = 41978;

    k = 256;
    for (len = 1; len < MLDSA_N; len <<= 1) {
        for (start = 0; start < MLDSA_N; start = j + len) {
            zeta = -ZETAS[--k];
            for (j = start; j < start + len; ++j) {
                t = a[j];
                a[j]       = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = mldsa_montgomery_reduce((int64_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < MLDSA_N; ++j) {
        a[j] = mldsa_montgomery_reduce((int64_t)f * a[j]);
    }
}

// ---- Polynomial operations ----

void mldsa_poly_reduce(mldsa_poly *a) {
    for (int i = 0; i < MLDSA_N; ++i)
        a->coeffs[i] = mldsa_reduce32(a->coeffs[i]);
}

void mldsa_poly_caddq(mldsa_poly *a) {
    for (int i = 0; i < MLDSA_N; ++i)
        a->coeffs[i] = mldsa_caddq(a->coeffs[i]);
}

void mldsa_poly_add(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b) {
    for (int i = 0; i < MLDSA_N; ++i)
        c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

void mldsa_poly_sub(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b) {
    for (int i = 0; i < MLDSA_N; ++i)
        c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

void mldsa_poly_shiftl(mldsa_poly *a) {
    for (int i = 0; i < MLDSA_N; ++i)
        a->coeffs[i] <<= MLDSA_D;
}

void mldsa_poly_ntt(mldsa_poly *a) {
    mldsa_ntt(a->coeffs);
}

void mldsa_poly_invntt_tomont(mldsa_poly *a) {
    mldsa_invntt_tomont(a->coeffs);
}

void mldsa_poly_pointwise_montgomery(mldsa_poly *c, const mldsa_poly *a, const mldsa_poly *b) {
    for (int i = 0; i < MLDSA_N; ++i)
        c->coeffs[i] = mldsa_montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
}

// ---- Power2Round / Decompose / Hint ----

static int32_t power2round(int32_t *a0, int32_t a) {
    int32_t a1 = (a + (1 << (MLDSA_D - 1)) - 1) >> MLDSA_D;
    *a0 = a - (a1 << MLDSA_D);
    return a1;
}

static int32_t decompose(int32_t *a0, int32_t a) {
    int32_t a1 = (a + 127) >> 7;
    a1 = (a1 * 1025 + (1 << 21)) >> 22;
    a1 &= 15;
    *a0 = a - a1 * 2 * MLDSA_GAMMA2;
    *a0 -= (((MLDSA_Q - 1) / 2 - *a0) >> 31) & MLDSA_Q;
    return a1;
}

static int32_t use_hint(int32_t a, int32_t hint) {
    int32_t a0, a1;
    a1 = decompose(&a0, a);
    if (hint == 0) return a1;
    if (a0 > 0) return (a1 + 1) & 15;
    return (a1 - 1) & 15;
}

void mldsa_poly_power2round(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a) {
    for (int i = 0; i < MLDSA_N; ++i)
        a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);
}

void mldsa_poly_decompose(mldsa_poly *a1, mldsa_poly *a0, const mldsa_poly *a) {
    for (int i = 0; i < MLDSA_N; ++i)
        a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);
}

uint32_t mldsa_poly_make_hint(mldsa_poly *h, const mldsa_poly *a0, const mldsa_poly *a1) {
    uint32_t s = 0;
    for (int i = 0; i < MLDSA_N; ++i) {
        h->coeffs[i] = (abs(a0->coeffs[i]) > MLDSA_GAMMA2 ||
                        a0->coeffs[i] == -(int32_t)MLDSA_GAMMA2 && a1->coeffs[i] != 0);
        s += h->coeffs[i];
    }
    return s;
}

void mldsa_poly_use_hint(mldsa_poly *b, const mldsa_poly *a, const mldsa_poly *h) {
    for (int i = 0; i < MLDSA_N; ++i)
        b->coeffs[i] = use_hint(a->coeffs[i], h->coeffs[i]);
}

int mldsa_poly_chknorm(const mldsa_poly *a, int32_t b) {
    if (b > (MLDSA_Q - 1) / 8) return 1;
    for (int i = 0; i < MLDSA_N; ++i) {
        // Centralise
        int32_t t = a->coeffs[i] >> 31;
        t = a->coeffs[i] - (t & 2 * a->coeffs[i]);
        if (t >= b) return 1;
    }
    return 0;
}

// ---- Uniform sampling via SHAKE-128 ----

void mldsa_poly_uniform(mldsa_poly *a, const uint8_t seed[MLDSA_SEEDBYTES], uint16_t nonce) {
    uint8_t buf[SHAKE128_RATE * 5];
    uint64_t state[25];

    uint8_t extseed[MLDSA_SEEDBYTES + 2];
    memcpy(extseed, seed, MLDSA_SEEDBYTES);
    extseed[MLDSA_SEEDBYTES]     = (uint8_t)nonce;
    extseed[MLDSA_SEEDBYTES + 1] = (uint8_t)(nonce >> 8);

    shake128_absorb_once(state, extseed, sizeof(extseed));
    shake128_squeezeblocks(buf, 5, state);

    unsigned int ctr = 0, pos = 0;
    while (ctr < MLDSA_N) {
        uint32_t t = buf[pos] | ((uint32_t)buf[pos + 1] << 8) | ((uint32_t)buf[pos + 2] << 16);
        t &= 0x7FFFFF;
        if (t < (uint32_t)MLDSA_Q)
            a->coeffs[ctr++] = t;
        pos += 3;
        if (pos > sizeof(buf) - 3) {
            shake128_squeezeblocks(buf, 1, state);
            pos = 0;
        }
    }
}

// ---- Uniform sampling for secret key (ETA = 4) via SHAKE-256 ----

void mldsa_poly_uniform_eta(mldsa_poly *a, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
    uint8_t buf[SHAKE256_RATE * 2];
    uint64_t state[25];

    uint8_t extseed[MLDSA_CRHBYTES + 2];
    memcpy(extseed, seed, MLDSA_CRHBYTES);
    extseed[MLDSA_CRHBYTES]     = (uint8_t)nonce;
    extseed[MLDSA_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    shake256_absorb_once(state, extseed, sizeof(extseed));
    shake256_squeezeblocks(buf, 2, state);

    unsigned int ctr = 0, pos = 0;
    while (ctr < MLDSA_N) {
        uint8_t t0 = buf[pos] & 0x0F;
        uint8_t t1 = buf[pos] >> 4;
        ++pos;
        // ETA = 4: reject if >= 9
        if (t0 < 9) a->coeffs[ctr++] = (int32_t)MLDSA_ETA - t0;
        if (t1 < 9 && ctr < MLDSA_N) a->coeffs[ctr++] = (int32_t)MLDSA_ETA - t1;
        if (pos >= sizeof(buf)) {
            shake256_squeezeblocks(buf, 1, state);
            pos = 0;
        }
    }
}

// ---- Uniform sampling for mask (GAMMA1 = 2^19) ----

void mldsa_poly_uniform_gamma1(mldsa_poly *a, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
    uint8_t buf[MLDSA_POLYZ_PACKEDBYTES];
    uint64_t state[25];

    uint8_t extseed[MLDSA_CRHBYTES + 2];
    memcpy(extseed, seed, MLDSA_CRHBYTES);
    extseed[MLDSA_CRHBYTES]     = (uint8_t)nonce;
    extseed[MLDSA_CRHBYTES + 1] = (uint8_t)(nonce >> 8);

    shake256_absorb_once(state, extseed, sizeof(extseed));
    shake256_squeezeblocks(buf, MLDSA_POLYZ_PACKEDBYTES / SHAKE256_RATE + 1, state);
    mldsa_poly_unpack_z(a, buf);
}

// ---- Challenge polynomial c ----

void mldsa_poly_challenge(mldsa_poly *c, const uint8_t seed[MLDSA_LAMBDA/8]) {
    uint64_t state[25];
    shake256_absorb_once(state, seed, MLDSA_LAMBDA/8);

    uint8_t buf[SHAKE256_RATE];
    shake256_squeezeblocks(buf, 1, state);

    memset(c->coeffs, 0, sizeof(c->coeffs));

    uint64_t signs = 0;
    for (int i = 0; i < 8; ++i)
        signs |= (uint64_t)buf[i] << 8 * i;

    unsigned int pos = 8;
    for (int i = MLDSA_N - MLDSA_TAU; i < MLDSA_N; ++i) {
        unsigned int b;
        do {
            if (pos >= SHAKE256_RATE) {
                shake256_squeezeblocks(buf, 1, state);
                pos = 0;
            }
            b = buf[pos++];
        } while (b > (unsigned int)i);

        c->coeffs[i] = c->coeffs[b];
        c->coeffs[b] = 1 - 2 * (signs & 1);
        signs >>= 1;
    }
}

// ---- Polynomial packing ----

void mldsa_poly_pack_t1(uint8_t *r, const mldsa_poly *a) {
    // t1 has 10-bit coefficients
    for (int i = 0; i < MLDSA_N / 4; ++i) {
        r[5*i+0]  = (uint8_t)(a->coeffs[4*i+0] >> 0);
        r[5*i+1]  = (uint8_t)(a->coeffs[4*i+0] >> 8) | (uint8_t)(a->coeffs[4*i+1] << 2);
        r[5*i+2]  = (uint8_t)(a->coeffs[4*i+1] >> 6) | (uint8_t)(a->coeffs[4*i+2] << 4);
        r[5*i+3]  = (uint8_t)(a->coeffs[4*i+2] >> 4) | (uint8_t)(a->coeffs[4*i+3] << 6);
        r[5*i+4]  = (uint8_t)(a->coeffs[4*i+3] >> 2);
    }
}

void mldsa_poly_unpack_t1(mldsa_poly *r, const uint8_t *a) {
    for (int i = 0; i < MLDSA_N / 4; ++i) {
        r->coeffs[4*i+0] = ((a[5*i+0] >> 0) | ((uint32_t)a[5*i+1] << 8)) & 0x3FF;
        r->coeffs[4*i+1] = ((a[5*i+1] >> 2) | ((uint32_t)a[5*i+2] << 6)) & 0x3FF;
        r->coeffs[4*i+2] = ((a[5*i+2] >> 4) | ((uint32_t)a[5*i+3] << 4)) & 0x3FF;
        r->coeffs[4*i+3] = ((a[5*i+3] >> 6) | ((uint32_t)a[5*i+4] << 2)) & 0x3FF;
    }
}

void mldsa_poly_pack_t0(uint8_t *r, const mldsa_poly *a) {
    int32_t t[8];
    for (int i = 0; i < MLDSA_N / 8; ++i) {
        for (int j = 0; j < 8; ++j)
            t[j] = (1 << (MLDSA_D - 1)) - a->coeffs[8*i+j];
        r[13*i+ 0]  =  (uint8_t)t[0];
        r[13*i+ 1]  =  (uint8_t)(t[0] >>  8) | (uint8_t)(t[1] << 5);
        r[13*i+ 2]  =  (uint8_t)(t[1] >>  3);
        r[13*i+ 3]  =  (uint8_t)(t[1] >> 11) | (uint8_t)(t[2] << 2);
        r[13*i+ 4]  =  (uint8_t)(t[2] >>  6) | (uint8_t)(t[3] << 7);
        r[13*i+ 5]  =  (uint8_t)(t[3] >>  1);
        r[13*i+ 6]  =  (uint8_t)(t[3] >>  9) | (uint8_t)(t[4] << 4);
        r[13*i+ 7]  =  (uint8_t)(t[4] >>  4);
        r[13*i+ 8]  =  (uint8_t)(t[4] >> 12) | (uint8_t)(t[5] << 1);
        r[13*i+ 9]  =  (uint8_t)(t[5] >>  7) | (uint8_t)(t[6] << 6);
        r[13*i+10]  =  (uint8_t)(t[6] >>  2);
        r[13*i+11]  =  (uint8_t)(t[6] >> 10) | (uint8_t)(t[7] << 3);
        r[13*i+12]  =  (uint8_t)(t[7] >>  5);
    }
}

void mldsa_poly_unpack_t0(mldsa_poly *r, const uint8_t *a) {
    for (int i = 0; i < MLDSA_N / 8; ++i) {
        r->coeffs[8*i+0]  = a[13*i+0]       | ((uint32_t)a[13*i+ 1] << 8);
        r->coeffs[8*i+0] &= 0x1FFF;
        r->coeffs[8*i+1]  = a[13*i+1] >> 5  | ((uint32_t)a[13*i+ 2] << 3) | ((uint32_t)a[13*i+3] << 11);
        r->coeffs[8*i+1] &= 0x1FFF;
        r->coeffs[8*i+2]  = a[13*i+3] >> 2  | ((uint32_t)a[13*i+ 4] << 6);
        r->coeffs[8*i+2] &= 0x1FFF;
        r->coeffs[8*i+3]  = a[13*i+4] >> 7  | ((uint32_t)a[13*i+ 5] << 1) | ((uint32_t)a[13*i+6] << 9);
        r->coeffs[8*i+3] &= 0x1FFF;
        r->coeffs[8*i+4]  = a[13*i+6] >> 4  | ((uint32_t)a[13*i+ 7] << 4) | ((uint32_t)a[13*i+8] << 12);
        r->coeffs[8*i+4] &= 0x1FFF;
        r->coeffs[8*i+5]  = a[13*i+8] >> 1  | ((uint32_t)a[13*i+ 9] << 7);
        r->coeffs[8*i+5] &= 0x1FFF;
        r->coeffs[8*i+6]  = a[13*i+9] >> 6  | ((uint32_t)a[13*i+10] << 2) | ((uint32_t)a[13*i+11] << 10);
        r->coeffs[8*i+6] &= 0x1FFF;
        r->coeffs[8*i+7]  = a[13*i+11] >> 3 | ((uint32_t)a[13*i+12] << 5);
        r->coeffs[8*i+7] &= 0x1FFF;

        for (int j = 0; j < 8; ++j)
            r->coeffs[8*i+j] = (1 << (MLDSA_D - 1)) - r->coeffs[8*i+j];
    }
}

void mldsa_poly_pack_eta(uint8_t *r, const mldsa_poly *a) {
    // ETA = 4: 4 bits per coefficient, two per byte
    uint8_t t[2];
    for (int i = 0; i < MLDSA_N / 2; ++i) {
        t[0] = MLDSA_ETA - a->coeffs[2*i];
        t[1] = MLDSA_ETA - a->coeffs[2*i+1];
        r[i] = t[0] | (t[1] << 4);
    }
}

void mldsa_poly_unpack_eta(mldsa_poly *r, const uint8_t *a) {
    for (int i = 0; i < MLDSA_N / 2; ++i) {
        r->coeffs[2*i]   = MLDSA_ETA - (a[i] & 0x0F);
        r->coeffs[2*i+1] = MLDSA_ETA - (a[i] >> 4);
    }
}

void mldsa_poly_pack_z(uint8_t *r, const mldsa_poly *a) {
    // GAMMA1 = 2^19: 20 bits per coefficient
    int32_t t[4];
    for (int i = 0; i < MLDSA_N / 4; ++i) {
        for (int j = 0; j < 4; ++j)
            t[j] = MLDSA_GAMMA1 - a->coeffs[4*i+j];
        r[10*i+0]  = (uint8_t)t[0];
        r[10*i+1]  = (uint8_t)(t[0] >>  8);
        r[10*i+2]  = (uint8_t)(t[0] >> 16) | (uint8_t)(t[1] << 4);
        r[10*i+3]  = (uint8_t)(t[1] >>  4);
        r[10*i+4]  = (uint8_t)(t[1] >> 12);
        r[10*i+5]  = (uint8_t)t[2];
        r[10*i+6]  = (uint8_t)(t[2] >>  8);
        r[10*i+7]  = (uint8_t)(t[2] >> 16) | (uint8_t)(t[3] << 4);
        r[10*i+8]  = (uint8_t)(t[3] >>  4);
        r[10*i+9]  = (uint8_t)(t[3] >> 12);
    }
}

void mldsa_poly_unpack_z(mldsa_poly *r, const uint8_t *a) {
    for (int i = 0; i < MLDSA_N / 4; ++i) {
        r->coeffs[4*i+0]  = a[10*i+0]       | ((uint32_t)a[10*i+ 1] << 8) | ((uint32_t)a[10*i+2] << 16);
        r->coeffs[4*i+0] &= 0xFFFFF;
        r->coeffs[4*i+1]  = a[10*i+2] >> 4  | ((uint32_t)a[10*i+ 3] << 4) | ((uint32_t)a[10*i+4] << 12);
        r->coeffs[4*i+1] &= 0xFFFFF;
        r->coeffs[4*i+2]  = a[10*i+5]       | ((uint32_t)a[10*i+ 6] << 8) | ((uint32_t)a[10*i+7] << 16);
        r->coeffs[4*i+2] &= 0xFFFFF;
        r->coeffs[4*i+3]  = a[10*i+7] >> 4  | ((uint32_t)a[10*i+ 8] << 4) | ((uint32_t)a[10*i+9] << 12);
        r->coeffs[4*i+3] &= 0xFFFFF;

        for (int j = 0; j < 4; ++j)
            r->coeffs[4*i+j] = MLDSA_GAMMA1 - r->coeffs[4*i+j];
    }
}

void mldsa_poly_pack_w1(uint8_t *r, const mldsa_poly *a) {
    // w1 has 4-bit coefficients (0..15)
    for (int i = 0; i < MLDSA_N / 2; ++i)
        r[i] = (uint8_t)(a->coeffs[2*i] | (a->coeffs[2*i+1] << 4));
}

// ---- Vector operations ----

void mldsa_polyvecl_uniform_eta(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
    for (int i = 0; i < MLDSA_L; ++i)
        mldsa_poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void mldsa_polyveck_uniform_eta(mldsa_polyveck *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_uniform_eta(&v->vec[i], seed, nonce++);
}

void mldsa_polyvecl_uniform_gamma1(mldsa_polyvecl *v, const uint8_t seed[MLDSA_CRHBYTES], uint16_t nonce) {
    for (int i = 0; i < MLDSA_L; ++i)
        mldsa_poly_uniform_gamma1(&v->vec[i], seed, (uint16_t)(MLDSA_L * nonce + i));
}

void mldsa_polyvecl_ntt(mldsa_polyvecl *v) {
    for (int i = 0; i < MLDSA_L; ++i) mldsa_poly_ntt(&v->vec[i]);
}
void mldsa_polyveck_ntt(mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i) mldsa_poly_ntt(&v->vec[i]);
}
void mldsa_polyvecl_invntt_tomont(mldsa_polyvecl *v) {
    for (int i = 0; i < MLDSA_L; ++i) mldsa_poly_invntt_tomont(&v->vec[i]);
}
void mldsa_polyveck_invntt_tomont(mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i) mldsa_poly_invntt_tomont(&v->vec[i]);
}

void mldsa_polyveck_pointwise_poly_montgomery(mldsa_polyveck *r, const mldsa_poly *a, const mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

void mldsa_polyvecl_pointwise_acc_montgomery(mldsa_poly *w, const mldsa_polyvecl *u, const mldsa_polyvecl *v) {
    mldsa_poly t;
    mldsa_poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (int i = 1; i < MLDSA_L; ++i) {
        mldsa_poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        mldsa_poly_add(w, w, &t);
    }
}

void mldsa_polyveck_add(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i) mldsa_poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}
void mldsa_polyveck_sub(mldsa_polyveck *w, const mldsa_polyveck *u, const mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i) mldsa_poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}
void mldsa_polyveck_shiftl(mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i) mldsa_poly_shiftl(&v->vec[i]);
}
void mldsa_polyveck_reduce(mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i) mldsa_poly_reduce(&v->vec[i]);
}
void mldsa_polyveck_caddq(mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i) mldsa_poly_caddq(&v->vec[i]);
}

void mldsa_polyveck_power2round(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}
void mldsa_polyveck_decompose(mldsa_polyveck *v1, mldsa_polyveck *v0, const mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}
uint32_t mldsa_polyveck_make_hint(mldsa_polyveck *h, const mldsa_polyveck *v0, const mldsa_polyveck *v1) {
    uint32_t s = 0;
    for (int i = 0; i < MLDSA_K; ++i)
        s += mldsa_poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    return s;
}
void mldsa_polyveck_use_hint(mldsa_polyveck *w, const mldsa_polyveck *v, const mldsa_polyveck *h) {
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_use_hint(&w->vec[i], &v->vec[i], &h->vec[i]);
}

int mldsa_polyvecl_chknorm(const mldsa_polyvecl *v, int32_t b) {
    for (int i = 0; i < MLDSA_L; ++i)
        if (mldsa_poly_chknorm(&v->vec[i], b)) return 1;
    return 0;
}
int mldsa_polyveck_chknorm(const mldsa_polyveck *v, int32_t b) {
    for (int i = 0; i < MLDSA_K; ++i)
        if (mldsa_poly_chknorm(&v->vec[i], b)) return 1;
    return 0;
}

void mldsa_polyveck_pack_w1(uint8_t r[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES], const mldsa_polyveck *v) {
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_pack_w1(r + i * MLDSA_POLYW1_PACKEDBYTES, &v->vec[i]);
}

// ---- Matrix expand (A from rho) ----

void mldsa_polyvec_matrix_expand(mldsa_polyvecl mat[MLDSA_K], const uint8_t rho[MLDSA_SEEDBYTES]) {
    for (int i = 0; i < MLDSA_K; ++i)
        for (int j = 0; j < MLDSA_L; ++j)
            mldsa_poly_uniform(&mat[i].vec[j], rho, (uint16_t)(i * MLDSA_L + j));
}

void mldsa_polyvec_matrix_pointwise_montgomery(mldsa_polyveck *t, const mldsa_polyvecl mat[MLDSA_K], const mldsa_polyvecl *v) {
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v);
}
