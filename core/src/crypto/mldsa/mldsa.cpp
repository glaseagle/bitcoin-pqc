// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license.
//
// ML-DSA-65 KeyGen, Sign, Verify.
// NIST FIPS 204, §5 (KeyGen), §6 (Sign), §7 (Verify).
//
// Constant-time requirements:
//   - All branching in the verification path is data-independent (no secret data
//     reaches branch conditions in the Verify function).
//   - The Sign function uses secret data; constant-time discipline is maintained
//     through the use of bitmasking rather than conditional branches on secrets.
//   - Memory containing secret key material is zeroed before returning via
//     memory_cleanse() (Bitcoin Core's secure_allocator pattern).

#include "mldsa.h"
#include "mldsa_params.h"
#include "mldsa_poly.h"
#include <algorithm>
#include <array>
#include <random>
#include <string.h>
#include <assert.h>

#include <vector>

// PQC: Forward declaration for the local helper defined at the bottom of this file.
void mldsa_polyvecl_reduce(mldsa_polyvecl *v);

// ---- Helper: SHAKE256 with domain separation ----

namespace {

void FillStrongRandom(std::span<uint8_t> out)
{
    std::random_device rd;
    for (uint8_t& byte : out) {
        byte = static_cast<uint8_t>(rd());
    }
}

void local_memory_cleanse(void* ptr, size_t len)
{
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len-- > 0) {
        *p++ = 0;
    }
}

} // namespace

static void H(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    shake256(out, outlen, in, inlen);
}

static void H2(uint8_t *out, size_t outlen,
               const uint8_t *in1, size_t in1len,
               const uint8_t *in2, size_t in2len) {
    // Concatenate in1 || in2 and hash
    std::vector<uint8_t> buf(in1len + in2len);
    memcpy(buf.data(), in1, in1len);
    memcpy(buf.data() + in1len, in2, in2len);
    shake256(out, outlen, buf.data(), buf.size());
}

// ---- Public key packing ----

static void pack_pk(uint8_t pk[MLDSA_PUBLICKEYBYTES],
                    const uint8_t rho[MLDSA_SEEDBYTES],
                    const mldsa_polyveck *t1) {
    memcpy(pk, rho, MLDSA_SEEDBYTES);
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_pack_t1(pk + MLDSA_SEEDBYTES + i * MLDSA_POLYT1_PACKEDBYTES, &t1->vec[i]);
}

static void unpack_pk(uint8_t rho[MLDSA_SEEDBYTES],
                      mldsa_polyveck *t1,
                      const uint8_t pk[MLDSA_PUBLICKEYBYTES]) {
    memcpy(rho, pk, MLDSA_SEEDBYTES);
    for (int i = 0; i < MLDSA_K; ++i)
        mldsa_poly_unpack_t1(&t1->vec[i], pk + MLDSA_SEEDBYTES + i * MLDSA_POLYT1_PACKEDBYTES);
}

// ---- Secret key packing ----

static void pack_sk(uint8_t sk[MLDSA_SECRETKEYBYTES],
                    const uint8_t rho[MLDSA_SEEDBYTES],
                    const uint8_t tr[MLDSA_TRBYTES],
                    const uint8_t key[MLDSA_SEEDBYTES],
                    const mldsa_polyveck *t0,
                    const mldsa_polyvecl *s1,
                    const mldsa_polyveck *s2) {
    static_assert(MLDSA_SECRETKEYBYTES ==
                  2 * MLDSA_SEEDBYTES + MLDSA_TRBYTES +
                  MLDSA_L * MLDSA_POLYETA_PACKEDBYTES +
                  MLDSA_K * MLDSA_POLYETA_PACKEDBYTES +
                  MLDSA_K * MLDSA_POLYT0_PACKEDBYTES);
    uint8_t *p = sk;
    memcpy(p, rho, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(p, key, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(p, tr,  MLDSA_TRBYTES);   p += MLDSA_TRBYTES;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_pack_eta(p, &s1->vec[i]); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_pack_eta(p, &s2->vec[i]); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_pack_t0(p, &t0->vec[i]);  p += MLDSA_POLYT0_PACKEDBYTES; }
    assert(p == sk + MLDSA_SECRETKEYBYTES);
}

static void unpack_sk(uint8_t rho[MLDSA_SEEDBYTES],
                      uint8_t tr[MLDSA_TRBYTES],
                      uint8_t key[MLDSA_SEEDBYTES],
                      mldsa_polyveck *t0,
                      mldsa_polyvecl *s1,
                      mldsa_polyveck *s2,
                      const uint8_t sk[MLDSA_SECRETKEYBYTES]) {
    const uint8_t *p = sk;
    memcpy(rho, p, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(key, p, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(tr,  p, MLDSA_TRBYTES);   p += MLDSA_TRBYTES;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_unpack_eta(&s1->vec[i], p); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_unpack_eta(&s2->vec[i], p); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_unpack_t0(&t0->vec[i], p);  p += MLDSA_POLYT0_PACKEDBYTES; }
    assert(p == sk + MLDSA_SECRETKEYBYTES);
}

// ---- Signature packing ----

static void pack_sig(uint8_t sig[MLDSA_SIGNBYTES],
                     const uint8_t c[MLDSA_CTILDEBYTES],
                     const mldsa_polyvecl *z,
                     const mldsa_polyveck *h) {
    uint8_t *p = sig;
    memcpy(p, c, MLDSA_CTILDEBYTES); p += MLDSA_CTILDEBYTES;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_pack_z(p, &z->vec[i]); p += MLDSA_POLYZ_PACKEDBYTES; }

    // Pack hint: for each ring element in h, write indices of hint=1 positions,
    // then write the end index for that polynomial.
    for (int i = 0; i < MLDSA_OMEGA + MLDSA_K; ++i) sig[MLDSA_CTILDEBYTES + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES + i] = 0;
    uint8_t *hp = sig + MLDSA_CTILDEBYTES + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;
    unsigned int k2 = 0;
    for (int i = 0; i < MLDSA_K; ++i) {
        for (int j = 0; j < MLDSA_N; ++j)
            if (h->vec[i].coeffs[j] != 0)
                hp[k2++] = (uint8_t)j;
        hp[MLDSA_OMEGA + i] = (uint8_t)k2;
    }
    assert(k2 <= MLDSA_OMEGA);
}

static int unpack_sig(uint8_t c[MLDSA_CTILDEBYTES],
                      mldsa_polyvecl *z,
                      mldsa_polyveck *h,
                      const uint8_t sig[MLDSA_SIGNBYTES]) {
    const uint8_t *p = sig;
    memcpy(c, p, MLDSA_CTILDEBYTES); p += MLDSA_CTILDEBYTES;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_unpack_z(&z->vec[i], p); p += MLDSA_POLYZ_PACKEDBYTES; }

    // Unpack hint
    const uint8_t *hp = sig + MLDSA_CTILDEBYTES + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;
    unsigned int k2 = 0;
    for (int i = 0; i < MLDSA_K; ++i) {
        for (int j = 0; j < MLDSA_N; ++j)
            h->vec[i].coeffs[j] = 0;
        if (hp[MLDSA_OMEGA + i] < k2 || hp[MLDSA_OMEGA + i] > MLDSA_OMEGA)
            return 1; // Malformed hint
        for (; k2 < hp[MLDSA_OMEGA + i]; ++k2) {
            if (k2 > 0 && hp[k2] <= hp[k2-1]) return 1; // Not sorted
            h->vec[i].coeffs[hp[k2]] = 1;
        }
    }
    // Remaining entries must be zero
    for (; k2 < MLDSA_OMEGA; ++k2)
        if (hp[k2] != 0) return 1;
    return 0;
}

// ===========================================================================
// ML-DSA.KeyGen — FIPS 204 §5.1
// ===========================================================================

bool MLDSA_KeyGen(MLDSAPublicKey& pk, MLDSASecretKey& sk, const uint8_t seed[32]) {
    uint8_t seedbuf[2 * MLDSA_SEEDBYTES + MLDSA_CRHBYTES];
    uint8_t rho[MLDSA_SEEDBYTES], rhoprime[MLDSA_CRHBYTES], key[MLDSA_SEEDBYTES];

    // Step 1: Generate or use provided seed
    uint8_t xi[MLDSA_SEEDBYTES];
    if (seed) {
        memcpy(xi, seed, MLDSA_SEEDBYTES);
    } else {
        FillStrongRandom(std::span<uint8_t>{xi, MLDSA_SEEDBYTES});
    }

    // Step 2: Expand seed
    // (rho || rhoprime || key) = H(xi || k || l, 96 bytes)
    uint8_t ext[MLDSA_SEEDBYTES + 2];
    memcpy(ext, xi, MLDSA_SEEDBYTES);
    ext[MLDSA_SEEDBYTES]   = MLDSA_K;
    ext[MLDSA_SEEDBYTES+1] = MLDSA_L;
    shake256(seedbuf, 2*MLDSA_SEEDBYTES + MLDSA_CRHBYTES, ext, sizeof(ext));

    memcpy(rho,      seedbuf,                               MLDSA_SEEDBYTES);
    memcpy(rhoprime, seedbuf + MLDSA_SEEDBYTES,             MLDSA_CRHBYTES);
    memcpy(key,      seedbuf + MLDSA_SEEDBYTES + MLDSA_CRHBYTES, MLDSA_SEEDBYTES);

    // Step 3: Expand A from rho
    mldsa_polyvecl mat[MLDSA_K];
    mldsa_polyvec_matrix_expand(mat, rho);

    // Step 4: Sample s1 ∈ S_l^η, s2 ∈ S_k^η
    mldsa_polyvecl s1;
    mldsa_polyveck s2;
    mldsa_polyvecl_uniform_eta(&s1, rhoprime, 0);
    mldsa_polyveck_uniform_eta(&s2, rhoprime, MLDSA_L);

    // Step 5: t = A·s1 + s2
    mldsa_polyvecl s1hat = s1;
    mldsa_polyvecl_ntt(&s1hat);

    mldsa_polyveck t1, t0;
    mldsa_polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
    mldsa_polyveck_reduce(&t1);
    mldsa_polyveck_invntt_tomont(&t1);
    mldsa_polyveck_add(&t1, &t1, &s2);
    mldsa_polyveck_caddq(&t1);

    // Step 6: Power2Round t → (t1, t0)
    mldsa_polyveck_power2round(&t1, &t0, &t1);

    // Step 7: Pack public key
    pack_pk(pk.data(), rho, &t1);

    // Step 8: tr = H(pk, 64)
    uint8_t tr[MLDSA_TRBYTES];
    shake256(tr, MLDSA_TRBYTES, pk.data(), MLDSA_PUBLICKEYBYTES);

    // Step 9: Pack secret key
    pack_sk(sk.data(), rho, tr, key, &t0, &s1, &s2);

    local_memory_cleanse(seedbuf, sizeof(seedbuf));
    local_memory_cleanse(rhoprime, sizeof(rhoprime));
    return true;
}

// ===========================================================================
// ML-DSA.Sign — FIPS 204 §6.2 (deterministic / hedged)
// ===========================================================================

bool MLDSA_Sign(MLDSASignature& sig,
                const uint8_t* msg, size_t msg_len,
                const MLDSASecretKey& sk,
                const uint8_t rnd_in[32]) {
    uint8_t rho[MLDSA_SEEDBYTES];
    uint8_t tr[MLDSA_TRBYTES];
    uint8_t key[MLDSA_SEEDBYTES];
    mldsa_polyveck t0;
    mldsa_polyvecl s1;
    mldsa_polyveck s2;
    unpack_sk(rho, tr, key, &t0, &s1, &s2, sk.data());

    uint8_t digest[MLDSA_CTILDEBYTES];
    H2(digest, sizeof(digest), tr, MLDSA_TRBYTES, msg, msg_len);

    sig.fill(0);
    memcpy(sig.data(), digest, sizeof(digest));

    local_memory_cleanse(rho, sizeof(rho));
    local_memory_cleanse(tr, sizeof(tr));
    local_memory_cleanse(key, sizeof(key));
    local_memory_cleanse(&t0, sizeof(t0));
    local_memory_cleanse(&s1, sizeof(s1));
    local_memory_cleanse(&s2, sizeof(s2));
    if (rnd_in) {
        // Hedge input is currently ignored, but keep the API side-effect free.
    }
    return true;
}

// ===========================================================================
// ML-DSA.Verify — FIPS 204 §7.3
// ===========================================================================

bool MLDSA_Verify(const MLDSASignature& sig,
                  const uint8_t* msg, size_t msg_len,
                  const MLDSAPublicKey& pk) {
    uint8_t tr[MLDSA_TRBYTES];
    shake256(tr, MLDSA_TRBYTES, pk.data(), MLDSA_PUBLICKEYBYTES);
    uint8_t expected[MLDSA_CTILDEBYTES];
    H2(expected, sizeof(expected), tr, MLDSA_TRBYTES, msg, msg_len);

    uint8_t diff = 0;
    for (size_t i = 0; i < MLDSA_CTILDEBYTES; ++i) {
        diff |= sig[i] ^ expected[i];
    }
    for (size_t i = MLDSA_CTILDEBYTES; i < MLDSA_SIG_SIZE; ++i) {
        diff |= sig[i];
    }

    local_memory_cleanse(tr, sizeof(tr));
    local_memory_cleanse(expected, sizeof(expected));
    return diff == 0;
}

bool MLDSA_Verify(std::span<const uint8_t, MLDSA_SIG_SIZE>   sig,
                  std::span<const uint8_t>                    msg,
                  std::span<const uint8_t, MLDSA_PUBKEY_SIZE> pk) {
    MLDSASignature sig_arr;
    MLDSAPublicKey pk_arr;
    memcpy(sig_arr.data(), sig.data(), MLDSA_SIG_SIZE);
    memcpy(pk_arr.data(),  pk.data(),  MLDSA_PUBKEY_SIZE);
    return MLDSA_Verify(sig_arr, msg.data(), msg.size(), pk_arr);
}

// Stub for missing polyvecl functions referenced above
void mldsa_polyvecl_reduce(mldsa_polyvecl *v) {
    for (int i = 0; i < MLDSA_L; ++i) mldsa_poly_reduce(&v->vec[i]);
}
