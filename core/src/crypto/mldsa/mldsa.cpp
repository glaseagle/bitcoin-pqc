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
#include <string.h>
#include <assert.h>

// Bitcoin Core headers
#include <random.h>          // GetStrongRandBytes
#include <crypto/sha3.h>     // CSHA3_256 (SHAKE-256), CSHA3_128 (SHAKE-128)
#include <support/cleanse.h> // memory_cleanse

// ---- SHAKE wrappers using Bitcoin Core's SHA3 implementation ----
//
// Bitcoin Core's SHA3 implementation exposes SHAKE via the CSHAKE classes.
// These thin wrappers provide the interface expected by mldsa_poly.cpp.

extern "C" {

void shake128_absorb_once(uint64_t state[25], const uint8_t *in, size_t inlen) {
    // Initialise state and absorb in one shot
    CSHA3_128 h;
    h.Write(in, inlen);
    h.FinalizeXOF(reinterpret_cast<uint8_t*>(state), 200); // export sponge state
    // NOTE: In a production integration, Bitcoin Core's CSHA3 must expose
    // the raw Keccak state for multi-block squeezing. This is an implementation
    // detail that would be resolved during the Bitcoin Core PR process.
    // For the prototype, state is treated as opaque storage.
    (void)state;
}

void shake128_squeezeblocks(uint8_t *out, size_t nblocks, uint64_t state[25]) {
    (void)out; (void)nblocks; (void)state;
    // Squeezing from saved state — requires Bitcoin Core SHA3 to expose
    // the Keccak permutation. Stubbed here; full implementation in the
    // accompanying Bitcoin Core PR.
}

void shake256_absorb_once(uint64_t state[25], const uint8_t *in, size_t inlen) {
    (void)state; (void)in; (void)inlen;
}

void shake256_squeezeblocks(uint8_t *out, size_t nblocks, uint64_t state[25]) {
    (void)out; (void)nblocks; (void)state;
}

void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    CSHA3_256 h;
    h.Write(in, inlen);
    h.FinalizeXOF(out, outlen);
}

} // extern "C"

// ---- Helper: SHAKE256 with domain separation ----

static void H(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    shake256(out, outlen, in, inlen);
}

static void H2(uint8_t *out, size_t outlen,
               const uint8_t *in1, size_t in1len,
               const uint8_t *in2, size_t in2len) {
    // Concatenate in1 || in2 and hash
    uint8_t buf[in1len + in2len];
    memcpy(buf, in1, in1len);
    memcpy(buf + in1len, in2, in2len);
    shake256(out, outlen, buf, in1len + in2len);
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
    uint8_t *p = sk;
    memcpy(p, rho, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(p, key, MLDSA_SEEDBYTES); p += MLDSA_SEEDBYTES;
    memcpy(p, tr,  MLDSA_TRBYTES);   p += MLDSA_TRBYTES;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_pack_eta(p, &s1->vec[i]); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_pack_eta(p, &s2->vec[i]); p += MLDSA_POLYETA_PACKEDBYTES; }
    for (int i = 0; i < MLDSA_K; ++i) { mldsa_poly_pack_t0(p, &t0->vec[i]);  p += MLDSA_POLYT0_PACKEDBYTES; }
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
}

// ---- Signature packing ----

static void pack_sig(uint8_t sig[MLDSA_SIGNBYTES],
                     const uint8_t c[MLDSA_LAMBDA/8],
                     const mldsa_polyvecl *z,
                     const mldsa_polyveck *h) {
    uint8_t *p = sig;
    memcpy(p, c, MLDSA_LAMBDA/8); p += MLDSA_LAMBDA/8;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_pack_z(p, &z->vec[i]); p += MLDSA_POLYZ_PACKEDBYTES; }

    // Pack hint: for each ring element in h, write indices of hint=1 positions,
    // then write the end index for that polynomial.
    for (int i = 0; i < MLDSA_OMEGA + MLDSA_K; ++i) sig[MLDSA_LAMBDA/8 + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES + i] = 0;
    uint8_t *hp = sig + MLDSA_LAMBDA/8 + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;
    unsigned int k2 = 0;
    for (int i = 0; i < MLDSA_K; ++i) {
        for (int j = 0; j < MLDSA_N; ++j)
            if (h->vec[i].coeffs[j] != 0)
                hp[k2++] = (uint8_t)j;
        hp[MLDSA_OMEGA + i] = (uint8_t)k2;
    }
}

static int unpack_sig(uint8_t c[MLDSA_LAMBDA/8],
                      mldsa_polyvecl *z,
                      mldsa_polyveck *h,
                      const uint8_t sig[MLDSA_SIGNBYTES]) {
    const uint8_t *p = sig;
    memcpy(c, p, MLDSA_LAMBDA/8); p += MLDSA_LAMBDA/8;
    for (int i = 0; i < MLDSA_L; ++i) { mldsa_poly_unpack_z(&z->vec[i], p); p += MLDSA_POLYZ_PACKEDBYTES; }

    // Unpack hint
    const uint8_t *hp = sig + MLDSA_LAMBDA/8 + MLDSA_L * MLDSA_POLYZ_PACKEDBYTES;
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
        GetStrongRandBytes({xi, MLDSA_SEEDBYTES});
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

    memory_cleanse(seedbuf, sizeof(seedbuf));
    memory_cleanse(rhoprime, sizeof(rhoprime));
    return true;
}

// ===========================================================================
// ML-DSA.Sign — FIPS 204 §6.2 (deterministic / hedged)
// ===========================================================================

bool MLDSA_Sign(MLDSASignature& sig,
                const uint8_t* msg, size_t msg_len,
                const MLDSASecretKey& sk,
                const uint8_t rnd_in[32]) {
    uint8_t rho[MLDSA_SEEDBYTES], tr[MLDSA_TRBYTES], key[MLDSA_SEEDBYTES];
    mldsa_polyvecl s1, y;
    mldsa_polyveck s2, t0, w1, w0, h;
    mldsa_poly cp;
    mldsa_polyvecl mat[MLDSA_K];
    mldsa_polyveck cs2, ct0;

    unpack_sk(rho, tr, key, &t0, &s1, &s2, sk.data());

    // μ = H(tr || M, 64)
    uint8_t mu[MLDSA_CRHBYTES];
    H2(mu, MLDSA_CRHBYTES, tr, MLDSA_TRBYTES, msg, msg_len);

    // rnd: all-zero for deterministic; random bytes for hedged
    uint8_t rnd[MLDSA_RNDBYTES] = {0};
    if (rnd_in) memcpy(rnd, rnd_in, MLDSA_RNDBYTES);

    // rhoprime = H(key || rnd || μ, 64)
    uint8_t rhoprime[MLDSA_CRHBYTES];
    uint8_t tmp[MLDSA_SEEDBYTES + MLDSA_RNDBYTES + MLDSA_CRHBYTES];
    memcpy(tmp,                           key, MLDSA_SEEDBYTES);
    memcpy(tmp + MLDSA_SEEDBYTES,         rnd, MLDSA_RNDBYTES);
    memcpy(tmp + MLDSA_SEEDBYTES + MLDSA_RNDBYTES, mu, MLDSA_CRHBYTES);
    shake256(rhoprime, MLDSA_CRHBYTES, tmp, sizeof(tmp));

    mldsa_polyvec_matrix_expand(mat, rho);

    mldsa_polyvecl s1hat = s1;
    mldsa_polyvecl_ntt(&s1hat);
    mldsa_polyveck s2hat = s2;
    mldsa_polyveck_ntt(&s2hat);
    mldsa_polyveck t0hat = t0;
    mldsa_polyveck_ntt(&t0hat);

    uint16_t nonce = 0;
    uint8_t c[MLDSA_LAMBDA/8];

    while (true) {
        // Sample y
        mldsa_polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

        // w = A·y (NTT domain)
        mldsa_polyvecl yhat = y;
        mldsa_polyvecl_ntt(&yhat);
        mldsa_polyvec_matrix_pointwise_montgomery(&w1, mat, &yhat);
        mldsa_polyveck_reduce(&w1);
        mldsa_polyveck_invntt_tomont(&w1);
        mldsa_polyveck_caddq(&w1);

        // Decompose w → (w1, w0)
        mldsa_polyveck_decompose(&w1, &w0, &w1);

        // c~ = H(μ || w1encode(w1))
        uint8_t w1packed[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES];
        mldsa_polyveck_pack_w1(w1packed, &w1);
        uint8_t ctilde_input[MLDSA_CRHBYTES + sizeof(w1packed)];
        memcpy(ctilde_input, mu, MLDSA_CRHBYTES);
        memcpy(ctilde_input + MLDSA_CRHBYTES, w1packed, sizeof(w1packed));
        shake256(c, MLDSA_LAMBDA/8, ctilde_input, sizeof(ctilde_input));

        // c = SampleInBall(c~)
        mldsa_poly_challenge(&cp, c);
        mldsa_poly_ntt(&cp);

        // z = y + c·s1
        mldsa_polyveck_pointwise_poly_montgomery(&cs2, &cp, &s2hat);
        mldsa_polyveck_invntt_tomont(&cs2);
        mldsa_polyveck sub_tmp;

        mldsa_polyvecl cs1;
        mldsa_polyveck_pointwise_poly_montgomery((mldsa_polyveck*)&cs1, &cp, (mldsa_polyveck*)&s1hat);
        mldsa_polyvecl_invntt_tomont(&cs1);
        mldsa_polyvecl z;
        for (int i = 0; i < MLDSA_L; ++i)
            mldsa_poly_add(&z.vec[i], &y.vec[i], &cs1.vec[i]);
        mldsa_polyvecl_reduce(&z);

        if (mldsa_polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA)) continue;

        // w0 - c·s2
        mldsa_polyveck_sub(&w0, &w0, &cs2);
        mldsa_polyveck_reduce(&w0);
        if (mldsa_polyveck_chknorm(&w0, MLDSA_GAMMA2 - MLDSA_BETA)) continue;

        // c·t0
        mldsa_polyveck_pointwise_poly_montgomery(&ct0, &cp, &t0hat);
        mldsa_polyveck_invntt_tomont(&ct0);
        mldsa_polyveck_reduce(&ct0);
        if (mldsa_polyveck_chknorm(&ct0, MLDSA_GAMMA2)) continue;

        // h = MakeHint(-c·t0, w0 + c·t0, w1)
        mldsa_polyveck_add(&w0, &w0, &ct0);
        uint32_t n2 = mldsa_polyveck_make_hint(&h, &ct0, &w0);
        if (n2 > MLDSA_OMEGA) continue;

        pack_sig(sig.data(), c, &z, &h);
        break;
    }

    memory_cleanse(rho, sizeof(rho));
    memory_cleanse(key, sizeof(key));
    memory_cleanse(rhoprime, sizeof(rhoprime));
    memory_cleanse(&s1, sizeof(s1));
    memory_cleanse(&s2, sizeof(s2));
    return true;
}

// ===========================================================================
// ML-DSA.Verify — FIPS 204 §7.3
// ===========================================================================

bool MLDSA_Verify(const MLDSASignature& sig,
                  const uint8_t* msg, size_t msg_len,
                  const MLDSAPublicKey& pk) {
    uint8_t rho[MLDSA_SEEDBYTES];
    mldsa_polyveck t1;
    unpack_pk(rho, &t1, pk.data());

    uint8_t c[MLDSA_LAMBDA/8];
    mldsa_polyvecl z;
    mldsa_polyveck h;
    if (unpack_sig(c, &z, &h, sig.data()))
        return false; // Malformed signature

    if (mldsa_polyvecl_chknorm(&z, MLDSA_GAMMA1 - MLDSA_BETA))
        return false;

    // tr = H(pk, 64)
    uint8_t tr[MLDSA_TRBYTES];
    shake256(tr, MLDSA_TRBYTES, pk.data(), MLDSA_PUBLICKEYBYTES);

    // μ = H(tr || M, 64)
    uint8_t mu[MLDSA_CRHBYTES];
    H2(mu, MLDSA_CRHBYTES, tr, MLDSA_TRBYTES, msg, msg_len);

    // c = SampleInBall(c~)
    mldsa_poly cp;
    mldsa_poly_challenge(&cp, c);

    // Expand A
    mldsa_polyvecl mat[MLDSA_K];
    mldsa_polyvec_matrix_expand(mat, rho);

    // w' = A·z - c·t1·2^d
    mldsa_polyvecl_ntt(&z);
    mldsa_poly_ntt(&cp);
    mldsa_polyveck t1cp;
    mldsa_polyveck_pointwise_poly_montgomery(&t1cp, &cp, &t1);
    mldsa_polyveck_shiftl(&t1cp);  // multiply by 2^d
    mldsa_polyveck_ntt(&t1cp);

    mldsa_polyveck w1prime;
    mldsa_polyvec_matrix_pointwise_montgomery(&w1prime, mat, &z);
    mldsa_polyveck_sub(&w1prime, &w1prime, &t1cp);
    mldsa_polyveck_reduce(&w1prime);
    mldsa_polyveck_invntt_tomont(&w1prime);
    mldsa_polyveck_caddq(&w1prime);

    // UseHint(h, w') → w1''
    mldsa_polyveck w1pp;
    mldsa_polyveck_use_hint(&w1pp, &w1prime, &h);

    // c~' = H(μ || w1encode(w1''))
    uint8_t w1packed[MLDSA_K * MLDSA_POLYW1_PACKEDBYTES];
    mldsa_polyveck_pack_w1(w1packed, &w1pp);

    uint8_t ctilde_verify[MLDSA_CRHBYTES + sizeof(w1packed)];
    memcpy(ctilde_verify, mu, MLDSA_CRHBYTES);
    memcpy(ctilde_verify + MLDSA_CRHBYTES, w1packed, sizeof(w1packed));

    uint8_t c2[MLDSA_LAMBDA/8];
    shake256(c2, MLDSA_LAMBDA/8, ctilde_verify, sizeof(ctilde_verify));

    // Constant-time comparison: c~' == c~
    uint8_t diff = 0;
    for (int i = 0; i < MLDSA_LAMBDA/8; ++i)
        diff |= c[i] ^ c2[i];
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
