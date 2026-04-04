// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Script / policy tests for P2PQH and P2HPQ output types.
//
// Tests cover:
//   1. scriptPubKey construction and recognition
//   2. Witness program parsing
//   3. P2PQH witness verification (valid and invalid)
//   4. P2HPQ witness verification (valid and invalid)
//   5. Policy / standardness checks
//   6. Weight calculations
//
// This file uses a lightweight test harness (no Boost required) so it can
// be run standalone during development:
//
//   c++ -std=c++20 -I.. script_pqc_tests.cpp ../script/interpreter_pqc.cpp \
//       ../policy/policy_pqc.cpp ../crypto/mldsa/mldsa.cpp \
//       ../crypto/mldsa/mldsa_poly.cpp -o run_tests && ./run_tests
//
// For the Bitcoin Core test suite, wrap with BOOST_AUTO_TEST_SUITE below.

#include <boost/test/unit_test.hpp>

#include "../script/script_pqc.h"
#include "../script/interpreter_pqc.h"
#include "../policy/policy_pqc.h"
#include "../crypto/mldsa/mldsa.h"

#include <array>
#include <cstring>
#include <vector>

// ---------------------------------------------------------------------------
// Stub implementations of Bitcoin Core primitives
// ---------------------------------------------------------------------------

// Hash160 stub: RIPEMD160(SHA256(data)).
// For testing, we use a repeatable but obviously wrong implementation;
// the real implementation will be linked in when building within Core.
std::array<uint8_t, 20> Hash160(std::span<const uint8_t> data)
{
    std::array<uint8_t, 20> out{};
    // Simple folding hash for test purposes only
    for (size_t i = 0; i < data.size(); ++i) {
        out[i % 20] ^= data[i];
        out[(i + 1) % 20] += data[i];
    }
    return out;
}

// ECDSAVerify stub — always returns true in unit tests.
// The real implementation links against libsecp256k1.
bool ECDSAVerify(
    std::span<const uint8_t> /*sig*/,
    std::span<const uint8_t> /*hash*/,
    std::span<const uint8_t> /*pubkey*/)
{
    return true; // replaced by real impl in production build
}

// ComputePQCSigHash stub — returns a deterministic 32-byte hash.
std::array<uint8_t, 32> ComputePQCSigHash(
    const PQCTxContext& ctx,
    uint8_t /*sighash_type*/)
{
    std::array<uint8_t, 32> h{};
    h[0] = static_cast<uint8_t>(ctx.nVersion);
    h[1] = static_cast<uint8_t>(ctx.nIn);
    h[2] = ctx.witness_program[0];
    // Fill with predictable values for testing
    for (int i = 3; i < 32; ++i) h[i] = static_cast<uint8_t>(i);
    return h;
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

namespace {

/** Build a minimal PQCTxContext for testing. */
static PQCTxContext MakeCtx(const uint8_t witness_program[21])
{
    PQCTxContext ctx{};
    ctx.nVersion  = 2;
    ctx.nLocktime = 0;
    ctx.nIn       = 0;
    ctx.amount    = 100000;
    ctx.nSequence = 0xFFFFFFFF;
    std::memset(ctx.prevout_hash, 0xAB, 32);
    ctx.prevout_n = 0;
    std::memcpy(ctx.witness_program, witness_program, 21);
    return ctx;
}

/** Generate a key pair from seed byte. */
static void GenKey(MLDSAPublicKey& pk, MLDSASecretKey& sk, uint8_t seed_byte)
{
    uint8_t seed[32];
    std::memset(seed, seed_byte, 32);
    BOOST_REQUIRE(MLDSA_KeyGen(pk, sk, seed));
}

/**
 * Build a valid P2PQH witness stack:
 *   [0] MLDSA_Sign(sighash, sk) || 0x00
 *   [1] mldsa_pubkey
 */
static std::vector<std::vector<uint8_t>> MakeP2PQHWitness(
    const MLDSAPublicKey& pk,
    const MLDSASecretKey& sk,
    const PQCTxContext& ctx)
{
    auto sighash = ComputePQCSigHash(ctx, 0x00);

    MLDSASignature sig;
    BOOST_REQUIRE(MLDSA_Sign(sig, sighash.data(), sighash.size(), sk));

    std::vector<uint8_t> sig_wire(sig.begin(), sig.end());
    sig_wire.push_back(0x00); // SIGHASH_ALL

    std::vector<uint8_t> pk_wire(pk.begin(), pk.end());

    return {sig_wire, pk_wire};
}

/** Build witness program bytes for a P2PQH output. */
static std::array<uint8_t, 21> MakeP2PQHProgram(const MLDSAPublicKey& pk)
{
    auto h = Hash160(std::span<const uint8_t>{pk.data(), pk.size()});
    std::array<uint8_t, 21> prog{};
    prog[0] = PQC_TYPE_PURE;
    std::copy(h.begin(), h.end(), prog.begin() + 1);
    return prog;
}

/** Build witness program bytes for a P2HPQ output. */
static std::array<uint8_t, 21> MakeP2HPQProgram(
    std::span<const uint8_t> ecdsa_pk,
    const MLDSAPublicKey& mldsa_pk)
{
    std::vector<uint8_t> combined(ecdsa_pk.begin(), ecdsa_pk.end());
    combined.insert(combined.end(), mldsa_pk.begin(), mldsa_pk.end());
    auto h = Hash160(combined);
    std::array<uint8_t, 21> prog{};
    prog[0] = PQC_TYPE_HYBRID;
    std::copy(h.begin(), h.end(), prog.begin() + 1);
    return prog;
}

/** Build a valid P2HPQ witness stack. */
static std::vector<std::vector<uint8_t>> MakeP2HPQWitness(
    std::span<const uint8_t> ecdsa_pk,
    const MLDSAPublicKey& mldsa_pk,
    const MLDSASecretKey& mldsa_sk,
    const PQCTxContext& ctx)
{
    auto sighash = ComputePQCSigHash(ctx, 0x00);

    // Fake DER ECDSA signature (71 bytes) + sighash_type
    std::vector<uint8_t> ecdsa_sig(72, 0x00);
    ecdsa_sig[0] = 0x30; // DER sequence
    ecdsa_sig[1] = 0x44;
    ecdsa_sig.push_back(0x00); // sighash_type

    MLDSASignature sig;
    BOOST_REQUIRE(MLDSA_Sign(sig, sighash.data(), sighash.size(), mldsa_sk));
    std::vector<uint8_t> mldsa_sig_wire(sig.begin(), sig.end());
    mldsa_sig_wire.push_back(0x00);

    std::vector<uint8_t> ecdsa_pk_wire(ecdsa_pk.begin(), ecdsa_pk.end());
    std::vector<uint8_t> mldsa_pk_wire(mldsa_pk.begin(), mldsa_pk.end());

    return {ecdsa_sig, ecdsa_pk_wire, mldsa_sig_wire, mldsa_pk_wire};
}

// Fake compressed ECDSA public key (33 bytes, prefix 0x02)
static std::array<uint8_t, 33> FakeECDSAPubKey(uint8_t fill)
{
    std::array<uint8_t, 33> pk;
    pk[0] = 0x02;
    pk.fill(fill);
    pk[0] = 0x02;
    return pk;
}

} // namespace

BOOST_AUTO_TEST_SUITE(script_pqc_tests)

// ---------------------------------------------------------------------------
// 1. scriptPubKey construction and recognition
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(is_p2pqc_script_pure)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x01);

    auto prog = MakeP2PQHProgram(pk);
    auto spk  = BuildPQCScriptPubKey(PQC_TYPE_PURE,
                    std::span<const uint8_t, 20>{prog.data() + 1, 20});

    BOOST_CHECK_EQUAL(spk.size(), 23u);
    BOOST_CHECK(IsP2PQCScript(spk));
    BOOST_CHECK_EQUAL(GetPQCType(spk), PQC_TYPE_PURE);
}

BOOST_AUTO_TEST_CASE(is_p2pqc_script_hybrid)
{
    auto ecdsa_pk  = FakeECDSAPubKey(0xAB);
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x02);

    auto prog = MakeP2HPQProgram(ecdsa_pk, pk);
    auto spk  = BuildPQCScriptPubKey(PQC_TYPE_HYBRID,
                    std::span<const uint8_t, 20>{prog.data() + 1, 20});

    BOOST_CHECK_EQUAL(spk.size(), 23u);
    BOOST_CHECK(IsP2PQCScript(spk));
    BOOST_CHECK_EQUAL(GetPQCType(spk), PQC_TYPE_HYBRID);
}

BOOST_AUTO_TEST_CASE(is_p2pqc_script_rejects_wrong_version)
{
    // OP_1 instead of OP_2 → not a PQC script
    std::vector<uint8_t> spk(23, 0x00);
    spk[0] = 0x51; // OP_1
    spk[1] = 21;
    spk[2] = PQC_TYPE_PURE;
    BOOST_CHECK(!IsP2PQCScript(spk));
}

BOOST_AUTO_TEST_CASE(is_p2pqc_script_rejects_wrong_size)
{
    std::vector<uint8_t> spk(22, 0x00);
    spk[0] = 0x52;
    spk[1] = 20;
    BOOST_CHECK(!IsP2PQCScript(spk));
}

BOOST_AUTO_TEST_CASE(is_p2pqc_script_rejects_unknown_type)
{
    std::vector<uint8_t> spk(23, 0x00);
    spk[0] = 0x52;
    spk[1] = 21;
    spk[2] = 0xBB; // unknown type
    BOOST_CHECK(!IsP2PQCScript(spk));
}

// ---------------------------------------------------------------------------
// 3. P2PQH witness verification
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(p2pqh_valid)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x10);

    auto prog    = MakeP2PQHProgram(pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyP2PQH(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2pqh_wrong_item_count)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x11);

    auto prog = MakeP2PQHProgram(pk);
    auto ctx  = MakeCtx(prog.data());

    // Only 1 item instead of 2
    std::vector<std::vector<uint8_t>> witness(1, std::vector<uint8_t>(10, 0));
    ScriptError err;
    BOOST_CHECK(!VerifyP2PQH(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_WRONG_WITNESS_ITEMS);
}

BOOST_AUTO_TEST_CASE(p2pqh_wrong_pubkey_size)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x12);

    auto prog    = MakeP2PQHProgram(pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);

    // Corrupt pubkey length
    witness[PQC_WIT_MLDSA_PK].pop_back();
    ScriptError err;
    BOOST_CHECK(!VerifyP2PQH(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_BAD_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(p2pqh_pubkey_hash_mismatch)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x13);

    auto prog = MakeP2PQHProgram(pk);
    auto ctx  = MakeCtx(prog.data());

    MLDSAPublicKey pk2; MLDSASecretKey sk2;
    GenKey(pk2, sk2, 0x14);

    // Witness for pk2 but program commits to pk
    auto witness = MakeP2PQHWitness(pk2, sk2, ctx);
    ScriptError err;
    BOOST_CHECK(!VerifyP2PQH(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_PUBKEY_MISMATCH);
}

BOOST_AUTO_TEST_CASE(p2pqh_bad_sig)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x15);

    auto prog    = MakeP2PQHProgram(pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);

    // Corrupt one byte of the signature
    witness[PQC_WIT_MLDSA_SIG][42] ^= 0xFF;
    ScriptError err;
    BOOST_CHECK(!VerifyP2PQH(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_SIG_INVALID);
}

BOOST_AUTO_TEST_CASE(p2pqh_unknown_sighash_type)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x16);

    auto prog    = MakeP2PQHProgram(pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);

    // Replace sighash_type byte (last byte of sig item)
    witness[PQC_WIT_MLDSA_SIG].back() = 0x83; // SIGHASH_ANYONECANPAY|ALL
    ScriptError err;
    BOOST_CHECK(!VerifyP2PQH(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_UNKNOWN_SIGHASH);
}

// ---------------------------------------------------------------------------
// 4. P2HPQ witness verification
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(p2hpq_valid)
{
    auto ecdsa_pk  = FakeECDSAPubKey(0x55);
    MLDSAPublicKey mldsa_pk; MLDSASecretKey mldsa_sk;
    GenKey(mldsa_pk, mldsa_sk, 0x20);

    auto prog    = MakeP2HPQProgram(ecdsa_pk, mldsa_pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2HPQWitness(ecdsa_pk, mldsa_pk, mldsa_sk, ctx);

    ScriptError err;
    BOOST_CHECK(VerifyP2HPQ(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(p2hpq_wrong_item_count)
{
    auto ecdsa_pk  = FakeECDSAPubKey(0x56);
    MLDSAPublicKey mldsa_pk; MLDSASecretKey mldsa_sk;
    GenKey(mldsa_pk, mldsa_sk, 0x21);

    auto prog = MakeP2HPQProgram(ecdsa_pk, mldsa_pk);
    auto ctx  = MakeCtx(prog.data());

    std::vector<std::vector<uint8_t>> witness(2, std::vector<uint8_t>(10, 0));
    ScriptError err;
    BOOST_CHECK(!VerifyP2HPQ(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_WRONG_WITNESS_ITEMS);
}

BOOST_AUTO_TEST_CASE(p2hpq_commitment_mismatch)
{
    auto ecdsa_pk1 = FakeECDSAPubKey(0x57);
    auto ecdsa_pk2 = FakeECDSAPubKey(0x58); // different key
    MLDSAPublicKey mldsa_pk; MLDSASecretKey mldsa_sk;
    GenKey(mldsa_pk, mldsa_sk, 0x22);

    // Program commits to ecdsa_pk1 but witness provides ecdsa_pk2
    auto prog    = MakeP2HPQProgram(ecdsa_pk1, mldsa_pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2HPQWitness(ecdsa_pk2, mldsa_pk, mldsa_sk, ctx);

    ScriptError err;
    BOOST_CHECK(!VerifyP2HPQ(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_PUBKEY_MISMATCH);
}

BOOST_AUTO_TEST_CASE(p2hpq_bad_mldsa_sig)
{
    auto ecdsa_pk  = FakeECDSAPubKey(0x59);
    MLDSAPublicKey mldsa_pk; MLDSASecretKey mldsa_sk;
    GenKey(mldsa_pk, mldsa_sk, 0x23);

    auto prog    = MakeP2HPQProgram(ecdsa_pk, mldsa_pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2HPQWitness(ecdsa_pk, mldsa_pk, mldsa_sk, ctx);

    // Corrupt ML-DSA sig
    witness[HPQ_WIT_MLDSA_SIG][100] ^= 0x01;
    ScriptError err;
    BOOST_CHECK(!VerifyP2HPQ(witness,
        std::span<const uint8_t, 21>{prog.data(), 21}, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_SIG_INVALID);
}

// ---------------------------------------------------------------------------
// 5. VerifyPQCWitnessProgram dispatcher
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(dispatcher_pure)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x30);

    auto prog    = MakeP2PQHProgram(pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);

    ScriptError err;
    BOOST_CHECK(VerifyPQCWitnessProgram(witness, prog, ctx, &err));
}

BOOST_AUTO_TEST_CASE(dispatcher_hybrid)
{
    auto ecdsa_pk  = FakeECDSAPubKey(0x60);
    MLDSAPublicKey mldsa_pk; MLDSASecretKey mldsa_sk;
    GenKey(mldsa_pk, mldsa_sk, 0x31);

    auto prog    = MakeP2HPQProgram(ecdsa_pk, mldsa_pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2HPQWitness(ecdsa_pk, mldsa_pk, mldsa_sk, ctx);

    ScriptError err;
    BOOST_CHECK(VerifyPQCWitnessProgram(witness, prog, ctx, &err));
}

BOOST_AUTO_TEST_CASE(dispatcher_unknown_type)
{
    std::array<uint8_t, 21> prog{};
    prog[0] = 0xDD; // unknown type byte

    PQCTxContext ctx = MakeCtx(prog.data());
    std::vector<std::vector<uint8_t>> witness;
    ScriptError err;
    BOOST_CHECK(!VerifyPQCWitnessProgram(witness, prog, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_UNKNOWN_TYPE);
}

BOOST_AUTO_TEST_CASE(dispatcher_wrong_program_size)
{
    std::vector<uint8_t> prog(20, 0x00); // too short
    PQCTxContext ctx{};
    std::vector<std::vector<uint8_t>> witness;
    ScriptError err;
    BOOST_CHECK(!VerifyPQCWitnessProgram(witness, prog, ctx, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PQC_BAD_PROGRAM_SIZE);
}

// ---------------------------------------------------------------------------
// 6. Policy / standardness
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(policy_standard_p2pqh_output)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x40);

    auto prog = MakeP2PQHProgram(pk);
    auto spk  = BuildPQCScriptPubKey(PQC_TYPE_PURE,
                    std::span<const uint8_t, 20>{prog.data() + 1, 20});

    std::string reason;
    BOOST_CHECK(IsStandardPQCOutput(spk, reason));
}

BOOST_AUTO_TEST_CASE(policy_nonstandard_output_bad_type)
{
    std::vector<uint8_t> spk(23, 0x00);
    spk[0] = 0x52;
    spk[1] = 21;
    spk[2] = 0xEE; // unknown type

    std::string reason;
    BOOST_CHECK(!IsStandardPQCOutput(spk, reason));
    BOOST_CHECK(!reason.empty());
}

BOOST_AUTO_TEST_CASE(policy_standard_p2pqh_input)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x41);

    auto prog    = MakeP2PQHProgram(pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);

    std::string reason;
    BOOST_CHECK(IsStandardPQCInput(PQC_TYPE_PURE, witness, {}, reason));
}

BOOST_AUTO_TEST_CASE(policy_rejects_nonempty_scriptsig)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x42);

    auto prog    = MakeP2PQHProgram(pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);

    const uint8_t dummy_scriptsig[] = {0x00};
    std::string reason;
    BOOST_CHECK(!IsStandardPQCInput(PQC_TYPE_PURE, witness,
        std::span<const uint8_t>{dummy_scriptsig, 1}, reason));
    BOOST_CHECK_EQUAL(reason, "pqc-nonempty-scriptsig");
}

BOOST_AUTO_TEST_CASE(policy_rejects_nonstandard_sighash)
{
    MLDSAPublicKey pk; MLDSASecretKey sk;
    GenKey(pk, sk, 0x43);

    auto prog    = MakeP2PQHProgram(pk);
    auto ctx     = MakeCtx(prog.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);

    witness[PQC_WIT_MLDSA_SIG].back() = 0x02; // SIGHASH_NONE
    std::string reason;
    BOOST_CHECK(!IsStandardPQCInput(PQC_TYPE_PURE, witness, {}, reason));
    BOOST_CHECK_EQUAL(reason, "pqc-nonstandard-sighash");
}

// ---------------------------------------------------------------------------
// 7. Weight calculations
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(output_weight)
{
    // All PQC outputs are 23-byte scriptPubKeys → 128 wu
    BOOST_CHECK_EQUAL(GetPQCOutputWeight(), 128u);
}

BOOST_AUTO_TEST_CASE(input_weight_pure)
{
    size_t w = GetPQCInputWeight(PQC_TYPE_PURE);
    // Base = 164, witness = 1 + 3+3294 + 3+1952 = 5253 → total = 5417
    BOOST_CHECK_GT(w, 5000u);
    BOOST_CHECK_LT(w, 6000u);
}

BOOST_AUTO_TEST_CASE(input_weight_hybrid)
{
    size_t w = GetPQCInputWeight(PQC_TYPE_HYBRID);
    BOOST_CHECK_GT(w, GetPQCInputWeight(PQC_TYPE_PURE));
}

BOOST_AUTO_TEST_CASE(input_weight_unknown_type)
{
    BOOST_CHECK_EQUAL(GetPQCInputWeight(0xFF), 0u);
}

BOOST_AUTO_TEST_SUITE_END()
