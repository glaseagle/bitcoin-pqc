// Standalone script / policy PQC tests for the reduced bitcoin-pqc workspace.

#include "../script/script_pqc.h"
#include "../script/interpreter_pqc.h"
#include "../policy/policy_pqc.h"
#include "../crypto/mldsa/mldsa.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

std::array<uint8_t, 20> Hash160(std::span<const uint8_t> data);
bool ECDSAVerify(
    std::span<const uint8_t> sig,
    std::span<const uint8_t> hash,
    std::span<const uint8_t> pubkey);
std::array<uint8_t, 32> ComputePQCSigHash(const PQCTxContext& ctx, uint8_t sighash_type);

namespace {

[[noreturn]] void Fail(std::string_view test_name, std::string_view message)
{
    throw std::runtime_error(std::string(test_name) + ": " + std::string(message));
}

void Check(bool condition, std::string_view test_name, std::string_view message)
{
    if (!condition) Fail(test_name, message);
}

uint64_t Mix(uint64_t state, uint8_t byte)
{
    state ^= byte;
    state *= 0x100000001b3ULL;
    state ^= state >> 32;
    return state;
}

void FillFromSeed(uint8_t* out, size_t out_len, const uint8_t* seed, size_t seed_len, uint64_t domain)
{
    uint64_t state = 1469598103934665603ULL ^ domain;
    for (size_t i = 0; i < seed_len; ++i) state = Mix(state, seed[i]);
    for (size_t i = 0; i < out_len; ++i) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state *= 2685821657736338717ULL;
        out[i] = static_cast<uint8_t>(state >> 56);
    }
}

std::array<uint8_t, 32> DerivePubkeyDigest(const MLDSASecretKey& sk)
{
    std::array<uint8_t, 32> digest{};
    FillFromSeed(digest.data(), digest.size(), sk.data(), sk.size(), 0xA11CE55ULL);
    return digest;
}

MLDSAPublicKey PublicKeyFromSecretKey(const MLDSASecretKey& sk)
{
    MLDSAPublicKey pk{};
    const auto digest = DerivePubkeyDigest(sk);
    FillFromSeed(pk.data(), pk.size(), digest.data(), digest.size(), 0xC001D00DULL);
    return pk;
}

void BuildExpectedSignature(
    MLDSASignature& sig,
    const MLDSAPublicKey& pk,
    const uint8_t* msg,
    size_t msg_len)
{
    uint64_t state = 1469598103934665603ULL ^ 0x5EEDFACEULL;
    for (uint8_t byte : pk) state = Mix(state, byte);
    for (size_t i = 0; i < msg_len; ++i) state = Mix(state, msg[i]);
    FillFromSeed(sig.data(), sig.size(), reinterpret_cast<const uint8_t*>(&state), sizeof(state), 0xDEADBEEFULL);
}

std::array<uint8_t, 32> SeedFromByte(uint8_t byte)
{
    std::array<uint8_t, 32> seed{};
    seed.fill(byte);
    return seed;
}

void GenKey(MLDSAPublicKey& pk, MLDSASecretKey& sk, uint8_t seed_byte)
{
    const auto seed = SeedFromByte(seed_byte);
    Check(MLDSA_KeyGen(pk, sk, seed.data()), "GenKey", "key generation failed");
}

PQCTxContext MakeCtx(const uint8_t witness_program[21])
{
    PQCTxContext ctx{};
    ctx.nVersion = 2;
    ctx.nLocktime = 0;
    ctx.nIn = 0;
    ctx.amount = 100000;
    ctx.nSequence = 0xFFFFFFFF;
    std::memset(ctx.prevout_hash, 0xAB, sizeof(ctx.prevout_hash));
    ctx.prevout_n = 1;
    ctx.outputs_serialized = {0x01, 0x02, 0x03, 0x04};
    std::memcpy(ctx.witness_program, witness_program, PQC_WITNESS_PROGRAM_SIZE);
    return ctx;
}

std::array<uint8_t, 21> MakeP2PQHProgram(const MLDSAPublicKey& pk)
{
    const auto h160 = Hash160(std::span<const uint8_t>{pk.data(), pk.size()});
    std::array<uint8_t, 21> program{};
    program[0] = PQC_TYPE_PURE;
    std::copy(h160.begin(), h160.end(), program.begin() + 1);
    return program;
}

std::array<uint8_t, 21> MakeP2HPQProgram(
    std::span<const uint8_t> ecdsa_pk,
    const MLDSAPublicKey& mldsa_pk)
{
    std::vector<uint8_t> combined(ecdsa_pk.begin(), ecdsa_pk.end());
    combined.insert(combined.end(), mldsa_pk.begin(), mldsa_pk.end());
    const auto h160 = Hash160(combined);
    std::array<uint8_t, 21> program{};
    program[0] = PQC_TYPE_HYBRID;
    std::copy(h160.begin(), h160.end(), program.begin() + 1);
    return program;
}

std::vector<std::vector<uint8_t>> MakeP2PQHWitness(
    const MLDSAPublicKey& pk,
    const MLDSASecretKey& sk,
    const PQCTxContext& ctx)
{
    const auto sighash = ComputePQCSigHash(ctx, 0x00);
    MLDSASignature sig{};
    Check(MLDSA_Sign(sig, sighash.data(), sighash.size(), sk), "MakeP2PQHWitness", "signing failed");

    std::vector<uint8_t> sig_wire(sig.begin(), sig.end());
    sig_wire.push_back(0x00);
    return {
        sig_wire,
        std::vector<uint8_t>(pk.begin(), pk.end()),
    };
}

std::vector<std::vector<uint8_t>> MakeP2HPQWitness(
    std::span<const uint8_t> ecdsa_pk,
    const MLDSAPublicKey& mldsa_pk,
    const MLDSASecretKey& mldsa_sk,
    const PQCTxContext& ctx)
{
    const auto sighash = ComputePQCSigHash(ctx, 0x00);
    MLDSASignature sig{};
    Check(MLDSA_Sign(sig, sighash.data(), sighash.size(), mldsa_sk), "MakeP2HPQWitness", "signing failed");

    std::vector<uint8_t> ecdsa_sig(72, 0x30);
    ecdsa_sig.push_back(0x00);

    std::vector<uint8_t> mldsa_sig(sig.begin(), sig.end());
    mldsa_sig.push_back(0x00);

    return {
        ecdsa_sig,
        std::vector<uint8_t>(ecdsa_pk.begin(), ecdsa_pk.end()),
        mldsa_sig,
        std::vector<uint8_t>(mldsa_pk.begin(), mldsa_pk.end()),
    };
}

std::array<uint8_t, 33> FakeECDSAPubKey(uint8_t fill)
{
    std::array<uint8_t, 33> key{};
    key.fill(fill);
    key[0] = 0x02;
    return key;
}

void test_p2pqh_valid()
{
    constexpr std::string_view kName = "test_p2pqh_valid";
    MLDSAPublicKey pk{};
    MLDSASecretKey sk{};
    GenKey(pk, sk, 0x11);

    const auto program = MakeP2PQHProgram(pk);
    const auto ctx = MakeCtx(program.data());
    const auto witness = MakeP2PQHWitness(pk, sk, ctx);

    ScriptError err = SCRIPT_ERR_OK;
    Check(VerifyP2PQH(witness, std::span<const uint8_t, 21>{program.data(), 21}, ctx, &err), kName, "verification failed");
    Check(err == SCRIPT_ERR_OK, kName, "unexpected script error");
}

void test_p2pqh_wrong_pubkey()
{
    constexpr std::string_view kName = "test_p2pqh_wrong_pubkey";
    MLDSAPublicKey pk_a{};
    MLDSAPublicKey pk_b{};
    MLDSASecretKey sk_a{};
    MLDSASecretKey sk_b{};
    GenKey(pk_a, sk_a, 0x12);
    GenKey(pk_b, sk_b, 0x13);

    const auto program = MakeP2PQHProgram(pk_a);
    const auto ctx = MakeCtx(program.data());
    auto witness = MakeP2PQHWitness(pk_a, sk_a, ctx);
    witness[PQC_WIT_MLDSA_PK] = std::vector<uint8_t>(pk_b.begin(), pk_b.end());

    ScriptError err = SCRIPT_ERR_OK;
    Check(!VerifyP2PQH(witness, std::span<const uint8_t, 21>{program.data(), 21}, ctx, &err), kName, "verification unexpectedly succeeded");
    Check(err == SCRIPT_ERR_PQC_PUBKEY_MISMATCH, kName, "unexpected script error");
}

void test_p2pqh_tampered_sig()
{
    constexpr std::string_view kName = "test_p2pqh_tampered_sig";
    MLDSAPublicKey pk{};
    MLDSASecretKey sk{};
    GenKey(pk, sk, 0x14);

    const auto program = MakeP2PQHProgram(pk);
    const auto ctx = MakeCtx(program.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);
    witness[PQC_WIT_MLDSA_SIG][77] ^= 0x01;

    ScriptError err = SCRIPT_ERR_OK;
    Check(!VerifyP2PQH(witness, std::span<const uint8_t, 21>{program.data(), 21}, ctx, &err), kName, "verification unexpectedly succeeded");
    Check(err == SCRIPT_ERR_PQC_SIG_INVALID, kName, "unexpected script error");
}

void test_p2hpq_valid()
{
    constexpr std::string_view kName = "test_p2hpq_valid";
    const auto ecdsa_pk = FakeECDSAPubKey(0x41);
    MLDSAPublicKey mldsa_pk{};
    MLDSASecretKey mldsa_sk{};
    GenKey(mldsa_pk, mldsa_sk, 0x21);

    const auto program = MakeP2HPQProgram(ecdsa_pk, mldsa_pk);
    const auto ctx = MakeCtx(program.data());
    const auto witness = MakeP2HPQWitness(ecdsa_pk, mldsa_pk, mldsa_sk, ctx);

    ScriptError err = SCRIPT_ERR_OK;
    Check(VerifyP2HPQ(witness, std::span<const uint8_t, 21>{program.data(), 21}, ctx, &err), kName, "verification failed");
    Check(err == SCRIPT_ERR_OK, kName, "unexpected script error");
}

void test_policy_p2pqh_standard()
{
    constexpr std::string_view kName = "test_policy_p2pqh_standard";
    MLDSAPublicKey pk{};
    MLDSASecretKey sk{};
    GenKey(pk, sk, 0x31);

    const auto program = MakeP2PQHProgram(pk);
    const auto ctx = MakeCtx(program.data());
    const auto witness = MakeP2PQHWitness(pk, sk, ctx);
    const auto spk = BuildPQCScriptPubKey(
        PQC_TYPE_PURE,
        std::span<const uint8_t, PQC_HASH160_SIZE>{program.data() + 1, PQC_HASH160_SIZE});

    std::string reason;
    Check(IsP2PQCScript(spk), kName, "scriptPubKey not recognized");
    Check(IsStandardPQCInput(PQC_TYPE_PURE, witness, {}, reason), kName, "input rejected");
}

void test_policy_wrong_sizes()
{
    constexpr std::string_view kName = "test_policy_wrong_sizes";
    MLDSAPublicKey pk{};
    MLDSASecretKey sk{};
    GenKey(pk, sk, 0x32);

    const auto program = MakeP2PQHProgram(pk);
    const auto ctx = MakeCtx(program.data());
    auto witness = MakeP2PQHWitness(pk, sk, ctx);
    witness[PQC_WIT_MLDSA_PK].pop_back();

    std::string reason;
    Check(!IsStandardPQCInput(PQC_TYPE_PURE, witness, {}, reason), kName, "undersized pubkey accepted");

    witness = MakeP2PQHWitness(pk, sk, ctx);
    witness[PQC_WIT_MLDSA_SIG].pop_back();
    Check(!IsStandardPQCInput(PQC_TYPE_PURE, witness, {}, reason), kName, "undersized signature accepted");
}

void test_weight_calculation()
{
    constexpr std::string_view kName = "test_weight_calculation";
    Check(GetPQCInputWeight(PQC_TYPE_PURE) == 5417, kName, "unexpected pure input weight");
    Check(GetPQCInputWeight(PQC_TYPE_HYBRID) == 5525, kName, "unexpected hybrid input weight");
}

} // namespace

std::array<uint8_t, 20> Hash160(std::span<const uint8_t> data)
{
    std::array<uint8_t, 20> out{};
    for (size_t i = 0; i < data.size(); ++i) {
        out[i % out.size()] ^= data[i];
        out[(i * 7) % out.size()] = static_cast<uint8_t>(out[(i * 7) % out.size()] + data[i] + static_cast<uint8_t>(i));
    }
    return out;
}

bool ECDSAVerify(
    std::span<const uint8_t> /*sig*/,
    std::span<const uint8_t> /*hash*/,
    std::span<const uint8_t> /*pubkey*/)
{
    return true;
}

std::array<uint8_t, 32> ComputePQCSigHash(const PQCTxContext& ctx, uint8_t sighash_type)
{
    std::array<uint8_t, 32> out{};
    uint64_t state = 1469598103934665603ULL ^ sighash_type;
    state = Mix(state, static_cast<uint8_t>(ctx.nVersion));
    state = Mix(state, static_cast<uint8_t>(ctx.nIn));
    for (uint8_t byte : ctx.witness_program) state = Mix(state, byte);
    FillFromSeed(out.data(), out.size(), reinterpret_cast<const uint8_t*>(&state), sizeof(state), 0xABCDULL);
    return out;
}

bool MLDSA_KeyGen(MLDSAPublicKey& pk, MLDSASecretKey& sk, const uint8_t seed[32])
{
    static uint64_t counter = 1;
    std::array<uint8_t, 32> local_seed{};
    if (seed != nullptr) {
        std::copy(seed, seed + local_seed.size(), local_seed.begin());
    } else {
        FillFromSeed(local_seed.data(), local_seed.size(),
                     reinterpret_cast<const uint8_t*>(&counter), sizeof(counter), 0xBADC0DEULL);
        ++counter;
    }

    FillFromSeed(sk.data(), sk.size(), local_seed.data(), local_seed.size(), 0x1234ULL);
    pk = PublicKeyFromSecretKey(sk);
    return true;
}

bool MLDSA_Sign(
    MLDSASignature& sig,
    const uint8_t* msg,
    size_t msg_len,
    const MLDSASecretKey& sk,
    const uint8_t /*rnd*/[32])
{
    const MLDSAPublicKey pk = PublicKeyFromSecretKey(sk);
    BuildExpectedSignature(sig, pk, msg, msg_len);
    return true;
}

bool MLDSA_Verify(
    const MLDSASignature& sig,
    const uint8_t* msg,
    size_t msg_len,
    const MLDSAPublicKey& pk)
{
    MLDSASignature expected{};
    BuildExpectedSignature(expected, pk, msg, msg_len);
    return expected == sig;
}

bool MLDSA_Verify(
    std::span<const uint8_t, MLDSA_SIG_SIZE> sig,
    std::span<const uint8_t> msg,
    std::span<const uint8_t, MLDSA_PUBKEY_SIZE> pk)
{
    MLDSASignature sig_array{};
    MLDSAPublicKey pk_array{};
    std::copy(sig.begin(), sig.end(), sig_array.begin());
    std::copy(pk.begin(), pk.end(), pk_array.begin());
    return MLDSA_Verify(sig_array, msg.data(), msg.size(), pk_array);
}

int main()
{
    const std::vector<std::pair<std::string_view, void (*)()>> tests = {
        {"test_p2pqh_valid", test_p2pqh_valid},
        {"test_p2pqh_wrong_pubkey", test_p2pqh_wrong_pubkey},
        {"test_p2pqh_tampered_sig", test_p2pqh_tampered_sig},
        {"test_p2hpq_valid", test_p2hpq_valid},
        {"test_policy_p2pqh_standard", test_policy_p2pqh_standard},
        {"test_policy_wrong_sizes", test_policy_wrong_sizes},
        {"test_weight_calculation", test_weight_calculation},
    };

    size_t passed = 0;
    for (const auto& [name, test] : tests) {
        try {
            test();
            ++passed;
            std::cout << "[PASS] " << name << '\n';
        } catch (const std::exception& e) {
            std::cerr << "[FAIL] " << e.what() << '\n';
            return EXIT_FAILURE;
        }
    }

    std::cout << passed << " tests passed\n";
    return EXIT_SUCCESS;
}
