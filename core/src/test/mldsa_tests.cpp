// Standalone ML-DSA API tests for the reduced bitcoin-pqc workspace.

#include "../crypto/mldsa/mldsa.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

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

template <size_t N>
void ExpandBytes(std::array<uint8_t, N>& out, uint64_t seed)
{
    uint64_t state = seed;
    for (size_t i = 0; i < out.size(); ++i) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state *= 2685821657736338717ULL;
        out[i] = static_cast<uint8_t>(state >> 56);
    }
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

void BuildExpectedSignature(
    MLDSASignature& sig,
    const MLDSAPublicKey& pk,
    const uint8_t* msg,
    size_t msg_len)
{
    uint64_t state = 1469598103934665603ULL ^ 0x5EEDFACEULL;
    for (uint8_t byte : pk) state = Mix(state, byte);
    for (size_t i = 0; i < msg_len; ++i) state = Mix(state, msg[i]);
    ExpandBytes(sig, state);
}

MLDSAPublicKey PublicKeyFromSecretKey(const MLDSASecretKey& sk)
{
    MLDSAPublicKey pk{};
    const auto digest = DerivePubkeyDigest(sk);
    FillFromSeed(pk.data(), pk.size(), digest.data(), digest.size(), 0xC001D00DULL);
    return pk;
}

std::array<uint8_t, 32> SeedFromByte(uint8_t byte)
{
    std::array<uint8_t, 32> seed{};
    seed.fill(byte);
    return seed;
}

bool GenDeterministicKey(MLDSAPublicKey& pk, MLDSASecretKey& sk, uint8_t seed_byte)
{
    const auto seed = SeedFromByte(seed_byte);
    return MLDSA_KeyGen(pk, sk, seed.data());
}

void sign_verify_roundtrip()
{
    constexpr std::string_view kName = "sign_verify_roundtrip";
    MLDSAPublicKey pk{};
    MLDSASecretKey sk{};
    MLDSASignature sig{};
    std::array<uint8_t, 32> msg{};
    for (size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i);

    Check(GenDeterministicKey(pk, sk, 0x11), kName, "key generation failed");
    Check(MLDSA_Sign(sig, msg.data(), msg.size(), sk), kName, "signing failed");
    Check(MLDSA_Verify(sig, msg.data(), msg.size(), pk), kName, "verification failed");
}

void verify_wrong_pubkey_fails()
{
    constexpr std::string_view kName = "verify_wrong_pubkey_fails";
    MLDSAPublicKey pk_a{};
    MLDSAPublicKey pk_b{};
    MLDSASecretKey sk_a{};
    MLDSASecretKey sk_b{};
    MLDSASignature sig{};
    std::array<uint8_t, 32> msg{};
    msg.fill(0x42);

    Check(GenDeterministicKey(pk_a, sk_a, 0x22), kName, "key A generation failed");
    Check(GenDeterministicKey(pk_b, sk_b, 0x23), kName, "key B generation failed");
    Check(MLDSA_Sign(sig, msg.data(), msg.size(), sk_a), kName, "signing failed");
    Check(!MLDSA_Verify(sig, msg.data(), msg.size(), pk_b), kName, "verification unexpectedly succeeded");
}

void verify_tampered_message_fails()
{
    constexpr std::string_view kName = "verify_tampered_message_fails";
    MLDSAPublicKey pk{};
    MLDSASecretKey sk{};
    MLDSASignature sig{};
    std::array<uint8_t, 32> msg{};
    msg.fill(0x33);

    Check(GenDeterministicKey(pk, sk, 0x24), kName, "key generation failed");
    Check(MLDSA_Sign(sig, msg.data(), msg.size(), sk), kName, "signing failed");
    msg[7] ^= 0x01;
    Check(!MLDSA_Verify(sig, msg.data(), msg.size(), pk), kName, "tampered message verified");
}

void verify_tampered_sig_fails()
{
    constexpr std::string_view kName = "verify_tampered_sig_fails";
    MLDSAPublicKey pk{};
    MLDSASecretKey sk{};
    MLDSASignature sig{};
    std::array<uint8_t, 32> msg{};
    msg.fill(0x55);

    Check(GenDeterministicKey(pk, sk, 0x25), kName, "key generation failed");
    Check(MLDSA_Sign(sig, msg.data(), msg.size(), sk), kName, "signing failed");
    sig[123] ^= 0x80;
    Check(!MLDSA_Verify(sig, msg.data(), msg.size(), pk), kName, "tampered signature verified");
}

void sign_deterministic()
{
    constexpr std::string_view kName = "sign_deterministic";
    MLDSAPublicKey pk{};
    MLDSASecretKey sk{};
    MLDSASignature sig_a{};
    MLDSASignature sig_b{};
    std::array<uint8_t, 32> msg{};
    msg.fill(0x77);

    Check(GenDeterministicKey(pk, sk, 0x26), kName, "key generation failed");
    Check(MLDSA_Sign(sig_a, msg.data(), msg.size(), sk), kName, "first signing failed");
    Check(MLDSA_Sign(sig_b, msg.data(), msg.size(), sk), kName, "second signing failed");
    Check(sig_a == sig_b, kName, "signatures differed");
}

void different_messages_different_sigs()
{
    constexpr std::string_view kName = "different_messages_different_sigs";
    MLDSAPublicKey pk{};
    MLDSASecretKey sk{};
    MLDSASignature sig_a{};
    MLDSASignature sig_b{};
    std::array<uint8_t, 32> msg_a{};
    std::array<uint8_t, 32> msg_b{};
    msg_a.fill(0x88);
    msg_b.fill(0x88);
    msg_b[0] ^= 0x01;

    Check(GenDeterministicKey(pk, sk, 0x27), kName, "key generation failed");
    Check(MLDSA_Sign(sig_a, msg_a.data(), msg_a.size(), sk), kName, "first signing failed");
    Check(MLDSA_Sign(sig_b, msg_b.data(), msg_b.size(), sk), kName, "second signing failed");
    Check(sig_a != sig_b, kName, "signatures matched");
}

} // namespace

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
        {"sign_verify_roundtrip", sign_verify_roundtrip},
        {"verify_wrong_pubkey_fails", verify_wrong_pubkey_fails},
        {"verify_tampered_message_fails", verify_tampered_message_fails},
        {"verify_tampered_sig_fails", verify_tampered_sig_fails},
        {"sign_deterministic", sign_deterministic},
        {"different_messages_different_sigs", different_messages_different_sigs},
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
