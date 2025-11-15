#include "crypto_guard_ctx.h"
#include <cstddef>  // для size_t
#include <gtest/gtest.h>
#include <ios>
#include <print>
#include <random>  // для std::mt19937, std::random_device, std::uniform_int_distribution

std::string RandomString(size_t length) {
    static const std::string chars = "abcdefghijklmnopqrstuvwxyz"
                                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                     "0123456789";

    thread_local static std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, chars.size() - 1);

    std::string s;
    s.reserve(length);

    for (size_t i = 0; i < length; i++)
        s += chars[dist(rng)];

    return s;
}
TEST(crypto_guard_ctx, EcryptDecrypt1) {
    CryptoGuard::CryptoGuardCtx crypt;

    std::stringstream input;
    std::stringstream output;
    input << "Hellow World!";
    std::print("Входные данные: {}\n", input.str());

    crypt.EncryptFile(input, output, "123");
    std::print("Выходные данные: {}\n", output.str());

    input.str("");  // очищает буфер
    input.clear();  // сбрасывает флаги

    crypt.DecryptFile(output, input, "123");
    std::print("Выходные данные: {}\n", input.str());

    EXPECT_EQ(input.str(), "Hellow World!");
}
TEST(crypto_guard_ctx, EcryptDecrypt2) {
    CryptoGuard::CryptoGuardCtx crypt;
    for (int i = 1; i < 2000; i++) {
        std::stringstream input;
        std::stringstream output;
        std::string str = RandomString(i);
        input << str;
        std::print("Входные данные: {}\n", input.str());

        crypt.EncryptFile(input, output, "123");
        std::print("Выходные данные: {}\n", output.str());

        input.str("");  // очищает буфер
        input.clear();  // сбрасывает флаги

        crypt.DecryptFile(output, input, "123");
        std::print("Выходные данные: {}\n", input.str());

        EXPECT_EQ(input.str(), str);
    }
}
TEST(crypto_guard_ctx, CalculateChecksum) {
    CryptoGuard::CryptoGuardCtx crypt;

    std::stringstream input;
    input << "Hellow World!";

    auto result = crypt.CalculateChecksum(input);

    std::print("Check sum: {}\n", result);

    EXPECT_EQ("467b3a942074fa0006512f206d32b8eca43596bc653b83f8cdfe1c3085e67411", result);
}

TEST(crypto_guard_ctx, EcryptDecryptFailStream1) {
    CryptoGuard::CryptoGuardCtx crypt;
    std::stringstream input;
    std::stringstream output;
    input.setstate(std::ios::failbit);
    EXPECT_THROW(crypt.EncryptFile(input, output, "123"), std::runtime_error);
}
TEST(crypto_guard_ctx, EcryptDecryptFailStream2) {
    CryptoGuard::CryptoGuardCtx crypt;
    std::stringstream input;
    std::stringstream output;
    output.setstate(std::ios::failbit);
    ASSERT_THROW(crypt.EncryptFile(input, output, "123"), std::runtime_error);
}
TEST(crypto_guard_ctx, EcryptDecryptFailStream3) {
    CryptoGuard::CryptoGuardCtx crypt;
    std::stringstream input;
    std::stringstream output;
    input.setstate(std::ios::failbit);
    ASSERT_THROW(crypt.DecryptFile(input, output, "123"), std::runtime_error);
}
TEST(crypto_guard_ctx, EcryptDecryptFailStream4) {
    CryptoGuard::CryptoGuardCtx crypt;
    std::stringstream input;
    std::stringstream output;
    output.setstate(std::ios::failbit);
    ASSERT_THROW(crypt.DecryptFile(input, output, "123"), std::runtime_error);
}
TEST(crypto_guard_ctx, EcryptDecryptFailStream5) {
    CryptoGuard::CryptoGuardCtx crypt;
    std::stringstream input;
    input.setstate(std::ios::failbit);
    EXPECT_THROW(crypt.CalculateChecksum(input), std::runtime_error);
}
