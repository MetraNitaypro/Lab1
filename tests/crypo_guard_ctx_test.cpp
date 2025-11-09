#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <print>

TEST(crypto_guard_ctx, EcryptDecrypt) {
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
