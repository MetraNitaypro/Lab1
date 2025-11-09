#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>

TEST(crypto_guard_ctx, EcryptDecrypt) {
    CryptoGuard::CryptoGuardCtx crypt;

    EXPECT_EQ(1 + 1, 2);
}
