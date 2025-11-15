#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <iostream>
#include <iterator>
#include <memory>
#include <openssl/evp.h>
#include <print>
#include <stdexcept>
#include <string>
#include <vector>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
private:
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }

public:
    Impl() {}
    ~Impl() {}

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {

        if (!inStream.good()) {
            throw std::runtime_error("Ошибка входного потока");
        }
        if (!outStream.good()) {
            throw std::runtime_error("Ошибка выходного потока");
        }

        // Чтение всех данных из inStream
        std::string input((std::istreambuf_iterator<char>(inStream)), std::istreambuf_iterator<char>());

        std::print("Входные данные: {}\n", input);

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;

        using UniquePtr =
            std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

        UniquePtr ctx{EVP_CIPHER_CTX_new()};

        std::vector<unsigned char> outBuf(input.size() + EVP_MAX_BLOCK_LENGTH);

        // Инициализируем cipher
        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error("Ошибка инициализации шифра");
        }

        int outLen1 = 0;
        int outLen2 = 0;

        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen1, reinterpret_cast<const unsigned char *>(input.data()),
                              input.size())) {
            throw std::runtime_error("Ошибка Update (данные повреждены?)");
        }

        // Заканчиваем работу с cipher
        if (!EVP_CipherFinal_ex(ctx.get(), std::next(outBuf.data(), outLen1), &outLen2)) {
            throw std::runtime_error("Ошибка Final (неверный ключ или повреждённый padding)");
        }

        std::string output(reinterpret_cast<char *>(outBuf.data()), outLen1 + outLen2);

        outStream << output;

        std::print("String encoded successfully. Result size: '{}'\n\n", output.size());
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {

        if (!inStream.good()) {
            throw std::runtime_error("Ошибка входного потока");
        }
        if (!outStream.good()) {
            throw std::runtime_error("Ошибка выходного потока");
        }

        // Чтение всех данных из inStream
        std::string input((std::istreambuf_iterator<char>(inStream)), std::istreambuf_iterator<char>());

        std::print("Входные данные: {}\n", input);

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;

        using UniquePtr =
            std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

        UniquePtr ctx{EVP_CIPHER_CTX_new()};

        // Инициализируем cipher
        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error("Ошибка инициализации шифра");
        }

        std::vector<unsigned char> outBuf(input.size() + EVP_MAX_BLOCK_LENGTH);

        int outLen1 = 0;
        int outLen2 = 0;

        if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen1, reinterpret_cast<const unsigned char *>(input.data()),
                              input.size())) {
            throw std::runtime_error("Ошибка Update (данные повреждены?)");
        }

        // Заканчиваем работу с cipher
        if (!EVP_CipherFinal_ex(ctx.get(), std::next(outBuf.data(), outLen1), &outLen2)) {
            throw std::runtime_error("Ошибка Final (неверный ключ или повреждённый padding)");
        }

        std::string output(reinterpret_cast<char *>(outBuf.data()), outLen1 + outLen2);

        outStream << output;

        std::print("String decoded successfully. Result size: '{}'\n\n", output.size());
    }

    std::string CalculateChecksum(std::iostream &inStream) {}
};

CryptoGuardCtx::CryptoGuardCtx() { OpenSSL_add_all_algorithms(); }
CryptoGuardCtx::~CryptoGuardCtx() { EVP_cleanup(); }

// API
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}
std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard
