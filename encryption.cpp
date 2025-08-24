//
// Created by hekaibang on 2025/8/18.
//

#include "encryption.h"
#include <iostream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>

namespace encryption {
    //base64解码
    std::string base64_decoder(const std::string &encoded) {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *mem = BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size()));
        BIO_push(b64, mem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 禁用换行
        char buffer[1024]; // 定义缓冲区
        std::string result;
        int len = 0;
        while ((len = BIO_read(b64, buffer, sizeof(buffer))) > 0) {
            result.append(buffer, len);
        }
        BIO_free_all(b64);
        return result;
    }

    //base64编码
    std::string base64_encoder(const std::string &decoded) {
        BIO *b64 = BIO_new(BIO_f_base64());
        BIO *mem = BIO_new(BIO_s_mem());
        BIO_push(b64, mem);
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // 禁用换行符
        BIO_write(b64, decoded.data(), static_cast<int>(decoded.size()));
        BIO_flush(b64);
        BUF_MEM *buffer = nullptr;
        BIO_get_mem_ptr(mem, &buffer);
        std::string result(buffer->data, buffer->length);
        BIO_free_all(b64);
        return result;
    }


    //RSA加密
    std::string rsa_encrypt(const std::string &public_key_str, const std::string &plaintext) {
        // 使用BIO加载PEM格式的公钥
        BIO *bio = BIO_new_mem_buf(public_key_str.data(), static_cast<int>(public_key_str.size()));
        EVP_PKEY *evp_public_key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio); // 释放BIO资源
        // 创建 与 初始化 EVP加密上下文 （OpenSSL默认使用 PKCS#1v1.5 填充）
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_public_key, nullptr);
        EVP_PKEY_encrypt_init(ctx);
        // 获取加密后的最大数据长度
        size_t encrypted_len = EVP_PKEY_size(evp_public_key);
        std::vector<unsigned char> encrypted_data(encrypted_len); // 用于存储加密后的数据
        // 执行加密操作
        EVP_PKEY_encrypt(ctx, encrypted_data.data(), &encrypted_len,
                         reinterpret_cast<const unsigned char *>(plaintext.data()), plaintext.size());
        // 清理资源
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(evp_public_key);
        // 返回Base64编码后的加密结果
        return base64_encoder(std::string(encrypted_data.begin(), encrypted_data.end()));
    }

    // AES加密
    std::string aes_encrypt(const std::string &data, const std::string &key, const std::string &iv) {
        // 创建EVP加密上下文
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        // 初始化EVP加密上下文，使用AES-256-CBC算法
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char *>(key.data()),
                           reinterpret_cast<const unsigned char *>(iv.data()));
        // 用于存储加密后的数据
        std::vector<unsigned char> encrypted_data(data.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
        int len = 0;
        int ciphertext_len = 0;
        // 执行加密操作
        EVP_EncryptUpdate(ctx, encrypted_data.data(), &len,
                          reinterpret_cast<const unsigned char *>(data.data()),
                          static_cast<int>(data.size()));
        ciphertext_len = len;
        // 完成加密操作
        EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &len);
        ciphertext_len += len;
        // 释放加密上下文
        EVP_CIPHER_CTX_free(ctx);
        // 返回Base64编码后的加密结果
        return base64_encoder(std::string(encrypted_data.begin(), encrypted_data.begin() + ciphertext_len));
    }

    //AES解密
    std::string aes_decryption(const std::string &data, const std::string &key, const std::string &iv) {
        // 创建EVP解密上下文
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        // 初始化EVP解密上下文，使用AES-256-CBC算法
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char *>(key.data()),
                           reinterpret_cast<const unsigned char *>(iv.data()));
        // 将Base64解码后的数据存储在此向量中
        std::string decoded_data = base64_decoder(data);
        std::vector<unsigned char> decrypted_data(decoded_data.size());
        int len = 0;
        int plaintext_len = 0;
        // 执行解密操作
        EVP_DecryptUpdate(ctx, decrypted_data.data(), &len,
                          reinterpret_cast<const unsigned char *>(decoded_data.data()),
                          static_cast<int>(decoded_data.size()));
        plaintext_len = len;
        // 完成解密操作
        EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &len);
        plaintext_len += len;
        // 释放解密上下文
        EVP_CIPHER_CTX_free(ctx);
        // 返回解密后的结果
        return base64_encoder(std::string(decrypted_data.begin(), decrypted_data.begin() + plaintext_len));
    }

    // hmac_sha256
    std::string hmac_sha256(const std::string &data_str, const std::string &key_base64) {
        // 解码 Base64 的密钥
        std::string key = base64_decoder(key_base64); // Decode base64 key
        // 使用 HMAC 函数进行 HMAC-SHA256 计算
        unsigned char result[EVP_MAX_MD_SIZE]; // 用于存储HMAC计算结果
        unsigned int len = 0;
        // 计算 HMAC
        HMAC(EVP_sha256(), key.c_str(), static_cast<int>(key.size()),
             reinterpret_cast<const unsigned char *>(data_str.c_str()), data_str.length(), result, &len);
        return {reinterpret_cast<char*>(result), len}; // Base64 编码结果
    }

    //签名
    std::string get_signature(const nlohmann::json &data, const std::string &key_base64) {
        std::string data_str = data.dump(); //将 JSON 数据转为字符串
        if (data["req"] != "util.crypto.getRSAPub" && data["req"] != "encrypted") {
            // 计算签名
            return base64_encoder(hmac_sha256(data_str, key_base64)) + data_str;
        }
        return data_str;
    }


    nlohmann::json login_encrypt(const std::string &data, const std::string &pub, const std::string &key,
                                 const std::string &iv) {
        //pub为服务器返回公钥，key为本地随即生成
        // RSA 加密
        std::string rsa_encrypted = rsa_encrypt(pub, key);
        // AES 加密
        std::string aes_encrypted = aes_encrypt(data, key, iv);

        return nlohmann::json{
            {"req", "encrypted"},
            {"iv", base64_encoder(iv)},
            {"rsa", rsa_encrypted},
            {"aes", aes_encrypted}
        };
    }
}
