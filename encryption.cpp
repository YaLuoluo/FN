//
// Created by hekaibang on 2025/8/18.
//

#include "encryption.h"
#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pem.h>
#include <string>
#include <cryptopp/modes.h>


namespace encryption {
    //base64解码
    std::string base64_decoder(const std::string &encoded) {
        std::string decoded;
        CryptoPP::StringSource(encoded, true,
                               new CryptoPP::Base64Decoder(
                                   new CryptoPP::StringSink(decoded)
                               )
        );
        return decoded;
    }

    //base64编码
    std::string base64_encoder(const std::string &decoded) {
        std::string encoded;
        CryptoPP::StringSource(decoded, true,
                               new CryptoPP::Base64Encoder(
                                   new CryptoPP::StringSink(encoded),
                                   false // 不插入换行符
                               )
        );
        return encoded;
    }

    //RSA加密
    std::string rsa_encrypt(const std::string &public_key_str, const std::string &plaintext) {
        // 创建内存源来读取PEM字符串
        CryptoPP::StringSource publicKeySource(public_key_str, true);

        // 加载公钥
        CryptoPP::RSA::PublicKey publicKey;
        CryptoPP::PEM_Load(publicKeySource, publicKey);

        CryptoPP::AutoSeededRandomPool prng;

        // 创建RSA加密器（PKCS#1 v1.5填充）
        CryptoPP::RSAES_PKCS1v15_Encryptor encryptor(publicKey);

        // 计算加密后的数据大小
        size_t ciphertextSize = encryptor.CiphertextLength(plaintext.size());
        std::string ciphertext;
        ciphertext.resize(ciphertextSize);

        // 执行加密
        encryptor.Encrypt(prng,
                          reinterpret_cast<const CryptoPP::byte *>(plaintext.data()),
                          plaintext.size(),
                          reinterpret_cast<CryptoPP::byte *>(&ciphertext[0]));

        // 返回Base64编码的密文
        return base64_encoder(ciphertext);


        // // 加载公钥
        // CryptoPP::RSA::PublicKey publicKey;
        // CryptoPP::StringSource(public_key_str, true).TransferTo(publicKey);
        //
        // // 创建RSA加密器（PKCS#1 v1.5填充）
        // CryptoPP::RSAES_PKCS1v15_Encryptor encryptor(publicKey);
        //
        // // 执行加密
        // std::string ciphertext;
        // CryptoPP::StringSource(plaintext, true,
        //     new CryptoPP::PK_EncryptorFilter(CryptoPP::AutoSeededRandomPool(), encryptor,
        //         new CryptoPP::StringSink(ciphertext)
        //     )
        // );
        //
        // // 返回Base64编码的密文
        // return base64_encoder(ciphertext);
    }

    //AES加密
    std::string aes_encrypt(const std::string &data, const std::string &key, const std::string &iv) {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte *>(key.data()), key.size(),
                       reinterpret_cast<const CryptoPP::byte *>(iv.data()));

        std::string ciphertext;
        CryptoPP::StringSource(data, true,
                               new CryptoPP::StreamTransformationFilter(
                                   e, new CryptoPP::StringSink(ciphertext)
                               )
        );
        return base64_encoder(ciphertext);
    }

    //AES解密
    std::string aes_decryption(const std::string &data, const std::string &key, const std::string &iv) {
        std::string data_de64 = base64_decoder(data);
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption e;
        e.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte *>(key.data()), key.size(),
                       reinterpret_cast<const CryptoPP::byte *>(iv.data()));
        std::string decryptedtext;
        CryptoPP::StringSource(data_de64, true,
                               new CryptoPP::StreamTransformationFilter(
                                   e, new CryptoPP::StringSink(decryptedtext),
                                   CryptoPP::StreamTransformationFilter::PKCS_PADDING));//设置 PKCS#7 填充
        return base64_encoder(decryptedtext);
    }

    //签名
    std::string get_signature(const nlohmann::json &data, const std::string &key_base64) {
        std::string data_str = data.dump(); //将 JSON 数据转为字符串
        if (data["req"] != "util.crypto.getRSAPub" && data["req"] != "encrypted") {
            // 签名
            std::string key_bytes = base64_decoder(key_base64);

            // 计算 HMAC-SHA256
            CryptoPP::HMAC<CryptoPP::SHA256> hmac(
                reinterpret_cast<const CryptoPP::byte *>(key_bytes.data()), key_bytes.size()
            );
            std::string signature;
            std::string mac;
            CryptoPP::StringSource ss(
                data_str, true,
                new CryptoPP::HashFilter(hmac,
                                         new CryptoPP::StringSink(mac)
                )
            );
            // Base64 编码 mac 得到 signature
            signature = base64_encoder(mac);

            return signature + data_str;
        }
        return data_str;
    }

    nlohmann::json login_encrypt(const std::string &data, const std::string &pub, const std::string &key,
                                 const std::string &iv) {
        std::string rsa_encrypted;
        std::string aes_encrypted;

        //pub服务器公钥 key本地随即生成
        // RSA 加密
        rsa_encrypted = rsa_encrypt(pub, key);
        // AES 加密
        aes_encrypted = aes_encrypt(data, key, iv);

        return nlohmann::json{
            {"req", "encrypted"},
            {"iv", base64_encoder(iv)},
            {"rsa", rsa_encrypted},
            {"aes", aes_encrypted}
        };
    }
}
