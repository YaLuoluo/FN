//
// Created by hekaibang on 2025/8/18.
//

#ifndef FN_ENCRYPTION_H
#define FN_ENCRYPTION_H

#include <iostream>
#include "include/json.hpp"

namespace encryption {
    std::string base64_decoder(const std::string &encoded); //base64解码

    std::string base64_encoder(const std::string &decoded); //base64编码

    std::string rsa_encrypt(const std::string &public_key_str, const std::string &plaintext); //RSA加密

    std::string aes_encrypt(const std::string &data, const std::string &key, const std::string &iv); //AES加密

    std::string aes_decryption(const std::string &data, const std::string &key, const std::string &iv); //AES解密

    std::string get_signature(const nlohmann::json &data, const std::string &key_base64); //签名

    nlohmann::json login_encrypt(const std::string &data, const std::string &pub, const std::string &key,
                                 const std::string &iv);
};


#endif //FN_ENCRYPTION_H
