//
// Created by hekaibang on 2025/8/27.
//

#include "client.h"

#include <iostream>

#include "encryption.h"
#include "utils.h"
#include "ixwebsocket/IXNetSystem.h"

client::client() {
    ix::initNetSystem();

    getRSAPub_reqid = "";
    login_reqid = "";
    setting_reqid = "";

    sign_key = "";
    key = utils::generate_random_string(32);
    iv = utils::generate_random_string(16);

    pub = "";
    si = "";

    secret = "";

    // 设置消息回调
    webSocket.setOnMessageCallback([this](const ix::WebSocketMessagePtr &msg) {
        switch (msg->type) {
            case ix::WebSocketMessageType::Open: {
                // 连接成功
                Connected = true;
                cv.notify_one();
                break;
            }
            case ix::WebSocketMessageType::Message: {
                // 收到服务器消息
                nlohmann::json data = nlohmann::json::parse(msg->str);
                if (!data.contains("reqid")) {
                    std::cout << "> 非法消息: " << msg->str << std::endl;
                    break;
                }
                if (data["result"] == "succ" && data["reqid"] == getRSAPub_reqid) {
                    //收到公钥
                    pub = data["pub"];
                    si = data["si"];
                    Response = true;
                    cv.notify_one();
                    break;
                }
                if (data["reqid"] == login_reqid) {
                    if (data["result"] == "succ") {
                        secret = data["secret"];
                        sign_key = encryption::aes_decryption(secret, key, iv);
                        Response = true;
                        cv.notify_one();
                        break;
                    }
                    throw std::runtime_error("登陆错误：" + std::to_string(data["errno"].get<int>()));
                }
                if (data["reqid"] == setting_reqid) {
                    if (data["result"] == "succ") {
                        Response = true;
                        cv.notify_one();
                        break;
                    }
                    throw std::runtime_error("设置回执：设置失败");
                }
                break;
            }
            case ix::WebSocketMessageType::Error: {
                // 发生错误
                throw std::runtime_error("连接错误: " + msg->errorInfo.reason);
                break;
            }
            case ix::WebSocketMessageType::Close: {
                std::cout << "> 连接断开" << std::endl;
            default:
                break;
            }
        }
    });
}

client::~client() {
    webSocket.stop();
}

void client::connect(const std::string &url) {
    Connected = false;
    webSocket.setUrl(url);
    std::cout << "> 正在连接：" << url << std::endl;
    webSocket.start();
    std::unique_lock<std::mutex> lock(mtx);
    if (!cv.wait_for(lock, std::chrono::seconds(3), [this]() { return Connected; })) {
        throw std::runtime_error("连接超时");
    }
    std::cout << "> 连接建立" << std::endl;
}

void client::send(const std::string &req, const nlohmann::json &js_data) {
    std::string reqid = utils::get_reqid();
    nlohmann::json data = {
        {"req", req},
        {"reqid", reqid}
    };
    data.update(js_data);

    if (req == "util.crypto.getRSAPub") {
        getRSAPub_reqid = reqid;
    }
    if (req == "user.login") {
        login_reqid = reqid;

        std::string data_str = data.dump(); //将 JSON 数据转为字符串
        data = encryption::login_encrypt(data_str, pub, key, iv);
    }
    if (req == "appcgi.network.gw.setting") {
        setting_reqid = reqid;
    }

    //签名
    std::string message = encryption::get_signature(data, sign_key);
    webSocket.send(message);
    std::cout << "> 发送数据：" << req << "：" << message << std::endl;
}

void client::getRSAPub() {
    Response = false;
    const std::string req = "util.crypto.getRSAPub";
    send(req);
    std::unique_lock<std::mutex> lock(mtx);
    if (!cv.wait_for(lock, std::chrono::seconds(3), [this]() { return Response; })) {
        throw std::runtime_error("密钥超时");
    }
    std::cout << "> 返回密钥：\n" << pub << std::endl;
}

void client::login(const std::string &username, const std::string &password, bool stay,
                   const std::string &deviceType, const std::string &deviceName) {
    Response = false;
    nlohmann::json data = {
        {"user", username},
        {"password", password},
        {"deviceType", deviceType},
        {"deviceName", deviceName},
        {"stay", stay},
        {"si", si}
    };
    send("user.login", data);
    std::unique_lock<std::mutex> lock(mtx);
    if (!cv.wait_for(lock, std::chrono::seconds(3), [this]() { return Response; })) {
        throw std::runtime_error("登陆超时");
    }
    std::cout << "> 登陆回执：登陆成功" << std::endl;
}

void client::setting_port(const int &http_port, const int &https_port, const bool &force_https, const bool &redirect) {
    Response = false;
    nlohmann::json data = {
        {
            "data", {
                {"force_https", force_https},
                {"redirect", redirect},
                {
                    "schema", {
                        {
                            "http", {
                                {"port", http_port}
                            }
                        },
                        {
                            "https", {
                                {"port", https_port}
                            }
                        }
                    }
                }
            }
        }
    };
    send("appcgi.network.gw.setting", data);
    std::unique_lock<std::mutex> lock(mtx);
    if (!cv.wait_for(lock, std::chrono::seconds(3), [this]() { return Response; })) {
        throw std::runtime_error("设置超时");
    }
    std::cout << "> 设置回执：设置成功" << std::endl;
}
