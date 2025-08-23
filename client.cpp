//
// Created by hekaibang on 2025/8/18.
//

#include "client.h"
#include "encryption.h"
#include "utils.h"
#include <iostream>
#include <ixwebsocket/IXHttpClient.h>
#include <ixwebsocket/IXNetSystem.h>

client::client() {
    getRSAPub_reqid = "";
    login_reqid = "";
    setting_reqid = "";

    sign_key = "";
    key = utils::generate_random_string(32);
    iv = utils::generate_random_string(16);

    pub = "";
    si = "";

    secret = "";

    ix::initNetSystem(); // ixWebSocket 初始化网络系统
}

client::~client() {
    webSocket_.close(); // 关闭 WebSocket 连接
}

void client::onWebSocketMessage(const ix::WebSocketMessagePtr &msg) {
    switch (msg->type) {
        case ix::WebSocketMessageType::Open: {
            // 连接成功
            std::cout << "> 连接成功" << std::endl;
            isConnected = true;
            break;
        }
        case ix::WebSocketMessageType::Message: {
            // 收到服务器消息
            std::cout << "> 收到消息: " << msg->str << std::endl;
            nlohmann::json data = nlohmann::json::parse(msg->str);
            if (!data.contains("reqid")) {
                std::cout << "> 非法消息: " << msg->str << std::endl;
                break;
            }
            if (data["result"] == "succ" && data["reqid"] == getRSAPub_reqid) {
                pub = data["pub"];
                si = data["si"];
                std::cout << "> 获取证书：" << '\n' << pub;
                break;
            }
            if (data["reqid"] == login_reqid) {
                if (data["result"] == "succ") {
                    secret = data["secret"];
                    sign_key = encryption::aes_decryption(secret, key, iv);
                    std::cout << "> 登陆回执：登陆成功" << std::endl;
                    break;
                }
                if (data["errno"] == 131072) {
                    std::cout << "> 登陆回执：用户名或密码错误" << std::endl;
                    std::exit(1);
                }
            }
            if (data["reqid"] == setting_reqid) {
                if (data["result"] == "succ") {
                    std::cout << "> 设置回执：设置成功" << std::endl;
                    break;
                }
                std::cout << "> 设置回执：设置失败" << std::endl;
                break;
            }
            break;
        }
        case ix::WebSocketMessageType::Error: {
            // 发生错误
            std::cout << "> 连接错误: " << msg->errorInfo.reason << std::endl;
            break;
        }
        case ix::WebSocketMessageType::Close: {
            std::cout << "> 连接断开" << std::endl;
            isConnected = false;
        default:
            break;
        }
    }
}

//异步，但阻塞
void client::connect(const std::string &url, int timeoutSecs) {
    // 设置目标服务器地址
    webSocket_.setUrl(url);

    // 调用消息回调函数（关键逻辑：处理连接状态、接收消息、错误）
    webSocket_.setOnMessageCallback(
        [this](const ix::WebSocketMessagePtr &msg) {
            this->onWebSocketMessage(msg);
        }
    );

    // 启动连接
    std::cout << "> 正在连接: " << url << " ..." << std::endl;
    webSocket_.start();

    const int checkIntervalMs = 100; // 检测间隔
    int elapsedMs = 0; // 计时器
    while (elapsedMs < timeoutSecs * 1000) {
        if (isConnected) {
            break; // 连接成功，跳出循环
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(checkIntervalMs));
        elapsedMs += checkIntervalMs;
    }
    // 连接超时
    if (!isConnected) {
        std::cout << "> 连接超时" << std::endl;
        std::exit(1);
    }
}

void client::send(const std::string &req, const nlohmann::json &js_data) {
    if (isConnected) {
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
        webSocket_.send(message);
        std::cout << "> 发送数据：" << req << "：" << message << std::endl;
    } else {
        std::cerr << "> 发送失败：连接断开" << std::endl;
    }
}

void client::getRSAPub(int timeoutSecs) {
    const std::string req = "util.crypto.getRSAPub";
    send(req);

    const int checkIntervalMs = 100; // 检测间隔
    int elapsedMs = 0; // 计时器
    while (elapsedMs < timeoutSecs * 1000) {
        if (pub != "") {
            break; // 收到公钥，跳出循环
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(checkIntervalMs));
        elapsedMs += checkIntervalMs;
    }
    // 连接超时
    if (!isConnected) {
        std::cout << "> 公钥超时" << std::endl;
        std::exit(1);
    }
}

void client::login(const std::string &username, const std::string &password, int timeoutSecs,
                   const std::string &deviceType, const std::string &deviceName, bool stay) {
    nlohmann::json data = {
        {"user", username},
        {"password", password},
        {"deviceType", deviceType},
        {"deviceName", deviceName},
        {"stay", stay},
        {"si", si}
    };
    send("user.login", data);

    const int checkIntervalMs = 100; // 检测间隔
    int elapsedMs = 0; // 计时器
    while (elapsedMs < timeoutSecs * 1000) {
        if (secret != "") {
            break; // 收到签名密钥，跳出循环
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(checkIntervalMs));
        elapsedMs += checkIntervalMs;
    }
    // 连接超时
    if (!isConnected) {
        std::cout << "> 登陆失败" << std::endl;
        std::exit(1);
    }
}


void client::setting_port(const int &http_port, const int &https_port, const bool &force_https, const bool &redirect,
                          int timeoutSecs) {
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
}
