//
// Created by hekaibang on 2025/8/18.
//

#ifndef FN_CLIENT_H
#define FN_CLIENT_H

#include "include/json.hpp"
#include <ixwebsocket/IXWebSocket.h>



class client {
public:
    client();

    ~client();

    void connect(const std::string &url, int timeoutSecs = 3); //异步

    void send(const std::string &req, const nlohmann::json &js_data = nlohmann::json::object());

    void getRSAPub(int timeoutSecs = 3);

    void login(const std::string &username, const std::string &password,int timeoutSecs = 3,
               const std::string &deviceType = "Browser", const std::string &deviceName = "Linux-PortUpdate",
               bool stay = false
    );

    void setting_port(const int &http_port, const int &https_port, const bool &force_https, const bool &redirect, int timeoutSecs = 3);

private:
    ix::WebSocket webSocket_; // IXWebSocket 客户端实例
    void onWebSocketMessage(const ix::WebSocketMessagePtr &msg); //回调函数
    bool isConnected = false; //连接状态标记

    std::string getRSAPub_reqid;
    std::string login_reqid;
    std::string setting_reqid;

    std::string sign_key;
    std::string key;
    std::string iv;

    std::string pub;
    std::string si;

    std::string secret;
};


#endif //FN_CLIENT_H
