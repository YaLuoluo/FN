//
// Created by hekaibang on 2025/8/27.
//

#ifndef FN_PORT_CLIENT_H
#define FN_PORT_CLIENT_H
#include <string>

#include "json.hpp"
#include "ixwebsocket/IXWebSocket.h"


class client {
public:
    client();

    ~client();

    void connect(const std::string &url);

    void send(const std::string &req, const nlohmann::json &js_data = nlohmann::json::object());

    void getRSAPub();

    void login(const std::string &username, const std::string &password, bool stay = false,
               const std::string &deviceType = "Browser", const std::string &deviceName = "Linux-PortUpdate");

    void setting_port(const int &http_port, const int &https_port, const bool &force_https, const bool &redirect);

private:
    ix::WebSocket webSocket;

    std::string getRSAPub_reqid;
    std::string login_reqid;
    std::string setting_reqid;

    std::string sign_key;
    std::string key;
    std::string iv;

    std::string pub;
    std::string si;

    std::string secret;

    std::mutex mtx;
    std::condition_variable cv;
    bool Connected = false;
    bool Response = false;
};


#endif //FN_PORT_CLIENT_H
