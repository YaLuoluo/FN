// main.cpp

#include <iostream>
#include <string>
#include <fstream>
#include <json.hpp>
#include "client.h"

bool readConfig(std::string &serverAddr, std::string &username, std::string &password) {
    std::ifstream configFile("config.json");
    if (!configFile.is_open()) {
        return false;
    }
    nlohmann::json config;
    configFile >> config;
    if (config.contains("username") && config.contains("password") && config.contains("serverAddr")) {
        username = config["username"];
        password = config["password"];
        serverAddr = config["serverAddr"];
        return true;
    }
    return false;
}

void saveConfig(const std::string &serverAddr, const std::string &username, const std::string &password) {
    nlohmann::ordered_json config;
    config["username"] = username;
    config["password"] = password;
    config["serverAddr"] = serverAddr;

    std::ofstream configFile("config.json");
    configFile << config.dump(4);
}

int main(int argc, char *argv[]) {
    std::string serverAddr, username, password;
    int port1, port2;
    if (readConfig(serverAddr, username, password)) {
        std::cout << "读取配置成功" << std::endl;
    } else {
        std::cout << "请输入服务器地址（如 127.0.0.1:5666）: ";
        std::cin >> serverAddr;
        std::cout << "请输入用户名: ";
        std::cin >> username;
        std::cout << "请输入密码: ";
        std::cin >> password;
        saveConfig(serverAddr, username, password);
    }
    if (argc == 3) {
        port1 = std::stoi(argv[1]);
        port2 = std::stoi(argv[2]);
    }else {
        std::cout << "请输入端口1: ";
        std::cin >> port1;
        std::cout << "请输入端口2: ";
        std::cin >> port2;
    }

    std::string wsUrl = "ws://" + serverAddr + "/websocket?type=main";

    // 创建客户端对象
    client fnos;

    // 建立连接
    fnos.connect(wsUrl); //异步

    //获取公钥
    fnos.getRSAPub();

    // 登陆
    fnos.login(username, password);

    // 设置端口
    fnos.setting_port(port1, port2, false, true);

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));

    return 0;
}
