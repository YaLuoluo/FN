// main.cpp

#include <iostream>
#include <string>
#include "client.h"

int main(int argc, char* argv[]) {
    std::string serverAddr, username, password;
    int port1, port2;
    if (argc == 6) {
        // 从命令行参数读取
        serverAddr = argv[1];
        username = argv[2];
        password = argv[3];
        port1 = std::stoi(argv[4]);
        port2 = std::stoi(argv[5]);
    }else {
        std::cout << "请输入服务器地址（如 127.0.0.1:5666）: ";
        std::cin >> serverAddr;
        std::cout << "请输入用户名: ";
        std::cin >> username;
        std::cout << "请输入密码: ";
        std::cin >> password;
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
    fnos.setting_port(port1,port2,false,true);

    std::this_thread::sleep_for(std::chrono::milliseconds(3000));


    return 0;
}
