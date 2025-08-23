//
// Created by hekaibang on 2025/8/18.
//

#include "utils.h"
#include <ctime>
#include <random>

namespace utils {
    //生成唯一访问ID
    int index = 1;
    std::string format_hex(unsigned int value, int width) {
        char buffer[32];
        // 格式化：%0<width>x 表示 width 位十六进制+前导补零
        std::snprintf(buffer, sizeof(buffer), "%0*x", width, value);
        return buffer;
    }
    std::string get_reqid() {
        std::time_t now = std::time(nullptr);
        // 时间戳转8位十六进制
        std::string t = format_hex(static_cast<unsigned int>(now), 8);
        // 序列号转4位十六进制
        std::string e = format_hex(index++, 4);
        return t + e;
    }
    // std::string get_reqid() {
    //     std::time_t now = std::time(nullptr); //获取时间戳
    //     std::string t = std::format("{:08x}", static_cast<unsigned int>(now)); //时间戳转8位16进制，固定8位，前面补零
    //     std::string e = std::format("{:04x}", index); //序列号转4位16进制，固定4位，前面补零
    //     index++;
    //     return t + e;
    // }

    //获取指定长度字符串
    std::string generate_random_string(size_t length) {
        const std::string chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        static std::random_device rd; //随机种子
        static std::mt19937 gen(rd()); //随机数生成引擎
        std::uniform_int_distribution<> dis(0, chars.size() - 1); //生成 [0, 61]范围内的均匀随机整数

        std::string result;
        for (size_t i = 0; i < length; ++i) {
            result += chars[dis(gen)];
        }
        return result;
    }
}
