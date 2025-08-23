//
// Created by hekaibang on 2025/8/18.
//

#ifndef FN_UTILS_H
#define FN_UTILS_H

#include <iostream>
#include <string>


namespace utils {
    std::string format_hex(unsigned int value, int width);
    std::string get_reqid();
    std::string generate_random_string(size_t length);
}


#endif //FN_UTILS_H