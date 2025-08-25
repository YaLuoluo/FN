cmake_minimum_required(VERSION 3.2)
project(FN)

set(CMAKE_CXX_STANDARD 17)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Os -ffunction-sections -fdata-sections")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections -s")
endif ()

add_executable(FN
        main.cpp
        client.cpp client.h
        utils.cpp utils.h
        encryption.cpp encryption.h
)
target_include_directories(FN PUBLIC ${PROJECT_SOURCE_DIR}/include) # 头文件目录

# 链接 IXWebSocket 并，关闭 TLS 和压缩
include(FetchContent)
FetchContent_Declare(
        IXWebSocket
        GIT_REPOSITORY https://github.com/machinezone/IXWebSocket.git
        GIT_TAG v11.4.6  # 指定稳定版本
)
set(USE_TLS OFF CACHE BOOL "Disable TLS" FORCE)
set(USE_ZLIB OFF CACHE BOOL "Disable ZLIB" FORCE)
FetchContent_MakeAvailable(IXWebSocket)
target_link_libraries(FN PRIVATE ixwebsocket)

# 链接OpenSSL库
find_package(OpenSSL REQUIRED)
target_link_libraries(FN PRIVATE OpenSSL::Crypto)



