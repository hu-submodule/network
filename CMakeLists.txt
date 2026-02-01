cmake_minimum_required(VERSION 3.10)

# 定义静态库
add_library(hs_network STATIC hs_network.c)

# 添加头文件搜索路径
target_include_directories(hs_network PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
