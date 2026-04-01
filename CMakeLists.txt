cmake_minimum_required(VERSION 4.2)
project(HookPassChecker)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
set(CMAKE_CXX_STANDARD 20)

add_library(HookPassChecker SHARED main.cpp)
