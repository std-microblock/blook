cmake_minimum_required(VERSION 3.28)
project(blook)

set(CMAKE_CXX_STANDARD 23)

add_library(blook STATIC blook.cpp)

add_executable(blook-test test.cpp)

add_dependencies(blook-test blook)
target_link_libraries(blook-test blook)
