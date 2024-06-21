cmake_minimum_required(VERSION 3.28)
project(blook)

set(CMAKE_CXX_STANDARD 23)

add_library(blook STATIC src/blook.cpp
        src/Process.cpp
        src/Process.h
        src/Module.cpp
        src/Module.h)

add_executable(blook-test src/test.cpp)

add_dependencies(blook-test blook)
target_link_libraries(blook-test blook)
