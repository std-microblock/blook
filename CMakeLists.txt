cmake_minimum_required(VERSION 3.25)
project(blook)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 90)
add_subdirectory(external/zasm)

add_library(blook STATIC src/blook.cpp
        src/Process.cpp
        src/Module.cpp
        src/Function.cpp
        src/Memo.cpp)
include_directories(blook include external/zasm/zasm/include external/zasm/)


add_executable(blook-test src/test.cpp)

add_dependencies(blook-test blook)
target_link_libraries(blook-test blook zasm::zasm)
