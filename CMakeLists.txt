cmake_minimum_required(VERSION 3.25)
project(blook)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_C_STANDARD 90)
add_subdirectory(external/zasm)

# MSVC runtime library
cmake_policy(SET CMP0091 NEW)
if (NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif ()

add_executable(blook-dll-hijack-codegen src/codegen/DllHijackCodegen.cpp)

add_library(blook STATIC
        src/Process.cpp
        src/Module.cpp
        src/Function.cpp
        src/Memo.cpp
        src/Hook.cpp
        src/utils.cpp
        src/Hook.cpp
        src/misc.cpp
        src/mb_kmp.cpp
        src/Disassembly.cpp
        include/blook/Disassembly.h
        include/blook/Concepts.h
        include/blook/Concepts.h
)
target_include_directories(blook PUBLIC ./include)

target_link_libraries(blook zasm::zasm)

### Testing targets
add_executable(blook-test src/test.cpp)
add_library(blook-test-dll SHARED src/test.cpp)
add_dependencies(blook-test-dll blook)
add_dependencies(blook-test blook)

target_link_libraries(blook-test blook)
target_link_libraries(blook-test-dll blook)