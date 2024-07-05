cmake_minimum_required(VERSION 3.25)
project(blook)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 90)
add_subdirectory(external/zasm external/libpeconv)
enable_language(C ASM_MASM)
add_library(blook STATIC
        src/Process.cpp
        src/Module.cpp
        src/Function.cpp
        src/Memo.cpp src/asm.asm
        src/Hook.cpp
        include/Hook.h
        src/utils.cpp
        include/utils.h
        src/Hook.cpp
        src/misc.cpp
        include/misc.h
)
include_directories(blook ./)
target_link_libraries(blook zasm::zasm libpeconv)
set_property(TARGET blook PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
add_executable(blook-test src/test.cpp)
add_library(blook-test-dll SHARED src/test.cpp)
add_dependencies(blook-test-dll blook)
add_dependencies(blook-test blook)
set_property(TARGET blook-test PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_property(TARGET blook-test-dll PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_link_libraries(blook-test blook)
target_link_libraries(blook-test-dll blook)