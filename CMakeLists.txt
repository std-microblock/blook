cmake_minimum_required(VERSION 3.25)
project(blook)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 90)

if(WIN32)
    # MSVC runtime library
    cmake_policy(SET CMP0091 NEW)
    if(NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY)
       
    endif()
endif()

add_subdirectory(external/zasm)

set(BLOOK_SOURCE_WINDOWS src/platform/windows/process.cpp
    src/platform/windows/module.cpp
    src/platform/windows/memory.cpp
    src/platform/windows/misc.cpp
    src/platform/windows/thread.cpp
    )

set(BLOOK_SOURCE_LINUX src/platform/linux/memory.cpp)

set(BLOOK_SOURCE_UNIVERSAL src/function.cpp
    src/memory.cpp
    src/hook.cpp
    src/utils.cpp
    src/mb_kmp.cpp
    src/disassembly.cpp)

if(WIN32)
    add_executable(blook-dll-hijack-codegen src/platform/windows/codegen/DllHijackCodegen.cpp)
    add_library(blook STATIC ${BLOOK_SOURCE_WINDOWS} ${BLOOK_SOURCE_UNIVERSAL})
elseif(UNIX)
    add_library(blook STATIC ${BLOOK_SOURCE_LINUX} ${BLOOK_SOURCE_UNIVERSAL})
endif()

target_include_directories(blook PUBLIC ./include)

target_link_libraries(blook zasm::zasm)

### Testing targets
if(WIN32)
    add_executable(blook-test src/tests/test_windows.cpp)
elseif(UNIX)
    add_executable(blook-test src/tests/test_linux.cpp)
endif()

add_dependencies(blook-test blook)

target_link_libraries(blook-test blook)
