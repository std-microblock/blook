set_xmakever("2.9.8")

set_allowedplats("windows", "linux")
add_rules("plugin.compile_commands.autoupdate", {outputdir = "build"})
add_rules("mode.debug", "mode.release", "mode.releasedbg")
set_allowedmodes("debug", "release", "releasedbg")

set_languages("c++23")
set_encodings("utf-8")

add_requires("zasm 2024.05.14", "gtest")

target("blook")
    set_kind("static")
    add_files("src/*.cpp", "src/**/*.cc")
    add_defines("WIN32_LEAN_AND_MEAN", "NOMINMAX")
    if is_plat("windows") then
        add_files("src/platform/windows/*.cpp")
    elseif is_plat("linux") then
        add_files("src/platform/linux/*.cpp")
    end
    add_includedirs("include", {public = true})
    add_headerfiles("include/(**.h)")

    if is_plat("windows") then
        add_syslinks("advapi32")
    end
    add_packages("zasm", {public = true})

target("blook-dll-hijack-codegen")
    set_enabled(is_plat("windows"))
    set_kind("binary")
    add_files("src/platform/windows/codegen/DllHijackCodegen.cpp")

target("blook-test")
    set_default(false)
    set_kind("binary")
    if is_plat("windows") then
        add_files("src/tests/test_windows.cpp")
    elseif is_plat("linux") then
        add_files("src/tests/test_linux.cpp")
    end

    if is_plat("windows") then
        add_syslinks("user32")
    end
    add_packages("gtest")
    add_deps("blook")

    add_tests("default")
