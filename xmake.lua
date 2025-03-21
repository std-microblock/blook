set_xmakever("2.9.8")

set_allowedplats("windows", "linux")

add_rules("mode.debug", "mode.release", "mode.releasedbg")
set_allowedmodes("debug", "release", "releasedbg")

set_languages("c++23")
set_encodings("utf-8")

add_requires("zasm edd30ff31d5a1d5f68002a61dca0ebf6e3c10ed0")

target("blook")
    set_kind("static")
    add_files("src/*.cpp")
    if is_plat("windows") then
        add_files("src/platform/windows/*.cpp")
    elseif is_plat("linux") then
        add_files("src/platform/linux/*.cpp")
    end
    add_includedirs("include", {public = true})

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
        add_syslinks("user32", "advapi32")
    end
    add_deps("blook")

    add_tests("default")

package("zasm")
    set_homepage("https://github.com/zyantific/zasm")
    set_description("x86-64 Assembler based on Zydis")

    set_urls("https://github.com/zyantific/zasm.git")

    add_versions("2025.03.02", "c239a78b51c1b0060296193174d78b802f02a618")
    add_versions("2024.05.14", "bea8af2c68f0cbe8a02e93ab79a8b5c596d2b232")
    add_versions("2023.06.21", "19a642518eccbb1740865642eaf3ce79d5d5b884")

    add_configs("shared", {description = "Build shared library.", default = false, type = "boolean", readonly = true})

    on_load(function (package)
        local map = {
            ["2025.03.02"] = "4.1.0",
            ["2024.05.14"] = "4.1.0",
            ["2023.06.21"] = "4.0.0",
        }
        local zydis_version = map[package:version()]
        if zydis_version then
            package:add("deps", "zydis " .. zydis_version)
        else
            package:add("deps", "zydis")
        end
    end)

    on_install("!wasm and !iphoneos", function (package)
        local src_include
        if package:version() and package:version():lt("2024.05.14") then
            src_include = [[
                add_files("src/zasm/**.cpp")
                add_includedirs("include", "src/zasm/src")
                add_headerfiles("include/(**.hpp)")
            ]]
        else
            src_include = [[
                add_files("zasm/**.cpp")
                add_includedirs("zasm/include")
                add_headerfiles("zasm/include/(**.hpp)")
            ]]
        end

        io.writefile("xmake.lua", format([[
            add_rules("mode.debug", "mode.release")
            add_requires("zydis v4.0.0")
            target("zasm")
                set_kind("$(kind)")
                set_languages("c++17")
                %s
                if is_plat("windows") then
                    add_cxxflags("/bigobj", "/MP", "/W3", "/permissive-")
                    if is_kind("shared") then
                        add_rules("utils.symbols.export_all", {export_classes = true})
                    end
                end
                add_packages("zydis")
        ]], src_include))
        import("package.tools.xmake").install(package)
    end)

    on_test(function (package)
        assert(package:check_cxxsnippets({test = [[
            #include <zasm/serialization/serializer.hpp>
            #include <zasm/zasm.hpp>
            using namespace zasm;
            void test() {
                Program program(MachineMode::AMD64);
            }
        ]]}, {configs = {languages = "c++17"}}))
    end)
