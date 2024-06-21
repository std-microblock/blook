#pragma once

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#include <minwindef.h>

#include "Module.h"

namespace blook {
    class Module;

    class Process {
#ifdef _WIN32
        HANDLE h;
        DWORD pid;
#endif
        explicit Process(HANDLE h);
        explicit Process(DWORD pid);
        explicit Process(std::string name);
    public:


        Process() = delete;
        Process(Process&) = delete;

        std::optional<std::vector<std::uint8_t>> read(void* addr, size_t size) const;

        [[nodiscard]] std::optional<Module> module(const std::string& name) const;
        bool is_self() const;

        static std::shared_ptr<Process> self();

        template<class ...T>
        static std::shared_ptr<Process> attach(T&&... argv);
    };


}