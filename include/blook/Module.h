#pragma once

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>

#include "Function.h"

namespace blook {
    class Process;

    class Module : public std::enable_shared_from_this<Module> {
        std::shared_ptr<Process> proc;
        HMODULE pModule;

        std::unordered_map<std::string, Function> exports_cache;

        std::unordered_map<std::string, Function> *obtain_exports();

    public:
        Module(std::shared_ptr<Process> proc, HMODULE pModule);
        CLASS_MOVE_ONLY(Module)

        template<class... T>
        inline static std::shared_ptr<Module> make(T &&...argv) {
            return std::shared_ptr<Module>(new Module(argv...));
        }

        std::optional<Function> exports(const std::string &name);

        template<class... T>
        inline std::optional<Function> exports(const std::string &name, T... rest) {
            return exports(name).or_else([&]() { return exports(rest...); });
        }

        std::optional<MemoryRange> section(const std::string &name);

        void *data();

        size_t size();

        enum class InjectMethod {
            CreateRemoteThread,
            NtCreateThread,
            RtlCreateUserThread
        };

        void *inject(const std::string &dll_path,
                     InjectMethod method = InjectMethod::CreateRemoteThread);
    };

} // namespace blook