#pragma once
#include "Process.h"
#include <map>
#include <unordered_map>

#include "Function.h"

namespace blook {
    class Module {
        std::shared_ptr<Process> proc;
        std::weak_ptr<Module> p_self;
        HMODULE pModule;

        std::unordered_map<std::string, Function> exports_cache;
        std::unordered_map<std::string, Function> obtain_exports();
        Module(std::shared_ptr<Process> proc, HMODULE pModule);
    public:
      template<class... T>
      inline static std::shared_ptr<Module> make(T&&... argv) {
        const auto proc = std::shared_ptr<Module>(new Module(argv...));
        proc->p_self = proc;
        return proc;
      }

      std::optional<Function> exports(const std::string& name);
    };

}