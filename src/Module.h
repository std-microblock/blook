#pragma once

#include <libloaderapi.h>
#include "Process.h"
#include "Function.h"

namespace blook {
    class Process;

    class Module {
        std::shared_ptr<Process> proc;
        HMODULE pModule;

    public:
        Module(std::shared_ptr<Process> proc, HMODULE pModule);

        std::optional<Function> exports(const std::string& name) {
            if(!proc)
        }
    };

}