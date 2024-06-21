//
// Created by MicroBlock on 2024/6/21.
//

#ifndef BLOOK_MODULE_H
#define BLOOK_MODULE_H

#include "Process.h"

namespace blook {
    class Process;

    class Module {
        Process* proc;
        void* pModule;

    public:
        Module(Process* proc, void* pModule): proc(proc), pModule(pModule) {

        }

        void* exports(const std::string& name) {}
    };

} // blook

#endif //BLOOK_MODULE_H
