#pragma once

#include <functional>

class Function {
public:
    void inline_hook(std::function<void()> func);
};
