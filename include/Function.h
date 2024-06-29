#pragma once

#include <functional>
#include <string>
#include <memory>



namespace blook {
class Module;
class Function {
  std::shared_ptr<Module> module;
  void* p_func;
  std::string name;
public:
    Function(std::shared_ptr<Module> module, void* p_func, std::string name);

    template <class FuncType>
    void inline_hook(std::function<FuncType(std::function<FuncType> origin)> func) {

    }

    template <typename ReturnVal, typename ...Args>
    static auto Function::into_function_pointer(std::function<ReturnVal(Args...)>* fn) -> ReturnVal(*)(Args...);
    static size_t function_arg_count(void* pfn);
};



}