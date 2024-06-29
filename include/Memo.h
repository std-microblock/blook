#pragma once
namespace blook {

class Memo {
public:
  static void* malloc_rwx(size_t size);
};

}