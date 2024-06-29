#pragma once
namespace blook {

class Memo {
public:
  static void *malloc_rwx(size_t size);
  static void protect_rwx(void *p, size_t size);
  static void *malloc_near_rwx(void *near, size_t size);
};

} // namespace blook