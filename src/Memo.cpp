//
// Created by MicroBlock on 2024/6/22.
//

#include "../include/Memo.h"
#include "Windows.h"
namespace blook {
void *Memo::malloc_rwx(size_t size) {
  return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}
}