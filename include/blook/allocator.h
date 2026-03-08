#pragma once

#include "process.h"
#include "protect.h"
#include <cstdint>
#include <expected>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace blook {
class Pointer;

class ProcessAllocator {
public:
  explicit ProcessAllocator(std::shared_ptr<Process> proc);
  ~ProcessAllocator();

  CLASS_MOVE_ONLY(ProcessAllocator)

  // Allocate memory with optional near address constraint
  std::expected<Pointer, std::string>
  try_allocate(size_t size, void *nearAddr = nullptr,
               Protect protection = Protect::rw);

  Pointer allocate(size_t size, void *nearAddr = nullptr,
                   Protect protection = Protect::rw);

  // Deallocate memory
  std::expected<void, std::string> try_deallocate(Pointer ptr);
  void deallocate(Pointer ptr);

  // Get allocation statistics
  size_t allocated_count() const;
  size_t total_allocated_bytes() const;
  size_t total_reserved_bytes() const;

private:
  struct AllocationInfo {
    size_t size;
    Protect protection;
  };

  struct PageInfo {
    void *base_address;
    size_t total_size;
    size_t used_size;
    Protect protection;
    std::map<void *, AllocationInfo> allocations;
  };

  // Direct allocation using VirtualAllocEx
  std::expected<void *, std::string>
  allocate_direct(size_t size, Protect protection,
                  void *nearAddr = nullptr);

  // Find or create a page suitable for allocation
  std::expected<void *, std::string>
  find_or_allocate_page(size_t size, void *nearAddr,
                        Protect protection);

  // Allocate a new page
  std::expected<void *, std::string>
  allocate_new_page(size_t size, void *nearAddr,
                    Protect protection);

  std::shared_ptr<Process> proc;
  std::map<void *, PageInfo> pages;

  static constexpr size_t DEFAULT_PAGE_SIZE = 64 * 1024; // 64KB
  static constexpr size_t LARGE_ALLOCATION_THRESHOLD = 32 * 1024; // 32KB
};

} // namespace blook
