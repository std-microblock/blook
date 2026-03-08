#include "blook/allocator.h"
#include "blook/memo.h"
#include "blook/process.h"
#include "windows.h"
#include <algorithm>
#include <format>

namespace blook {

static DWORD ProtectToWin(Protect protect) {
  using P = Protect;
  if ((int)protect & (int)P::Execute) {
    if ((int)protect & (int)P::Write)
      return PAGE_EXECUTE_READWRITE;
    if ((int)protect & (int)P::Read)
      return PAGE_EXECUTE_READ;
    return PAGE_EXECUTE;
  }
  if ((int)protect & (int)P::Write)
    return PAGE_READWRITE;
  if ((int)protect & (int)P::Read)
    return PAGE_READONLY;
  return PAGE_NOACCESS;
}

ProcessAllocator::ProcessAllocator(std::shared_ptr<Process> proc)
    : proc(std::move(proc)) {}

ProcessAllocator::~ProcessAllocator() {
  // Free all allocated pages
  for (auto &[base, page_info] : pages) {
    VirtualFreeEx(proc->h, base, 0, MEM_RELEASE);
  }
}

std::expected<void *, std::string>
ProcessAllocator::allocate_direct(size_t size,
                                   Protect protection,
                                   void *nearAddr) {
  if (nearAddr) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

    uint64_t startAddr = (uint64_t(nearAddr) & ~(PAGE_SIZE - 1));
    uint64_t minAddr =
        (uint64_t)std::max((int64_t)startAddr - 0x7FFFFF00,
                           (int64_t)sysInfo.lpMinimumApplicationAddress);
    uint64_t maxAddr =
        (uint64_t)std::min((int64_t)startAddr + 0x7FFFFF00,
                           (int64_t)sysInfo.lpMaximumApplicationAddress);

    uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));
    uint64_t pageOffset = 1;

    while (true) {
      uint64_t byteOffset = pageOffset * PAGE_SIZE;
      uint64_t highAddr = startPage + byteOffset;
      uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

      bool canTryHigh = highAddr < maxAddr;
      bool canTryLow = lowAddr > minAddr;

      if (!canTryHigh && !canTryLow)
        break;

      if (canTryHigh) {
        void *outAddr =
            VirtualAllocEx(proc->h, (void *)highAddr, size,
                           MEM_COMMIT | MEM_RESERVE, ProtectToWin(protection));
        if (outAddr)
          return outAddr;
      }

      if (canTryLow) {
        void *outAddr =
            VirtualAllocEx(proc->h, (void *)lowAddr, size,
                           MEM_COMMIT | MEM_RESERVE, ProtectToWin(protection));
        if (outAddr)
          return outAddr;
      }

      pageOffset++;
    }
    return std::unexpected("Failed to allocate memory near address");
  } else {
    void *ptr = VirtualAllocEx(proc->h, nullptr, size, MEM_COMMIT | MEM_RESERVE,
                               ProtectToWin(protection));
    if (ptr)
      return ptr;
    return std::unexpected(
        std::format("VirtualAllocEx failed: {}", GetLastError()));
  }
}

std::expected<Pointer, std::string>
ProcessAllocator::try_allocate(size_t size, void *nearAddr,
                                Protect protection) {
  if (size == 0) {
    return std::unexpected("Cannot allocate zero bytes");
  }

  // For large allocations, allocate directly
  if (size >= LARGE_ALLOCATION_THRESHOLD) {
    auto result = allocate_direct(size, protection, nearAddr);
    if (!result) {
      return std::unexpected(result.error());
    }

    // Track as a dedicated page
    PageInfo page_info{
        .base_address = *result,
        .total_size = size,
        .used_size = size,
        .protection = protection,
        .allocations = {{*result, {size, protection}}}};

    pages[*result] = std::move(page_info);
    return Pointer(proc, *result);
  }

  // Try to find existing page with enough space
  auto addr_result = find_or_allocate_page(size, nearAddr, protection);
  if (!addr_result) {
    return std::unexpected(addr_result.error());
  }

  return Pointer(proc, *addr_result);
}

Pointer ProcessAllocator::allocate(size_t size, void *nearAddr,
                                    Protect protection) {
  auto result = try_allocate(size, nearAddr, protection);
  if (!result) {
    throw std::runtime_error(result.error());
  }
  return *result;
}

std::expected<void, std::string>
ProcessAllocator::try_deallocate(Pointer ptr) {
  void *addr = ptr.data();

  // Find the page containing this allocation
  for (auto &[base, page_info] : pages) {
    auto it = page_info.allocations.find(addr);
    if (it != page_info.allocations.end()) {
      page_info.used_size -= it->second.size;
      page_info.allocations.erase(it);

      // If page is empty, free it
      if (page_info.allocations.empty()) {
        if (!VirtualFreeEx(proc->h, base, 0, MEM_RELEASE)) {
          return std::unexpected(
              std::format("VirtualFreeEx failed: {}", GetLastError()));
        }
        pages.erase(base);
      }

      return {};
    }
  }

  return std::unexpected(
      std::format("Address {:p} not found in allocator", addr));
}

void ProcessAllocator::deallocate(Pointer ptr) {
  auto result = try_deallocate(ptr);
  if (!result) {
    throw std::runtime_error(result.error());
  }
}

std::expected<void *, std::string>
ProcessAllocator::find_or_allocate_page(size_t size, void *nearAddr,
                                         Protect protection) {
  constexpr size_t NEAR_THRESHOLD = 2LL * 1024 * 1024 * 1024; // 2GB

  // Try to find an existing page with enough space
  for (auto &[base, page_info] : pages) {
    // Check if protection matches
    if (page_info.protection != protection) {
      continue;
    }

    // Check if near address constraint is satisfied
    if (nearAddr) {
      int64_t distance = std::abs((int64_t)base - (int64_t)nearAddr);
      if (distance >= NEAR_THRESHOLD) {
        continue;
      }
    }

    // Check if there's enough space
    size_t available = page_info.total_size - page_info.used_size;
    if (available >= size) {
      // Find the allocation address
      void *alloc_addr = (char *)base + page_info.used_size;

      // Record the allocation
      page_info.allocations[alloc_addr] = {size, protection};
      page_info.used_size += size;

      return alloc_addr;
    }
  }

  // No suitable page found, allocate a new one
  return allocate_new_page(size, nearAddr, protection);
}

std::expected<void *, std::string>
ProcessAllocator::allocate_new_page(size_t size, void *nearAddr,
                                     Protect protection) {
  // Determine page size
  size_t page_size = std::max(DEFAULT_PAGE_SIZE, size);

  // Allocate the page
  auto result = allocate_direct(page_size, protection, nearAddr);
  if (!result) {
    return std::unexpected(result.error());
  }

  void *base = *result;

  // Create page info
  PageInfo page_info{.base_address = base,
                     .total_size = page_size,
                     .used_size = size,
                     .protection = protection,
                     .allocations = {{base, {size, protection}}}};

  pages[base] = std::move(page_info);

  return base;
}

size_t ProcessAllocator::allocated_count() const {
  size_t count = 0;
  for (const auto &[_, page_info] : pages) {
    count += page_info.allocations.size();
  }
  return count;
}

size_t ProcessAllocator::total_allocated_bytes() const {
  size_t total = 0;
  for (const auto &[_, page_info] : pages) {
    total += page_info.used_size;
  }
  return total;
}

size_t ProcessAllocator::total_reserved_bytes() const {
  size_t total = 0;
  for (const auto &[_, page_info] : pages) {
    total += page_info.total_size;
  }
  return total;
}

} // namespace blook
