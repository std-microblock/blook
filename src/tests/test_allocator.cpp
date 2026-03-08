#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "blook/allocator.h"
#include "blook/blook.h"
#include "blook/memo.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <vector>

TEST(ProcessAllocatorTests, BasicAllocation) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Allocate a small block
  auto ptr = allocator.try_allocate(128);
  ASSERT_TRUE(ptr.has_value());
  EXPECT_NE(ptr->data(), nullptr);

  // Verify we can write to it
  std::vector<uint8_t> test_data(128, 0xAB);
  EXPECT_NO_THROW(ptr->write_bytearray(test_data));

  // Verify we can read from it
  auto read_result = ptr->try_read_bytearray(128);
  ASSERT_TRUE(read_result.has_value());
  EXPECT_EQ(*read_result, test_data);

  // Deallocate
  EXPECT_NO_THROW(allocator.deallocate(*ptr));
}

TEST(ProcessAllocatorTests, MultipleAllocations) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Allocate multiple blocks
  std::vector<blook::Pointer> ptrs;
  for (int i = 0; i < 10; i++) {
    auto ptr = allocator.try_allocate(256);
    ASSERT_TRUE(ptr.has_value());
    ptrs.push_back(*ptr);
  }

  // Verify all allocations are unique
  for (size_t i = 0; i < ptrs.size(); i++) {
    for (size_t j = i + 1; j < ptrs.size(); j++) {
      EXPECT_NE(ptrs[i].data(), ptrs[j].data());
    }
  }

  // Write different data to each
  for (size_t i = 0; i < ptrs.size(); i++) {
    std::vector<uint8_t> data(256, static_cast<uint8_t>(i));
    EXPECT_NO_THROW(ptrs[i].write_bytearray(data));
  }

  // Verify data integrity
  for (size_t i = 0; i < ptrs.size(); i++) {
    auto read_result = ptrs[i].try_read_bytearray(256);
    ASSERT_TRUE(read_result.has_value());
    std::vector<uint8_t> expected(256, static_cast<uint8_t>(i));
    EXPECT_EQ(*read_result, expected);
  }

  // Deallocate all
  for (auto &ptr : ptrs) {
    EXPECT_NO_THROW(allocator.deallocate(ptr));
  }
}

TEST(ProcessAllocatorTests, LargeAllocation) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Allocate a large block (> 32KB threshold)
  size_t large_size = 64 * 1024;
  auto ptr = allocator.try_allocate(large_size);
  ASSERT_TRUE(ptr.has_value());

  // Verify we can write to it
  std::vector<uint8_t> test_data(large_size, 0xCD);
  EXPECT_NO_THROW(ptr->write_bytearray(test_data));

  // Verify we can read from it
  auto read_result = ptr->try_read_bytearray(large_size);
  ASSERT_TRUE(read_result.has_value());
  EXPECT_EQ(*read_result, test_data);

  // Deallocate
  EXPECT_NO_THROW(allocator.deallocate(*ptr));
}

TEST(ProcessAllocatorTests, NearAllocation) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Allocate a reference block
  auto ref_ptr = allocator.try_allocate(128);
  ASSERT_TRUE(ref_ptr.has_value());

  // Allocate near the reference
  auto near_ptr = allocator.try_allocate(128, ref_ptr->data());
  ASSERT_TRUE(near_ptr.has_value());

  // Check that they're within 2GB of each other
  int64_t distance =
      std::abs((int64_t)near_ptr->data() - (int64_t)ref_ptr->data());
  EXPECT_LT(distance, 2LL * 1024 * 1024 * 1024);

  // Deallocate
  EXPECT_NO_THROW(allocator.deallocate(*ref_ptr));
  EXPECT_NO_THROW(allocator.deallocate(*near_ptr));
}

TEST(ProcessAllocatorTests, PageReuse) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Record initial state
  size_t initial_reserved = allocator.total_reserved_bytes();

  // Allocate multiple small blocks (should reuse pages)
  std::vector<blook::Pointer> ptrs;
  for (int i = 0; i < 20; i++) {
    auto ptr = allocator.try_allocate(512);
    ASSERT_TRUE(ptr.has_value());
    ptrs.push_back(*ptr);
  }

  // Check that total reserved didn't grow by 20 * 64KB
  // (indicating page reuse)
  size_t new_reserved = allocator.total_reserved_bytes();
  size_t reserved_growth = new_reserved - initial_reserved;

  EXPECT_LT(reserved_growth, 20 * 64 * 1024); // Should reuse pages

  // Deallocate all
  for (auto &ptr : ptrs) {
    EXPECT_NO_THROW(allocator.deallocate(ptr));
  }
}

TEST(ProcessAllocatorTests, DifferentProtections) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Allocate with RW protection
  auto rw_ptr = allocator.try_allocate(
      128, nullptr, blook::Protect::ReadWrite);
  ASSERT_TRUE(rw_ptr.has_value());

  // Allocate with RWX protection
  auto rwx_ptr = allocator.try_allocate(
      128, nullptr, blook::Protect::ReadWriteExecute);
  ASSERT_TRUE(rwx_ptr.has_value());

  // Verify both work
  std::vector<uint8_t> test_data(128, 0xEF);
  EXPECT_NO_THROW(rw_ptr->write_bytearray(test_data));
  EXPECT_NO_THROW(rwx_ptr->write_bytearray(test_data));

  // Deallocate
  EXPECT_NO_THROW(allocator.deallocate(*rw_ptr));
  EXPECT_NO_THROW(allocator.deallocate(*rwx_ptr));
}

TEST(ProcessAllocatorTests, Statistics) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Record initial state (may not be zero due to other tests)
  size_t initial_count = allocator.allocated_count();
  size_t initial_bytes = allocator.total_allocated_bytes();

  // Allocate some blocks
  std::vector<blook::Pointer> ptrs;
  for (int i = 0; i < 5; i++) {
    auto ptr = allocator.try_allocate(1024);
    ASSERT_TRUE(ptr.has_value());
    ptrs.push_back(*ptr);
  }

  // Check statistics
  EXPECT_EQ(allocator.allocated_count(), initial_count + 5);
  EXPECT_EQ(allocator.total_allocated_bytes(), initial_bytes + 5 * 1024);
  EXPECT_GT(allocator.total_reserved_bytes(), 0);

  // Deallocate some
  allocator.deallocate(ptrs[0]);
  allocator.deallocate(ptrs[1]);

  EXPECT_EQ(allocator.allocated_count(), initial_count + 3);
  EXPECT_EQ(allocator.total_allocated_bytes(), initial_bytes + 3 * 1024);

  // Deallocate rest
  for (size_t i = 2; i < ptrs.size(); i++) {
    allocator.deallocate(ptrs[i]);
  }

  EXPECT_EQ(allocator.allocated_count(), initial_count);
  EXPECT_EQ(allocator.total_allocated_bytes(), initial_bytes);
}

TEST(ProcessAllocatorTests, ZeroSizeAllocation) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Try to allocate zero bytes
  auto ptr = allocator.try_allocate(0);
  EXPECT_FALSE(ptr.has_value());
}

TEST(ProcessAllocatorTests, InvalidDeallocation) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Try to deallocate an invalid pointer
  blook::Pointer invalid_ptr(proc, (void *)0x12345678);
  auto result = allocator.try_deallocate(invalid_ptr);
  EXPECT_FALSE(result.has_value());
}

TEST(ProcessAllocatorTests, StressTest) {
  auto proc = blook::Process::self();
  ASSERT_TRUE(proc);

  auto &allocator = proc->allocator();

  // Record initial state
  size_t initial_count = allocator.allocated_count();

  // Allocate and deallocate many blocks
  std::vector<blook::Pointer> ptrs;
  for (int i = 0; i < 100; i++) {
    size_t size = 64 + (i % 10) * 128;
    auto ptr = allocator.try_allocate(size);
    ASSERT_TRUE(ptr.has_value());

    // Write and verify
    std::vector<uint8_t> data(size, static_cast<uint8_t>(i & 0xFF));
    EXPECT_NO_THROW(ptr->write_bytearray(data));

    auto read_result = ptr->try_read_bytearray(size);
    ASSERT_TRUE(read_result.has_value());
    EXPECT_EQ(*read_result, data);

    ptrs.push_back(*ptr);

    // Deallocate every other one
    if (i % 2 == 1) {
      allocator.deallocate(ptrs[i - 1]);
      ptrs[i - 1] = blook::Pointer();
    }
  }

  // Deallocate remaining
  for (auto &ptr : ptrs) {
    if (ptr.data() != nullptr) {
      EXPECT_NO_THROW(allocator.deallocate(ptr));
    }
  }

  EXPECT_EQ(allocator.allocated_count(), initial_count);
}
