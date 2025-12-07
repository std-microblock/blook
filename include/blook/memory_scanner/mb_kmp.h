#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>


namespace blook {

namespace memory_scanner {
constexpr unsigned char ANYpattern = 0xBC;

class mb_kmp {
public:
  static std::optional<size_t> searchOne(uint8_t *data, size_t size,
                                         const std::vector<uint8_t> &pattern);
};
} // namespace memory_scanner

} // namespace blook
