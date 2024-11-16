#pragma once

#include <vector>
#include <optional>
#include <span>
#include <cstdint>

namespace blook {

    namespace memory_scanner {
        constexpr unsigned char ANYpattern = 0xBC;

        class mb_kmp {
        public:
            static std::optional<size_t> searchOne(std::span<uint8_t>, const std::vector<uint8_t> &);
        };
    }

} // blook
