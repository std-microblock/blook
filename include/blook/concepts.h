#pragma once

#include <concepts>
#include <cstdint>

namespace blook {
    template<typename ByteIterateAble, typename Iter = ByteIterateAble::iterator>
    concept ByteRangeIterable = requires(ByteIterateAble a, Iter b) {
        { a.begin() } -> std::same_as<Iter>;
        { a.end() } -> std::same_as<Iter>;
        { b++ } -> std::convertible_to<Iter>;
        { *b } -> std::convertible_to<uint8_t>;
    };
}