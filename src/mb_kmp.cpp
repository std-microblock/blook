//
// Created by MicroBlock on 2024/7/6.
//

#include "blook/memory_scanner/mb_kmp.h"
#include <vector>

namespace blook {
    void ComputeLPSArray(
            void *pattern, size_t patternSize, std::vector<size_t> &lps) {
        size_t len = 0;
        lps[0] = 0;

        size_t i = 1;
        while (i < patternSize) {
            if (*((unsigned char *) pattern + i) == *((unsigned char *) pattern + len) ||
                *((unsigned char *) pattern + len) == memory_scanner::ANYpattern) {
                len++;
                lps[i] = len;
                i++;
            } else {
                if (len != 0)
                    len = lps[len - 1];
                else {
                    lps[i] = 0;
                    i++;
                }
            }
        }
    }


    std::optional<size_t>
    memory_scanner::mb_kmp::searchOne(std::span<uint8_t> data, const std::vector<uint8_t> &pattern) {
        if (data.size() == 0 || pattern.size() == 0 || pattern.size() > data.size())
            return {};

        std::vector<size_t> lps(pattern.size(), 0);
        ComputeLPSArray((void *) pattern.data(), pattern.size(), lps);

        size_t i = 0, j = 0;
        char *dataa = (char *) data.data();
        while (i < data.size()) {
            if (*(data.data() + i) == *(pattern.data() + j) ||
                *(pattern.data() + j) == memory_scanner::ANYpattern) {
                i++;
                j++;

                if (j == pattern.size())
                    return i - pattern.size();
            } else {
                if (j != 0)
                    j = lps[j - 1];
                else
                    i++;
            }
        }

        return {};

    }
} // blook