// Copyright (c) 2019-2021 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/bitfield.h>

#include <cstddef>
#include <limits>

namespace {
inline bool set_error(ScriptError *ret, const ScriptError serror) {
    if (ret) {
        *ret = serror;
    }
    return false;
}
} // namespace

bool DecodeBitfield(const std::vector<uint8_t> &vch, unsigned size,
                    uint32_t &bitfield, ScriptError *serror) {
    if (size > 32) {
        return set_error(serror, SCRIPT_ERR_INVALID_BITFIELD_SIZE);
    }

    const size_t bitfield_size = (size + 7) / 8;
    if (vch.size() != bitfield_size) {
        return set_error(serror, SCRIPT_ERR_INVALID_BITFIELD_SIZE);
    }

    bitfield = 0;
    for (size_t i = 0; i < bitfield_size; i++) {
        // Decode the bitfield as little endian.
        bitfield |= uint32_t(vch[i]) << (8 * i);
    }

    const uint32_t mask = (uint64_t(1) << size) - 1;
    if ((bitfield & mask) != bitfield) {
        return set_error(serror, SCRIPT_ERR_INVALID_BIT_RANGE);
    }

    return true;
}
