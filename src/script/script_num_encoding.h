// Copyright (c) 2024 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_SCRIPT_SCRIPT_NUM_ENCODING_H
#define BITCOINII_SCRIPT_SCRIPT_NUM_ENCODING_H

#include <cstddef>
#include <cstdint>
#include <vector>

/** Encapsulates the logic of "minimal encoding" for CScript numbers. Usable as a mixin or as a helper. */
struct ScriptNumEncoding {
    static bool IsMinimallyEncoded(const std::vector<uint8_t> &vch, size_t maxIntegerSize);
    static bool MinimallyEncode(std::vector<uint8_t> &data);
};

#endif // BITCOINII_SCRIPT_SCRIPT_NUM_ENCODING_H
