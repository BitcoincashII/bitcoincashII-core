// Copyright (c) 2025 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_SCRIPT_CONTAINER_TYPES_H
#define BITCOINII_SCRIPT_CONTAINER_TYPES_H

#include <cstdint>
#include <span>
#include <vector>

using valtype = std::vector<uint8_t>; ///< used by the script interpreter as the stack element type
using StackT = std::vector<valtype>; ///< used by the script interpreter as the stack type

using ByteView = std::span<const uint8_t>; ///< read-only view into a vector or other array type

#endif // BITCOINII_SCRIPT_CONTAINER_TYPES_H
