// Copyright (c) 2019-2021 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_SCRIPT_BITFIELD_H
#define BITCOINII_SCRIPT_BITFIELD_H

#include <cstdint>
#include <vector>

#include <script/script_error.h>

bool DecodeBitfield(const std::vector<uint8_t> &vch, unsigned size,
                    uint32_t &bitfield, ScriptError *serror);

#endif // BITCOINII_SCRIPT_BITFIELD_H
