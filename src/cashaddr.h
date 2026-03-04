// Copyright (c) 2017-2020 The Bitcoin Cash developers
// Distributed under the MIT software license

#ifndef BITCOIN_CASHADDR_H
#define BITCOIN_CASHADDR_H

#include <cstdint>
#include <string>
#include <vector>

namespace cashaddr {

// Encode a CashAddr address
std::string Encode(const std::string &prefix, const std::vector<uint8_t> &payload);

// Decode a CashAddr address - returns prefix and 5-bit payload
std::pair<std::string, std::vector<uint8_t>> Decode(const std::string &str, const std::string &default_prefix);

// Convert 8-bit data to 5-bit groups
std::vector<uint8_t> PackAddrData(const std::vector<uint8_t> &id, uint8_t type);

// Convert 5-bit groups back to 8-bit data, returns type and hash
std::pair<uint8_t, std::vector<uint8_t>> UnpackAddrData(const std::vector<uint8_t> &data);

} // namespace cashaddr

#endif // BITCOIN_CASHADDR_H
