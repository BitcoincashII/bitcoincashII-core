// Copyright (c) 2017-2020 The Bitcoin Cash developers
// Distributed under the MIT software license

#include <cashaddr.h>
#include <algorithm>

namespace cashaddr {

const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

uint64_t PolyMod(const std::vector<uint8_t> &v) {
    uint64_t c = 1;
    for (uint8_t d : v) {
        uint8_t c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ d;
        if (c0 & 0x01) c ^= 0x98f2bc8e61;
        if (c0 & 0x02) c ^= 0x79b76d99e2;
        if (c0 & 0x04) c ^= 0xf33e5fb3c4;
        if (c0 & 0x08) c ^= 0xae2eabe2a8;
        if (c0 & 0x10) c ^= 0x1e4f43e470;
    }
    return c ^ 1;
}

std::vector<uint8_t> ExpandPrefix(const std::string &prefix) {
    std::vector<uint8_t> ret;
    ret.resize(prefix.size() + 1);
    for (size_t i = 0; i < prefix.size(); ++i) {
        ret[i] = prefix[i] & 0x1f;
    }
    ret[prefix.size()] = 0;
    return ret;
}

std::vector<uint8_t> CreateChecksum(const std::string &prefix, const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> enc = ExpandPrefix(prefix);
    enc.insert(enc.end(), payload.begin(), payload.end());
    enc.resize(enc.size() + 8);
    uint64_t mod = PolyMod(enc);
    std::vector<uint8_t> ret(8);
    for (size_t i = 0; i < 8; ++i) {
        ret[i] = (mod >> (5 * (7 - i))) & 0x1f;
    }
    return ret;
}

bool VerifyChecksum(const std::string &prefix, const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> exp = ExpandPrefix(prefix);
    exp.insert(exp.end(), payload.begin(), payload.end());
    return PolyMod(exp) == 0;
}

std::string Encode(const std::string &prefix, const std::vector<uint8_t> &payload) {
    std::vector<uint8_t> checksum = CreateChecksum(prefix, payload);
    std::string ret = prefix + ':';
    ret.reserve(ret.size() + payload.size() + checksum.size());
    for (uint8_t c : payload) {
        ret += CHARSET[c];
    }
    for (uint8_t c : checksum) {
        ret += CHARSET[c];
    }
    return ret;
}

std::pair<std::string, std::vector<uint8_t>> Decode(const std::string &str, const std::string &default_prefix) {
    auto pos = str.rfind(':');
    std::string prefix;
    std::string payload_str;
    
    if (pos == std::string::npos) {
        prefix = default_prefix;
        payload_str = str;
    } else {
        prefix = str.substr(0, pos);
        payload_str = str.substr(pos + 1);
    }
    
    std::string lower_prefix = prefix;
    std::transform(lower_prefix.begin(), lower_prefix.end(), lower_prefix.begin(), ::tolower);
    
    std::vector<uint8_t> payload;
    payload.reserve(payload_str.size());
    for (char c : payload_str) {
        if (static_cast<unsigned char>(c) > 127) {
            return {{}, {}};
        }
        int8_t rev = CHARSET_REV[static_cast<uint8_t>(c)];
        if (rev == -1) {
            return {{}, {}};
        }
        payload.push_back(rev);
    }
    
    if (payload.size() < 8) {
        return {{}, {}};
    }
    
    if (!VerifyChecksum(lower_prefix, payload)) {
        return {{}, {}};
    }
    
    payload.resize(payload.size() - 8);
    return {lower_prefix, payload};
}

std::vector<uint8_t> PackAddrData(const std::vector<uint8_t> &id, uint8_t type) {
    uint8_t version_byte = type << 3;
    size_t size = id.size();
    uint8_t encoded_size = 0;
    switch (size) {
        case 20: encoded_size = 0; break;  // 160 bits
        case 24: encoded_size = 1; break;  // 192 bits
        case 28: encoded_size = 2; break;  // 224 bits
        case 32: encoded_size = 3; break;  // 256 bits
        case 40: encoded_size = 4; break;  // 320 bits
        case 48: encoded_size = 5; break;  // 384 bits
        case 56: encoded_size = 6; break;  // 448 bits
        case 64: encoded_size = 7; break;  // 512 bits
        default: return {};
    }
    version_byte |= encoded_size;

    std::vector<uint8_t> payload;
    payload.reserve(1 + (8 + id.size() * 8 + 4) / 5);

    // Version byte is 8 bits, then convert hash bytes to 5-bit groups
    uint32_t acc = version_byte;
    int bits = 8;
    
    for (uint8_t byte : id) {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            payload.push_back((acc >> bits) & 0x1f);
        }
    }
    if (bits > 0) {
        payload.push_back((acc << (5 - bits)) & 0x1f);
    }
    
    return payload;
}

std::pair<uint8_t, std::vector<uint8_t>> UnpackAddrData(const std::vector<uint8_t> &data) {
    if (data.size() < 2) {
        return {0, {}};
    }

    // Convert 5-bit groups to 8-bit bytes
    // First 8 bits are the version byte, rest is hash data
    uint32_t acc = 0;
    int bits = 0;
    std::vector<uint8_t> result;
    uint8_t version = 0;
    bool version_extracted = false;

    for (size_t i = 0; i < data.size(); ++i) {
        acc = (acc << 5) | data[i];
        bits += 5;

        // First extract the 8-bit version byte
        if (!version_extracted && bits >= 8) {
            bits -= 8;
            version = (acc >> bits) & 0xff;
            version_extracted = true;
        }

        // Then extract hash bytes
        while (version_extracted && bits >= 8) {
            bits -= 8;
            result.push_back((acc >> bits) & 0xff);
        }
    }

    uint8_t type = version >> 3;
    
    // Trim to correct size based on encoded size
    uint8_t encoded_size = version & 0x07;
    size_t expected_size = 0;
    switch (encoded_size) {
        case 0: expected_size = 20; break;
        case 1: expected_size = 24; break;
        case 2: expected_size = 28; break;
        case 3: expected_size = 32; break;
        case 4: expected_size = 40; break;
        case 5: expected_size = 48; break;
        case 6: expected_size = 56; break;
        case 7: expected_size = 64; break;
    }
    
    if (result.size() >= expected_size) {
        result.resize(expected_size);
    }
    
    return {type, result};
}

} // namespace cashaddr
