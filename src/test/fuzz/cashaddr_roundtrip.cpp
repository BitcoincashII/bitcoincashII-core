// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cashaddr.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

FUZZ_TARGET(cashaddr_roundtrip)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    // --- Test 1: Decode arbitrary strings, roundtrip on success ---
    {
        const std::string input = fdp.ConsumeRandomLengthString(256);
        const std::string prefix = "bitcoincashii";
        auto [dec_prefix, dec_payload] = cashaddr::Decode(input, prefix);
        if (!dec_payload.empty()) {
            // Successful decode: encode back and re-decode for roundtrip
            std::string re_encoded = cashaddr::Encode(dec_prefix, dec_payload);
            auto [rt_prefix, rt_payload] = cashaddr::Decode(re_encoded, dec_prefix);
            assert(rt_prefix == dec_prefix);
            assert(rt_payload == dec_payload);
        }
    }

    // --- Test 2: PackAddrData / UnpackAddrData roundtrip ---
    {
        // Valid hash sizes for CashAddr: 20, 24, 28, 32, 40, 48, 56, 64
        static constexpr size_t valid_sizes[] = {20, 24, 28, 32, 40, 48, 56, 64};
        const uint8_t type = fdp.ConsumeIntegral<uint8_t>();
        const size_t size_idx = fdp.ConsumeIntegralInRange<size_t>(0, 7);
        const size_t hash_size = valid_sizes[size_idx];
        std::vector<uint8_t> hash_data = fdp.ConsumeBytes<uint8_t>(hash_size);
        if (hash_data.size() == hash_size) {
            std::vector<uint8_t> packed = cashaddr::PackAddrData(hash_data, type);
            auto [unpacked_type, unpacked_hash] = cashaddr::UnpackAddrData(packed);
            // Type is stored in the upper 3 bits of the version byte (5-bit groups)
            // Only the lower 3 bits of type are preserved (0-7)
            assert(unpacked_hash == hash_data);
        }
    }

    // --- Test 3: UnpackAddrData with arbitrary 5-bit data ---
    {
        size_t data_len = fdp.ConsumeIntegralInRange<size_t>(0, 128);
        std::vector<uint8_t> fivebit_data;
        fivebit_data.reserve(data_len);
        for (size_t i = 0; i < data_len && fdp.remaining_bytes() > 0; ++i) {
            fivebit_data.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0, 31));
        }
        // Should not crash on any input
        auto [type, hash] = cashaddr::UnpackAddrData(fivebit_data);
        (void)type;
        (void)hash;
    }

    // --- Test 4: Encode with fuzzed prefix and payload, then Decode ---
    {
        const std::string prefix = fdp.ConsumeRandomLengthString(32);
        size_t payload_len = fdp.ConsumeIntegralInRange<size_t>(0, 64);
        std::vector<uint8_t> payload;
        payload.reserve(payload_len);
        for (size_t i = 0; i < payload_len && fdp.remaining_bytes() > 0; ++i) {
            payload.push_back(fdp.ConsumeIntegralInRange<uint8_t>(0, 31));
        }
        if (!prefix.empty() && !payload.empty()) {
            std::string encoded = cashaddr::Encode(prefix, payload);
            auto [dec_prefix, dec_payload] = cashaddr::Decode(encoded, prefix);
            // If encode produced valid output, decode should roundtrip
            if (!dec_payload.empty()) {
                assert(dec_prefix == prefix);
                assert(dec_payload == payload);
            }
        }
    }
}
