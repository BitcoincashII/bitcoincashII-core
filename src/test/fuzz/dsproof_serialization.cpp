// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dsp/dsproof.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <vector>

FUZZ_TARGET(dsproof_serialization)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    // --- Test 1: Deserialize raw buffer as DSProof, roundtrip ---
    {
        DataStream ds{buffer};
        DoubleSpendProof dsp;
        try {
            ds >> dsp;
            // Successful deserialization — check basic accessors don't crash
            (void)dsp.isEmpty();
            (void)dsp.GetId();
            (void)dsp.prevTxId();
            (void)dsp.prevOutIndex();
            (void)dsp.outPoint();
            (void)dsp.spender1();
            (void)dsp.spender2();

            // Re-serialize and verify roundtrip
            DataStream ss{};
            ss << dsp;

            DoubleSpendProof dsp2;
            ss >> dsp2;
            assert(dsp == dsp2);
        } catch (const std::ios_base::failure&) {
            // Expected for most fuzz inputs
        } catch (const std::runtime_error&) {
            // DSProof may throw runtime_error for sanity violations
        }
    }

    // --- Test 2: Construct DSProof with fuzzed field values ---
    {
        // Build a DoubleSpendProof by serializing fuzzed components
        DataStream builder{};
        try {
            // Outpoint: 32-byte hash + uint32 index
            std::vector<uint8_t> txid_bytes = fdp.ConsumeBytes<uint8_t>(32);
            if (txid_bytes.size() < 32) txid_bytes.resize(32, 0);
            builder.write(MakeByteSpan(txid_bytes));
            uint32_t outIdx = fdp.ConsumeIntegral<uint32_t>();
            builder << outIdx;

            // Build two spenders
            for (int s = 0; s < 2; ++s) {
                uint32_t txVersion = fdp.ConsumeIntegral<uint32_t>();
                uint32_t outSequence = fdp.ConsumeIntegral<uint32_t>();
                uint32_t lockTime = fdp.ConsumeIntegral<uint32_t>();
                builder << txVersion << outSequence << lockTime;

                // Three 32-byte hashes
                for (int h = 0; h < 3; ++h) {
                    std::vector<uint8_t> hash = fdp.ConsumeBytes<uint8_t>(32);
                    if (hash.size() < 32) hash.resize(32, 0);
                    builder.write(MakeByteSpan(hash));
                }

                // pushData: vector of vectors
                uint8_t num_push = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
                WriteCompactSize(builder, num_push);
                for (uint8_t p = 0; p < num_push; ++p) {
                    size_t push_len = fdp.ConsumeIntegralInRange<size_t>(0, 600);
                    std::vector<uint8_t> push_data = fdp.ConsumeBytes<uint8_t>(push_len);
                    WriteCompactSize(builder, push_data.size());
                    if (!push_data.empty()) {
                        builder.write(MakeByteSpan(push_data));
                    }
                }
            }

            // Try to deserialize the constructed proof
            DoubleSpendProof dsp;
            builder >> dsp;

            (void)dsp.isEmpty();
            (void)dsp.GetId();

            // Re-serialize for roundtrip check
            DataStream rt{};
            rt << dsp;
            DoubleSpendProof dsp2;
            rt >> dsp2;
            assert(dsp == dsp2);
        } catch (const std::ios_base::failure&) {
            // Expected for malformed data
        } catch (const std::runtime_error&) {
            // Expected for sanity failures
        }
    }

    // --- Test 3: Empty proof checks ---
    {
        DoubleSpendProof empty;
        assert(empty.isEmpty());
        (void)empty.GetId();
    }
}
