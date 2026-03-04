// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/abla.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>

#include <cassert>
#include <cstdint>
#include <limits>

FUZZ_TARGET(abla)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    // --- Test 1: Config::IsValid() with adversarial parameters ---
    {
        abla::Config cfg;
        cfg.epsilon0 = fdp.ConsumeIntegral<uint64_t>();
        cfg.beta0 = fdp.ConsumeIntegral<uint64_t>();
        cfg.gammaReciprocal = fdp.ConsumeIntegral<uint64_t>();
        cfg.zeta_xB7 = fdp.ConsumeIntegral<uint64_t>();
        cfg.thetaReciprocal = fdp.ConsumeIntegral<uint64_t>();
        cfg.delta = fdp.ConsumeIntegral<uint64_t>();
        cfg.epsilonMax = fdp.ConsumeIntegral<uint64_t>();
        cfg.betaMax = fdp.ConsumeIntegral<uint64_t>();

        const char *err = nullptr;
        (void)cfg.IsValid(&err);
        (void)cfg.IsFixedSize();
        (void)cfg.ToString();
    }

    // --- Test 2: NextBlockState iterations with default config ---
    {
        abla::Config cfg = abla::Config::MakeDefault();
        assert(cfg.IsValid());

        abla::State state(cfg, 0);
        assert(state.IsValid(cfg));

        // Iterate a few blocks with fuzzed sizes
        uint8_t num_blocks = fdp.ConsumeIntegralInRange<uint8_t>(1, 20);
        for (uint8_t i = 0; i < num_blocks && fdp.remaining_bytes() >= 8; ++i) {
            uint64_t blk_size = fdp.ConsumeIntegral<uint64_t>();
            abla::State next = state.NextBlockState(cfg, blk_size);
            (void)next.GetBlockSizeLimit();
            (void)next.GetBlockSize();
            (void)next.GetControlBlockSize();
            (void)next.GetElasticBufferSize();
            (void)next.IsValid(cfg);
            state = next;
        }
    }

    // --- Test 3: State serialization roundtrip ---
    {
        // Build from fuzzed tuple
        uint64_t bs = fdp.ConsumeIntegral<uint64_t>();
        uint64_t cbs = fdp.ConsumeIntegral<uint64_t>();
        uint64_t ebs = fdp.ConsumeIntegral<uint64_t>();
        abla::State state = abla::State::FromTuple({bs, cbs, ebs});

        // Serialize
        DataStream ss{};
        ss << state;

        // Deserialize
        abla::State state2;
        ss >> state2;

        assert(state == state2);
    }

    // --- Test 4: Deserialize State from raw fuzz input ---
    {
        DataStream ds{buffer};
        abla::State state;
        try {
            ds >> state;
            // Re-serialize for roundtrip
            DataStream ss{};
            ss << state;
            abla::State state2;
            ss >> state2;
            assert(state == state2);
        } catch (const std::ios_base::failure&) {
            // Expected for most inputs
        }
    }

    // --- Test 5: CalcLookaheadBlockSizeLimit ---
    {
        abla::Config cfg = abla::Config::MakeDefault();
        abla::State state(cfg, fdp.ConsumeIntegral<uint64_t>());
        size_t count = fdp.ConsumeIntegralInRange<size_t>(0, 100);
        (void)state.CalcLookaheadBlockSizeLimit(cfg, count);
        (void)state.CalcLookaheadBlockSizeLimit(cfg, count, true);
    }

    // --- Test 6: SetMax and re-validate ---
    {
        abla::Config cfg = abla::Config::MakeDefault();
        cfg.SetMax();
        assert(cfg.IsValid());
    }

    // --- Test 7: MakeDefault with fuzzed block size ---
    {
        uint64_t block_size = fdp.ConsumeIntegralInRange<uint64_t>(1, std::numeric_limits<uint32_t>::max());
        abla::Config cfg = abla::Config::MakeDefault(block_size);
        (void)cfg.IsValid();
        (void)cfg.ToString();

        // Fixed-size variant
        abla::Config cfg_fixed = abla::Config::MakeDefault(block_size, true);
        (void)cfg_fixed.IsValid();
        assert(cfg_fixed.IsFixedSize());
    }
}
