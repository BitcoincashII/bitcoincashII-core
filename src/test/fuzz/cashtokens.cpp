// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tokens.h>
#include <primitives/token.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <uint256.h>
#include <util/transaction_identifier.h>

#include <cassert>
#include <cstdint>
#include <vector>

namespace {
/** Consume exactly 32 bytes, zero-padding if fuzz data is exhausted. */
uint256 ConsumeUint256(FuzzedDataProvider& fdp)
{
    auto bytes = fdp.ConsumeBytes<uint8_t>(32);
    bytes.resize(32, 0);
    return uint256(bytes);
}
} // namespace

FUZZ_TARGET(cashtokens)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    // --- Test 1: OutputToken IsValid() with random fields ---
    {
        OutputToken tok;
        tok.categoryId = ConsumeUint256(fdp);
        tok.bitfield = fdp.ConsumeIntegral<uint8_t>();
        size_t commit_len = fdp.ConsumeIntegralInRange<size_t>(0, 64);
        tok.commitment = fdp.ConsumeBytes<uint8_t>(commit_len);
        tok.amount = fdp.ConsumeIntegral<int64_t>();
        // IsValid() should not crash
        (void)tok.IsValid();
        (void)tok.HasAmount();
        (void)tok.HasNFT();
        (void)tok.HasCommitment();
        (void)tok.GetCapability();
        (void)tok.IsMintingToken();
        (void)tok.IsMutableToken();
        (void)tok.IsImmutableToken();
    }

    // --- Test 2: OutputToken serialization roundtrip ---
    {
        // Build a valid-ish token for serialization
        OutputToken tok;
        tok.categoryId = ConsumeUint256(fdp);
        tok.bitfield = fdp.ConsumeIntegral<uint8_t>();
        if (tok.HasCommitment()) {
            size_t cl = fdp.ConsumeIntegralInRange<size_t>(1, token::MAX_COMMITMENT_LENGTH);
            tok.commitment = fdp.ConsumeBytes<uint8_t>(cl);
        }
        if (tok.HasAmount()) {
            tok.amount = fdp.ConsumeIntegralInRange<int64_t>(1, token::MAX_AMOUNT);
        }

        // Serialize
        DataStream ss{};
        tok.Serialize(ss);

        // Deserialize
        OutputToken tok2;
        try {
            tok2.Unserialize(ss);
            // If deserialization succeeded, check roundtrip
            assert(tok2.categoryId == tok.categoryId);
            assert(tok2.bitfield == tok.bitfield);
        } catch (const std::ios_base::failure&) {
            // Malformed data is expected sometimes
        }
    }

    // --- Test 3: Deserialize from raw fuzzed bytes ---
    {
        DataStream ds{buffer};
        OutputToken tok;
        try {
            tok.Unserialize(ds);
            // If deserialization succeeded, re-serialize
            DataStream ss2{};
            tok.Serialize(ss2);
            // And try to deserialize again
            OutputToken tok2;
            tok2.Unserialize(ss2);
            assert(tok == tok2);
        } catch (const std::ios_base::failure&) {
            // Expected for most fuzz inputs
        }
    }

    // --- Test 4: CheckTokens with fuzzed transaction ---
    {
        CMutableTransaction mtx;
        mtx.nVersion = fdp.ConsumeIntegralInRange<int32_t>(1, 2);

        // Create 1-2 inputs
        uint8_t num_inputs = fdp.ConsumeIntegralInRange<uint8_t>(1, 2);
        for (uint8_t i = 0; i < num_inputs; ++i) {
            CTxIn in;
            in.prevout.hash = Txid::FromUint256(ConsumeUint256(fdp));
            in.prevout.n = fdp.ConsumeIntegral<uint32_t>();
            mtx.vin.push_back(in);
        }

        // Create 1-2 outputs with optional token data
        uint8_t num_outputs = fdp.ConsumeIntegralInRange<uint8_t>(1, 2);
        std::vector<CTxOut> spent_outputs;
        for (uint8_t i = 0; i < num_outputs; ++i) {
            CTxOut out;
            out.nValue = fdp.ConsumeIntegralInRange<int64_t>(0, 50 * 100000000LL);

            if (fdp.ConsumeBool()) {
                OutputToken tok;
                tok.categoryId = ConsumeUint256(fdp);
                tok.bitfield = fdp.ConsumeIntegral<uint8_t>();
                if (tok.HasCommitment()) {
                    size_t cl = fdp.ConsumeIntegralInRange<size_t>(0, token::MAX_COMMITMENT_LENGTH);
                    tok.commitment = fdp.ConsumeBytes<uint8_t>(cl);
                }
                if (tok.HasAmount()) {
                    tok.amount = fdp.ConsumeIntegralInRange<int64_t>(1, token::MAX_AMOUNT);
                }
                out.tokenData.emplace(tok);
            }
            mtx.vout.push_back(out);

            // Build matching spent output
            CTxOut spent;
            spent.nValue = fdp.ConsumeIntegralInRange<int64_t>(0, 50 * 100000000LL);
            if (fdp.ConsumeBool()) {
                OutputToken stok;
                stok.categoryId = ConsumeUint256(fdp);
                stok.bitfield = fdp.ConsumeIntegral<uint8_t>();
                if (stok.HasCommitment()) {
                    size_t cl = fdp.ConsumeIntegralInRange<size_t>(0, token::MAX_COMMITMENT_LENGTH);
                    stok.commitment = fdp.ConsumeBytes<uint8_t>(cl);
                }
                if (stok.HasAmount()) {
                    stok.amount = fdp.ConsumeIntegralInRange<int64_t>(1, token::MAX_AMOUNT);
                }
                spent.tokenData.emplace(stok);
            }
            spent_outputs.push_back(spent);
        }

        const CTransaction tx(mtx);
        // CheckTokens should not crash
        (void)CheckTokens(tx, spent_outputs, false);
        (void)IsTokenGenesis(tx);
        (void)HasTokenOutputs(tx);
        (void)HasTokenInputs(spent_outputs);
    }
}
