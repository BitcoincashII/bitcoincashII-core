// Copyright (c) 2015-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;

    // Here (and below): expected_nbits is calculated in
    // CalculateNextWorkRequired(); redoing the calculation here would be just
    // reimplementing the same code that is written in pow.cpp. Rather than
    // copy that code, we just hardcode the expected result.
    unsigned int expected_nbits = 0x1d00d86aU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1d00ffff;
    unsigned int expected_nbits = 0x1d00ffffU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    unsigned int expected_nbits = 0x1c0168fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that reducing nbits further would not be a PermittedDifficultyTransition.
    // NOTE: This check only applies to pre-fork (original DAA) blocks. Post-fork ASERT
    // doesn't have per-block change limits - difficulty is deterministic based on timestamps.
    unsigned int invalid_nbits = expected_nbits-1;
    if (!chainParams->GetConsensus().IsBCH2ForkActive(pindexLast.nHeight+1)) {
        BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
    }
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    unsigned int expected_nbits = 0x1d00e1fdU;
    BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), expected_nbits);
    BOOST_CHECK(PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, expected_nbits));
    // Test that increasing nbits further would not be a PermittedDifficultyTransition.
    unsigned int invalid_nbits = expected_nbits+1;
    BOOST_CHECK(!PermittedDifficultyTransition(chainParams->GetConsensus(), pindexLast.nHeight+1, pindexLast.nBits, invalid_nbits));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_negative_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    nBits = UintToArith256(consensus.powLimit).GetCompact(true);
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_overflow_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits{~0x00800000U};
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_too_easy_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 nBits_arith = UintToArith256(consensus.powLimit);
    nBits_arith *= 2;
    nBits = nBits_arith.GetCompact();
    hash.SetHex("0x1");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_biger_hash_than_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith = UintToArith256(consensus.powLimit);
    nBits = hash_arith.GetCompact();
    hash_arith *= 2; // hash > nBits
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(CheckProofOfWork_test_zero_target)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    uint256 hash;
    unsigned int nBits;
    arith_uint256 hash_arith{0};
    nBits = hash_arith.GetCompact();
    hash = ArithToUint256(hash_arith);
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}

void sanity_check_chainparams(const ArgsManager& args, ChainType chain_type)
{
    const auto chainParams = CreateChainParams(args, chain_type);
    const auto consensus = chainParams->GetConsensus();

    // hash genesis is correct
    BOOST_CHECK_EQUAL(consensus.hashGenesisBlock, chainParams->GenesisBlock().GetHash());

    // target timespan is an even multiple of spacing
    BOOST_CHECK_EQUAL(consensus.nPowTargetTimespan % consensus.nPowTargetSpacing, 0);

    // genesis nBits is positive, doesn't overflow and is lower than powLimit
    arith_uint256 pow_compact;
    bool neg, over;
    pow_compact.SetCompact(chainParams->GenesisBlock().nBits, &neg, &over);
    BOOST_CHECK(!neg && pow_compact != 0);
    BOOST_CHECK(!over);
    BOOST_CHECK(UintToArith256(consensus.powLimit) >= pow_compact);

    // check max target * 4*nPowTargetTimespan doesn't overflow -- see pow.cpp:CalculateNextWorkRequired()
    if (!consensus.fPowNoRetargeting) {
        arith_uint256 targ_max{UintToArith256(uint256S("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))};
        targ_max /= consensus.nPowTargetTimespan*4;
        BOOST_CHECK(UintToArith256(consensus.powLimit) < targ_max);
    }
}

BOOST_AUTO_TEST_CASE(ChainParams_MAIN_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(ChainParams_REGTEST_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::REGTEST);
}

BOOST_AUTO_TEST_CASE(ChainParams_TESTNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(ChainParams_SIGNET_sanity)
{
    sanity_check_chainparams(*m_node.args, ChainType::SIGNET);
}

// ============================================================================
// BCH2 ASERT Difficulty Adjustment Tests
// ============================================================================
// These tests verify the CalculateASERT() function directly, which implements
// the ASERT (aserti3-2d) algorithm from Bitcoin Cash Node (BCHN).

BOOST_AUTO_TEST_CASE(asert_on_schedule)
{
    // When blocks are exactly on schedule (600 seconds apart), difficulty should stay the same
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    arith_uint256 refTarget;
    refTarget.SetCompact(0x1d00ffff);  // Standard initial difficulty

    const arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    const int64_t nPowTargetSpacing = 600;  // 10 minutes
    const int64_t nHalfLife = 172800;       // 2 days

    // Test: 10 blocks, exactly 6000 seconds elapsed (on schedule)
    // timeDiff = 6000, heightDiff = 10
    // exponent = (6000 - 600 * (10 + 1)) / 172800 = (6000 - 6600) / 172800 = -600/172800 ≈ -0.00347
    // Result should be very close to refTarget (slightly lower due to -600 seconds)
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 6000, 10, powLimit, nHalfLife);

    // The result should be within 1% of refTarget for on-schedule blocks
    arith_uint256 diff = (result > refTarget) ? result - refTarget : refTarget - result;
    arith_uint256 tolerance = refTarget / 100;  // 1%
    BOOST_CHECK(diff < tolerance);
}

BOOST_AUTO_TEST_CASE(asert_slow_blocks)
{
    // When blocks are slower than schedule, difficulty should decrease (target increases)
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c0fffff);  // Some arbitrary difficulty

    const arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    const int64_t nPowTargetSpacing = 600;
    const int64_t nHalfLife = 172800;

    // Test: 10 blocks but 12000 seconds elapsed (blocks taking 20 min each instead of 10 min)
    // Ideal time for 10 blocks = 6000 seconds, actual = 12000 seconds
    // Blocks are slow, so difficulty should decrease (target increases)
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 12000, 10, powLimit, nHalfLife);

    BOOST_CHECK(result > refTarget);  // Target increased (difficulty decreased)
}

BOOST_AUTO_TEST_CASE(asert_fast_blocks)
{
    // When blocks are faster than schedule, difficulty should increase (target decreases)
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c0fffff);

    const arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    const int64_t nPowTargetSpacing = 600;
    const int64_t nHalfLife = 172800;

    // Test: 10 blocks but only 3000 seconds elapsed (blocks taking 5 min each instead of 10 min)
    // Blocks are fast, so difficulty should increase (target decreases)
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 3000, 10, powLimit, nHalfLife);

    BOOST_CHECK(result < refTarget);  // Target decreased (difficulty increased)
}

BOOST_AUTO_TEST_CASE(asert_halflife)
{
    // After exactly half-life seconds of delay, difficulty should halve (target should double)
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c00ffff);  // Use a target that won't overflow when doubled

    const arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    const int64_t nPowTargetSpacing = 600;
    const int64_t nHalfLife = 172800;  // 2 days

    // Test: 1 block, but half-life + 600 seconds elapsed
    // timeDiff - spacing * (heightDiff + 1) = (nHalfLife + 600) - 600 * 2 = nHalfLife - 600
    // We want exponent = nHalfLife exactly, so:
    // timeDiff = nHalfLife + spacing * (heightDiff + 1) = 172800 + 600 * 2 = 174000 for heightDiff=1
    int64_t timeDiff = nHalfLife + nPowTargetSpacing * 2;  // 174000 for heightDiff=1
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, timeDiff, 1, powLimit, nHalfLife);

    // Target should approximately double (2x refTarget)
    arith_uint256 expectedTarget = refTarget * 2;
    arith_uint256 diff = (result > expectedTarget) ? result - expectedTarget : expectedTarget - result;
    arith_uint256 tolerance = expectedTarget / 100;  // 1% tolerance for fixed-point math approximation
    BOOST_CHECK(diff < tolerance);
}

BOOST_AUTO_TEST_CASE(asert_clamped_to_powlimit)
{
    // When difficulty would go below minimum (target > powLimit), clamp to powLimit
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    arith_uint256 refTarget;
    refTarget.SetCompact(0x1d00ffff);  // Near powLimit already

    const arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    const int64_t nPowTargetSpacing = 600;
    const int64_t nHalfLife = 172800;

    // Test: Very slow blocks - 10x halflife delay
    // This would push target way above powLimit
    int64_t timeDiff = nHalfLife * 10 + nPowTargetSpacing * 2;
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, timeDiff, 1, powLimit, nHalfLife);

    // Result should be clamped to powLimit
    BOOST_CHECK(result == powLimit);
}

BOOST_AUTO_TEST_CASE(asert_never_zero)
{
    // Target should never be zero, even with extreme fast blocks
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    arith_uint256 refTarget;
    refTarget.SetCompact(0x1d00ffff);

    const arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    const int64_t nPowTargetSpacing = 600;
    const int64_t nHalfLife = 172800;

    // Test: Extremely fast blocks - negative time drift
    // 100 blocks in just 1 second (impossible but tests edge case)
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 1, 100, powLimit, nHalfLife);

    // Result should never be zero
    BOOST_CHECK(result >= arith_uint256(1));
}

BOOST_AUTO_TEST_CASE(asert_deterministic)
{
    // ASERT should be deterministic - same inputs always produce same output
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c0fffff);

    const arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    const int64_t nPowTargetSpacing = 600;
    const int64_t nHalfLife = 172800;

    // Calculate same result multiple times
    arith_uint256 result1 = CalculateASERT(refTarget, nPowTargetSpacing, 10000, 15, powLimit, nHalfLife);
    arith_uint256 result2 = CalculateASERT(refTarget, nPowTargetSpacing, 10000, 15, powLimit, nHalfLife);
    arith_uint256 result3 = CalculateASERT(refTarget, nPowTargetSpacing, 10000, 15, powLimit, nHalfLife);

    BOOST_CHECK(result1 == result2);
    BOOST_CHECK(result2 == result3);
}

BOOST_AUTO_TEST_CASE(asert_height_zero)
{
    // Test at height diff 0 (anchor block itself)
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c0fffff);

    const arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    const int64_t nPowTargetSpacing = 600;
    const int64_t nHalfLife = 172800;

    // At height diff 0, timeDiff should be 0 for on-schedule
    // Formula: exponent = (timeDiff - spacing * (0 + 1)) / halflife = (0 - 600) / 172800
    // This is a small negative exponent, so target should decrease slightly
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 0, 0, powLimit, nHalfLife);

    // Should be slightly less than refTarget (more difficulty)
    BOOST_CHECK(result < refTarget);
    // But should be close (within 1%)
    arith_uint256 diff = refTarget - result;
    arith_uint256 tolerance = refTarget / 100;
    BOOST_CHECK(diff < tolerance);
}

BOOST_AUTO_TEST_CASE(asert_symmetric_adjustment)
{
    // ASERT should produce sensible adjustments in both directions
    const auto chainParams = CreateChainParams(*m_node.args, ChainType::MAIN);
    const auto& consensus = chainParams->GetConsensus();

    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c00ffff);

    const arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    const int64_t nPowTargetSpacing = 600;
    const int64_t nHalfLife = 172800;

    // First: slow blocks (target increases/difficulty decreases)
    // 10 blocks in 12000 seconds (should take 6600 ideally for 11 intervals)
    arith_uint256 slowResult = CalculateASERT(refTarget, nPowTargetSpacing, 12000, 10, powLimit, nHalfLife);

    // Then: fast blocks (target decreases/difficulty increases)
    // 10 blocks in 3000 seconds (should take 6600 ideally)
    arith_uint256 fastResult = CalculateASERT(refTarget, nPowTargetSpacing, 3000, 10, powLimit, nHalfLife);

    // Verify direction of adjustments:
    // Slow blocks -> target increases (difficulty decreases)
    // Fast blocks -> target decreases (difficulty increases)
    BOOST_CHECK(slowResult > refTarget);
    BOOST_CHECK(fastResult < refTarget);

    // Verify adjustments are reasonable (within 2x for these moderate deviations)
    BOOST_CHECK(slowResult < refTarget * 2);
    BOOST_CHECK(fastResult > refTarget / 2);

    // Verify that adjustment magnitudes are non-trivial but not extreme
    // slowResult should be noticeably higher than refTarget
    BOOST_CHECK(slowResult > refTarget + refTarget / 100);  // At least 1% higher
    // fastResult should be noticeably lower than refTarget
    BOOST_CHECK(fastResult < refTarget - refTarget / 100);  // At least 1% lower
}

BOOST_AUTO_TEST_SUITE_END()
