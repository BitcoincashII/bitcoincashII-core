// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for BCH2 PoW and ASERT difficulty adjustment.
// Covers CalculateASERT boundary conditions, CheckProofOfWork edge cases,
// and PermittedDifficultyTransition validation.

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

namespace {

// Helper to get mainnet powLimit (has required 32+ leading zero bits for ASERT)
arith_uint256 GetMainnetPowLimit() {
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    return UintToArith256(params->GetConsensus().powLimit);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(bch2_pow_tests, BasicTestingSetup)

// ============================================================================
// CalculateASERT tests
// ============================================================================

BOOST_AUTO_TEST_CASE(asert_no_change_at_exact_target_spacing)
{
    // When blocks arrive exactly at target spacing, difficulty should not change
    const arith_uint256 powLimit = GetMainnetPowLimit();
    const arith_uint256 refTarget = powLimit >> 4; // Some reasonable target (powLimit/16)
    const int64_t targetSpacing = 600;             // 10 minutes
    const int64_t halfLife = 172800;               // 2 days

    // 10 blocks each at exactly 600 seconds
    // timeDiff = 10 * 600 = 6000 seconds from anchor parent
    // heightDiff = 10
    // exponent = (6000 - 600*(10+1)) * 65536 / 172800 = (6000 - 6600) * 65536 / 172800
    //          = (-600) * 65536 / 172800 = -227 (approximately)
    //
    // Actually, at exact spacing, timeDiff should equal targetSpacing * heightDiff
    // Then exponent = (targetSpacing * heightDiff - targetSpacing * (heightDiff + 1)) * 65536 / halfLife
    //              = (-targetSpacing) * 65536 / halfLife
    //
    // For no change, timeDiff = targetSpacing * (heightDiff + 1)
    // Then exponent = 0

    const int64_t nHeightDiff = 10;
    const int64_t nTimeDiff = targetSpacing * (nHeightDiff + 1); // Perfect timing

    arith_uint256 result = CalculateASERT(refTarget, targetSpacing, nTimeDiff, nHeightDiff, powLimit, halfLife);

    // Should return the same target (modulo rounding from factor calculation)
    // The polynomial approximation has <0.013% error, so check within ~0.02%
    arith_uint256 diff;
    if (result > refTarget)
        diff = result - refTarget;
    else
        diff = refTarget - result;

    // diff should be tiny compared to refTarget
    BOOST_CHECK(diff * 10000 < refTarget); // Less than 0.01% difference
}

BOOST_AUTO_TEST_CASE(asert_difficulty_increases_when_fast)
{
    // When blocks arrive faster than target, target should decrease (difficulty increases)
    const arith_uint256 powLimit = GetMainnetPowLimit();
    const arith_uint256 refTarget = powLimit >> 4;
    const int64_t targetSpacing = 600;
    const int64_t halfLife = 172800;

    const int64_t nHeightDiff = 10;
    // Blocks arrived in half the expected time → difficulty should roughly double
    // Perfect time = 600 * 11 = 6600. Fast time = 3300
    const int64_t nTimeDiff = targetSpacing * (nHeightDiff + 1) / 2;

    arith_uint256 result = CalculateASERT(refTarget, targetSpacing, nTimeDiff, nHeightDiff, powLimit, halfLife);

    // Target should be lower than reference (harder difficulty)
    BOOST_CHECK(result < refTarget);
}

BOOST_AUTO_TEST_CASE(asert_difficulty_decreases_when_slow)
{
    // When blocks arrive slower than target, target should increase (difficulty decreases)
    const arith_uint256 powLimit = GetMainnetPowLimit();
    const arith_uint256 refTarget = powLimit >> 4;
    const int64_t targetSpacing = 600;
    const int64_t halfLife = 172800;

    const int64_t nHeightDiff = 10;
    // Blocks arrived in double the expected time
    const int64_t nTimeDiff = targetSpacing * (nHeightDiff + 1) * 2;

    arith_uint256 result = CalculateASERT(refTarget, targetSpacing, nTimeDiff, nHeightDiff, powLimit, halfLife);

    // Target should be higher than reference (easier difficulty)
    BOOST_CHECK(result > refTarget);
}

BOOST_AUTO_TEST_CASE(asert_zero_height_diff)
{
    // At height diff 0 (first block after anchor), time diff affects result
    const arith_uint256 powLimit = GetMainnetPowLimit();
    const arith_uint256 refTarget = powLimit >> 4;
    const int64_t targetSpacing = 600;
    const int64_t halfLife = 172800;

    // Perfect timing: timeDiff = 600 * (0 + 1) = 600
    const int64_t nTimeDiff = targetSpacing;
    arith_uint256 result = CalculateASERT(refTarget, targetSpacing, nTimeDiff, 0, powLimit, halfLife);

    // Should be approximately the same as refTarget
    arith_uint256 diff;
    if (result > refTarget)
        diff = result - refTarget;
    else
        diff = refTarget - result;
    BOOST_CHECK(diff * 10000 < refTarget);
}

BOOST_AUTO_TEST_CASE(asert_result_clamped_to_powlimit)
{
    // Very slow blocks should never exceed powLimit
    const arith_uint256 powLimit = GetMainnetPowLimit();
    const arith_uint256 refTarget = powLimit >> 1; // Already close to limit
    const int64_t targetSpacing = 600;
    const int64_t halfLife = 172800;

    // Extremely slow: 100x expected time
    const int64_t nHeightDiff = 1;
    const int64_t nTimeDiff = targetSpacing * (nHeightDiff + 1) * 100;

    arith_uint256 result = CalculateASERT(refTarget, targetSpacing, nTimeDiff, nHeightDiff, powLimit, halfLife);

    // Should be clamped at powLimit
    BOOST_CHECK(result <= powLimit);
}

BOOST_AUTO_TEST_CASE(asert_result_never_zero)
{
    // Very fast blocks should never produce target of 0
    const arith_uint256 powLimit = GetMainnetPowLimit();
    const arith_uint256 refTarget(1); // Minimum possible target
    const int64_t targetSpacing = 600;
    const int64_t halfLife = 172800;

    // Extremely fast blocks — but not so extreme as to overflow the exponent calculation
    const int64_t nHeightDiff = 100;
    const int64_t nTimeDiff = 1; // Almost no time passed

    arith_uint256 result = CalculateASERT(refTarget, targetSpacing, nTimeDiff, nHeightDiff, powLimit, halfLife);

    // Target should be at least 1
    BOOST_CHECK(result >= arith_uint256(1));
}

BOOST_AUTO_TEST_CASE(asert_half_life_symmetry)
{
    // Doubling the time difference by exactly one half-life should approximately
    // double the target (and vice versa for half)
    const arith_uint256 powLimit = GetMainnetPowLimit();
    const arith_uint256 refTarget = powLimit >> 8; // Well below limit
    const int64_t targetSpacing = 600;
    const int64_t halfLife = 172800;

    // Calculate with exactly one half-life of extra time
    const int64_t nHeightDiff = 10;
    const int64_t perfectTime = targetSpacing * (nHeightDiff + 1);

    arith_uint256 resultNormal = CalculateASERT(refTarget, targetSpacing, perfectTime, nHeightDiff, powLimit, halfLife);
    arith_uint256 resultDouble = CalculateASERT(refTarget, targetSpacing, perfectTime + halfLife, nHeightDiff, powLimit, halfLife);

    // resultDouble should be approximately 2x resultNormal
    // Check that ratio is between 1.95 and 2.05
    arith_uint256 ratio_check = resultDouble * 100 / resultNormal;
    uint64_t ratio_pct = (ratio_check == arith_uint256(0)) ? 0 : ratio_check.GetLow64();
    BOOST_CHECK(ratio_pct >= 195 && ratio_pct <= 205);
}

BOOST_AUTO_TEST_CASE(asert_deterministic)
{
    // Same inputs should always produce same output
    const arith_uint256 powLimit = GetMainnetPowLimit();
    const arith_uint256 refTarget = powLimit >> 4;
    const int64_t targetSpacing = 600;
    const int64_t halfLife = 172800;

    arith_uint256 r1 = CalculateASERT(refTarget, targetSpacing, 7200, 10, powLimit, halfLife);
    arith_uint256 r2 = CalculateASERT(refTarget, targetSpacing, 7200, 10, powLimit, halfLife);

    BOOST_CHECK(r1 == r2);
}

// ============================================================================
// CheckProofOfWork tests
// ============================================================================

BOOST_AUTO_TEST_CASE(pow_valid_hash_below_target)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    // Use powLimit nBits (easiest difficulty)
    uint32_t nBits = UintToArith256(consensus.powLimit).GetCompact();

    // A hash of all zeros is below any valid target
    uint256 hash = uint256::ZERO;
    BOOST_CHECK(CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(pow_hash_exceeds_target)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    // Set a very tight target (difficulty very high)
    arith_uint256 tightTarget(1);
    uint32_t nBits = tightTarget.GetCompact();

    // Almost any hash will exceed this target
    uint256 hash = uint256S("0000000000000000000000000000000000000000000000000000000000000002");
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(pow_negative_nbits_rejected)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    // nBits with negative flag set: exponent=0x20, mantissa with sign bit
    uint32_t nBits = 0x20FF0000; // fNegative=true
    uint256 hash = uint256::ZERO;
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(pow_overflow_nbits_rejected)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    // nBits that overflows when decoded
    uint32_t nBits = 0xFF7FFFFF; // Very large exponent → overflow
    uint256 hash = uint256::ZERO;
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(pow_zero_target_rejected)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    // nBits = 0 → zero target
    uint32_t nBits = 0;
    uint256 hash = uint256::ZERO;
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(pow_above_powlimit_rejected)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    // Target above powLimit
    arith_uint256 aboveLimit = UintToArith256(consensus.powLimit) + arith_uint256(1);
    uint32_t nBits = aboveLimit.GetCompact();
    uint256 hash = uint256::ZERO;
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(pow_hash_exactly_equals_target)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    // Set target to a known value and create hash matching it exactly
    arith_uint256 target(0x1000);
    uint32_t nBits = target.GetCompact();

    // Decompress to get actual target after compact rounding
    arith_uint256 actualTarget;
    actualTarget.SetCompact(nBits);

    uint256 hash = ArithToUint256(actualTarget);

    // hash == target: UintToArith256(hash) > bnTarget is false, so should pass
    // Actually: hash == target means hash is NOT > target, so it passes
    BOOST_CHECK(CheckProofOfWork(hash, nBits, consensus));
}

// ============================================================================
// PermittedDifficultyTransition tests (post-fork ASERT path)
// ============================================================================

BOOST_AUTO_TEST_CASE(permitted_difficulty_valid_post_fork)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    // Post-fork height — any valid target within powLimit should be accepted
    int64_t postForkHeight = consensus.BCH2ForkHeight + 10;
    arith_uint256 powLimitArith = UintToArith256(consensus.powLimit);
    uint32_t oldBits = powLimitArith.GetCompact();
    arith_uint256 halfLimit = powLimitArith >> 1;
    uint32_t newBits = halfLimit.GetCompact();

    BOOST_CHECK(PermittedDifficultyTransition(consensus, postForkHeight, oldBits, newBits));
}

BOOST_AUTO_TEST_CASE(permitted_difficulty_negative_nbits_post_fork)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    int64_t postForkHeight = consensus.BCH2ForkHeight + 10;
    uint32_t oldBits = UintToArith256(consensus.powLimit).GetCompact();
    uint32_t negativeBits = 0x20FF0000; // Negative target

    BOOST_CHECK(!PermittedDifficultyTransition(consensus, postForkHeight, oldBits, negativeBits));
}

BOOST_AUTO_TEST_CASE(permitted_difficulty_zero_target_post_fork)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    int64_t postForkHeight = consensus.BCH2ForkHeight + 10;
    uint32_t oldBits = UintToArith256(consensus.powLimit).GetCompact();
    uint32_t zeroBits = 0; // Zero target

    BOOST_CHECK(!PermittedDifficultyTransition(consensus, postForkHeight, oldBits, zeroBits));
}

BOOST_AUTO_TEST_CASE(permitted_difficulty_above_powlimit_post_fork)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    int64_t postForkHeight = consensus.BCH2ForkHeight + 10;
    uint32_t oldBits = UintToArith256(consensus.powLimit).GetCompact();

    // Create target above powLimit
    arith_uint256 aboveLimit = UintToArith256(consensus.powLimit) + arith_uint256(1);
    uint32_t aboveBits = aboveLimit.GetCompact();

    BOOST_CHECK(!PermittedDifficultyTransition(consensus, postForkHeight, oldBits, aboveBits));
}

// ============================================================================
// ASERT anchor parameter tests
// ============================================================================

BOOST_AUTO_TEST_CASE(asert_anchor_configured_for_mainnet)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    // Mainnet should have ASERT anchor configured
    BOOST_CHECK(consensus.asertAnchorParams.has_value());
    if (consensus.asertAnchorParams) {
        BOOST_CHECK(consensus.asertAnchorParams->nHeight >= 0);
        BOOST_CHECK(consensus.asertAnchorParams->nBits != 0);
    }
}

BOOST_AUTO_TEST_CASE(asert_half_life_before_transition)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    // Before transition height, half-life should be the configured default
    int64_t hl = consensus.GetASERTHalfLife(1);
    BOOST_CHECK(hl > 0);
}

BOOST_AUTO_TEST_CASE(asert_half_life_transition)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    // If transition height is configured, verify half-life changes
    if (consensus.nASERTHalfLifeTransitionHeight != Consensus::NEVER_ACTIVE_HEIGHT) {
        int64_t hlBefore = consensus.GetASERTHalfLife(consensus.nASERTHalfLifeTransitionHeight - 1);
        int64_t hlAfter = consensus.GetASERTHalfLife(consensus.nASERTHalfLifeTransitionHeight);

        // After transition, should be 2-day half-life
        BOOST_CHECK_EQUAL(hlAfter, Consensus::Params::ASERT_HALFLIFE_2_DAYS);

        // Before transition, could be different (likely 1-hour)
        BOOST_CHECK(hlBefore > 0);
    }
}

BOOST_AUTO_TEST_CASE(asert_target_spacing)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    // BCH2 target spacing should be 600 seconds (10 minutes)
    BOOST_CHECK_EQUAL(consensus.nPowTargetSpacing, 600);
}

// ============================================================================
// Pre-fork PermittedDifficultyTransition
// ============================================================================

BOOST_AUTO_TEST_CASE(permitted_difficulty_pre_fork_same_bits)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    // Pre-fork, non-retarget block: old_nbits == new_nbits should pass
    // Pick a height that's not on a difficulty adjustment boundary
    int64_t height = 100; // Well before fork, not on 2016 boundary
    uint32_t bits = UintToArith256(consensus.powLimit).GetCompact();

    BOOST_CHECK(PermittedDifficultyTransition(consensus, height, bits, bits));
}

BOOST_AUTO_TEST_CASE(permitted_difficulty_pre_fork_different_bits_non_retarget)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    // Pre-fork, non-retarget block: different bits should fail
    int64_t height = 100;
    arith_uint256 powLimitArith = UintToArith256(consensus.powLimit);
    uint32_t oldBits = powLimitArith.GetCompact();
    arith_uint256 halfLimit = powLimitArith >> 1;
    uint32_t newBits = halfLimit.GetCompact();

    BOOST_CHECK(!PermittedDifficultyTransition(consensus, height, oldBits, newBits));
}

// ============================================================================
// CalculateASERT: additional edge cases
// ============================================================================

// ============================================================================
// ASERT additional edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(asert_halflife_approximately_doubles_target)
{
    // After exactly nHalfLife seconds behind, target should roughly double
    arith_uint256 powLimit = GetMainnetPowLimit();
    arith_uint256 refTarget = powLimit >> 10;

    int64_t halfLife = 172800; // 2 days
    arith_uint256 result = CalculateASERT(refTarget, 600, 600 + halfLife, 1, powLimit, halfLife);

    BOOST_CHECK(result > refTarget);
    // Should be approximately 2x
    arith_uint256 lower = refTarget + (refTarget * 9 / 10); // 1.9x
    arith_uint256 upper = refTarget * 21 / 10; // 2.1x
    BOOST_CHECK(result >= lower);
    BOOST_CHECK(result <= upper);
}

BOOST_AUTO_TEST_CASE(asert_10_blocks_exact_timing_approximately_unchanged)
{
    // 10 blocks at exact target spacing → difficulty should be very close to refTarget
    arith_uint256 powLimit = GetMainnetPowLimit();
    arith_uint256 refTarget = powLimit >> 5;

    // For zero exponent: nTimeDiff = targetSpacing * (nHeightDiff + 1)
    arith_uint256 result = CalculateASERT(refTarget, 600, 6600, 10, powLimit, 172800);

    // Check within 0.01% due to polynomial rounding
    arith_uint256 diff;
    if (result > refTarget)
        diff = result - refTarget;
    else
        diff = refTarget - result;
    BOOST_CHECK(diff * 10000 < refTarget);
}

BOOST_AUTO_TEST_CASE(asert_extreme_slowdown_clamped)
{
    // Even with huge positive exponent, result shouldn't exceed powLimit
    arith_uint256 powLimit = GetMainnetPowLimit();
    arith_uint256 refTarget = powLimit >> 1;

    // 30 days late for 1 block
    arith_uint256 result = CalculateASERT(refTarget, 600, 86400 * 30, 1, powLimit, 172800);
    BOOST_CHECK(result <= powLimit);
}

// ============================================================================
// CheckProofOfWork: additional edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(checkpow_zero_hash_passes)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    uint256 hash;
    uint32_t nBits = UintToArith256(consensus.powLimit).GetCompact();
    BOOST_CHECK(CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(checkpow_max_hash_rejected)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    uint256 hash = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    uint32_t nBits = UintToArith256(consensus.powLimit).GetCompact();
    BOOST_CHECK(!CheckProofOfWork(hash, nBits, consensus));
}

BOOST_AUTO_TEST_CASE(checkpow_zero_nbits_rejected)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    uint256 hash;
    BOOST_CHECK(!CheckProofOfWork(hash, 0, consensus));
}

// ============================================================================
// PermittedDifficultyTransition: post-fork
// ============================================================================

BOOST_AUTO_TEST_CASE(permitted_difficulty_post_fork_wide_transition)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    // Post-fork: ASERT active, wide transitions permitted
    int64_t height = consensus.BCH2ForkHeight + 100;
    arith_uint256 powLimitArith = UintToArith256(consensus.powLimit);
    uint32_t bits1 = powLimitArith.GetCompact();
    arith_uint256 halfLimit = powLimitArith >> 2;
    uint32_t bits2 = halfLimit.GetCompact();

    BOOST_CHECK(PermittedDifficultyTransition(consensus, height, bits1, bits2));
}

BOOST_AUTO_TEST_SUITE_END()
