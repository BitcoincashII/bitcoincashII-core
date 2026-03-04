// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for the Adaptive Block Limit Algorithm (ABLA) - Upgrade 11.
// ABLA dynamically adjusts block size limits based on actual block usage.
// Initial limit = epsilon0 + beta0 = 32MB. Max = 2GB.

#include <consensus/abla.h>
#include <consensus/consensus.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bch2_abla_tests, BasicTestingSetup)

// ============================================================================
// Config tests
// ============================================================================

BOOST_AUTO_TEST_CASE(config_make_default)
{
    auto config = abla::Config::MakeDefault();

    // Initial control and elastic buffer should each be half the default block size
    BOOST_CHECK_EQUAL(config.epsilon0, DEFAULT_CONSENSUS_BLOCK_SIZE / 2); // 16,000,000
    BOOST_CHECK_EQUAL(config.beta0, DEFAULT_CONSENSUS_BLOCK_SIZE / 2);    // 16,000,000
    BOOST_CHECK_EQUAL(config.gammaReciprocal, 37938u);
    BOOST_CHECK_EQUAL(config.zeta_xB7, 192u); // zeta = 1.5
    BOOST_CHECK_EQUAL(config.thetaReciprocal, 37938u);
    BOOST_CHECK_EQUAL(config.delta, 10u);
    BOOST_CHECK(config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_fixed_size)
{
    auto config = abla::Config::MakeDefault(DEFAULT_CONSENSUS_BLOCK_SIZE, true);

    // Fixed size: max = initial (no growth)
    BOOST_CHECK_EQUAL(config.epsilonMax, config.epsilon0);
    BOOST_CHECK_EQUAL(config.betaMax, config.beta0);
    BOOST_CHECK(config.IsFixedSize());
    BOOST_CHECK(config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_not_fixed_size)
{
    auto config = abla::Config::MakeDefault();

    BOOST_CHECK(!config.IsFixedSize());
    // Max should be much larger than initial
    BOOST_CHECK(config.epsilonMax > config.epsilon0);
    BOOST_CHECK(config.betaMax > config.beta0);
}

// ============================================================================
// State: initial block size limit
// ============================================================================

BOOST_AUTO_TEST_CASE(state_initial_limit)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0); // Empty genesis block

    // Initial limit = epsilon0 + beta0 = 32MB
    uint64_t limit = state.GetBlockSizeLimit();
    BOOST_CHECK_EQUAL(limit, config.epsilon0 + config.beta0);
    BOOST_CHECK_EQUAL(limit, DEFAULT_CONSENSUS_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(limit, 32000000u);
}

// ============================================================================
// State: empty blocks don't change the limit
// ============================================================================

BOOST_AUTO_TEST_CASE(state_empty_blocks_maintain_floor)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    uint64_t initialLimit = state.GetBlockSizeLimit();

    // Mine 100 empty blocks
    for (int i = 0; i < 100; i++) {
        state = state.NextBlockState(config, 0);
    }

    // Limit should stay at the floor (epsilon0 + beta0)
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), initialLimit);
    BOOST_CHECK_EQUAL(state.GetControlBlockSize(), config.epsilon0);
    BOOST_CHECK_EQUAL(state.GetElasticBufferSize(), config.beta0);
}

// ============================================================================
// State: full blocks increase the limit
// ============================================================================

BOOST_AUTO_TEST_CASE(state_full_blocks_increase_limit)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    uint64_t initialLimit = state.GetBlockSizeLimit();

    // Mine blocks that are completely full (at the current limit)
    for (int i = 0; i < 100; i++) {
        uint64_t currentLimit = state.GetBlockSizeLimit();
        state = state.NextBlockState(config, currentLimit);
    }

    // After sustained full blocks, limit should have increased
    BOOST_CHECK_GT(state.GetBlockSizeLimit(), initialLimit);
    BOOST_CHECK_GT(state.GetControlBlockSize(), config.epsilon0);
}

// ============================================================================
// State: partial blocks
// ============================================================================

BOOST_AUTO_TEST_CASE(state_partial_blocks)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    // Mine blocks at 50% capacity
    for (int i = 0; i < 1000; i++) {
        uint64_t currentLimit = state.GetBlockSizeLimit();
        state = state.NextBlockState(config, currentLimit / 2);
    }

    // With 50% usage, the limit should stay near the initial value
    // (control block size should oscillate near epsilon0)
    uint64_t limit = state.GetBlockSizeLimit();
    // Allow some tolerance - should be within 2x of initial
    BOOST_CHECK_LE(limit, DEFAULT_CONSENSUS_BLOCK_SIZE * 2);
}

// ============================================================================
// State: 2GB hard cap
// ============================================================================

BOOST_AUTO_TEST_CASE(state_2gb_cap)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    // Even with unrealistically large blocks, limit is capped at 2GB
    uint64_t limit = state.GetBlockSizeLimit(false); // disable2GBCap=false
    BOOST_CHECK_LE(limit, MAX_CONSENSUS_BLOCK_SIZE);
    BOOST_CHECK_EQUAL(MAX_CONSENSUS_BLOCK_SIZE, 2'000'000'000u);
}

// ============================================================================
// State: GetNextBlockSizeLimit convenience method
// ============================================================================

BOOST_AUTO_TEST_CASE(state_next_block_limit)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 1000000); // 1MB block

    uint64_t nextLimit = state.GetNextBlockSizeLimit(config);
    abla::State nextState = state.NextBlockState(config, 1000000);
    uint64_t nextStateLimit = nextState.GetBlockSizeLimit();

    // GetNextBlockSizeLimit should predict the next block's limit
    BOOST_CHECK_EQUAL(nextLimit, nextStateLimit);
}

// ============================================================================
// State: serialization round-trip
// ============================================================================

BOOST_AUTO_TEST_CASE(state_serialization)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 5000000); // 5MB block

    // Advance a few blocks
    state = state.NextBlockState(config, 10000000);
    state = state.NextBlockState(config, 15000000);

    // Round-trip via tuple
    auto tup = state.ToTuple();
    abla::State restored = abla::State::FromTuple(tup);

    BOOST_CHECK(state == restored);
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), restored.GetBlockSizeLimit());
    BOOST_CHECK_EQUAL(state.GetControlBlockSize(), restored.GetControlBlockSize());
    BOOST_CHECK_EQUAL(state.GetElasticBufferSize(), restored.GetElasticBufferSize());
}

// ============================================================================
// State: validity checks
// ============================================================================

BOOST_AUTO_TEST_CASE(state_validity)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    BOOST_CHECK(state.IsValid(config));

    // State after normal usage should remain valid
    for (int i = 0; i < 10; i++) {
        state = state.NextBlockState(config, state.GetBlockSizeLimit());
    }
    BOOST_CHECK(state.IsValid(config));
}

// ============================================================================
// Config: validation rejects bad parameters
// ============================================================================

BOOST_AUTO_TEST_CASE(config_validation)
{
    // Valid config
    auto config = abla::Config::MakeDefault();
    BOOST_CHECK(config.IsValid());

    // Invalid: zeta_xB7 out of range
    auto badConfig = config;
    badConfig.zeta_xB7 = 0; // below MIN_ZETA_XB7 (129)
    BOOST_CHECK(!badConfig.IsValid());

    badConfig.zeta_xB7 = 1000; // above MAX_ZETA_XB7 (256)
    BOOST_CHECK(!badConfig.IsValid());

    // Invalid: gamma reciprocal out of range
    badConfig = config;
    badConfig.gammaReciprocal = 0; // below MIN_GAMMA_RECIPROCAL
    BOOST_CHECK(!badConfig.IsValid());
}

// ============================================================================
// Lookahead calculation
// ============================================================================

BOOST_AUTO_TEST_CASE(state_lookahead)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    // Lookahead of 0 blocks = current limit
    BOOST_CHECK_EQUAL(state.CalcLookaheadBlockSizeLimit(config, 0),
                      state.GetBlockSizeLimit());

    // Lookahead of 1 block (assuming empty blocks) = next limit
    uint64_t lookahead1 = state.CalcLookaheadBlockSizeLimit(config, 1);
    BOOST_CHECK_GE(lookahead1, state.GetBlockSizeLimit());
}

// ============================================================================
// ABLA cache: initial values at fork activation
// ============================================================================

BOOST_AUTO_TEST_CASE(initial_values_at_fork_activation)
{
    auto config = abla::Config::MakeDefault();

    // At fork activation, ABLA state should start with default config values
    abla::State state(config, 0);

    // Control block size = epsilon0 (half of 32MB = 16MB)
    BOOST_CHECK_EQUAL(state.GetControlBlockSize(), 16000000u);
    BOOST_CHECK_EQUAL(state.GetControlBlockSize(), config.epsilon0);

    // Elastic buffer size = beta0 (half of 32MB = 16MB)
    BOOST_CHECK_EQUAL(state.GetElasticBufferSize(), 16000000u);
    BOOST_CHECK_EQUAL(state.GetElasticBufferSize(), config.beta0);

    // Total limit = epsilon0 + beta0 = 32MB
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), 32000000u);
}

// ============================================================================
// ABLA cache: state updates correctly after block processing
// ============================================================================

BOOST_AUTO_TEST_CASE(state_updates_after_block)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    uint64_t initialControl = state.GetControlBlockSize();

    // ABLA uses the PREVIOUS block's size for the control function.
    // state(config, 0) has blockSize=0, so first NextBlockState won't grow.
    // Need two full-block iterations to observe growth.
    uint64_t fullSize = state.GetBlockSizeLimit();
    abla::State afterFirst = state.NextBlockState(config, fullSize);
    abla::State afterSecond = afterFirst.NextBlockState(config, fullSize);

    // After two full blocks, control block size should have increased
    BOOST_CHECK_GT(afterSecond.GetControlBlockSize(), initialControl);

    // Process several empty blocks to observe decay.
    // Due to 1-block lag, the first empty block still applies the previous full block's growth.
    // Need at least 3 empty blocks: first applies previous full, second applies empty, third continues decay.
    abla::State decayState = afterSecond;
    for (int i = 0; i < 3; i++) {
        decayState = decayState.NextBlockState(config, 0);
    }

    // After 3 empty blocks, control block size should be less than the peak after second full block
    // (The peak is the state after the 1st empty block, which still reflects the full block's lag growth)
    abla::State peakState = afterSecond.NextBlockState(config, 0);
    BOOST_CHECK_LT(decayState.GetControlBlockSize(), peakState.GetControlBlockSize());

    // But should not go below floor (epsilon0)
    BOOST_CHECK_GE(decayState.GetControlBlockSize(), config.epsilon0);
}

// ============================================================================
// ABLA cache: limit monotonically increases with consistently full blocks
// ============================================================================

BOOST_AUTO_TEST_CASE(limit_increases_with_full_blocks)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    uint64_t prevLimit = state.GetBlockSizeLimit();

    // Mine 50 full blocks and verify limit never decreases
    for (int i = 0; i < 50; i++) {
        uint64_t currentLimit = state.GetBlockSizeLimit();
        state = state.NextBlockState(config, currentLimit);
        uint64_t newLimit = state.GetBlockSizeLimit();

        // After a full block, the new limit should be >= previous
        BOOST_CHECK_GE(newLimit, prevLimit);
        prevLimit = newLimit;
    }

    // After 50 full blocks, limit should have grown meaningfully
    BOOST_CHECK_GT(state.GetBlockSizeLimit(), 32000000u);
}

// ============================================================================
// ABLA cache: limit stays at floor with consistently empty blocks
// ============================================================================

BOOST_AUTO_TEST_CASE(limit_stays_at_floor_with_empty_blocks)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    uint64_t initialLimit = state.GetBlockSizeLimit();

    // Mine 200 empty blocks
    for (int i = 0; i < 200; i++) {
        state = state.NextBlockState(config, 0);
    }

    // Limit should be exactly at the floor
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), initialLimit);
    BOOST_CHECK_EQUAL(state.GetControlBlockSize(), config.epsilon0);
    BOOST_CHECK_EQUAL(state.GetElasticBufferSize(), config.beta0);
}

// ============================================================================
// ABLA cache: growth then decay returns to floor
// ============================================================================

BOOST_AUTO_TEST_CASE(growth_then_decay)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    // Grow with 100 full blocks
    for (int i = 0; i < 100; i++) {
        state = state.NextBlockState(config, state.GetBlockSizeLimit());
    }

    uint64_t grownLimit = state.GetBlockSizeLimit();
    BOOST_CHECK_GT(grownLimit, 32000000u);

    // Decay with 10000 empty blocks (should return close to floor)
    for (int i = 0; i < 10000; i++) {
        state = state.NextBlockState(config, 0);
    }

    // Should be back at floor
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), 32000000u);
}

// ============================================================================
// ABLA cache: 2GB cap enforced during extreme growth
// ============================================================================

BOOST_AUTO_TEST_CASE(extreme_growth_respects_2gb_cap)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    // Simulate extreme growth - mine many full blocks
    for (int i = 0; i < 100000; i++) {
        uint64_t currentLimit = state.GetBlockSizeLimit();
        state = state.NextBlockState(config, currentLimit);

        // Limit should never exceed 2GB
        BOOST_CHECK_LE(state.GetBlockSizeLimit(), MAX_CONSENSUS_BLOCK_SIZE);
    }
}

// ============================================================================
// Config::IsValid() — edge cases for each error path
// ============================================================================

BOOST_AUTO_TEST_CASE(config_invalid_epsilon0_gt_epsilonMax)
{
    // epsilon0 > epsilonMax → "initial control block size limit sanity check failed"
    auto config = abla::Config::MakeDefault();
    config.epsilonMax = config.epsilon0 - 1;
    const char *err = nullptr;
    BOOST_CHECK(!config.IsValid(&err));
    BOOST_CHECK(err != nullptr);
}

BOOST_AUTO_TEST_CASE(config_invalid_beta0_gt_betaMax)
{
    // beta0 > betaMax → "initial elastic buffer size sanity check failed"
    auto config = abla::Config::MakeDefault();
    config.betaMax = config.beta0 - 1;
    const char *err = nullptr;
    BOOST_CHECK(!config.IsValid(&err));
    BOOST_CHECK(err != nullptr);
}

BOOST_AUTO_TEST_CASE(config_invalid_zeta_below_min)
{
    // zeta_xB7 < MIN_ZETA_XB7 (129) → "zeta sanity check failed"
    auto config = abla::Config::MakeDefault();
    config.zeta_xB7 = abla::MIN_ZETA_XB7 - 1; // 128
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_zeta_above_max)
{
    // zeta_xB7 > MAX_ZETA_XB7 (256) → "zeta sanity check failed"
    auto config = abla::Config::MakeDefault();
    config.zeta_xB7 = abla::MAX_ZETA_XB7 + 1; // 257
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_valid_zeta_at_boundaries)
{
    // zeta_xB7 == MIN_ZETA_XB7 should be valid
    auto config = abla::Config::MakeDefault();
    config.zeta_xB7 = abla::MIN_ZETA_XB7;
    // May need epsilon0 adjustment for the epsilon0 relative check
    // Re-set max to accommodate
    config.SetMax();
    // epsilon0 must be >= gammaReciprocal * B7 / (zeta_xB7 - B7)
    // With zeta_xB7 = 129, B7 = 128: zeta - B7 = 1
    // Need epsilon0 >= 37938 * 128 / 1 = 4,856,064
    // Default epsilon0 = 16,000,000, so this should be fine
    BOOST_CHECK(config.IsValid());

    // zeta_xB7 == MAX_ZETA_XB7 should be valid
    config = abla::Config::MakeDefault();
    config.zeta_xB7 = abla::MAX_ZETA_XB7;
    config.SetMax();
    BOOST_CHECK(config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_gamma_below_min)
{
    // gammaReciprocal < MIN_GAMMA_RECIPROCAL → "gammaReciprocal sanity check failed"
    auto config = abla::Config::MakeDefault();
    config.gammaReciprocal = abla::MIN_GAMMA_RECIPROCAL - 1;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_gamma_above_max)
{
    // gammaReciprocal > MAX_GAMMA_RECIPROCAL → "gammaReciprocal sanity check failed"
    auto config = abla::Config::MakeDefault();
    config.gammaReciprocal = abla::MAX_GAMMA_RECIPROCAL + 1;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_delta_above_max)
{
    // delta > MAX_DELTA (32) → "delta sanity check failed"
    auto config = abla::Config::MakeDefault();
    config.delta = abla::MAX_DELTA + 1; // 33
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_theta_below_min)
{
    // thetaReciprocal < MIN_THETA_RECIPROCAL → "thetaReciprocal sanity check failed"
    auto config = abla::Config::MakeDefault();
    config.thetaReciprocal = abla::MIN_THETA_RECIPROCAL - 1;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_theta_above_max)
{
    // thetaReciprocal > MAX_THETA_RECIPROCAL → "thetaReciprocal sanity check failed"
    auto config = abla::Config::MakeDefault();
    config.thetaReciprocal = abla::MAX_THETA_RECIPROCAL + 1;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_epsilon0_too_low)
{
    // epsilon0 < gammaReciprocal * B7 / (zeta_xB7 - B7)
    // With defaults: gammaReciprocal=37938, B7=128, zeta_xB7=192
    // Min epsilon0 = 37938 * 128 / (192 - 128) = 37938 * 128 / 64 = 75,876
    auto config = abla::Config::MakeDefault();
    config.epsilon0 = 1000; // way too low
    config.epsilonMax = config.epsilon0; // keep epsilon0 <= epsilonMax
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_error_string_populated)
{
    // Verify the error out-parameter is set on failure
    auto config = abla::Config::MakeDefault();
    config.zeta_xB7 = 0;
    const char *err = nullptr;
    BOOST_CHECK(!config.IsValid(&err));
    BOOST_CHECK(err != nullptr);
    BOOST_CHECK(std::string(err).find("zeta") != std::string::npos);
}

// ============================================================================
// State::IsValid() — edge cases for each error path
// ============================================================================

BOOST_AUTO_TEST_CASE(state_invalid_control_below_epsilon0)
{
    // controlBlockSize < epsilon0 → "invalid controlBlockSize state"
    auto config = abla::Config::MakeDefault();
    auto state = abla::State::FromTuple({0, config.epsilon0 - 1, config.beta0});
    BOOST_CHECK(!state.IsValid(config));
}

BOOST_AUTO_TEST_CASE(state_invalid_control_above_epsilonMax)
{
    // controlBlockSize > epsilonMax → "invalid controlBlockSize state"
    auto config = abla::Config::MakeDefault();
    auto state = abla::State::FromTuple({0, config.epsilonMax + 1, config.beta0});
    BOOST_CHECK(!state.IsValid(config));
}

BOOST_AUTO_TEST_CASE(state_invalid_elastic_below_beta0)
{
    // elasticBufferSize < beta0 → "invalid elasticBufferSize state"
    auto config = abla::Config::MakeDefault();
    auto state = abla::State::FromTuple({0, config.epsilon0, config.beta0 - 1});
    BOOST_CHECK(!state.IsValid(config));
}

BOOST_AUTO_TEST_CASE(state_invalid_elastic_above_betaMax)
{
    // elasticBufferSize > betaMax → "invalid elasticBufferSize state"
    auto config = abla::Config::MakeDefault();
    auto state = abla::State::FromTuple({0, config.epsilon0, config.betaMax + 1});
    BOOST_CHECK(!state.IsValid(config));
}

BOOST_AUTO_TEST_CASE(state_valid_at_boundaries)
{
    // State at exact boundary values should be valid
    auto config = abla::Config::MakeDefault();

    // At floor (epsilon0, beta0)
    auto stateFloor = abla::State::FromTuple({0, config.epsilon0, config.beta0});
    BOOST_CHECK(stateFloor.IsValid(config));

    // At ceiling (epsilonMax, betaMax)
    auto stateCeiling = abla::State::FromTuple({0, config.epsilonMax, config.betaMax});
    BOOST_CHECK(stateCeiling.IsValid(config));
}

BOOST_AUTO_TEST_CASE(state_error_string_populated)
{
    // Verify the error out-parameter is set on failure
    auto config = abla::Config::MakeDefault();
    auto state = abla::State::FromTuple({0, 0, config.beta0}); // controlBlockSize=0 < epsilon0
    const char *err = nullptr;
    BOOST_CHECK(!state.IsValid(config, &err));
    BOOST_CHECK(err != nullptr);
    BOOST_CHECK(std::string(err).find("controlBlockSize") != std::string::npos);
}

// ============================================================================
// Config + State: fixed-size config edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(config_fixed_size_boundary)
{
    // Fixed size: epsilon0 == epsilonMax, beta0 == betaMax
    auto config = abla::Config::MakeDefault(DEFAULT_CONSENSUS_BLOCK_SIZE, true);
    BOOST_CHECK(config.IsFixedSize());
    BOOST_CHECK_EQUAL(config.epsilon0, config.epsilonMax);
    BOOST_CHECK_EQUAL(config.beta0, config.betaMax);

    // State at these values should be valid
    abla::State state(config, 0);
    BOOST_CHECK(state.IsValid(config));

    // After many full blocks, state should still be valid and limit unchanged
    for (int i = 0; i < 100; i++) {
        state = state.NextBlockState(config, state.GetBlockSizeLimit());
    }
    BOOST_CHECK(state.IsValid(config));
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), DEFAULT_CONSENSUS_BLOCK_SIZE);
}

// ============================================================================
// MakeDefault — custom block sizes
// ============================================================================

BOOST_AUTO_TEST_CASE(makedefault_custom_blocksize)
{
    // Non-fixed, custom default block size
    auto config = abla::Config::MakeDefault(64000000u, false);
    BOOST_CHECK(config.IsValid());
    BOOST_CHECK_EQUAL(config.epsilon0, 32000000u); // half of 64MB
    BOOST_CHECK_EQUAL(config.beta0, 32000000u);
    BOOST_CHECK(!config.IsFixedSize()); // epsilonMax >> epsilon0

    abla::State state(config, 0);
    BOOST_CHECK(state.IsValid(config));
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), 64000000u);
}

BOOST_AUTO_TEST_CASE(makedefault_small_blocksize)
{
    // Very small default block size
    auto config = abla::Config::MakeDefault(200000u, false);
    BOOST_CHECK(config.IsValid());
    BOOST_CHECK_EQUAL(config.epsilon0, 100000u); // half of 200K
    BOOST_CHECK_EQUAL(config.beta0, 100000u);

    abla::State state(config, 0);
    BOOST_CHECK(state.IsValid(config));
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), 200000u);
}

BOOST_AUTO_TEST_CASE(makedefault_fixed_custom_size)
{
    // Fixed-size with a custom block size
    auto config = abla::Config::MakeDefault(8000000u, true);
    BOOST_CHECK(config.IsValid());
    BOOST_CHECK(config.IsFixedSize());
    BOOST_CHECK_EQUAL(config.epsilon0, 4000000u);
    BOOST_CHECK_EQUAL(config.epsilonMax, 4000000u);
    BOOST_CHECK_EQUAL(config.beta0, 4000000u);
    BOOST_CHECK_EQUAL(config.betaMax, 4000000u);

    // Block size limit should stay constant regardless of load
    abla::State state(config, 0);
    for (int i = 0; i < 100; i++) {
        state = state.NextBlockState(config, state.GetBlockSizeLimit());
    }
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), 8000000u);
}

// ============================================================================
// CalcLookaheadBlockSizeLimit — multi-step lookahead
// ============================================================================

BOOST_AUTO_TEST_CASE(calc_lookahead_count_zero)
{
    // count=0 should return current block size limit
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);
    BOOST_CHECK_EQUAL(state.CalcLookaheadBlockSizeLimit(config, 0), state.GetBlockSizeLimit());
}

BOOST_AUTO_TEST_CASE(calc_lookahead_count_one)
{
    // count=1 should simulate one block of max-size mining
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    uint64_t lookahead1 = state.CalcLookaheadBlockSizeLimit(config, 1);

    // Manually simulate: mine one block at max size, check limit
    uint64_t maxSize = state.GetNextBlockSizeLimit(config);
    abla::State nextState = state.NextBlockState(config, maxSize);
    BOOST_CHECK_EQUAL(lookahead1, nextState.GetBlockSizeLimit());
}

BOOST_AUTO_TEST_CASE(calc_lookahead_multi_step_growth)
{
    // Multi-step lookahead should grow monotonically (all full blocks)
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    uint64_t prev = state.GetBlockSizeLimit();
    for (size_t steps = 1; steps <= 10; steps++) {
        uint64_t lookahead = state.CalcLookaheadBlockSizeLimit(config, steps);
        BOOST_CHECK_GE(lookahead, prev);
        prev = lookahead;
    }
}

BOOST_AUTO_TEST_CASE(calc_lookahead_fixed_config_no_change)
{
    // With fixed-size config, lookahead should always return same limit
    auto config = abla::Config::MakeDefault(DEFAULT_CONSENSUS_BLOCK_SIZE, true);
    abla::State state(config, 0);

    uint64_t baseLimit = state.GetBlockSizeLimit();
    for (size_t steps = 1; steps <= 50; steps++) {
        BOOST_CHECK_EQUAL(state.CalcLookaheadBlockSizeLimit(config, steps), baseLimit);
    }
}

// ============================================================================
// Block size limit integration tests
// ============================================================================

BOOST_AUTO_TEST_CASE(state_get_block_size_limit_default)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    // Default limit = epsilon0 + beta0 = DEFAULT_CONSENSUS_BLOCK_SIZE
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), DEFAULT_CONSENSUS_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(state_get_block_size_limit_capped_at_2gb)
{
    // With disable2GBCap=false (default), limit should never exceed MAX_CONSENSUS_BLOCK_SIZE
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);
    BOOST_CHECK(state.GetBlockSizeLimit() <= MAX_CONSENSUS_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(state_get_block_size_limit_uncapped)
{
    // With disable2GBCap=true, limit can exceed MAX_CONSENSUS_BLOCK_SIZE theoretically
    // But with default config, it's only 32MB so still well within
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(true), state.GetBlockSizeLimit(false));
}

BOOST_AUTO_TEST_CASE(state_get_next_block_size_limit)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0); // Block with 0 size

    // Next block limit after empty block should be approximately the same
    uint64_t nextLimit = state.GetNextBlockSizeLimit(config);
    BOOST_CHECK(nextLimit > 0);
    // With no block usage, limit should stay around DEFAULT_CONSENSUS_BLOCK_SIZE or decrease
    BOOST_CHECK(nextLimit <= DEFAULT_CONSENSUS_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(state_next_block_after_full_grows)
{
    auto config = abla::Config::MakeDefault();
    uint64_t baseLimit = DEFAULT_CONSENSUS_BLOCK_SIZE;

    // Simulate a full block
    abla::State state(config, baseLimit);

    // After a full block, the next limit should be larger
    abla::State nextState = state.NextBlockState(config, 0);
    uint64_t nextLimit = nextState.GetBlockSizeLimit();
    BOOST_CHECK(nextLimit > baseLimit);
}

BOOST_AUTO_TEST_CASE(state_next_block_after_empty_shrinks)
{
    auto config = abla::Config::MakeDefault();
    uint64_t baseLimit = DEFAULT_CONSENSUS_BLOCK_SIZE;

    // Start after a full block to get a larger limit
    abla::State fullState(config, baseLimit);
    abla::State grownState = fullState.NextBlockState(config, 0);

    uint64_t grownLimit = grownState.GetBlockSizeLimit();

    // Now simulate an empty block
    abla::State afterEmpty = grownState.NextBlockState(config, 0);
    uint64_t shrunkLimit = afterEmpty.GetBlockSizeLimit();

    // After empty block, limit should have decreased
    BOOST_CHECK(shrunkLimit < grownLimit);
}

BOOST_AUTO_TEST_CASE(state_control_and_elastic_accessors)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 1000);

    BOOST_CHECK_EQUAL(state.GetBlockSize(), 1000U);
    BOOST_CHECK_EQUAL(state.GetControlBlockSize(), config.epsilon0);
    BOOST_CHECK_EQUAL(state.GetElasticBufferSize(), config.beta0);
}

BOOST_AUTO_TEST_CASE(state_serialization_roundtrip)
{
    auto config = abla::Config::MakeDefault();
    abla::State original(config, 5000);

    // Serialize
    DataStream ss{};
    ss << original;

    // Deserialize
    abla::State deserialized;
    ss >> deserialized;

    BOOST_CHECK(original == deserialized);
    BOOST_CHECK_EQUAL(deserialized.GetBlockSize(), 5000U);
    BOOST_CHECK_EQUAL(deserialized.GetControlBlockSize(), config.epsilon0);
}

BOOST_AUTO_TEST_CASE(state_from_tuple)
{
    auto tup = std::make_tuple(uint64_t(100), uint64_t(200), uint64_t(300));
    abla::State state = abla::State::FromTuple(tup);

    BOOST_CHECK_EQUAL(state.GetBlockSize(), 100U);
    BOOST_CHECK_EQUAL(state.GetControlBlockSize(), 200U);
    BOOST_CHECK_EQUAL(state.GetElasticBufferSize(), 300U);
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(), 500U); // 200 + 300
}

BOOST_AUTO_TEST_CASE(config_is_valid)
{
    auto config = abla::Config::MakeDefault();
    BOOST_CHECK(config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_is_not_fixed_for_mainnet)
{
    auto config = abla::Config::MakeDefault();
    BOOST_CHECK(!config.IsFixedSize());
}

BOOST_AUTO_TEST_CASE(config_is_fixed_when_requested)
{
    auto config = abla::Config::MakeDefault(DEFAULT_CONSENSUS_BLOCK_SIZE, true);
    BOOST_CHECK(config.IsFixedSize());
    BOOST_CHECK_EQUAL(config.epsilon0, config.epsilonMax);
}

BOOST_AUTO_TEST_CASE(state_is_valid_with_default_config)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);
    BOOST_CHECK(state.IsValid(config));
}

// ============================================================================
// Additional ABLA edge cases (non-duplicate tests)
// ============================================================================

BOOST_AUTO_TEST_CASE(state_serialization_multi_step_roundtrip)
{
    // Serialize state after multiple NextBlockState calls
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 1000000);
    auto state2 = state.NextBlockState(config, 500000);
    auto state3 = state2.NextBlockState(config, 2000000);

    DataStream ss{};
    ss << state3;

    auto deserialized = abla::State::FromTuple({0, 0, 0});
    ss >> deserialized;

    BOOST_CHECK(deserialized == state3);
    BOOST_CHECK_EQUAL(deserialized.GetBlockSize(), state3.GetBlockSize());
    BOOST_CHECK_EQUAL(deserialized.GetControlBlockSize(), state3.GetControlBlockSize());
    BOOST_CHECK_EQUAL(deserialized.GetElasticBufferSize(), state3.GetElasticBufferSize());
}

BOOST_AUTO_TEST_CASE(next_state_decay_with_elevated_state)
{
    auto config = abla::Config::MakeDefault();
    // Block size = 0 (empty), but control and elastic are elevated
    // With blockSize=0, amplifiedCurrentBlockSize = zeta * 0 = 0 < controlBlockSize → decay path
    auto state = abla::State::FromTuple({0, 20000000, 20000000});

    auto next = state.NextBlockState(config, 0);
    BOOST_CHECK(next.GetControlBlockSize() <= state.GetControlBlockSize());
    BOOST_CHECK(next.GetElasticBufferSize() <= state.GetElasticBufferSize());
}

BOOST_AUTO_TEST_CASE(next_state_full_block_growth)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    // Full block at limit causes control increase
    uint64_t limit = state.GetBlockSizeLimit();
    auto fullState = abla::State::FromTuple({limit, state.GetControlBlockSize(), state.GetElasticBufferSize()});
    auto next = fullState.NextBlockState(config, 0);
    BOOST_CHECK(next.GetControlBlockSize() >= state.GetControlBlockSize());
}

BOOST_AUTO_TEST_CASE(next_state_100_empty_blocks_stays_at_floor)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    auto current = state;
    for (int i = 0; i < 100; i++) {
        current = current.NextBlockState(config, 0);
    }
    BOOST_CHECK(current.GetControlBlockSize() >= config.epsilon0);
    BOOST_CHECK(current.GetElasticBufferSize() >= config.beta0);
}

BOOST_AUTO_TEST_CASE(next_state_at_max_stays_capped)
{
    auto config = abla::Config::MakeDefault();
    auto state = abla::State::FromTuple({config.epsilonMax + config.betaMax, config.epsilonMax, config.betaMax});

    auto next = state.NextBlockState(config, 0);
    BOOST_CHECK(next.GetControlBlockSize() <= config.epsilonMax);
    BOOST_CHECK(next.GetElasticBufferSize() <= config.betaMax);
}

BOOST_AUTO_TEST_CASE(block_size_limit_2gb_cap_applied)
{
    auto state = abla::State::FromTuple({0, 2000000000, 2000000000});
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(false), MAX_CONSENSUS_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(block_size_limit_2gb_cap_disabled)
{
    auto state = abla::State::FromTuple({0, 2000000000, 2000000000});
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(true), 4000000000ULL);
}

BOOST_AUTO_TEST_CASE(fixed_config_nextstate_stable)
{
    auto config = abla::Config::MakeDefault(DEFAULT_CONSENSUS_BLOCK_SIZE, true);
    BOOST_CHECK(config.IsFixedSize());

    abla::State state(config, 0);
    auto fullState = abla::State::FromTuple({state.GetBlockSizeLimit(), config.epsilon0, config.beta0});
    auto next = fullState.NextBlockState(config, 0);

    BOOST_CHECK_EQUAL(next.GetControlBlockSize(), config.epsilon0);
    BOOST_CHECK_EQUAL(next.GetElasticBufferSize(), config.beta0);
}

BOOST_AUTO_TEST_CASE(state_tostring_output)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 500);
    std::string s = state.ToString();
    BOOST_CHECK(s.find("blockSize=500") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(config_tostring_output)
{
    auto config = abla::Config::MakeDefault();
    std::string s = config.ToString();
    BOOST_CHECK(s.find("epsilon0=") != std::string::npos);
    BOOST_CHECK(s.find("gammaReciprocal=37938") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(config_epsilon0_minimum_boundary)
{
    // epsilon0 must be >= gammaReciprocal * B7 / (zeta_xB7 - B7) = 37938 * 128 / 64 = 75876
    auto config = abla::Config::MakeDefault();
    config.epsilon0 = 75875;
    config.epsilonMax = config.epsilon0;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_error_string_content)
{
    auto config = abla::Config::MakeDefault();
    config.zeta_xB7 = 0;
    const char* err = nullptr;
    BOOST_CHECK(!config.IsValid(&err));
    BOOST_CHECK(err != nullptr);
    BOOST_CHECK(std::string(err).find("zeta") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(state_isvalid_error_string_content)
{
    auto config = abla::Config::MakeDefault();
    auto state = abla::State::FromTuple({0, config.epsilon0 - 1, config.beta0});
    const char* err = nullptr;
    BOOST_CHECK(!state.IsValid(config, &err));
    BOOST_CHECK(err != nullptr);
    BOOST_CHECK(std::string(err).find("controlBlockSize") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(lookahead_grows_monotonically)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 0);

    uint64_t limit0 = state.CalcLookaheadBlockSizeLimit(config, 0);
    uint64_t limit10 = state.CalcLookaheadBlockSizeLimit(config, 10);
    uint64_t limit100 = state.CalcLookaheadBlockSizeLimit(config, 100);

    BOOST_CHECK(limit10 >= limit0);
    BOOST_CHECK(limit100 >= limit10);
}

// ============================================================================
// NextBlockState: oversized block clamping
// ============================================================================

BOOST_AUTO_TEST_CASE(next_state_oversized_block_clamped)
{
    // When blockSize > controlBlockSize + elasticBufferSize, the algorithm
    // clamps blockSize to the limit before computing the next state.
    // This can happen if -excessiveblocksize allows larger blocks.
    auto config = abla::Config::MakeDefault();
    uint64_t epsilon0 = config.epsilon0; // 16,000,000
    uint64_t beta0 = config.beta0;       // 16,000,000
    uint64_t limit = epsilon0 + beta0;   // 32,000,000

    // Create state where blockSize > limit (oversized block)
    auto oversized = abla::State::FromTuple({limit + 1000000, epsilon0, beta0});
    // Create state where blockSize == limit (exactly at limit)
    auto atLimit = abla::State::FromTuple({limit, epsilon0, beta0});

    auto nextOversized = oversized.NextBlockState(config, 0);
    auto nextAtLimit = atLimit.NextBlockState(config, 0);

    // The clamping means the oversized block should produce the same control
    // block size increase as a block exactly at the limit
    auto [bs1, cbs1, ebs1] = nextOversized.ToTuple();
    auto [bs2, cbs2, ebs2] = nextAtLimit.ToTuple();
    BOOST_CHECK_EQUAL(cbs1, cbs2);
    BOOST_CHECK_EQUAL(ebs1, ebs2);
}

BOOST_AUTO_TEST_CASE(next_state_oversized_vs_normal)
{
    // An oversized block (blockSize > limit) should produce the same result
    // as a block at the limit, but a half-full block should produce different
    // (lower) growth.
    auto config = abla::Config::MakeDefault();
    uint64_t epsilon0 = config.epsilon0;
    uint64_t beta0 = config.beta0;
    uint64_t limit = epsilon0 + beta0;

    auto atLimit = abla::State::FromTuple({limit, epsilon0, beta0});
    auto halfFull = abla::State::FromTuple({limit / 2, epsilon0, beta0});

    auto nextFull = atLimit.NextBlockState(config, 0);
    auto nextHalf = halfFull.NextBlockState(config, 0);

    // Full block should cause more growth than half-full
    auto [bs1, cbs1, ebs1] = nextFull.ToTuple();
    auto [bs2, cbs2, ebs2] = nextHalf.ToTuple();
    BOOST_CHECK(cbs1 >= cbs2);
}

// ============================================================================
// Config::ToString() and State::ToString()
// ============================================================================

BOOST_AUTO_TEST_CASE(config_to_string_not_empty)
{
    auto config = abla::Config::MakeDefault();
    std::string s = config.ToString();
    BOOST_CHECK(!s.empty());
    // Should contain some expected parameter names/values
    BOOST_CHECK(s.find("epsilon0") != std::string::npos || s.find("16000000") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(state_to_string_not_empty)
{
    auto config = abla::Config::MakeDefault();
    abla::State state(config, 1000);
    std::string s = state.ToString();
    BOOST_CHECK(!s.empty());
    // Should contain "abla::State"
    BOOST_CHECK(s.find("abla::State") != std::string::npos);
    // Should show blockSize=1000
    BOOST_CHECK(s.find("1000") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(state_to_string_default)
{
    abla::State state;
    std::string s = state.ToString();
    BOOST_CHECK(!s.empty());
    // Default state has all zeros
    BOOST_CHECK(s.find("blockSize=0") != std::string::npos);
}

// ============================================================================
// Config::IsValid() edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(config_invalid_zeta_too_low)
{
    auto config = abla::Config::MakeDefault();
    config.zeta_xB7 = abla::MIN_ZETA_XB7 - 1; // Below minimum
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_zeta_too_high)
{
    auto config = abla::Config::MakeDefault();
    config.zeta_xB7 = abla::MAX_ZETA_XB7 + 1; // Above maximum
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_valid_at_zeta_boundaries)
{
    auto config = abla::Config::MakeDefault();
    config.zeta_xB7 = abla::MIN_ZETA_XB7;
    BOOST_CHECK(config.IsValid());
    config.zeta_xB7 = abla::MAX_ZETA_XB7;
    BOOST_CHECK(config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_gamma_too_low)
{
    auto config = abla::Config::MakeDefault();
    config.gammaReciprocal = abla::MIN_GAMMA_RECIPROCAL - 1;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_gamma_too_high)
{
    auto config = abla::Config::MakeDefault();
    config.gammaReciprocal = abla::MAX_GAMMA_RECIPROCAL + 1;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_theta_too_low)
{
    auto config = abla::Config::MakeDefault();
    config.thetaReciprocal = abla::MIN_THETA_RECIPROCAL - 1;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_delta_too_high)
{
    auto config = abla::Config::MakeDefault();
    config.delta = abla::MAX_DELTA + 1;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_epsilon0_zero)
{
    auto config = abla::Config::MakeDefault();
    config.epsilon0 = 0;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_beta0_zero_valid)
{
    // Config allows beta0=0 if betaMax is also 0 (beta0 > betaMax check only)
    auto config = abla::Config::MakeDefault();
    config.beta0 = 0;
    config.betaMax = 0;
    BOOST_CHECK(config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_epsilon_max_below_epsilon0)
{
    auto config = abla::Config::MakeDefault();
    config.epsilonMax = config.epsilon0 - 1;
    BOOST_CHECK(!config.IsValid());
}

BOOST_AUTO_TEST_CASE(config_invalid_beta_max_below_beta0)
{
    auto config = abla::Config::MakeDefault();
    config.betaMax = config.beta0 - 1;
    BOOST_CHECK(!config.IsValid());
}

// ============================================================================
// Config::MakeDefault with custom block size
// ============================================================================

BOOST_AUTO_TEST_CASE(config_make_default_custom_size)
{
    auto config = abla::Config::MakeDefault(64000000); // 64 MB
    BOOST_CHECK_EQUAL(config.epsilon0, 32000000u);
    BOOST_CHECK_EQUAL(config.beta0, 32000000u);
    BOOST_CHECK(config.IsValid());
}

// ============================================================================
// State equality and comparison operators
// ============================================================================

BOOST_AUTO_TEST_CASE(state_equality)
{
    auto s1 = abla::State::FromTuple({100, 200, 300});
    auto s2 = abla::State::FromTuple({100, 200, 300});
    auto s3 = abla::State::FromTuple({100, 200, 301});
    BOOST_CHECK(s1 == s2);
    BOOST_CHECK(s1 != s3);
}

BOOST_AUTO_TEST_CASE(state_less_than)
{
    auto s1 = abla::State::FromTuple({100, 200, 300});
    auto s2 = abla::State::FromTuple({100, 200, 301});
    BOOST_CHECK(s1 < s2);
    BOOST_CHECK(!(s2 < s1));
}

// ============================================================================
// GetBlockSizeLimit with 2GB cap
// ============================================================================

BOOST_AUTO_TEST_CASE(block_size_limit_2gb_cap)
{
    // Create state where control + elastic > 2GB
    auto state = abla::State::FromTuple({0, 1500000000u, 1500000000u});
    // With cap (default): should be capped at MAX_CONSENSUS_BLOCK_SIZE
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(false), MAX_CONSENSUS_BLOCK_SIZE);
    // Without cap: returns actual sum
    BOOST_CHECK_EQUAL(state.GetBlockSizeLimit(true), 3000000000u);
}

BOOST_AUTO_TEST_SUITE_END()
