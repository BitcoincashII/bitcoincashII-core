// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for BCH2 chain parameter correctness.
// Verifies genesis hashes, fork heights, ASERT anchors, ports, dust relay fee,
// and other consensus parameters match their expected values.

#include <addresstype.h>
#include <bch2_fork.h>
#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <key.h>
#include <key_io.h>
#include <script/script.h>
#include <policy/policy.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <limits>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bch2_chain_params_tests, BasicTestingSetup)

// ============================================================================
// Mainnet genesis block
// ============================================================================

BOOST_AUTO_TEST_CASE(mainnet_genesis_hash)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    BOOST_CHECK_EQUAL(params->GenesisBlock().GetHash().ToString(),
                      "0000000028f062b221c1a8a5cf0244b1627315f7aa5b775b931cfec46dc17ceb");
}

BOOST_AUTO_TEST_CASE(mainnet_genesis_merkle_root)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    BOOST_CHECK_EQUAL(params->GenesisBlock().hashMerkleRoot.ToString(),
                      "80d1b4e9ca868f83b88b9301036205876072bdd3ded0ad4dc022e1f9266ddc49");
}

// ============================================================================
// Mainnet fork parameters
// ============================================================================

BOOST_AUTO_TEST_CASE(mainnet_fork_height)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.BCH2ForkHeight, 53200);
}

BOOST_AUTO_TEST_CASE(mainnet_all_upgrades_at_fork_height)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.uahfHeight, 53200);
    BOOST_CHECK_EQUAL(consensus.daaHeight, 53200);
    BOOST_CHECK_EQUAL(consensus.magneticAnomalyHeight, 53200);
    BOOST_CHECK_EQUAL(consensus.gravitonHeight, 53200);
    BOOST_CHECK_EQUAL(consensus.phononHeight, 53200);
    BOOST_CHECK_EQUAL(consensus.axionHeight, 53200);
    BOOST_CHECK_EQUAL(consensus.upgrade8Height, 53200);
    BOOST_CHECK_EQUAL(consensus.upgrade9Height, 53200);
    BOOST_CHECK_EQUAL(consensus.upgrade10Height, 53200);
    BOOST_CHECK_EQUAL(consensus.upgrade11Height, 53200);
}

BOOST_AUTO_TEST_CASE(mainnet_asert_anchor)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK(consensus.asertAnchorParams.has_value());
    const auto& anchor = *consensus.asertAnchorParams;
    BOOST_CHECK_EQUAL(anchor.nHeight, 53201);
    BOOST_CHECK_EQUAL(anchor.nBits, 0x1903a30cu);
}

BOOST_AUTO_TEST_CASE(mainnet_default_port)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 8339);
}

BOOST_AUTO_TEST_CASE(mainnet_message_start)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& ms = params->MessageStart();
    BOOST_CHECK_EQUAL(ms[0], 0xb2);
    BOOST_CHECK_EQUAL(ms[1], 0xc2);
    BOOST_CHECK_EQUAL(ms[2], 0xb2);
    BOOST_CHECK_EQUAL(ms[3], 0xc2);
}

BOOST_AUTO_TEST_CASE(mainnet_block_size)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    BOOST_CHECK_EQUAL(params->GetConsensus().nDefaultConsensusBlockSize, 32000000u);
}

BOOST_AUTO_TEST_CASE(mainnet_max_reorg_depth)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    BOOST_CHECK_EQUAL(params->GetConsensus().maxReorgDepth, 10);
}

BOOST_AUTO_TEST_CASE(mainnet_asert_halflife)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.nASERTHalfLife, Consensus::Params::ASERT_HALFLIFE_1_HOUR);
    BOOST_CHECK_EQUAL(consensus.nASERTHalfLifeTransitionHeight, 92736);
}

// ============================================================================
// Regtest parameters
// ============================================================================

BOOST_AUTO_TEST_CASE(regtest_genesis_hash)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    BOOST_CHECK_EQUAL(params->GenesisBlock().GetHash().ToString(),
                      "5ac3b379cfa0600d059b007cb2b6b1b293832f6e398af62ec4e009b369e532b6");
}

BOOST_AUTO_TEST_CASE(regtest_fork_height)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    BOOST_CHECK_EQUAL(params->GetConsensus().BCH2ForkHeight, 200);
}

BOOST_AUTO_TEST_CASE(regtest_all_upgrades_at_200)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.uahfHeight, 200);
    BOOST_CHECK_EQUAL(consensus.daaHeight, 200);
    BOOST_CHECK_EQUAL(consensus.magneticAnomalyHeight, 200);
    BOOST_CHECK_EQUAL(consensus.gravitonHeight, 200);
    BOOST_CHECK_EQUAL(consensus.phononHeight, 200);
    BOOST_CHECK_EQUAL(consensus.axionHeight, 200);
    BOOST_CHECK_EQUAL(consensus.upgrade8Height, 200);
    BOOST_CHECK_EQUAL(consensus.upgrade9Height, 200);
    BOOST_CHECK_EQUAL(consensus.upgrade10Height, 200);
    BOOST_CHECK_EQUAL(consensus.upgrade11Height, 200);
}

BOOST_AUTO_TEST_CASE(regtest_asert_anchor)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK(consensus.asertAnchorParams.has_value());
    const auto& anchor = *consensus.asertAnchorParams;
    BOOST_CHECK_EQUAL(anchor.nHeight, 201);
    BOOST_CHECK_EQUAL(anchor.nBits, 0x207fffffu);
    BOOST_CHECK_EQUAL(anchor.nPrevBlockTime, 0); // dynamic
}

BOOST_AUTO_TEST_CASE(regtest_default_port)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 18448);
}

BOOST_AUTO_TEST_CASE(regtest_message_start)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& ms = params->MessageStart();
    BOOST_CHECK_EQUAL(ms[0], 0xb2);
    BOOST_CHECK_EQUAL(ms[1], 0xc2);
    BOOST_CHECK_EQUAL(ms[2], 0xfa);
    BOOST_CHECK_EQUAL(ms[3], 0xbf);
}

BOOST_AUTO_TEST_CASE(regtest_max_reorg_depth)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    BOOST_CHECK_EQUAL(params->GetConsensus().maxReorgDepth, 10000);
}

BOOST_AUTO_TEST_CASE(regtest_asert_halflife_transition)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();

    BOOST_CHECK_EQUAL(consensus.nASERTHalfLife, Consensus::Params::ASERT_HALFLIFE_1_HOUR);
    BOOST_CHECK_EQUAL(consensus.nASERTHalfLifeTransitionHeight, 432);

    // Before transition: 1 hour
    BOOST_CHECK_EQUAL(consensus.GetASERTHalfLife(431), Consensus::Params::ASERT_HALFLIFE_1_HOUR);
    // At transition: 2 days
    BOOST_CHECK_EQUAL(consensus.GetASERTHalfLife(432), Consensus::Params::ASERT_HALFLIFE_2_DAYS);
}

// ============================================================================
// Consensus constants
// ============================================================================

BOOST_AUTO_TEST_CASE(block_size_constants)
{
    BOOST_CHECK_EQUAL(BCH2_MAX_BLOCK_SIZE, 32000000u);
    BOOST_CHECK_EQUAL(DEFAULT_CONSENSUS_BLOCK_SIZE, 32000000u);
    BOOST_CHECK_EQUAL(MAX_CONSENSUS_BLOCK_SIZE, 2'000'000'000u);
}

BOOST_AUTO_TEST_CASE(dust_relay_fee)
{
    BOOST_CHECK_EQUAL(DUST_RELAY_TX_FEE, 1000);
}

BOOST_AUTO_TEST_CASE(witness_scale_factor)
{
    BOOST_CHECK_EQUAL(WITNESS_SCALE_FACTOR, 1);
}

BOOST_AUTO_TEST_CASE(coinbase_maturity)
{
    BOOST_CHECK_EQUAL(COINBASE_MATURITY, 100);
}

BOOST_AUTO_TEST_CASE(asert_halflife_constants)
{
    BOOST_CHECK_EQUAL(Consensus::Params::ASERT_HALFLIFE_1_HOUR, 3600);
    BOOST_CHECK_EQUAL(Consensus::Params::ASERT_HALFLIFE_2_DAYS, 172800);
}

// ============================================================================
// CashAddr prefix: verify encoding uses "bitcoincashii:" prefix
// ============================================================================

BOOST_AUTO_TEST_CASE(cashaddr_prefix)
{
    // Generate a key and encode as P2PKH CashAddr
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // P2PKH address
    std::string p2pkh_addr = EncodeDestination(PKHash(pubkey));
    BOOST_CHECK_MESSAGE(p2pkh_addr.substr(0, 14) == "bitcoincashii:",
        "P2PKH CashAddr should start with 'bitcoincashii:' but got: " + p2pkh_addr);

    // P2PKH addresses have type byte 0 which encodes to 'q' after the prefix
    // The character after "bitcoincashii:" should be 'q'
    BOOST_CHECK_EQUAL(p2pkh_addr[14], 'q');

    // P2SH address (use a dummy script hash)
    CScript redeemScript;
    redeemScript << OP_TRUE;
    std::string p2sh_addr = EncodeDestination(ScriptHash(redeemScript));
    BOOST_CHECK_MESSAGE(p2sh_addr.substr(0, 14) == "bitcoincashii:",
        "P2SH CashAddr should start with 'bitcoincashii:' but got: " + p2sh_addr);

    // P2SH addresses have type byte 8 which encodes to 'p' after the prefix
    BOOST_CHECK_EQUAL(p2sh_addr[14], 'p');
}

// ============================================================================
// Testnet parameters
// ============================================================================

BOOST_AUTO_TEST_CASE(testnet_genesis_hash)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    BOOST_CHECK_EQUAL(params->GenesisBlock().GetHash().ToString(),
                      "000000004d52d701341aa65ad81dfd0b9c29132d261fc8b8a7f4ebcd75633c37");
}

BOOST_AUTO_TEST_CASE(testnet_fork_height)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    BOOST_CHECK_EQUAL(params->GetConsensus().BCH2ForkHeight, 0);
}

BOOST_AUTO_TEST_CASE(testnet_default_port)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    BOOST_CHECK_EQUAL(params->GetDefaultPort(), 18338);
}

BOOST_AUTO_TEST_CASE(testnet_message_start)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    const auto& ms = params->MessageStart();
    BOOST_CHECK_EQUAL(ms[0], 0xb2);
    BOOST_CHECK_EQUAL(ms[1], 0xc2);
    BOOST_CHECK_EQUAL(ms[2], 0x0b);
    BOOST_CHECK_EQUAL(ms[3], 0x11);
}

BOOST_AUTO_TEST_CASE(testnet_asert_halflife_transition)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    const auto& consensus = params->GetConsensus();

    // Testnet starts with 1-hour halflife, transitions to 2-day
    BOOST_CHECK_EQUAL(consensus.nASERTHalfLife, Consensus::Params::ASERT_HALFLIFE_1_HOUR);
    BOOST_CHECK_GT(consensus.nASERTHalfLifeTransitionHeight, 0);

    // Before transition: 1 hour
    int transHeight = consensus.nASERTHalfLifeTransitionHeight;
    BOOST_CHECK_EQUAL(consensus.GetASERTHalfLife(transHeight - 1), Consensus::Params::ASERT_HALFLIFE_1_HOUR);
    // At transition: 2 days
    BOOST_CHECK_EQUAL(consensus.GetASERTHalfLife(transHeight), Consensus::Params::ASERT_HALFLIFE_2_DAYS);
}

BOOST_AUTO_TEST_CASE(testnet_block_size)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    BOOST_CHECK_EQUAL(params->GetConsensus().nDefaultConsensusBlockSize, 32000000u);
}

// ============================================================================
// Min tx size constants
// ============================================================================

BOOST_AUTO_TEST_CASE(min_tx_size_constants)
{
    // Pre-fork min tx size (Bitcoin Core default)
    BOOST_CHECK_EQUAL(MIN_STANDARD_TX_NONWITNESS_SIZE, 100u);
    // Post-fork min tx size (Magnetic Anomaly)
    BOOST_CHECK_EQUAL(BCH2_MIN_STANDARD_TX_SIZE, 65u);
}

// ============================================================================
// Signet not available (BCH2 has no signet)
// ============================================================================

BOOST_AUTO_TEST_CASE(signet_params_available)
{
    // Signet type exists in enum but may just be regtest-like
    const auto params = CreateChainParams(ArgsManager{}, ChainType::SIGNET);
    // Just verify it doesn't crash - signet is defined but not used for BCH2
    BOOST_CHECK(!params->GenesisBlock().GetHash().IsNull());
}

BOOST_AUTO_TEST_CASE(signet_bch2_fork_never_active)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::SIGNET);
    const auto& c = params->GetConsensus();
    BOOST_CHECK_EQUAL(c.BCH2ForkHeight, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK(!c.IsBCH2ForkActive(0));
    BOOST_CHECK(!c.IsBCH2ForkActive(1000000));
    BOOST_CHECK(!c.IsBCH2ForkActive(std::numeric_limits<int>::max()));
}

BOOST_AUTO_TEST_CASE(signet_all_upgrades_never_active)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::SIGNET);
    const auto& c = params->GetConsensus();
    BOOST_CHECK_EQUAL(c.uahfHeight, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(c.daaHeight, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(c.magneticAnomalyHeight, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(c.gravitonHeight, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(c.phononHeight, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(c.axionHeight, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(c.upgrade8Height, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(c.upgrade9Height, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(c.upgrade10Height, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK_EQUAL(c.upgrade11Height, Consensus::NEVER_ACTIVE_HEIGHT);
}

BOOST_AUTO_TEST_CASE(signet_is_signet_chain)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::SIGNET);
    BOOST_CHECK(params->GetConsensus().signet_blocks);
}

BOOST_AUTO_TEST_CASE(signet_segwit_active_post_activation)
{
    // On signet, BCH2 fork never activates, so SegWit remains active after SegwitHeight
    const auto params = CreateChainParams(ArgsManager{}, ChainType::SIGNET);
    const auto& c = params->GetConsensus();
    // SegwitHeight = 1 on signet
    BOOST_CHECK(!c.IsSegwitActive(0));     // Before SegWit activation
    BOOST_CHECK(c.IsSegwitActive(1));      // At SegWit activation
    BOOST_CHECK(c.IsSegwitActive(1000000)); // Stays active (no BCH2 fork to disable it)
}

// ============================================================================
// Subsidy halving interval
// ============================================================================

BOOST_AUTO_TEST_CASE(mainnet_subsidy_halving)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    // BCH2 mainnet should have a halving interval
    BOOST_CHECK_GT(params->GetConsensus().nSubsidyHalvingInterval, 0);
}

BOOST_AUTO_TEST_CASE(regtest_subsidy_halving)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    // Regtest halving every 150 blocks
    BOOST_CHECK_EQUAL(params->GetConsensus().nSubsidyHalvingInterval, 150);
}

// ============================================================================
// Activation functions coverage
// ============================================================================

BOOST_AUTO_TEST_CASE(upgrade_activation_at_exact_fork_height)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();
    int forkHeight = consensus.BCH2ForkHeight; // 200 for regtest

    // At fork height, upgrades should NOT be active (they activate at height+1)
    BOOST_CHECK(!consensus.IsGravitonActive(forkHeight));
    BOOST_CHECK(!consensus.IsPhononActive(forkHeight));
    BOOST_CHECK(!consensus.IsUpgrade8Active(forkHeight));
    BOOST_CHECK(!consensus.IsUpgrade9Active(forkHeight));
    BOOST_CHECK(!consensus.IsUpgrade10Active(forkHeight));

    // At fork height + 1, all should be active
    BOOST_CHECK(consensus.IsGravitonActive(forkHeight + 1));
    BOOST_CHECK(consensus.IsPhononActive(forkHeight + 1));
    BOOST_CHECK(consensus.IsUpgrade8Active(forkHeight + 1));
    BOOST_CHECK(consensus.IsUpgrade9Active(forkHeight + 1));
    BOOST_CHECK(consensus.IsUpgrade10Active(forkHeight + 1));
}

BOOST_AUTO_TEST_CASE(pow_limit_sanity)
{
    const auto mainParams = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto regParams = CreateChainParams(ArgsManager{}, ChainType::REGTEST);

    // Pow limits should be non-zero
    BOOST_CHECK(!mainParams->GetConsensus().powLimit.IsNull());
    BOOST_CHECK(!regParams->GetConsensus().powLimit.IsNull());

    // Regtest pow limit should be maximum (easy mining)
    // Regtest: fPowAllowMinDifficultyBlocks = true
    BOOST_CHECK(regParams->GetConsensus().fPowAllowMinDifficultyBlocks);
    // Mainnet: no min difficulty blocks
    BOOST_CHECK(!mainParams->GetConsensus().fPowAllowMinDifficultyBlocks);
}

BOOST_AUTO_TEST_CASE(pow_target_spacing)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    // BCH2 target spacing = 600 seconds (10 minutes)
    BOOST_CHECK_EQUAL(params->GetConsensus().nPowTargetSpacing, 600);
}

// ============================================================================
// Upgrade 12 activation parameters
// ============================================================================

BOOST_AUTO_TEST_CASE(upgrade12_activation_time_mainnet_default)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();
    // Upgrade 12 defaults to max (never active) until set
    BOOST_CHECK_EQUAL(consensus.upgrade12ActivationTime, std::numeric_limits<int64_t>::max());
}

BOOST_AUTO_TEST_CASE(upgrade12_activation_time_regtest_default)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& consensus = params->GetConsensus();
    BOOST_CHECK_EQUAL(consensus.upgrade12ActivationTime, std::numeric_limits<int64_t>::max());
}

BOOST_AUTO_TEST_CASE(upgrade12_activation_time_testnet_default)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    const auto& consensus = params->GetConsensus();
    BOOST_CHECK_EQUAL(consensus.upgrade12ActivationTime, std::numeric_limits<int64_t>::max());
}

BOOST_AUTO_TEST_CASE(upgrade11_height_per_network)
{
    const auto mainParams = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto regParams = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto testParams = CreateChainParams(ArgsManager{}, ChainType::TESTNET);

    BOOST_CHECK_EQUAL(mainParams->GetConsensus().upgrade11Height, 53200);
    BOOST_CHECK_EQUAL(regParams->GetConsensus().upgrade11Height, 200);
    BOOST_CHECK_EQUAL(testParams->GetConsensus().upgrade11Height, 0);
}

BOOST_AUTO_TEST_CASE(upgrade9_height_per_network)
{
    const auto mainParams = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto regParams = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto testParams = CreateChainParams(ArgsManager{}, ChainType::TESTNET);

    BOOST_CHECK_EQUAL(mainParams->GetConsensus().upgrade9Height, 53200);
    BOOST_CHECK_EQUAL(regParams->GetConsensus().upgrade9Height, 200);
    BOOST_CHECK_EQUAL(testParams->GetConsensus().upgrade9Height, 0);
}

BOOST_AUTO_TEST_CASE(upgrade10_height_per_network)
{
    const auto mainParams = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto regParams = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto testParams = CreateChainParams(ArgsManager{}, ChainType::TESTNET);

    BOOST_CHECK_EQUAL(mainParams->GetConsensus().upgrade10Height, 53200);
    BOOST_CHECK_EQUAL(regParams->GetConsensus().upgrade10Height, 200);
    BOOST_CHECK_EQUAL(testParams->GetConsensus().upgrade10Height, 0);
}

// ============================================================================
// BCH2 consensus constants (block size, sigops, weights)
// ============================================================================

BOOST_AUTO_TEST_CASE(legacy_block_size)
{
    BOOST_CHECK_EQUAL(BCH2_LEGACY_MAX_BLOCK_SIZE, 4000000u);
}

BOOST_AUTO_TEST_CASE(max_block_sigops_cost)
{
    BOOST_CHECK_EQUAL(BCH2_MAX_BLOCK_SIGOPS_COST, 640000);
}

BOOST_AUTO_TEST_CASE(legacy_max_block_sigops_cost)
{
    BOOST_CHECK_EQUAL(BCH2_LEGACY_MAX_BLOCK_SIGOPS_COST, 80000);
}

BOOST_AUTO_TEST_CASE(max_block_serialized_size_equals_block_size)
{
    // BCH2: MAX_BLOCK_SERIALIZED_SIZE == BCH2_MAX_BLOCK_SIZE (no witness discount)
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE, BCH2_MAX_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(max_block_weight_equals_block_size)
{
    // BCH2: MAX_BLOCK_WEIGHT == BCH2_MAX_BLOCK_SIZE (WITNESS_SCALE_FACTOR=1)
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, BCH2_MAX_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(min_transaction_weight)
{
    // BCH2: MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60 = 60
    BOOST_CHECK_EQUAL(MIN_TRANSACTION_WEIGHT, 60u);
}

BOOST_AUTO_TEST_CASE(min_serializable_transaction_weight)
{
    BOOST_CHECK_EQUAL(MIN_SERIALIZABLE_TRANSACTION_WEIGHT, 10u);
}

BOOST_AUTO_TEST_CASE(max_consensus_block_size_2gb)
{
    // ABLA hard cap is 2 GB
    BOOST_CHECK_EQUAL(MAX_CONSENSUS_BLOCK_SIZE, 2'000'000'000u);
}

// ============================================================================
// BCH2 introspection opcode enum values
// ============================================================================

BOOST_AUTO_TEST_CASE(introspection_opcode_values)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_INPUTINDEX), 0xc0);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_ACTIVEBYTECODE), 0xc1);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_TXVERSION), 0xc2);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_TXINPUTCOUNT), 0xc3);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_TXOUTPUTCOUNT), 0xc4);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_TXLOCKTIME), 0xc5);
}

BOOST_AUTO_TEST_CASE(utxo_introspection_opcode_values)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_UTXOVALUE), 0xc6);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_UTXOBYTECODE), 0xc7);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_OUTPOINTTXHASH), 0xc8);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_OUTPOINTINDEX), 0xc9);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_INPUTBYTECODE), 0xca);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_INPUTSEQUENCENUMBER), 0xcb);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_OUTPUTVALUE), 0xcc);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_OUTPUTBYTECODE), 0xcd);
}

BOOST_AUTO_TEST_CASE(token_introspection_opcode_values)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_UTXOTOKENCATEGORY), 0xce);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_UTXOTOKENCOMMITMENT), 0xcf);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_UTXOTOKENAMOUNT), 0xd0);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_OUTPUTTOKENCATEGORY), 0xd1);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_OUTPUTTOKENCOMMITMENT), 0xd2);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_OUTPUTTOKENAMOUNT), 0xd3);
}

BOOST_AUTO_TEST_CASE(bch2_specific_opcode_values)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_CHECKDATASIG), 0xba);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_CHECKDATASIGVERIFY), 0xbb);
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(OP_REVERSEBYTES), 0xbc);
}

BOOST_AUTO_TEST_CASE(max_opcode_is_output_token_amount)
{
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(MAX_OPCODE), static_cast<uint8_t>(OP_OUTPUTTOKENAMOUNT));
}

// ============================================================================
// Script size and stack constants
// ============================================================================

BOOST_AUTO_TEST_CASE(script_constants)
{
    BOOST_CHECK_EQUAL(MAX_SCRIPT_ELEMENT_SIZE, 520u);
    BOOST_CHECK_EQUAL(MAX_OPS_PER_SCRIPT, 201);
    BOOST_CHECK_EQUAL(MAX_PUBKEYS_PER_MULTISIG, 20);
    BOOST_CHECK_EQUAL(MAX_SCRIPT_SIZE, 10000u);
    BOOST_CHECK_EQUAL(MAX_STACK_SIZE, 1000u);
}

// ============================================================================
// BCH2 namespace constants (bch2_fork.h)
// ============================================================================

BOOST_AUTO_TEST_CASE(bch2_fork_height_constant)
{
    BOOST_CHECK_EQUAL(BCH2::FORK_HEIGHT, 53200);
}

BOOST_AUTO_TEST_CASE(bch2_network_magic)
{
    BOOST_CHECK_EQUAL(BCH2::MAGIC[0], 0xb2);
    BOOST_CHECK_EQUAL(BCH2::MAGIC[1], 0xc2);
    BOOST_CHECK_EQUAL(BCH2::MAGIC[2], 0xb2);
    BOOST_CHECK_EQUAL(BCH2::MAGIC[3], 0xc2);
}

BOOST_AUTO_TEST_CASE(bch2_ports)
{
    BOOST_CHECK_EQUAL(BCH2::P2P_PORT, 8339);
    BOOST_CHECK_EQUAL(BCH2::RPC_PORT, 8342);
}

BOOST_AUTO_TEST_CASE(bch2_max_block_size_constant)
{
    BOOST_CHECK_EQUAL(BCH2::MAX_BLOCK_SIZE, 32000000u);
    // Should match consensus BCH2_MAX_BLOCK_SIZE
    BOOST_CHECK_EQUAL(BCH2::MAX_BLOCK_SIZE, BCH2_MAX_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(bch2_sighash_constants)
{
    BOOST_CHECK_EQUAL(BCH2::SIGHASH_FORKID, 0x40u);
    BOOST_CHECK_EQUAL(BCH2::FORKID, 0u);
}

// ============================================================================
// BCH2 namespace helper functions (bch2_fork.h)
// ============================================================================

BOOST_AUTO_TEST_CASE(bch2_is_fork_active)
{
    // Fork activates at FORK_HEIGHT + 1 (height > FORK_HEIGHT)
    BOOST_CHECK(!BCH2::IsForkActive(0));
    BOOST_CHECK(!BCH2::IsForkActive(53199));
    BOOST_CHECK(!BCH2::IsForkActive(53200)); // Not active AT fork height
    BOOST_CHECK(BCH2::IsForkActive(53201));  // Active AFTER fork height
    BOOST_CHECK(BCH2::IsForkActive(100000));
}

BOOST_AUTO_TEST_CASE(bch2_is_segwit_allowed)
{
    // SegWit allowed for historical BC2 blocks (height <= FORK_HEIGHT)
    BOOST_CHECK(BCH2::IsSegWitAllowed(0));
    BOOST_CHECK(BCH2::IsSegWitAllowed(53200)); // Allowed AT fork height
    BOOST_CHECK(!BCH2::IsSegWitAllowed(53201)); // NOT allowed after fork
    BOOST_CHECK(!BCH2::IsSegWitAllowed(100000));
}

BOOST_AUTO_TEST_CASE(bch2_is_fork_active_and_segwit_mutually_exclusive)
{
    // At any height > 0, IsForkActive and IsSegWitAllowed should be mutually exclusive
    // (except at exactly FORK_HEIGHT where neither is fork-active but segwit is still allowed)
    for (int h = 1; h <= 53200; h++) {
        BOOST_CHECK(!BCH2::IsForkActive(h));
        BOOST_CHECK(BCH2::IsSegWitAllowed(h));
    }
    for (int h = 53201; h <= 53210; h++) {
        BOOST_CHECK(BCH2::IsForkActive(h));
        BOOST_CHECK(!BCH2::IsSegWitAllowed(h));
    }
}

BOOST_AUTO_TEST_CASE(bch2_get_max_block_size)
{
    // Pre-fork: 4MB
    BOOST_CHECK_EQUAL(BCH2::GetMaxBlockSize(0), 4u * 1024u * 1024u);
    BOOST_CHECK_EQUAL(BCH2::GetMaxBlockSize(53200), 4u * 1024u * 1024u);

    // Post-fork: 32MB
    BOOST_CHECK_EQUAL(BCH2::GetMaxBlockSize(53201), 32000000u);
    BOOST_CHECK_EQUAL(BCH2::GetMaxBlockSize(100000), 32000000u);
}

// ============================================================================
// Consensus::Params upgrade activation via inline methods
// ============================================================================

BOOST_AUTO_TEST_CASE(upgrade12_default_not_active)
{
    // Default upgrade12ActivationTime = int64_t::max, so never active
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();

    // Even at very high heights, upgrade12 uses MTP, not height
    // The height-based IsUpgrade12Active should be false with max activation time
    // unless the height somehow translates to a valid MTP check
    BOOST_CHECK_EQUAL(consensus.upgrade12ActivationTime, std::numeric_limits<int64_t>::max());
}

BOOST_AUTO_TEST_CASE(upgrade2027_default_not_active)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& consensus = params->GetConsensus();
    BOOST_CHECK_EQUAL(consensus.upgrade2027ActivationTime, std::numeric_limits<int64_t>::max());
}

BOOST_AUTO_TEST_CASE(upgrade_activation_times_are_mtp_based)
{
    // Verify that upgrade12 and 2027 use MTP-based activation (not height-based)
    // Their activation times default to max int64 → never active without override
    Consensus::Params consensus;
    BOOST_CHECK_EQUAL(consensus.upgrade12ActivationTime, std::numeric_limits<int64_t>::max());
    BOOST_CHECK_EQUAL(consensus.upgrade2027ActivationTime, std::numeric_limits<int64_t>::max());
}

BOOST_AUTO_TEST_CASE(all_upgrade_heights_at_fork_mainnet)
{
    // For mainnet, all BCH upgrade heights should equal BCH2ForkHeight
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto& c = params->GetConsensus();
    int fh = c.BCH2ForkHeight;

    BOOST_CHECK_EQUAL(c.uahfHeight, fh);
    BOOST_CHECK_EQUAL(c.daaHeight, fh);
    BOOST_CHECK_EQUAL(c.magneticAnomalyHeight, fh);
    BOOST_CHECK_EQUAL(c.gravitonHeight, fh);
    BOOST_CHECK_EQUAL(c.phononHeight, fh);
    BOOST_CHECK_EQUAL(c.upgrade8Height, fh);
    BOOST_CHECK_EQUAL(c.upgrade9Height, fh);
    BOOST_CHECK_EQUAL(c.upgrade10Height, fh);
    BOOST_CHECK_EQUAL(c.upgrade11Height, fh);
}

BOOST_AUTO_TEST_CASE(all_upgrade_heights_at_fork_regtest)
{
    // Same check for regtest
    const auto& c = Params().GetConsensus();
    int fh = c.BCH2ForkHeight;

    BOOST_CHECK_EQUAL(c.uahfHeight, fh);
    BOOST_CHECK_EQUAL(c.daaHeight, fh);
    BOOST_CHECK_EQUAL(c.magneticAnomalyHeight, fh);
    BOOST_CHECK_EQUAL(c.gravitonHeight, fh);
    BOOST_CHECK_EQUAL(c.phononHeight, fh);
    BOOST_CHECK_EQUAL(c.upgrade8Height, fh);
    BOOST_CHECK_EQUAL(c.upgrade9Height, fh);
    BOOST_CHECK_EQUAL(c.upgrade10Height, fh);
    BOOST_CHECK_EQUAL(c.upgrade11Height, fh);
}

BOOST_AUTO_TEST_CASE(upgrade_active_boundary_consistency)
{
    // All IsUpgrade*Active(height) should return same result at boundaries
    const auto& c = Params().GetConsensus();
    int fh = c.BCH2ForkHeight;

    // All OFF at fork height (last pre-fork block)
    BOOST_CHECK(!c.IsUAHFActive(fh));
    BOOST_CHECK(!c.IsDAAActive(fh));
    BOOST_CHECK(!c.IsGravitonActive(fh));
    BOOST_CHECK(!c.IsUpgrade8Active(fh));
    BOOST_CHECK(!c.IsUpgrade9Active(fh));
    BOOST_CHECK(!c.IsUpgrade10Active(fh));
    BOOST_CHECK(!c.IsUpgrade11Active(fh));

    // All ON at fh + 1 (first post-fork block)
    BOOST_CHECK(c.IsUAHFActive(fh + 1));
    BOOST_CHECK(c.IsDAAActive(fh + 1));
    BOOST_CHECK(c.IsGravitonActive(fh + 1));
    BOOST_CHECK(c.IsUpgrade8Active(fh + 1));
    BOOST_CHECK(c.IsUpgrade9Active(fh + 1));
    BOOST_CHECK(c.IsUpgrade10Active(fh + 1));
    BOOST_CHECK(c.IsUpgrade11Active(fh + 1));
}

BOOST_AUTO_TEST_CASE(segwit_active_inversely_correlated)
{
    // SegWit active pre-fork, inactive post-fork
    const auto& c = Params().GetConsensus();
    int fh = c.BCH2ForkHeight;

    BOOST_CHECK(c.IsSegwitActive(fh));     // Last pre-fork: SegWit ON
    BOOST_CHECK(!c.IsSegwitActive(fh + 1)); // First post-fork: SegWit OFF

    // Verify no overlap: when fork active, segwit is off
    BOOST_CHECK(!c.IsBCH2ForkActive(fh));
    BOOST_CHECK(c.IsBCH2ForkActive(fh + 1));
}

BOOST_AUTO_TEST_CASE(testnet_upgrade_heights_at_fork)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    const auto& c = params->GetConsensus();
    int fh = c.BCH2ForkHeight;

    // All upgrade heights should also equal fork height for testnet
    BOOST_CHECK_EQUAL(c.uahfHeight, fh);
    BOOST_CHECK_EQUAL(c.upgrade9Height, fh);
    BOOST_CHECK_EQUAL(c.upgrade10Height, fh);
    BOOST_CHECK_EQUAL(c.upgrade11Height, fh);
}

// ============================================================================
// Consensus constant relationships (BCH2-specific)
// ============================================================================

BOOST_AUTO_TEST_CASE(consensus_max_block_weight_equals_block_size)
{
    // BCH2: no segwit discount, weight == serialized size
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, BCH2_MAX_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(consensus_max_block_serialized_size_equals_block_size)
{
    BOOST_CHECK_EQUAL(MAX_BLOCK_SERIALIZED_SIZE, BCH2_MAX_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(consensus_sigops_proportional_to_block_size)
{
    // BCH2 sigops limit = block size / 50
    BOOST_CHECK_EQUAL(BCH2_MAX_BLOCK_SIGOPS_COST, static_cast<int64_t>(BCH2_MAX_BLOCK_SIZE) / 50);
}

BOOST_AUTO_TEST_CASE(consensus_legacy_sigops_proportional)
{
    // Legacy sigops = legacy block size / 50
    BOOST_CHECK_EQUAL(BCH2_LEGACY_MAX_BLOCK_SIGOPS_COST, static_cast<int64_t>(BCH2_LEGACY_MAX_BLOCK_SIZE) / 50);
}

BOOST_AUTO_TEST_CASE(consensus_max_block_sigops_cost_alias)
{
    BOOST_CHECK_EQUAL(MAX_BLOCK_SIGOPS_COST, BCH2_MAX_BLOCK_SIGOPS_COST);
}

BOOST_AUTO_TEST_CASE(consensus_witness_scale_factor_one)
{
    // BCH2: no segwit discount
    BOOST_CHECK_EQUAL(WITNESS_SCALE_FACTOR, 1);
}

BOOST_AUTO_TEST_CASE(consensus_abla_default_equals_block_size)
{
    BOOST_CHECK_EQUAL(DEFAULT_CONSENSUS_BLOCK_SIZE, BCH2_MAX_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(consensus_abla_hard_cap)
{
    BOOST_CHECK_EQUAL(MAX_CONSENSUS_BLOCK_SIZE, 2'000'000'000ULL);
}

BOOST_AUTO_TEST_CASE(consensus_abla_hard_cap_exceeds_default)
{
    BOOST_CHECK(MAX_CONSENSUS_BLOCK_SIZE > DEFAULT_CONSENSUS_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(consensus_min_transaction_weight_no_discount)
{
    // With WITNESS_SCALE_FACTOR=1, MIN_TRANSACTION_WEIGHT = 60
    BOOST_CHECK_EQUAL(MIN_TRANSACTION_WEIGHT, 60u);
}

BOOST_AUTO_TEST_CASE(consensus_coinbase_maturity)
{
    BOOST_CHECK_EQUAL(COINBASE_MATURITY, 100);
}

BOOST_AUTO_TEST_CASE(consensus_block_size_values)
{
    BOOST_CHECK_EQUAL(BCH2_MAX_BLOCK_SIZE, 32000000u);
    BOOST_CHECK_EQUAL(BCH2_LEGACY_MAX_BLOCK_SIZE, 4000000u);
}

// ============================================================================
// Activation function aliases and coverage
// ============================================================================

BOOST_AUTO_TEST_CASE(is_cash_tokens_active_alias)
{
    // IsCashTokensActive should be an alias for IsUpgrade9Active
    const auto& c = Params().GetConsensus();
    int fh = c.BCH2ForkHeight;
    BOOST_CHECK(!c.IsCashTokensActive(fh));
    BOOST_CHECK(c.IsCashTokensActive(fh + 1));
    BOOST_CHECK_EQUAL(c.IsCashTokensActive(fh), c.IsUpgrade9Active(fh));
    BOOST_CHECK_EQUAL(c.IsCashTokensActive(fh + 1), c.IsUpgrade9Active(fh + 1));
}

BOOST_AUTO_TEST_CASE(is_axion_active_at_boundary)
{
    const auto& c = Params().GetConsensus();
    int fh = c.BCH2ForkHeight;
    BOOST_CHECK(!c.IsAxionActive(fh));
    BOOST_CHECK(c.IsAxionActive(fh + 1));
}

BOOST_AUTO_TEST_CASE(is_asert_active_equals_axion)
{
    // IsASERTActive is an alias for IsAxionActive
    const auto& c = Params().GetConsensus();
    int fh = c.BCH2ForkHeight;
    BOOST_CHECK_EQUAL(c.IsASERTActive(fh), c.IsAxionActive(fh));
    BOOST_CHECK_EQUAL(c.IsASERTActive(fh + 1), c.IsAxionActive(fh + 1));
}

BOOST_AUTO_TEST_CASE(is_magnetic_anomaly_active_at_boundary)
{
    const auto& c = Params().GetConsensus();
    int fh = c.BCH2ForkHeight;
    BOOST_CHECK(!c.IsMagneticAnomalyActive(fh));
    BOOST_CHECK(c.IsMagneticAnomalyActive(fh + 1));
}

BOOST_AUTO_TEST_CASE(mainnet_halving_interval_is_210000)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    BOOST_CHECK_EQUAL(params->GetConsensus().nSubsidyHalvingInterval, 210000);
}

BOOST_AUTO_TEST_CASE(testnet_asert_anchor_timestamp)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    const auto& c = params->GetConsensus();
    // Testnet anchor has a real timestamp
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nPrevBlockTime, 1750495449);
}

BOOST_AUTO_TEST_CASE(never_active_height_is_max_int)
{
    BOOST_CHECK_EQUAL(Consensus::NEVER_ACTIVE_HEIGHT, std::numeric_limits<int>::max());
}

// ============================================================================
// ASERTAnchor::IsValid() boundary conditions
// ============================================================================

BOOST_AUTO_TEST_CASE(asert_anchor_is_valid_all_set)
{
    Consensus::ASERTAnchor anchor;
    anchor.nHeight = 0;
    anchor.nBits = 0x1d00ffff;
    anchor.nPrevBlockTime = 1700000000;
    BOOST_CHECK(anchor.IsValid());
}

BOOST_AUTO_TEST_CASE(asert_anchor_invalid_default)
{
    // Default-constructed anchor: nHeight=-1, nBits=0, nPrevBlockTime=0
    Consensus::ASERTAnchor anchor;
    BOOST_CHECK(!anchor.IsValid());
}

BOOST_AUTO_TEST_CASE(asert_anchor_invalid_negative_height)
{
    Consensus::ASERTAnchor anchor;
    anchor.nHeight = -1;
    anchor.nBits = 0x1d00ffff;
    anchor.nPrevBlockTime = 1700000000;
    BOOST_CHECK(!anchor.IsValid());
}

BOOST_AUTO_TEST_CASE(asert_anchor_invalid_zero_bits)
{
    Consensus::ASERTAnchor anchor;
    anchor.nHeight = 100;
    anchor.nBits = 0;
    anchor.nPrevBlockTime = 1700000000;
    BOOST_CHECK(!anchor.IsValid());
}

BOOST_AUTO_TEST_CASE(asert_anchor_invalid_zero_time)
{
    Consensus::ASERTAnchor anchor;
    anchor.nHeight = 100;
    anchor.nBits = 0x1d00ffff;
    anchor.nPrevBlockTime = 0;
    BOOST_CHECK(!anchor.IsValid());
}

BOOST_AUTO_TEST_CASE(asert_anchor_valid_height_zero)
{
    // Height 0 is valid (genesis block)
    Consensus::ASERTAnchor anchor;
    anchor.nHeight = 0;
    anchor.nBits = 1;
    anchor.nPrevBlockTime = 1;
    BOOST_CHECK(anchor.IsValid());
}

BOOST_AUTO_TEST_CASE(asert_anchor_invalid_negative_time)
{
    Consensus::ASERTAnchor anchor;
    anchor.nHeight = 100;
    anchor.nBits = 0x1d00ffff;
    anchor.nPrevBlockTime = -1;
    BOOST_CHECK(!anchor.IsValid());
}

// ============================================================================
// ASERTAnchor from actual chain params
// ============================================================================

BOOST_AUTO_TEST_CASE(mainnet_asert_anchor_has_value)
{
    const auto& c = Params().GetConsensus();
    // Mainnet ASERT anchor: block 53201 (first BCH2 block), parent time from block 53200
    BOOST_CHECK(c.asertAnchorParams.has_value());
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nHeight, 53201);
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nBits, 0x1903a30c);
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nPrevBlockTime, 1772649180);
    BOOST_CHECK(c.asertAnchorParams->IsValid());
}

BOOST_AUTO_TEST_CASE(regtest_asert_anchor_has_value)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& c = params->GetConsensus();
    // Regtest anchor is set but nPrevBlockTime=0 (dynamic at runtime)
    BOOST_CHECK(c.asertAnchorParams.has_value());
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nHeight, 201);
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nBits, 0x207fffff);
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nPrevBlockTime, 0);
    BOOST_CHECK(!c.asertAnchorParams->IsValid());
}

BOOST_AUTO_TEST_CASE(testnet_asert_anchor_is_valid)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    const auto& c = params->GetConsensus();
    // Testnet (signet) has a valid anchor with timestamp set
    BOOST_CHECK(c.asertAnchorParams.has_value());
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nHeight, 0);
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nBits, 0x1d00ffff);
    BOOST_CHECK_EQUAL(c.asertAnchorParams->nPrevBlockTime, 1750495449);
    BOOST_CHECK(c.asertAnchorParams->IsValid());
}

// ============================================================================
// ASERT half-life constants
// ============================================================================

BOOST_AUTO_TEST_CASE(asert_halflife_1_hour_is_3600)
{
    BOOST_CHECK_EQUAL(Consensus::Params::ASERT_HALFLIFE_1_HOUR, 3600);
}

BOOST_AUTO_TEST_CASE(asert_halflife_2_days_is_172800)
{
    BOOST_CHECK_EQUAL(Consensus::Params::ASERT_HALFLIFE_2_DAYS, 172800);
}

BOOST_AUTO_TEST_CASE(mainnet_initial_halflife_is_1_hour)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.nASERTHalfLife, Consensus::Params::ASERT_HALFLIFE_1_HOUR);
}

BOOST_AUTO_TEST_CASE(mainnet_halflife_transition_at_92736)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.nASERTHalfLifeTransitionHeight, 92736);

    // Before transition: 1-hour half-life
    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(92735), Consensus::Params::ASERT_HALFLIFE_1_HOUR);
    // At transition: 2-day half-life
    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(92736), Consensus::Params::ASERT_HALFLIFE_2_DAYS);
    // After transition: 2-day half-life
    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(100000), Consensus::Params::ASERT_HALFLIFE_2_DAYS);
}

BOOST_AUTO_TEST_CASE(testnet_halflife_transition_at_40320)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    const auto& c = params->GetConsensus();
    BOOST_CHECK_EQUAL(c.nASERTHalfLifeTransitionHeight, 40320);

    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(40319), Consensus::Params::ASERT_HALFLIFE_1_HOUR);
    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(40320), Consensus::Params::ASERT_HALFLIFE_2_DAYS);
}

// ============================================================================
// Individual activation function boundary tests at specific upgrade heights
// ============================================================================

BOOST_AUTO_TEST_CASE(is_graviton_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int gh = c.gravitonHeight;
    // Graviton uses strict greater-than: height > gravitonHeight
    BOOST_CHECK(!c.IsGravitonActive(gh));
    BOOST_CHECK(c.IsGravitonActive(gh + 1));
}

BOOST_AUTO_TEST_CASE(is_phonon_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int ph = c.phononHeight;
    BOOST_CHECK(!c.IsPhononActive(ph));
    BOOST_CHECK(c.IsPhononActive(ph + 1));
}

BOOST_AUTO_TEST_CASE(is_uahf_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int uh = c.uahfHeight;
    BOOST_CHECK(!c.IsUAHFActive(uh));
    BOOST_CHECK(c.IsUAHFActive(uh + 1));
}

BOOST_AUTO_TEST_CASE(is_daa_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int dh = c.daaHeight;
    BOOST_CHECK(!c.IsDAAActive(dh));
    BOOST_CHECK(c.IsDAAActive(dh + 1));
}

BOOST_AUTO_TEST_CASE(is_upgrade8_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int u8h = c.upgrade8Height;
    BOOST_CHECK(!c.IsUpgrade8Active(u8h));
    BOOST_CHECK(c.IsUpgrade8Active(u8h + 1));
}

BOOST_AUTO_TEST_CASE(is_upgrade10_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int u10h = c.upgrade10Height;
    BOOST_CHECK(!c.IsUpgrade10Active(u10h));
    BOOST_CHECK(c.IsUpgrade10Active(u10h + 1));
}

BOOST_AUTO_TEST_CASE(is_upgrade11_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int u11h = c.upgrade11Height;
    BOOST_CHECK(!c.IsUpgrade11Active(u11h));
    BOOST_CHECK(c.IsUpgrade11Active(u11h + 1));
}

// ============================================================================
// All upgrades at BCH2 fork height are simultaneously active
// ============================================================================

BOOST_AUTO_TEST_CASE(all_upgrades_active_post_fork)
{
    const auto& c = Params().GetConsensus();
    int postFork = c.BCH2ForkHeight + 1;

    BOOST_CHECK(c.IsBCH2ForkActive(postFork));
    BOOST_CHECK(c.IsUAHFActive(postFork));
    BOOST_CHECK(c.IsDAAActive(postFork));
    BOOST_CHECK(c.IsMagneticAnomalyActive(postFork));
    BOOST_CHECK(c.IsGravitonActive(postFork));
    BOOST_CHECK(c.IsPhononActive(postFork));
    BOOST_CHECK(c.IsAxionActive(postFork));
    BOOST_CHECK(c.IsASERTActive(postFork));
    BOOST_CHECK(c.IsUpgrade8Active(postFork));
    BOOST_CHECK(c.IsUpgrade9Active(postFork));
    BOOST_CHECK(c.IsCashTokensActive(postFork));
    BOOST_CHECK(c.IsUpgrade10Active(postFork));
    BOOST_CHECK(c.IsUpgrade11Active(postFork));
    // SegWit should be OFF post-fork
    BOOST_CHECK(!c.IsSegwitActive(postFork));
}

BOOST_AUTO_TEST_CASE(no_upgrades_at_height_zero)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK(!c.IsBCH2ForkActive(0));
    BOOST_CHECK(!c.IsUAHFActive(0));
    BOOST_CHECK(!c.IsDAAActive(0));
    BOOST_CHECK(!c.IsMagneticAnomalyActive(0));
    BOOST_CHECK(!c.IsGravitonActive(0));
    BOOST_CHECK(!c.IsPhononActive(0));
    BOOST_CHECK(!c.IsAxionActive(0));
    BOOST_CHECK(!c.IsUpgrade8Active(0));
    BOOST_CHECK(!c.IsUpgrade9Active(0));
    BOOST_CHECK(!c.IsUpgrade10Active(0));
    BOOST_CHECK(!c.IsUpgrade11Active(0));
}

// ============================================================================
// Inline activation function completeness
// ============================================================================

BOOST_AUTO_TEST_CASE(is_asert_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int ah = c.axionHeight;
    BOOST_CHECK(!c.IsASERTActive(ah));
    BOOST_CHECK(c.IsASERTActive(ah + 1));
    // IsASERTActive is an alias for IsAxionActive
    BOOST_CHECK_EQUAL(c.IsASERTActive(ah), c.IsAxionActive(ah));
    BOOST_CHECK_EQUAL(c.IsASERTActive(ah + 1), c.IsAxionActive(ah + 1));
}

BOOST_AUTO_TEST_CASE(is_cashtokens_active_boundary)
{
    const auto& c = Params().GetConsensus();
    // CashTokens = Upgrade 9
    int u9h = c.upgrade9Height;
    BOOST_CHECK(!c.IsCashTokensActive(u9h));
    BOOST_CHECK(c.IsCashTokensActive(u9h + 1));
}

BOOST_AUTO_TEST_CASE(segwit_disabled_after_fork)
{
    const auto& c = Params().GetConsensus();
    // Before fork: SegWit is active (if height >= SegwitHeight)
    BOOST_CHECK(!c.IsSegwitActive(0));
    BOOST_CHECK(c.IsSegwitActive(c.SegwitHeight));
    // At exact fork height: fork not yet active (uses >), so SegWit still on
    BOOST_CHECK(c.IsSegwitActive(c.BCH2ForkHeight));
    // After fork: SegWit disabled
    BOOST_CHECK(!c.IsSegwitActive(c.BCH2ForkHeight + 1));
    BOOST_CHECK(!c.IsSegwitActive(c.BCH2ForkHeight + 1000));
}

BOOST_AUTO_TEST_CASE(is_magnetic_anomaly_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int mh = c.magneticAnomalyHeight;
    BOOST_CHECK(!c.IsMagneticAnomalyActive(mh));
    BOOST_CHECK(c.IsMagneticAnomalyActive(mh + 1));
}

BOOST_AUTO_TEST_CASE(is_axion_active_boundary)
{
    const auto& c = Params().GetConsensus();
    int ah = c.axionHeight;
    BOOST_CHECK(!c.IsAxionActive(ah));
    BOOST_CHECK(c.IsAxionActive(ah + 1));
}

// ============================================================================
// Regtest halving interval
// ============================================================================

BOOST_AUTO_TEST_CASE(regtest_halving_interval)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& c = params->GetConsensus();
    BOOST_CHECK_EQUAL(c.nSubsidyHalvingInterval, 150);
}

// ============================================================================
// Signet chain params
// ============================================================================

BOOST_AUTO_TEST_CASE(signet_asert_anchor_not_set)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::SIGNET);
    const auto& c = params->GetConsensus();
    // Signet has an empty (default) anchor — not valid
    BOOST_CHECK(c.asertAnchorParams.has_value());
    // Default constructed ASERTAnchor has all zeros
    BOOST_CHECK(!c.asertAnchorParams->IsValid());
}

// ============================================================================
// Regtest fork height at 200
// ============================================================================

BOOST_AUTO_TEST_CASE(regtest_all_upgrades_at_fork_height)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& c = params->GetConsensus();
    BOOST_CHECK_EQUAL(c.BCH2ForkHeight, 200);
    // All upgrade heights match fork height in regtest
    BOOST_CHECK_EQUAL(c.uahfHeight, c.BCH2ForkHeight);
    BOOST_CHECK_EQUAL(c.daaHeight, c.BCH2ForkHeight);
    BOOST_CHECK_EQUAL(c.magneticAnomalyHeight, c.BCH2ForkHeight);
    BOOST_CHECK_EQUAL(c.gravitonHeight, c.BCH2ForkHeight);
    BOOST_CHECK_EQUAL(c.phononHeight, c.BCH2ForkHeight);
    BOOST_CHECK_EQUAL(c.upgrade8Height, c.BCH2ForkHeight);
    BOOST_CHECK_EQUAL(c.upgrade9Height, c.BCH2ForkHeight);
    BOOST_CHECK_EQUAL(c.upgrade10Height, c.BCH2ForkHeight);
    BOOST_CHECK_EQUAL(c.upgrade11Height, c.BCH2ForkHeight);
}

// ============================================================================
// IsWitnessDestination — BCH2-specific witness destination detection
// ============================================================================

BOOST_AUTO_TEST_CASE(is_witness_destination_p2pkh)
{
    PKHash pkh{uint160(std::vector<uint8_t>(20, 0xAA))};
    BOOST_CHECK(!IsWitnessDestination(CTxDestination{pkh}));
}

BOOST_AUTO_TEST_CASE(is_witness_destination_p2sh)
{
    ScriptHash sh{CScriptID(uint160(std::vector<uint8_t>(20, 0xBB)))};
    BOOST_CHECK(!IsWitnessDestination(CTxDestination{sh}));
}

BOOST_AUTO_TEST_CASE(is_witness_destination_p2wpkh)
{
    WitnessV0KeyHash wkh{uint160(std::vector<uint8_t>(20, 0xCC))};
    BOOST_CHECK(IsWitnessDestination(CTxDestination{wkh}));
}

BOOST_AUTO_TEST_CASE(is_witness_destination_p2wsh)
{
    WitnessV0ScriptHash wsh{uint256(std::vector<uint8_t>(32, 0xDD))};
    BOOST_CHECK(IsWitnessDestination(CTxDestination{wsh}));
}

BOOST_AUTO_TEST_CASE(is_witness_destination_p2tr)
{
    XOnlyPubKey xpk{uint256(std::vector<uint8_t>(32, 0xEE))};
    WitnessV1Taproot tap{xpk};
    BOOST_CHECK(IsWitnessDestination(CTxDestination{tap}));
}

BOOST_AUTO_TEST_CASE(is_witness_destination_unknown_witness)
{
    std::vector<unsigned char> prog(20, 0xFF);
    WitnessUnknown wu(2, prog);
    BOOST_CHECK(IsWitnessDestination(CTxDestination{wu}));
}

BOOST_AUTO_TEST_CASE(is_witness_destination_no_destination)
{
    BOOST_CHECK(!IsWitnessDestination(CTxDestination{CNoDestination{}}));
}

BOOST_AUTO_TEST_CASE(is_witness_destination_pubkey_destination)
{
    // PubKeyDestination is not a witness destination
    CPubKey dummy_key;
    PubKeyDestination pkd{dummy_key};
    BOOST_CHECK(!IsWitnessDestination(CTxDestination{pkd}));
}

// ============================================================================
// Consensus constants verification
// ============================================================================

BOOST_AUTO_TEST_CASE(max_consensus_block_size)
{
    BOOST_CHECK_EQUAL(MAX_CONSENSUS_BLOCK_SIZE, 2000000000u); // 2GB
}

BOOST_AUTO_TEST_CASE(default_consensus_block_size)
{
    BOOST_CHECK_EQUAL(DEFAULT_CONSENSUS_BLOCK_SIZE, 32000000u); // 32MB
}

BOOST_AUTO_TEST_CASE(bch2_fork_height_matches_consensus)
{
    // BCH2::FORK_HEIGHT should match mainnet consensus
    BOOST_CHECK_EQUAL(BCH2::FORK_HEIGHT, 53200);
    BOOST_CHECK_EQUAL(BCH2::FORK_HEIGHT, Params().GetConsensus().BCH2ForkHeight);
}

BOOST_AUTO_TEST_CASE(bch2_sighash_forkid_constant)
{
    BOOST_CHECK_EQUAL(BCH2::SIGHASH_FORKID, 0x40u);
    BOOST_CHECK_EQUAL(BCH2::FORKID, 0u);
}

BOOST_AUTO_TEST_CASE(bch2_network_ports)
{
    BOOST_CHECK_EQUAL(BCH2::P2P_PORT, 8339);
    BOOST_CHECK_EQUAL(BCH2::RPC_PORT, 8342);
}

BOOST_AUTO_TEST_CASE(bch2_magic_bytes)
{
    BOOST_CHECK_EQUAL(BCH2::MAGIC[0], 0xb2);
    BOOST_CHECK_EQUAL(BCH2::MAGIC[1], 0xc2);
    BOOST_CHECK_EQUAL(BCH2::MAGIC[2], 0xb2);
    BOOST_CHECK_EQUAL(BCH2::MAGIC[3], 0xc2);
}

// ============================================================================
// Mainnet consensus parameter consistency
// ============================================================================

BOOST_AUTO_TEST_CASE(mainnet_pow_target_spacing)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.nPowTargetSpacing, 600); // 10 minutes
}

BOOST_AUTO_TEST_CASE(mainnet_default_block_size)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.nDefaultConsensusBlockSize, DEFAULT_CONSENSUS_BLOCK_SIZE);
}

BOOST_AUTO_TEST_CASE(mainnet_subsidy_interval_matches_btc)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.nSubsidyHalvingInterval, 210000);
}

BOOST_AUTO_TEST_CASE(regtest_pow_no_retargeting)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& c = params->GetConsensus();
    BOOST_CHECK(c.fPowNoRetargeting);
}

BOOST_AUTO_TEST_CASE(mainnet_pow_retargeting_on)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK(!c.fPowNoRetargeting);
}

// ============================================================================
// DifficultyAdjustmentInterval and PowTargetSpacing
// ============================================================================

BOOST_AUTO_TEST_CASE(difficulty_adjustment_interval)
{
    const auto& c = Params().GetConsensus();
    // nPowTargetTimespan / nPowTargetSpacing
    int64_t expected = c.nPowTargetTimespan / c.nPowTargetSpacing;
    BOOST_CHECK_EQUAL(c.DifficultyAdjustmentInterval(), expected);
    // Standard Bitcoin value: 2016 blocks
    BOOST_CHECK_EQUAL(c.DifficultyAdjustmentInterval(), 2016);
}

BOOST_AUTO_TEST_CASE(pow_target_spacing_chrono)
{
    const auto& c = Params().GetConsensus();
    auto spacing = c.PowTargetSpacing();
    BOOST_CHECK_EQUAL(spacing.count(), 600); // 10 minutes in seconds
}

// ============================================================================
// DeploymentHeight
// ============================================================================

BOOST_AUTO_TEST_CASE(deployment_height_segwit)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.DeploymentHeight(Consensus::DEPLOYMENT_SEGWIT), c.SegwitHeight);
}

BOOST_AUTO_TEST_CASE(deployment_height_csv)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.DeploymentHeight(Consensus::DEPLOYMENT_CSV), c.CSVHeight);
}

BOOST_AUTO_TEST_CASE(deployment_height_cltv)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.DeploymentHeight(Consensus::DEPLOYMENT_CLTV), c.BIP65Height);
}

BOOST_AUTO_TEST_CASE(deployment_height_dersig)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.DeploymentHeight(Consensus::DEPLOYMENT_DERSIG), c.BIP66Height);
}

BOOST_AUTO_TEST_CASE(deployment_height_heightincb)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK_EQUAL(c.DeploymentHeight(Consensus::DEPLOYMENT_HEIGHTINCB), c.BIP34Height);
}

// ============================================================================
// IsUpgrade12Active boundary test
// ============================================================================

BOOST_AUTO_TEST_CASE(upgrade12_not_yet_active)
{
    const auto& c = Params().GetConsensus();
    // Upgrade 12 uses NEVER_ACTIVE_HEIGHT by default — not yet scheduled
    BOOST_CHECK_EQUAL(c.upgrade12Height, Consensus::NEVER_ACTIVE_HEIGHT);
    BOOST_CHECK(!c.IsUpgrade12Active(0));
    BOOST_CHECK(!c.IsUpgrade12Active(c.BCH2ForkHeight + 1));
    BOOST_CHECK(!c.IsUpgrade12Active(1000000));
}

// ============================================================================
// GetASERTHalfLife with NEVER_ACTIVE_HEIGHT transition
// ============================================================================

BOOST_AUTO_TEST_CASE(asert_halflife_never_active_transition)
{
    // Signet has nASERTHalfLifeTransitionHeight = NEVER_ACTIVE_HEIGHT
    const auto params = CreateChainParams(ArgsManager{}, ChainType::SIGNET);
    const auto& c = params->GetConsensus();
    // Should always return the initial half-life, never transition
    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(0), c.nASERTHalfLife);
    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(1000000), c.nASERTHalfLife);
    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(std::numeric_limits<int>::max() - 1), c.nASERTHalfLife);
}

// ============================================================================
// IsCashTokensActive is alias for IsUpgrade9Active
// ============================================================================

BOOST_AUTO_TEST_CASE(cashtokens_is_upgrade9_alias)
{
    const auto& c = Params().GetConsensus();
    for (int h : {0, c.upgrade9Height, c.upgrade9Height + 1, c.BCH2ForkHeight + 1}) {
        BOOST_CHECK_EQUAL(c.IsCashTokensActive(h), c.IsUpgrade9Active(h));
    }
}

// ============================================================================
// Testnet chain type params
// ============================================================================

BOOST_AUTO_TEST_CASE(testnet_not_signet)
{
    // BCH2 testnet is NOT signet-based
    const auto params = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    const auto& c = params->GetConsensus();
    BOOST_CHECK(!c.signet_blocks);
}

BOOST_AUTO_TEST_CASE(mainnet_not_signet)
{
    const auto& c = Params().GetConsensus();
    BOOST_CHECK(!c.signet_blocks);
}

BOOST_AUTO_TEST_CASE(regtest_not_signet)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& c = params->GetConsensus();
    BOOST_CHECK(!c.signet_blocks);
}

// ============================================================================
// Regtest ASERT half-life
// ============================================================================

BOOST_AUTO_TEST_CASE(regtest_asert_halflife)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& c = params->GetConsensus();
    // Regtest should have 1-hour half-life
    BOOST_CHECK_EQUAL(c.nASERTHalfLife, Consensus::Params::ASERT_HALFLIFE_1_HOUR);
}

BOOST_AUTO_TEST_CASE(regtest_halflife_transition)
{
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    const auto& c = params->GetConsensus();
    // Regtest transition at 432
    BOOST_CHECK_EQUAL(c.nASERTHalfLifeTransitionHeight, 432);
    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(431), Consensus::Params::ASERT_HALFLIFE_1_HOUR);
    BOOST_CHECK_EQUAL(c.GetASERTHalfLife(432), Consensus::Params::ASERT_HALFLIFE_2_DAYS);
}

BOOST_AUTO_TEST_SUITE_END()
