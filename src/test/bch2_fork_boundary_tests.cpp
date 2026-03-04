// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// These tests verify correct behavior at the exact fork activation height.
// For regtest, BCH2ForkHeight = 200.

#include <chainparams.h>
#include <consensus/activation.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <key.h>
#include <node/miner.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <arith_uint256.h>
#include <crypto/sha256.h>
#include <uint256.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <vector>

using node::BlockAssembler;
using node::CBlockTemplate;

namespace bch2_fork_boundary_tests {

// Test fixture that can mine blocks to specific heights
struct ForkBoundaryTestSetup : public TestingSetup {
    ForkBoundaryTestSetup() : TestingSetup(ChainType::REGTEST) {}

    // Mine blocks up to (but not including) the target height
    void MineToHeight(int targetHeight) {
        LOCK(cs_main);
        int currentHeight = m_node.chainman->ActiveChain().Height();
        while (currentHeight < targetHeight - 1) {
            CScript coinbaseScript = CScript() << OP_TRUE;
            std::vector<CMutableTransaction> txns;
            CBlock block = CreateAndProcessBlock(txns, coinbaseScript);
            currentHeight = m_node.chainman->ActiveChain().Height();
        }
    }

    // Create and process a block with given transactions
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns,
                                  const CScript& scriptPubKey) {
        BlockAssembler::Options options;
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler{m_node.chainman->ActiveChainstate(), m_node.mempool.get(), options}.CreateNewBlock(scriptPubKey);
        CBlock& block = pblocktemplate->block;

        // Add provided transactions
        for (const auto& tx : txns) {
            block.vtx.push_back(MakeTransactionRef(tx));
        }

        // Update merkle root
        block.hashMerkleRoot = BlockMerkleRoot(block);

        // Mine the block
        while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) {
            ++block.nNonce;
        }

        // Process the block
        std::shared_ptr<const CBlock> shared_block = std::make_shared<const CBlock>(block);
        m_node.chainman->ProcessNewBlock(shared_block, true, true, nullptr);

        return block;
    }

    // Get current chain height
    int GetHeight() {
        LOCK(cs_main);
        return m_node.chainman->ActiveChain().Height();
    }

    // Get consensus params
    const Consensus::Params& GetConsensus() {
        return Params().GetConsensus();
    }
};

} // namespace bch2_fork_boundary_tests

BOOST_FIXTURE_TEST_SUITE(bch2_fork_boundary_tests, bch2_fork_boundary_tests::ForkBoundaryTestSetup)

// ============================================================================
// Test: Fork activation height is correctly configured
// ============================================================================
BOOST_AUTO_TEST_CASE(fork_height_configuration)
{
    const Consensus::Params& consensus = GetConsensus();

    // Regtest fork height should be 200
    BOOST_CHECK_EQUAL(consensus.BCH2ForkHeight, 200);

    // Pre-fork: height 199 should NOT activate BCH2
    BOOST_CHECK(!consensus.IsBCH2ForkActive(199));

    // Fork block 200 is the LAST pre-fork block (Is*Active uses > not >=)
    BOOST_CHECK(!consensus.IsBCH2ForkActive(200));

    // Post-fork: height 201 is the first active block
    BOOST_CHECK(consensus.IsBCH2ForkActive(201));
}

// ============================================================================
// Test: SegWit activation status changes at fork
// ============================================================================
BOOST_AUTO_TEST_CASE(segwit_disabled_at_fork)
{
    const Consensus::Params& consensus = GetConsensus();

    // Pre-fork: SegWit should be active (assuming SegwitHeight < 200)
    BOOST_CHECK(consensus.SegwitHeight < consensus.BCH2ForkHeight);

    // At height 199 (pre-fork), SegWit should be active
    BOOST_CHECK(consensus.IsSegwitActive(199));

    // At height 200 (last pre-fork), SegWit should still be active
    BOOST_CHECK(consensus.IsSegwitActive(200));

    // At height 201 (first post-fork), SegWit should be DISABLED
    BOOST_CHECK(!consensus.IsSegwitActive(201));
}

// ============================================================================
// Test: All BCH upgrades activate at fork height
// ============================================================================
BOOST_AUTO_TEST_CASE(bch_upgrades_activate_at_fork)
{
    const Consensus::Params& consensus = GetConsensus();

    // All these should activate at or after fork height
    // For regtest, they should all be at height 200

    // Pre-fork (height 199): None of these should be active
    BOOST_CHECK(!consensus.IsUAHFActive(199));
    BOOST_CHECK(!consensus.IsDAAActive(199));
    BOOST_CHECK(!consensus.IsMagneticAnomalyActive(199));
    BOOST_CHECK(!consensus.IsGravitonActive(199));
    BOOST_CHECK(!consensus.IsPhononActive(199));
    BOOST_CHECK(!consensus.IsAxionActive(199));

    // Post-fork (height 201): All should be active
    BOOST_CHECK(consensus.IsUAHFActive(201));
    BOOST_CHECK(consensus.IsDAAActive(201));
    BOOST_CHECK(consensus.IsMagneticAnomalyActive(201));
    BOOST_CHECK(consensus.IsGravitonActive(201));
    BOOST_CHECK(consensus.IsPhononActive(201));
    BOOST_CHECK(consensus.IsAxionActive(201));
}

// ============================================================================
// Test: ASERT activates at fork height
// ============================================================================
BOOST_AUTO_TEST_CASE(asert_activates_at_fork)
{
    const Consensus::Params& consensus = GetConsensus();

    // ASERT is controlled by axionHeight, which should equal BCH2ForkHeight for regtest
    // Pre-fork: ASERT not active
    BOOST_CHECK(!consensus.IsASERTActive(199));

    // Post-fork: ASERT active
    BOOST_CHECK(consensus.IsASERTActive(201));
}

// ============================================================================
// Test: Script verification flags change at fork
// ============================================================================
BOOST_AUTO_TEST_CASE(script_flags_at_fork)
{
    // BCH2 post-fork flags should include:
    // - SCRIPT_VERIFY_SIGHASH_FORKID (requires FORKID in signatures)
    // - SCRIPT_VERIFY_NO_SEGWIT (disables witness validation)

    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_SIGHASH_FORKID);
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_NO_SEGWIT);

    // Should NOT have witness-related flags
    BOOST_CHECK(!(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_WITNESS));
    BOOST_CHECK(!(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_TAPROOT));
}

// ============================================================================
// Test: P2PKH transaction with SIGHASH_FORKID post-fork
// ============================================================================
BOOST_AUTO_TEST_CASE(p2pkh_with_forkid_valid_postfork)
{
    // Generate a key pair
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Create P2PKH scriptPubKey
    CScript scriptPubKey = GetScriptForDestination(PKHash(pubkey));

    // Create a spending transaction
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Sign with SIGHASH_ALL | SIGHASH_FORKID (0x41)
    uint256 sighash = SignatureHash(scriptPubKey, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    // Build scriptSig
    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    // Verify with BCH2 post-fork flags
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig,
        scriptPubKey,
        nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "P2PKH with FORKID should succeed post-fork: " + ScriptErrorString(serror));
}

// ============================================================================
// Test: P2PKH transaction WITHOUT SIGHASH_FORKID fails post-fork
// ============================================================================
BOOST_AUTO_TEST_CASE(p2pkh_without_forkid_fails_postfork)
{
    // Generate a key pair
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Create P2PKH scriptPubKey
    CScript scriptPubKey = GetScriptForDestination(PKHash(pubkey));

    // Create a spending transaction
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Sign WITHOUT FORKID (pre-fork style)
    uint256 sighash = SignatureHash(scriptPubKey, tx, 0, SIGHASH_ALL, 1000, SigVersion::BASE);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL)); // No FORKID!

    // Build scriptSig
    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    // Verify with BCH2 post-fork flags - should FAIL
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig,
        scriptPubKey,
        nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2PKH without FORKID should fail post-fork");
    // Should fail with SCRIPT_ERR_SIG_HASHTYPE (missing FORKID)
    BOOST_CHECK(serror == SCRIPT_ERR_SIG_HASHTYPE || serror == SCRIPT_ERR_EVAL_FALSE);
}

// ============================================================================
// Test: Witness transaction fails with NO_SEGWIT flag
// ============================================================================
BOOST_AUTO_TEST_CASE(witness_tx_fails_with_no_segwit)
{
    // Generate a key pair
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Create P2WPKH scriptPubKey
    CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));

    // Create a spending transaction with witness data
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Create witness-style signature
    CScript implicitP2PKH;
    implicitP2PKH << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    uint256 sighash = SignatureHash(implicitP2PKH, tx, 0, SIGHASH_ALL, 1000, SigVersion::WITNESS_V0);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    // Put in witness (pre-fork style)
    CScriptWitness witness;
    witness.stack.push_back(sig);
    witness.stack.push_back(ToByteVector(pubkey));
    tx.vin[0].scriptWitness = witness;

    // Verify with BCH2 post-fork flags - should FAIL due to witness data
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig,
        scriptPubKey,
        &witness,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Witness transaction should fail with NO_SEGWIT flag");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SEGWIT_NOT_ALLOWED);
}

// ============================================================================
// Test: ASERT difficulty calculation at anchor block
// ============================================================================
BOOST_AUTO_TEST_CASE(asert_anchor_block_difficulty)
{
    const Consensus::Params& consensus = GetConsensus();

    // For regtest, verify ASERT anchor is configured
    if (consensus.asertAnchorParams) {
        const auto& anchor = *consensus.asertAnchorParams;

        // Anchor height should be BCH2ForkHeight + 1 (first BCH2 block)
        // For regtest: 200 + 1 = 201
        BOOST_CHECK_EQUAL(anchor.nHeight, consensus.BCH2ForkHeight + 1);

        // Anchor bits should be non-zero
        BOOST_CHECK(anchor.nBits != 0);
    }
}

// ============================================================================
// Test: Block size limit changes at fork (conceptual)
// ============================================================================
BOOST_AUTO_TEST_CASE(block_size_limit_at_fork)
{
    const Consensus::Params& consensus = GetConsensus();

    // Post-fork block size should be 32MB
    BOOST_CHECK_EQUAL(consensus.nDefaultConsensusBlockSize, 32000000);
}

// ============================================================================
// Test: maxReorgDepth is configured (rolling checkpoints)
// ============================================================================
BOOST_AUTO_TEST_CASE(max_reorg_depth_configured)
{
    const Consensus::Params& consensus = GetConsensus();

    // maxReorgDepth should be > 0 (enabled)
    // Mainnet/testnet: 10 (BCHN standard), Regtest: 10000 (allows deep reorg testing)
    BOOST_CHECK(consensus.maxReorgDepth > 0);
}

// ============================================================================
// Test: ASERT half-life transition is configured correctly
// ============================================================================
BOOST_AUTO_TEST_CASE(asert_halflife_transition)
{
    const Consensus::Params& consensus = GetConsensus();

    // Initial half-life should be 1 hour (3600 seconds)
    BOOST_CHECK_EQUAL(consensus.nASERTHalfLife, Consensus::Params::ASERT_HALFLIFE_1_HOUR);

    // Transition height should be configured for regtest
    // Regtest uses 432 for easy testing
    BOOST_CHECK(consensus.nASERTHalfLifeTransitionHeight > 0);
    BOOST_CHECK(consensus.nASERTHalfLifeTransitionHeight != Consensus::NEVER_ACTIVE_HEIGHT);

    // Before transition: 1 hour half-life
    int preTransition = consensus.nASERTHalfLifeTransitionHeight - 1;
    BOOST_CHECK_EQUAL(consensus.GetASERTHalfLife(preTransition), Consensus::Params::ASERT_HALFLIFE_1_HOUR);

    // At transition: 2 day half-life
    int atTransition = consensus.nASERTHalfLifeTransitionHeight;
    BOOST_CHECK_EQUAL(consensus.GetASERTHalfLife(atTransition), Consensus::Params::ASERT_HALFLIFE_2_DAYS);

    // After transition: 2 day half-life
    int postTransition = consensus.nASERTHalfLifeTransitionHeight + 1000;
    BOOST_CHECK_EQUAL(consensus.GetASERTHalfLife(postTransition), Consensus::Params::ASERT_HALFLIFE_2_DAYS);
}

// ============================================================================
// Test: IsBCH2ForkActive boundary precision
// ============================================================================
BOOST_AUTO_TEST_CASE(fork_active_boundary_precision)
{
    const Consensus::Params& consensus = GetConsensus();
    int forkHeight = consensus.BCH2ForkHeight;

    // Test exact boundary (Is*Active uses strictly greater than)
    BOOST_CHECK(!consensus.IsBCH2ForkActive(forkHeight - 1));  // Pre-fork
    BOOST_CHECK(!consensus.IsBCH2ForkActive(forkHeight));       // forkHeight is last pre-fork block
    BOOST_CHECK(consensus.IsBCH2ForkActive(forkHeight + 1));    // First post-fork

    // Test edge cases
    BOOST_CHECK(!consensus.IsBCH2ForkActive(0));
    BOOST_CHECK(!consensus.IsBCH2ForkActive(1));
    BOOST_CHECK(consensus.IsBCH2ForkActive(forkHeight + 1000));
}

// ============================================================================
// Test: IsSegwitActive boundary precision (inverse of fork)
// ============================================================================
BOOST_AUTO_TEST_CASE(segwit_active_boundary_precision)
{
    const Consensus::Params& consensus = GetConsensus();
    int forkHeight = consensus.BCH2ForkHeight;

    // SegWit should be active pre-fork (including at forkHeight), disabled after
    if (consensus.SegwitHeight < forkHeight) {
        BOOST_CHECK(consensus.IsSegwitActive(forkHeight - 1));   // Pre-fork: SegWit ON
        BOOST_CHECK(consensus.IsSegwitActive(forkHeight));        // forkHeight: still pre-fork, SegWit ON
        BOOST_CHECK(!consensus.IsSegwitActive(forkHeight + 1));   // Post-fork: SegWit OFF
    }
}

// ============================================================================
// Test: Multiple upgrade heights are synchronized
// ============================================================================
BOOST_AUTO_TEST_CASE(upgrade_heights_synchronized)
{
    const Consensus::Params& consensus = GetConsensus();

    // For BCH2, all BCH upgrades should activate at the same height
    // They should all equal BCH2ForkHeight (for regtest = 200)
    int forkHeight = consensus.BCH2ForkHeight;

    BOOST_CHECK_EQUAL(consensus.uahfHeight, forkHeight);
    BOOST_CHECK_EQUAL(consensus.daaHeight, forkHeight);
    BOOST_CHECK_EQUAL(consensus.magneticAnomalyHeight, forkHeight);
    BOOST_CHECK_EQUAL(consensus.gravitonHeight, forkHeight);
    BOOST_CHECK_EQUAL(consensus.phononHeight, forkHeight);
    BOOST_CHECK_EQUAL(consensus.axionHeight, forkHeight);
    BOOST_CHECK_EQUAL(consensus.upgrade8Height, forkHeight);
    BOOST_CHECK_EQUAL(consensus.upgrade9Height, forkHeight);
    BOOST_CHECK_EQUAL(consensus.upgrade10Height, forkHeight);
    BOOST_CHECK_EQUAL(consensus.upgrade11Height, forkHeight);
}

// ============================================================================
// Test: SIGHASH_FORKID value is correct
// ============================================================================
BOOST_AUTO_TEST_CASE(sighash_forkid_value)
{
    // SIGHASH_FORKID should be 0x40
    BOOST_CHECK_EQUAL(SIGHASH_FORKID, 0x40);

    // SIGHASH_ALL | SIGHASH_FORKID should be 0x41
    BOOST_CHECK_EQUAL(SIGHASH_ALL | SIGHASH_FORKID, 0x41);
}

// ============================================================================
// Test: Fork activation returns false at height 199, true at 200
// ============================================================================
BOOST_AUTO_TEST_CASE(fork_activation_at_exact_height)
{
    const Consensus::Params& consensus = GetConsensus();

    // IsBCH2ForkActive uses > comparison (height > BCH2ForkHeight)
    // Block 200 is the LAST pre-fork block
    BOOST_CHECK(!consensus.IsBCH2ForkActive(199));
    BOOST_CHECK(!consensus.IsBCH2ForkActive(200));
    BOOST_CHECK(consensus.IsBCH2ForkActive(201));
}

// ============================================================================
// Test: CTOR not required pre-fork (out-of-order tx IDs allowed)
// ============================================================================
BOOST_AUTO_TEST_CASE(ctor_not_required_pre_fork)
{
    const Consensus::Params& consensus = GetConsensus();

    // Magnetic Anomaly (which includes CTOR) should not be active pre-fork
    BOOST_CHECK(!consensus.IsMagneticAnomalyActive(199));
    BOOST_CHECK(!consensus.IsMagneticAnomalyActive(200));

    // Active post-fork (height > forkHeight)
    BOOST_CHECK(consensus.IsMagneticAnomalyActive(201));
}

// ============================================================================
// Test: CTOR required post-fork
// ============================================================================
BOOST_AUTO_TEST_CASE(ctor_required_post_fork)
{
    const Consensus::Params& consensus = GetConsensus();

    // Magnetic Anomaly (CTOR) activates after fork height (height > 200)
    BOOST_CHECK(!consensus.IsMagneticAnomalyActive(200));
    BOOST_CHECK(consensus.IsMagneticAnomalyActive(201));
    BOOST_CHECK(consensus.IsMagneticAnomalyActive(1000));
}

// ============================================================================
// Test: Pre-fork allows SegWit
// ============================================================================
BOOST_AUTO_TEST_CASE(pre_fork_allows_segwit)
{
    const Consensus::Params& consensus = GetConsensus();

    // SegWit is active pre-fork (SegwitHeight=0 for regtest)
    BOOST_CHECK(consensus.IsSegwitActive(0));
    BOOST_CHECK(consensus.IsSegwitActive(100));
    BOOST_CHECK(consensus.IsSegwitActive(199));
}

// ============================================================================
// Test: Post-fork rejects SegWit
// ============================================================================
BOOST_AUTO_TEST_CASE(post_fork_rejects_segwit)
{
    const Consensus::Params& consensus = GetConsensus();

    // SegWit is active at forkHeight (200 is still pre-fork), disabled after
    BOOST_CHECK(consensus.IsSegwitActive(200));
    BOOST_CHECK(!consensus.IsSegwitActive(201));
    BOOST_CHECK(!consensus.IsSegwitActive(10000));
}

// ============================================================================
// Test: All BCH features OFF pre-fork, ON post-fork at exact boundary
// ============================================================================
BOOST_AUTO_TEST_CASE(all_features_boundary)
{
    const Consensus::Params& consensus = GetConsensus();

    // Pre-fork (199): All BCH upgrades inactive
    BOOST_CHECK(!consensus.IsUAHFActive(199));
    BOOST_CHECK(!consensus.IsDAAActive(199));
    BOOST_CHECK(!consensus.IsMagneticAnomalyActive(199));
    BOOST_CHECK(!consensus.IsGravitonActive(199));
    BOOST_CHECK(!consensus.IsPhononActive(199));
    BOOST_CHECK(!consensus.IsAxionActive(199));
    BOOST_CHECK(!consensus.IsUpgrade8Active(199));
    BOOST_CHECK(!consensus.IsUpgrade9Active(199));
    BOOST_CHECK(!consensus.IsUpgrade10Active(199));
    BOOST_CHECK(!consensus.IsUpgrade11Active(199));

    // At height 200 (last pre-fork block): All BCH upgrades still inactive
    BOOST_CHECK(!consensus.IsUAHFActive(200));
    BOOST_CHECK(!consensus.IsDAAActive(200));
    BOOST_CHECK(!consensus.IsMagneticAnomalyActive(200));
    BOOST_CHECK(!consensus.IsGravitonActive(200));
    BOOST_CHECK(!consensus.IsPhononActive(200));
    BOOST_CHECK(!consensus.IsAxionActive(200));
    BOOST_CHECK(!consensus.IsUpgrade8Active(200));
    BOOST_CHECK(!consensus.IsUpgrade9Active(200));
    BOOST_CHECK(!consensus.IsUpgrade10Active(200));
    BOOST_CHECK(!consensus.IsUpgrade11Active(200));

    // Post-fork (201): All BCH upgrades active
    BOOST_CHECK(consensus.IsUAHFActive(201));
    BOOST_CHECK(consensus.IsDAAActive(201));
    BOOST_CHECK(consensus.IsMagneticAnomalyActive(201));
    BOOST_CHECK(consensus.IsGravitonActive(201));
    BOOST_CHECK(consensus.IsPhononActive(201));
    BOOST_CHECK(consensus.IsAxionActive(201));
    BOOST_CHECK(consensus.IsUpgrade8Active(201));
    BOOST_CHECK(consensus.IsUpgrade9Active(201));
    BOOST_CHECK(consensus.IsUpgrade10Active(201));
    BOOST_CHECK(consensus.IsUpgrade11Active(201));
}

// ============================================================================
// Test: VM limits active only post-fork (Upgrade 10)
// ============================================================================
BOOST_AUTO_TEST_CASE(vm_limits_post_fork_only)
{
    const Consensus::Params& consensus = GetConsensus();

    // Upgrade 10 (VM Limits) not active pre-fork
    BOOST_CHECK(!consensus.IsUpgrade10Active(199));
    BOOST_CHECK(!consensus.IsUpgrade10Active(200));

    // Active post-fork
    BOOST_CHECK(consensus.IsUpgrade10Active(201));
}

// ============================================================================
// Test: Schnorr signatures active only post-fork (Graviton)
// ============================================================================
BOOST_AUTO_TEST_CASE(schnorr_post_fork_only)
{
    const Consensus::Params& consensus = GetConsensus();

    // Graviton (Schnorr) not active pre-fork
    BOOST_CHECK(!consensus.IsGravitonActive(199));
    BOOST_CHECK(!consensus.IsGravitonActive(200));

    // Active post-fork
    BOOST_CHECK(consensus.IsGravitonActive(201));
}

// ============================================================================
// Test: SegWit migration — P2WPKH wrong program length rejected
// ============================================================================
BOOST_AUTO_TEST_CASE(segwit_migration_p2wpkh_wrong_length)
{
    // A witness v0 program that isn't 20 or 32 bytes should fail
    // with SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH
    std::vector<unsigned char> badProgram(25, 0x42); // 25 bytes - not 20 (P2WPKH) or 32 (P2WSH)

    CScript scriptPubKey;
    scriptPubKey << OP_0 << badProgram; // v0 witness program

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Provide a dummy scriptSig (needed for scriptSig-based evaluation)
    CScript scriptSig;
    scriptSig << OP_TRUE;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2WPKH wrong length should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
}

// ============================================================================
// Test: SegWit migration — P2TR empty stack rejected
// ============================================================================
BOOST_AUTO_TEST_CASE(segwit_migration_p2tr_empty_stack)
{
    // P2TR (witness v1, 32-byte program) with empty scriptSig should fail
    std::vector<unsigned char> program(WITNESS_V1_TAPROOT_SIZE, 0x42);

    CScript scriptPubKey;
    scriptPubKey << OP_1 << program; // v1 witness program

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Empty scriptSig — nothing to satisfy the witness program
    CScript scriptSig;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    // Use flags without CLEANSTACK and SIGPUSHONLY since we have empty scriptSig
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    // Empty scriptSig → stack empty → EVAL_FALSE before reaching witness program
    BOOST_CHECK(!result);
}

// ============================================================================
// Test: SegWit migration — Unknown witness version rejected
// ============================================================================
BOOST_AUTO_TEST_CASE(segwit_migration_unknown_witness_version)
{
    // Witness version 16 with any program should be unspendable
    std::vector<unsigned char> program(20, 0x42);

    CScript scriptPubKey;
    scriptPubKey << OP_16 << program; // v16 witness program

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptSig;
    scriptSig << OP_TRUE;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Unknown witness version should be rejected");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
}

// ============================================================================
// Test: PermittedDifficultyTransition — ASERT path (post-fork)
// ============================================================================
BOOST_AUTO_TEST_CASE(permitted_difficulty_asert_path)
{
    const Consensus::Params& consensus = GetConsensus();
    int postForkHeight = consensus.BCH2ForkHeight + 10;

    // Valid target at powLimit should pass
    arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    uint32_t powLimitBits = powLimit.GetCompact();
    BOOST_CHECK(PermittedDifficultyTransition(consensus, postForkHeight, powLimitBits, powLimitBits));

    // Zero target should fail
    uint32_t zeroBits = 0;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, postForkHeight, powLimitBits, zeroBits));

    // Target above powLimit should fail
    arith_uint256 overLimit = powLimit + 1;
    uint32_t overLimitBits = overLimit.GetCompact();
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, postForkHeight, powLimitBits, overLimitBits));

    // Target at half powLimit should pass (valid ASERT adjustment)
    arith_uint256 halfLimit = powLimit >> 1;
    uint32_t halfBits = halfLimit.GetCompact();
    BOOST_CHECK(PermittedDifficultyTransition(consensus, postForkHeight, powLimitBits, halfBits));

    // Very small but valid target should pass
    arith_uint256 smallTarget;
    smallTarget = 1;
    uint32_t smallBits = smallTarget.GetCompact();
    BOOST_CHECK(PermittedDifficultyTransition(consensus, postForkHeight, powLimitBits, smallBits));
}

BOOST_AUTO_TEST_CASE(permitted_difficulty_pre_fork)
{
    const Consensus::Params& consensus = GetConsensus();
    int preForkHeight = consensus.BCH2ForkHeight - 10;

    // Pre-fork with fPowAllowMinDifficultyBlocks=true (regtest), anything is permitted
    arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    uint32_t powLimitBits = powLimit.GetCompact();

    // For regtest, fPowAllowMinDifficultyBlocks=true, so should always pass
    BOOST_CHECK(PermittedDifficultyTransition(consensus, preForkHeight, powLimitBits, powLimitBits));
}

// ============================================================================
// Test: PermittedDifficultyTransition — Malformed nBits (negative, overflow)
// ============================================================================
BOOST_AUTO_TEST_CASE(permitted_difficulty_negative_nbits)
{
    const Consensus::Params& consensus = GetConsensus();
    int postForkHeight = consensus.BCH2ForkHeight + 10;
    arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    uint32_t powLimitBits = powLimit.GetCompact();

    // nBits with negative flag set: bit 23 of lower 3 bytes must be 1,
    // AND mantissa (nWord & 0x7fffff) must be nonzero for fNegative=true.
    // 0x20FF0000: exponent=0x20, nWord=0x7F0000 (nonzero), bit 23 set → negative
    uint32_t negativeBits = 0x20FF0000;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, postForkHeight, powLimitBits, negativeBits));
}

BOOST_AUTO_TEST_CASE(permitted_difficulty_overflow_nbits)
{
    const Consensus::Params& consensus = GetConsensus();
    int postForkHeight = consensus.BCH2ForkHeight + 10;
    arith_uint256 powLimit = UintToArith256(consensus.powLimit);
    uint32_t powLimitBits = powLimit.GetCompact();

    // nBits with overflow: exponent = 0xFF → 255*8 = 2040 bits → overflow
    uint32_t overflowBits = 0xFF7FFFFF;
    BOOST_CHECK(!PermittedDifficultyTransition(consensus, postForkHeight, powLimitBits, overflowBits));
}

// ============================================================================
// Test: SegWit migration — P2TR script-path rejected (stack > 1)
// ============================================================================
BOOST_AUTO_TEST_CASE(segwit_migration_p2tr_script_path_rejected)
{
    // P2TR with 2 items on scriptSig stack → script-path → rejected
    std::vector<unsigned char> program(WITNESS_V1_TAPROOT_SIZE, 0x42);

    CScript scriptPubKey;
    scriptPubKey << OP_1 << program; // v1 witness program

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Push 2 items onto scriptSig stack (simulating script-path spend attempt)
    CScript scriptSig;
    std::vector<unsigned char> fakeSig(64, 0x42); // Schnorr sig size
    std::vector<unsigned char> fakeScript(32, 0x01); // Control block
    scriptSig << fakeSig << fakeScript;
    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2TR script-path (stack > 1) should be rejected");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

// ============================================================================
// Test: SegWit migration — P2WPKH valid program length but bad sig
// ============================================================================
BOOST_AUTO_TEST_CASE(segwit_migration_p2wpkh_bad_sig)
{
    // P2WPKH with valid 20-byte program but wrong sig → EVAL_FALSE
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Create P2WPKH scriptPubKey: OP_0 <20-byte-hash>
    CKeyID keyId = pubkey.GetID();
    std::vector<unsigned char> keyHash(keyId.begin(), keyId.end());
    CScript scriptPubKey;
    scriptPubKey << OP_0 << keyHash;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Provide wrong sig + correct pubkey in scriptSig
    std::vector<unsigned char> badSig(72, 0x30);
    badSig.back() = 0x41; // SIGHASH_ALL|FORKID
    CScript scriptSig;
    scriptSig << badSig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    // Should fail — bad signature
    BOOST_CHECK(!result);
}

// ============================================================================
// Test: SegWit migration — P2WSH hash mismatch
// ============================================================================
BOOST_AUTO_TEST_CASE(segwit_migration_p2wsh_hash_mismatch)
{
    // Create P2WSH with one script hash, but put a different script in scriptSig
    CScript correctScript;
    correctScript << OP_TRUE;

    CScript wrongScript;
    wrongScript << OP_1 << OP_DROP << OP_TRUE;

    // P2WSH scriptPubKey = OP_0 <SHA256(correctScript)>
    uint256 correctHash;
    CSHA256().Write(correctScript.data(), correctScript.size()).Finalize(correctHash.begin());
    std::vector<unsigned char> programHash(correctHash.begin(), correctHash.end());

    CScript scriptPubKey;
    scriptPubKey << OP_0 << programHash;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Put the WRONG script on the stack
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(wrongScript.begin(), wrongScript.end());
    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2WSH hash mismatch should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

// ============================================================================
// BCH Schnorr signature (64-byte, implicit SIGHASH_ALL|FORKID)
// ============================================================================

// Test: BCH Schnorr signature in P2PKH OP_CHECKSIG (Graviton style)
BOOST_AUTO_TEST_CASE(bch_schnorr_in_p2pkh)
{
    CKey key;
    key.MakeNewKey(true); // must be compressed for BCH Schnorr
    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(pubkey.IsCompressed());

    CScript scriptPubKey = GetScriptForDestination(PKHash(pubkey));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // BCH Schnorr: implicit SIGHASH_ALL | SIGHASH_FORKID (0x41)
    int nHashType = SIGHASH_ALL | SIGHASH_FORKID;
    uint256 sighash = SignatureHash(scriptPubKey, tx, 0, nHashType, 1000, SigVersion::BCH_FORKID);

    // Create 64-byte Schnorr signature (BCH Graviton style, no hashtype byte appended)
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key.SignSchnorr(sighash, schnorrSig, nullptr, {}));
    BOOST_CHECK_EQUAL(schnorrSig.size(), 64u);

    // Build scriptSig: <64-byte-schnorr-sig> <compressed-pubkey>
    CScript scriptSig;
    scriptSig << schnorrSig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "BCH Schnorr P2PKH should succeed: " + ScriptErrorString(serror));
}

// Test: BCH Schnorr with wrong key fails
BOOST_AUTO_TEST_CASE(bch_schnorr_wrong_key_fails)
{
    CKey key, wrongKey;
    key.MakeNewKey(true);
    wrongKey.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey = GetScriptForDestination(PKHash(pubkey));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Sign with wrong key
    int nHashType = SIGHASH_ALL | SIGHASH_FORKID;
    uint256 sighash = SignatureHash(scriptPubKey, tx, 0, nHashType, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(wrongKey.SignSchnorr(sighash, schnorrSig, nullptr, {}));

    // Build scriptSig with CORRECT pubkey but WRONG signature
    CScript scriptSig;
    scriptSig << schnorrSig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "BCH Schnorr with wrong key should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_NULLFAIL);
}

// Test: BCH Schnorr fails without SCRIPT_ENABLE_SCHNORR flag
BOOST_AUTO_TEST_CASE(bch_schnorr_without_enable_flag)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey = GetScriptForDestination(PKHash(pubkey));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    int nHashType = SIGHASH_ALL | SIGHASH_FORKID;
    uint256 sighash = SignatureHash(scriptPubKey, tx, 0, nHashType, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key.SignSchnorr(sighash, schnorrSig, nullptr, {}));

    CScript scriptSig;
    scriptSig << schnorrSig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    // Use BCH2 flags but remove SCRIPT_ENABLE_SCHNORR
    // Without Schnorr enabled, 64-byte sig is treated as ECDSA → DER decode fails
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_SCHNORR;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Schnorr sig without ENABLE_SCHNORR should fail");
    // 64-byte sig treated as ECDSA → DER encoding error
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_DER);
}

// Test: BCH Schnorr with uncompressed pubkey fails
BOOST_AUTO_TEST_CASE(bch_schnorr_uncompressed_pubkey_fails)
{
    CKey key;
    key.MakeNewKey(false); // uncompressed
    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(!pubkey.IsCompressed());

    // Use PKHash of the uncompressed key for scriptPubKey
    CScript scriptPubKey = GetScriptForDestination(PKHash(pubkey));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Sign with the key (we need a valid Schnorr sig for the hash)
    // Note: SignSchnorr works on the key regardless of compression flag
    int nHashType = SIGHASH_ALL | SIGHASH_FORKID;
    uint256 sighash = SignatureHash(scriptPubKey, tx, 0, nHashType, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key.SignSchnorr(sighash, schnorrSig, nullptr, {}));

    // Build scriptSig with uncompressed pubkey
    CScript scriptSig;
    scriptSig << schnorrSig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "BCH Schnorr with uncompressed pubkey should fail");
    // CheckBCHSchnorrSignature returns false (!IsCompressed), then NULLFAIL triggers
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_NULLFAIL);
}

// Test: BCH Schnorr in OP_CHECKDATASIG
BOOST_AUTO_TEST_CASE(bch_schnorr_in_checkdatasig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Hash the message for CHECKDATASIG
    std::vector<unsigned char> message = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    uint256 msgHash;
    CSHA256().Write(message.data(), message.size()).Finalize(msgHash.begin());

    // Create Schnorr signature over the message hash
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key.SignSchnorr(msgHash, schnorrSig, nullptr, {}));

    // scriptPubKey: OP_CHECKDATASIG
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << message << OP_2 << OP_PICK
                 << OP_CHECKDATASIGVERIFY << OP_TRUE;

    // Actually, OP_CHECKDATASIG takes: sig msg pubkey
    // Let's construct properly:
    // scriptPubKey: <pubkey> OP_CHECKDATASIG
    // scriptSig: <sig> <msg>
    CScript scriptPubKey2;
    scriptPubKey2 << ToByteVector(pubkey) << OP_CHECKDATASIG;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // OP_CHECKDATASIG: pops sig, msg, pubkey from stack
    // Stack order (bottom to top): sig, msg, pubkey
    // scriptSig pushes sig and msg, scriptPubKey pushes pubkey then does CHECKDATASIG
    CScript scriptSig;
    scriptSig << schnorrSig << message;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey2, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "BCH Schnorr in OP_CHECKDATASIG should succeed: " + ScriptErrorString(serror));
}

// Test: ECDSA and Schnorr signatures coexist in the same script
BOOST_AUTO_TEST_CASE(mixed_ecdsa_schnorr_same_script)
{
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();

    // scriptPubKey: <pubkey1> OP_CHECKSIGVERIFY <pubkey2> OP_CHECKSIG
    // This requires two valid signatures: one for key1, one for key2
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey1) << OP_CHECKSIGVERIFY
                 << ToByteVector(pubkey2) << OP_CHECKSIG;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Sign with key1 using ECDSA (DER + hashtype byte)
    int nHashType = SIGHASH_ALL | SIGHASH_FORKID;
    uint256 sighash = SignatureHash(scriptPubKey, tx, 0, nHashType, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> ecdsaSig;
    BOOST_CHECK(key1.Sign(sighash, ecdsaSig));
    ecdsaSig.push_back(static_cast<unsigned char>(nHashType));

    // Sign with key2 using Schnorr (64 bytes, no hashtype)
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key2.SignSchnorr(sighash, schnorrSig, nullptr, {}));

    // scriptSig: <schnorr_sig2> <ecdsa_sig1>
    // Stack: bottom→ <schnorr_sig2> <ecdsa_sig1> ←top
    // scriptPubKey execution: <pubkey1> CHECKSIGVERIFY consumes ecdsa_sig1
    //                        <pubkey2> CHECKSIG consumes schnorr_sig2
    CScript scriptSig;
    scriptSig << schnorrSig << ecdsaSig;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "Mixed ECDSA+Schnorr should succeed: " + ScriptErrorString(serror));
}

// ============================================================================
// OP_CHECKDATASIG edge cases
// ============================================================================

// Helper to create a basic tx for OP_CHECKDATASIG tests
static CMutableTransaction CreateBasicTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

// Test: OP_CHECKDATASIG with valid ECDSA signature
BOOST_AUTO_TEST_CASE(checkdatasig_ecdsa_valid)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> message = {0x68, 0x65, 0x6c, 0x6c, 0x6f}; // "hello"
    uint256 msgHash;
    CSHA256().Write(message.data(), message.size()).Finalize(msgHash.begin());

    // Create ECDSA signature (raw DER, no hashtype byte for OP_CHECKDATASIG)
    std::vector<unsigned char> ecdsaSig;
    BOOST_CHECK(key.Sign(msgHash, ecdsaSig));

    // scriptPubKey: <pubkey> OP_CHECKDATASIG
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKDATASIG;

    CMutableTransaction tx = CreateBasicTx();
    CScript scriptSig;
    scriptSig << ecdsaSig << message;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "ECDSA OP_CHECKDATASIG should succeed: " + ScriptErrorString(serror));
}

// Test: OP_CHECKDATASIGVERIFY with valid ECDSA signature
BOOST_AUTO_TEST_CASE(checkdatasigverify_ecdsa_valid)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> message = {0x74, 0x65, 0x73, 0x74}; // "test"
    uint256 msgHash;
    CSHA256().Write(message.data(), message.size()).Finalize(msgHash.begin());

    std::vector<unsigned char> ecdsaSig;
    BOOST_CHECK(key.Sign(msgHash, ecdsaSig));

    // scriptPubKey: <pubkey> OP_CHECKDATASIGVERIFY OP_TRUE
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKDATASIGVERIFY << OP_TRUE;

    CMutableTransaction tx = CreateBasicTx();
    CScript scriptSig;
    scriptSig << ecdsaSig << message;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "ECDSA OP_CHECKDATASIGVERIFY should succeed: " + ScriptErrorString(serror));
}

// Test: OP_CHECKDATASIG with empty signature (should push FALSE)
BOOST_AUTO_TEST_CASE(checkdatasig_empty_sig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> message = {0x41};

    // scriptPubKey: <pubkey> OP_CHECKDATASIG OP_NOT
    // Empty sig → FALSE, then NOT → TRUE
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKDATASIG << OP_NOT;

    CMutableTransaction tx = CreateBasicTx();
    std::vector<unsigned char> emptySig;
    CScript scriptSig;
    scriptSig << emptySig << message;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "Empty sig CHECKDATASIG should push FALSE: " + ScriptErrorString(serror));
}

// Test: OP_CHECKDATASIGVERIFY with wrong signature fails
BOOST_AUTO_TEST_CASE(checkdatasigverify_wrong_sig_fails)
{
    CKey key, wrongKey;
    key.MakeNewKey(true);
    wrongKey.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> message = {0x42};
    uint256 msgHash;
    CSHA256().Write(message.data(), message.size()).Finalize(msgHash.begin());

    // Sign with wrong key
    std::vector<unsigned char> wrongSig;
    BOOST_CHECK(wrongKey.Sign(msgHash, wrongSig));

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKDATASIGVERIFY << OP_TRUE;

    CMutableTransaction tx = CreateBasicTx();
    CScript scriptSig;
    scriptSig << wrongSig << message;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Wrong sig CHECKDATASIGVERIFY should fail");
    // NULLFAIL triggers because sig is non-empty and verification failed
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_NULLFAIL);
}

// Test: OP_CHECKDATASIG Schnorr with wrong message fails
BOOST_AUTO_TEST_CASE(checkdatasig_schnorr_wrong_message)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> message = {0x41, 0x42, 0x43};
    std::vector<unsigned char> wrongMessage = {0x44, 0x45, 0x46};

    // Sign correct message
    uint256 msgHash;
    CSHA256().Write(message.data(), message.size()).Finalize(msgHash.begin());
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key.SignSchnorr(msgHash, schnorrSig, nullptr, {}));

    // But verify against wrong message
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKDATASIG;

    CMutableTransaction tx = CreateBasicTx();
    CScript scriptSig;
    scriptSig << schnorrSig << wrongMessage;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Schnorr wrong message should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_NULLFAIL);
}

// Test: OP_CHECKDATASIG with uncompressed pubkey + Schnorr fails (NULLFAIL)
BOOST_AUTO_TEST_CASE(checkdatasig_schnorr_uncompressed_pubkey)
{
    CKey key;
    key.MakeNewKey(false); // uncompressed
    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(!pubkey.IsCompressed());

    std::vector<unsigned char> message = {0x41};
    uint256 msgHash;
    CSHA256().Write(message.data(), message.size()).Finalize(msgHash.begin());

    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key.SignSchnorr(msgHash, schnorrSig, nullptr, {}));

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKDATASIG;

    CMutableTransaction tx = CreateBasicTx();
    CScript scriptSig;
    scriptSig << schnorrSig << message;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Schnorr with uncompressed pubkey should fail");
    // fSchnorrCDS=true, !pubkey.IsCompressed() → NULLFAIL
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_NULLFAIL);
}

// Test: OP_CHECKDATASIG with empty message succeeds
BOOST_AUTO_TEST_CASE(checkdatasig_empty_message)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    std::vector<unsigned char> emptyMessage;
    uint256 msgHash;
    CSHA256().Write(emptyMessage.data(), emptyMessage.size()).Finalize(msgHash.begin());

    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key.SignSchnorr(msgHash, schnorrSig, nullptr, {}));

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKDATASIG;

    CMutableTransaction tx = CreateBasicTx();
    CScript scriptSig;
    scriptSig << schnorrSig << emptyMessage;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "CHECKDATASIG with empty message should succeed: " + ScriptErrorString(serror));
}

// ============================================================================
// OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY: BCH2-specific tests
// ============================================================================

BOOST_AUTO_TEST_CASE(cltv_negative_locktime_fails)
{
    // <-1> OP_CHECKLOCKTIMEVERIFY should fail with NEGATIVE_LOCKTIME
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 500;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = 0xFFFFFFFE; // not final
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptSig;
    scriptSig << CScriptNum(-1);
    tx.vin[0].scriptSig = scriptSig;

    CScript scriptPubKey;
    scriptPubKey << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_TRUE;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(cltv_valid_locktime_passes)
{
    // <500> OP_CHECKLOCKTIMEVERIFY should pass when tx.nLockTime >= 500
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 500;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = 0xFFFFFFFE; // not final
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptSig;
    scriptSig << CScriptNum(500);
    tx.vin[0].scriptSig = scriptSig;

    CScript scriptPubKey;
    scriptPubKey << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_TRUE;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror);
    BOOST_CHECK_MESSAGE(result, "CLTV with valid locktime should pass: " + ScriptErrorString(serror));
}

BOOST_AUTO_TEST_CASE(cltv_unsatisfied_locktime_fails)
{
    // <600> OP_CHECKLOCKTIMEVERIFY should fail when tx.nLockTime < 600
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 500;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = 0xFFFFFFFE;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptSig;
    scriptSig << CScriptNum(600);
    tx.vin[0].scriptSig = scriptSig;

    CScript scriptPubKey;
    scriptPubKey << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_TRUE;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(csv_negative_sequence_fails)
{
    // <-1> OP_CHECKSEQUENCEVERIFY should fail with NEGATIVE_LOCKTIME
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = 0x0001; // relative locktime of 1 block
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptSig;
    scriptSig << CScriptNum(-1);
    tx.vin[0].scriptSig = scriptSig;

    CScript scriptPubKey;
    scriptPubKey << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_TRUE;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_NEGATIVE_LOCKTIME);
}

BOOST_AUTO_TEST_CASE(csv_disable_flag_acts_as_nop)
{
    // With SEQUENCE_LOCKTIME_DISABLE_FLAG set, CSV acts as NOP
    // 0x80000000 = SEQUENCE_LOCKTIME_DISABLE_FLAG
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL; // 0xFFFFFFFF
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Push value with disable flag set: 0x80000000
    CScript scriptSig;
    scriptSig << CScriptNum(static_cast<int64_t>(CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG));
    tx.vin[0].scriptSig = scriptSig;

    CScript scriptPubKey;
    scriptPubKey << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_TRUE;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror);
    BOOST_CHECK_MESSAGE(result, "CSV with disable flag should act as NOP: " + ScriptErrorString(serror));
}

BOOST_AUTO_TEST_CASE(cltv_empty_stack_fails)
{
    // OP_CHECKLOCKTIMEVERIFY with empty stack fails
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 500;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].nSequence = 0xFFFFFFFE;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptSig;
    tx.vin[0].scriptSig = scriptSig;

    CScript scriptPubKey;
    scriptPubKey << OP_CHECKLOCKTIMEVERIFY;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_SUITE_END()
