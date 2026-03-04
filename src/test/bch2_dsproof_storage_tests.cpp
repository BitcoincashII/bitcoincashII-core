// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for DoubleSpendProofStorage.
// Covers add/remove, orphan lifecycle, lookup, clear, limits, and cleanup.

#include <dsp/dsproof.h>
#include <dsp/storage.h>
#include <key.h>
#include <script/interpreter.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

// Helper: create a fake signature with SIGHASH_FORKID
std::vector<uint8_t> MakeFakeSig(uint8_t hashtype = SIGHASH_ALL | SIGHASH_FORKID) {
    std::vector<uint8_t> sig = {
        0x30, 0x44,
        0x02, 0x20,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x02, 0x20,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
    };
    sig.push_back(hashtype);
    return sig;
}

// Helper: create a spending tx for a given outpoint
CMutableTransaction MakeSpendingTx(const COutPoint& prevout, const CKey& key, CAmount amount) {
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].prevout = prevout;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;

    auto sig = MakeFakeSig();
    CScript scriptSig;
    scriptSig << sig << ToByteVector(key.GetPubKey());
    tx.vin[0].scriptSig = scriptSig;

    tx.vout.resize(1);
    tx.vout[0].nValue = amount;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    return tx;
}

// Helper: create a valid DoubleSpendProof for testing storage
DoubleSpendProof MakeTestProof(const COutPoint& prevout, CAmount amt1 = 900, CAmount amt2 = 800) {
    CKey key;
    key.MakeNewKey(true);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key, amt1);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key, amt2);

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    return DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(bch2_dsproof_storage_tests, BasicTestingSetup)

// ============================================================================
// Basic add/remove operations
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_initially_empty)
{
    DoubleSpendProofStorage storage;
    BOOST_CHECK_EQUAL(storage.size(), 0U);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
}

BOOST_AUTO_TEST_CASE(storage_add_proof)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    BOOST_CHECK(storage.add(proof));
    BOOST_CHECK_EQUAL(storage.size(), 1U);
    BOOST_CHECK(storage.exists(proof.GetId()));
}

BOOST_AUTO_TEST_CASE(storage_add_duplicate_returns_false)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    BOOST_CHECK(storage.add(proof));
    BOOST_CHECK(!storage.add(proof)); // Duplicate
    BOOST_CHECK_EQUAL(storage.size(), 1U);
}

BOOST_AUTO_TEST_CASE(storage_add_empty_proof_throws)
{
    DoubleSpendProofStorage storage;
    DoubleSpendProof empty;

    BOOST_CHECK_THROW(storage.add(empty), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(storage_remove_existing)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.add(proof);
    BOOST_CHECK(storage.remove(proof.GetId()));
    BOOST_CHECK_EQUAL(storage.size(), 0U);
    BOOST_CHECK(!storage.exists(proof.GetId()));
}

BOOST_AUTO_TEST_CASE(storage_remove_nonexistent_returns_false)
{
    DoubleSpendProofStorage storage;
    DspId fakeId = uint256S("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    BOOST_CHECK(!storage.remove(fakeId));
}

// ============================================================================
// Lookup
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_lookup_existing)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.add(proof);
    auto found = storage.lookup(proof.GetId());
    BOOST_CHECK(!found.isEmpty());
    BOOST_CHECK(found == proof);
}

BOOST_AUTO_TEST_CASE(storage_lookup_nonexistent_returns_empty)
{
    DoubleSpendProofStorage storage;
    DspId fakeId = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    auto found = storage.lookup(fakeId);
    BOOST_CHECK(found.isEmpty());
}

// ============================================================================
// Orphan management
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_add_orphan)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    BOOST_CHECK(storage.addOrphan(proof, 42));
    BOOST_CHECK_EQUAL(storage.size(), 1U);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);
    BOOST_CHECK(storage.exists(proof.GetId()));
}

BOOST_AUTO_TEST_CASE(storage_claim_orphan)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.addOrphan(proof, 42);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);

    storage.claimOrphan(proof.GetId());
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
    BOOST_CHECK_EQUAL(storage.size(), 1U); // Still exists, just not an orphan
}

BOOST_AUTO_TEST_CASE(storage_claim_nonexistent_orphan_noop)
{
    DoubleSpendProofStorage storage;
    DspId fakeId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    // Should be a no-op
    storage.claimOrphan(fakeId);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
}

BOOST_AUTO_TEST_CASE(storage_orphan_existing_proof)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    // Add as non-orphan first
    storage.add(proof);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);

    // Convert to orphan
    storage.orphanExisting(proof.GetId());
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);
    BOOST_CHECK_EQUAL(storage.size(), 1U);
}

BOOST_AUTO_TEST_CASE(storage_orphan_existing_already_orphan_noop)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.addOrphan(proof, 42);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);

    // Already an orphan — should be no-op
    storage.orphanExisting(proof.GetId());
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);
}

BOOST_AUTO_TEST_CASE(storage_add_existing_orphan_claims_it)
{
    // Adding an existing orphan via add() should claim it (mark non-orphan)
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.addOrphan(proof, 42);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);

    // add() on existing orphan should claim it
    BOOST_CHECK(!storage.add(proof)); // Returns false (already exists)
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
    BOOST_CHECK_EQUAL(storage.size(), 1U);
}

BOOST_AUTO_TEST_CASE(storage_add_orphan_only_if_not_exists)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    // First add should succeed
    BOOST_CHECK(storage.addOrphan(proof, 42, true));

    // Second add with onlyIfNotExists=true should return false
    BOOST_CHECK(!storage.addOrphan(proof, 43, true));
    BOOST_CHECK_EQUAL(storage.size(), 1U);
}

BOOST_AUTO_TEST_CASE(storage_orphan_all)
{
    DoubleSpendProofStorage storage;

    // Add multiple non-orphan proofs
    COutPoint prevout1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint prevout2(Txid::FromUint256(uint256::ONE), 1);
    auto proof1 = MakeTestProof(prevout1, 900, 800);
    auto proof2 = MakeTestProof(prevout2, 700, 600);

    storage.add(proof1);
    storage.add(proof2);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
    BOOST_CHECK_EQUAL(storage.size(), 2U);

    // orphanAll
    storage.orphanAll();
    BOOST_CHECK_EQUAL(storage.numOrphans(), 2U);
    BOOST_CHECK_EQUAL(storage.size(), 2U);
}

// ============================================================================
// findOrphans by outpoint
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_find_orphans_by_outpoint)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.addOrphan(proof, 42);

    auto orphans = storage.findOrphans(prevout);
    BOOST_CHECK_EQUAL(orphans.size(), 1U);
    BOOST_CHECK(orphans.front().first == proof.GetId());
    BOOST_CHECK_EQUAL(orphans.front().second, 42); // nodeId
}

BOOST_AUTO_TEST_CASE(storage_find_orphans_empty_for_non_orphan)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.add(proof); // Non-orphan

    auto orphans = storage.findOrphans(prevout);
    BOOST_CHECK(orphans.empty());
}

BOOST_AUTO_TEST_CASE(storage_find_orphans_wrong_outpoint)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    COutPoint otherPoint(Txid::FromUint256(uint256::ONE), 99);
    auto proof = MakeTestProof(prevout);

    storage.addOrphan(proof, 42);

    auto orphans = storage.findOrphans(otherPoint);
    BOOST_CHECK(orphans.empty());
}

// ============================================================================
// getAll
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_getall_excludes_orphans_by_default)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint prevout2(Txid::FromUint256(uint256::ONE), 1);
    auto proof1 = MakeTestProof(prevout1, 900, 800);
    auto proof2 = MakeTestProof(prevout2, 700, 600);

    storage.add(proof1);
    storage.addOrphan(proof2, 42);

    auto all = storage.getAll(false);
    BOOST_CHECK_EQUAL(all.size(), 1U);
    BOOST_CHECK(!all[0].second); // Not an orphan
}

BOOST_AUTO_TEST_CASE(storage_getall_includes_orphans)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint prevout2(Txid::FromUint256(uint256::ONE), 1);
    auto proof1 = MakeTestProof(prevout1, 900, 800);
    auto proof2 = MakeTestProof(prevout2, 700, 600);

    storage.add(proof1);
    storage.addOrphan(proof2, 42);

    auto all = storage.getAll(true);
    BOOST_CHECK_EQUAL(all.size(), 2U);
}

// ============================================================================
// Clear
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_clear_all)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.add(proof);
    storage.clear();

    BOOST_CHECK_EQUAL(storage.size(), 0U);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
}

BOOST_AUTO_TEST_CASE(storage_clear_keep_orphans)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint prevout2(Txid::FromUint256(uint256::ONE), 1);
    auto proof1 = MakeTestProof(prevout1, 900, 800);
    auto proof2 = MakeTestProof(prevout2, 700, 600);

    storage.add(proof1);
    storage.addOrphan(proof2, 42);

    storage.clear(false); // Keep orphans

    BOOST_CHECK_EQUAL(storage.size(), 1U); // Only orphan remains
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);
    BOOST_CHECK(!storage.exists(proof1.GetId()));
    BOOST_CHECK(storage.exists(proof2.GetId()));
}

// ============================================================================
// Rejected proof tracking
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_rejected_proof_tracking)
{
    DoubleSpendProofStorage storage;
    DspId proofId = uint256S("aaaa000000000000000000000000000000000000000000000000000000000001");

    BOOST_CHECK(!storage.isRecentlyRejectedProof(proofId));

    storage.markProofRejected(proofId);
    BOOST_CHECK(storage.isRecentlyRejectedProof(proofId));
}

BOOST_AUTO_TEST_CASE(storage_new_block_clears_rejections)
{
    DoubleSpendProofStorage storage;
    DspId proofId = uint256S("bbbb000000000000000000000000000000000000000000000000000000000002");

    storage.markProofRejected(proofId);
    BOOST_CHECK(storage.isRecentlyRejectedProof(proofId));

    storage.newBlockFound();
    // After new block, bloom filter is reset
    BOOST_CHECK(!storage.isRecentlyRejectedProof(proofId));
}

// ============================================================================
// Orphan configuration
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_default_orphan_config)
{
    DoubleSpendProofStorage storage;
    BOOST_CHECK_EQUAL(storage.secondsToKeepOrphans(),
                      DoubleSpendProofStorage::defaultSecondsToKeepOrphans());
    BOOST_CHECK_EQUAL(storage.maxOrphans(),
                      DoubleSpendProofStorage::defaultMaxOrphans());
}

BOOST_AUTO_TEST_CASE(storage_set_orphan_keep_time)
{
    DoubleSpendProofStorage storage;
    storage.setSecondsToKeepOrphans(300);
    BOOST_CHECK_EQUAL(storage.secondsToKeepOrphans(), 300);
}

BOOST_AUTO_TEST_CASE(storage_set_max_orphans)
{
    DoubleSpendProofStorage storage;
    storage.setMaxOrphans(100);
    BOOST_CHECK_EQUAL(storage.maxOrphans(), 100U);
}

BOOST_AUTO_TEST_CASE(storage_default_values)
{
    BOOST_CHECK_EQUAL(DoubleSpendProofStorage::defaultSecondsToKeepOrphans(), 90);
    BOOST_CHECK_EQUAL(DoubleSpendProofStorage::defaultMaxOrphans(), 65535U);
}

// ============================================================================
// Remove orphan updates counter
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_remove_orphan_decrements_counter)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.addOrphan(proof, 42);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);

    storage.remove(proof.GetId());
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
    BOOST_CHECK_EQUAL(storage.size(), 0U);
}

// ============================================================================
// Multiple proofs for same outpoint
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_multiple_proofs_same_outpoint)
{
    // Multiple proofs can reference the same outpoint (different double-spends)
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    auto proof1 = MakeTestProof(prevout, 900, 800);
    auto proof2 = MakeTestProof(prevout, 700, 600);

    // They should have different IDs (different tx amounts → different hashes)
    BOOST_CHECK(proof1.GetId() != proof2.GetId());

    storage.add(proof1);
    storage.add(proof2);
    BOOST_CHECK_EQUAL(storage.size(), 2U);
}

// ============================================================================
// Periodic cleanup
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_periodic_cleanup_returns_true)
{
    // periodicCleanup always returns true (to be re-scheduled)
    DoubleSpendProofStorage storage;
    BOOST_CHECK(storage.periodicCleanup());
}

BOOST_AUTO_TEST_CASE(storage_periodic_cleanup_removes_expired_orphans)
{
    // Set keepOrphans to 0 so all orphans expire immediately
    DoubleSpendProofStorage storage;
    storage.setSecondsToKeepOrphans(0);

    COutPoint prevout1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint prevout2(Txid::FromUint256(uint256::ONE), 1);
    auto proof1 = MakeTestProof(prevout1, 900, 800);
    auto proof2 = MakeTestProof(prevout2, 700, 600);

    storage.addOrphan(proof1, 42);
    storage.addOrphan(proof2, 43);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 2U);
    BOOST_CHECK_EQUAL(storage.size(), 2U);

    // All orphans have timestamp <= now, so with keepOrphans=0, they expire
    storage.periodicCleanup();
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
    BOOST_CHECK_EQUAL(storage.size(), 0U);
}

BOOST_AUTO_TEST_CASE(storage_periodic_cleanup_keeps_non_orphans)
{
    DoubleSpendProofStorage storage;
    storage.setSecondsToKeepOrphans(0);

    COutPoint prevout1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint prevout2(Txid::FromUint256(uint256::ONE), 1);
    auto proof1 = MakeTestProof(prevout1, 900, 800);
    auto proof2 = MakeTestProof(prevout2, 700, 600);

    // Add one orphan and one non-orphan
    storage.addOrphan(proof1, 42);
    storage.add(proof2);
    BOOST_CHECK_EQUAL(storage.size(), 2U);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);

    storage.periodicCleanup();
    // Orphan removed, non-orphan remains
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
    BOOST_CHECK_EQUAL(storage.size(), 1U);
    BOOST_CHECK(storage.exists(proof2.GetId()));
    BOOST_CHECK(!storage.exists(proof1.GetId()));
}

BOOST_AUTO_TEST_CASE(storage_periodic_cleanup_no_orphans_noop)
{
    DoubleSpendProofStorage storage;
    storage.setSecondsToKeepOrphans(0);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);
    storage.add(proof);

    // No orphans to clean
    storage.periodicCleanup();
    BOOST_CHECK_EQUAL(storage.size(), 1U);
}

BOOST_AUTO_TEST_CASE(storage_periodic_cleanup_high_keep_time_preserves_orphans)
{
    // With very high keepOrphans (1 hour), recent orphans should NOT expire
    DoubleSpendProofStorage storage;
    storage.setSecondsToKeepOrphans(3600);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);
    storage.addOrphan(proof, 42);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);

    storage.periodicCleanup();
    // Should still be there (just added, won't expire for an hour)
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);
    BOOST_CHECK_EQUAL(storage.size(), 1U);
}

// ============================================================================
// Orphan limit reaping (checkOrphanLimit)
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_orphan_limit_reaping)
{
    // Set maxOrphans to 4. High water mark = 4 * 1.25 = 5.
    // Adding 6 orphans should trigger reaping back down to 4.
    DoubleSpendProofStorage storage;
    storage.setMaxOrphans(4);

    std::vector<DoubleSpendProof> proofs;
    for (int i = 0; i < 6; ++i) {
        COutPoint prevout(Txid::FromUint256(uint256::ONE), i);
        auto proof = MakeTestProof(prevout, 900 + i, 800 + i);
        proofs.push_back(proof);
    }

    // Add first 5 — at high water mark (5), no reaping yet (> not >=)
    for (int i = 0; i < 5; ++i) {
        storage.addOrphan(proofs[i], i);
    }
    BOOST_CHECK_EQUAL(storage.numOrphans(), 5U);

    // Add 6th — exceeds high water mark (6 > 5), triggers reaping to 4
    storage.addOrphan(proofs[5], 5);
    BOOST_CHECK(storage.numOrphans() <= 4U);
}

BOOST_AUTO_TEST_CASE(storage_orphan_limit_reaping_preserves_non_orphans)
{
    // Non-orphan proofs should not be reaped by orphan limit
    DoubleSpendProofStorage storage;
    storage.setMaxOrphans(2);

    // Add a non-orphan
    COutPoint prevout0(Txid::FromUint256(uint256::ONE), 0);
    auto nonOrphan = MakeTestProof(prevout0, 999, 998);
    storage.add(nonOrphan);

    // Add 4 orphans (high water = 2*1.25 = 2, so 3 should trigger reaping)
    for (int i = 1; i <= 4; ++i) {
        COutPoint prevout(Txid::FromUint256(uint256::ONE), i);
        auto proof = MakeTestProof(prevout, 900 + i, 800 + i);
        storage.addOrphan(proof, i);
    }

    // Non-orphan should survive reaping
    BOOST_CHECK(storage.exists(nonOrphan.GetId()));
    BOOST_CHECK(storage.numOrphans() <= 2U);
}

// ============================================================================
// exists() edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_exists_after_orphan_all)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.add(proof);
    storage.orphanAll();

    // Should still exist even after orphan conversion
    BOOST_CHECK(storage.exists(proof.GetId()));
}

BOOST_AUTO_TEST_CASE(storage_exists_false_after_clear)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.add(proof);
    storage.clear(true);
    BOOST_CHECK(!storage.exists(proof.GetId()));
}

// ============================================================================
// add() and addOrphan() edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(storage_add_orphan_empty_proof_throws)
{
    DoubleSpendProofStorage storage;
    DoubleSpendProof empty;
    BOOST_CHECK_THROW(storage.addOrphan(empty, 42), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(storage_add_orphan_recategorize_non_orphan)
{
    // addOrphan() on a non-orphan proof should recategorize it as orphan
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.add(proof);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);

    storage.addOrphan(proof, 42);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 1U);
    BOOST_CHECK_EQUAL(storage.size(), 1U);
}

BOOST_AUTO_TEST_CASE(storage_lookup_returns_same_proof_data)
{
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.add(proof);
    auto found = storage.lookup(proof.GetId());
    BOOST_CHECK(!found.isEmpty());
    BOOST_CHECK(found.GetId() == proof.GetId());
    BOOST_CHECK(found.outPoint() == proof.outPoint());
}

BOOST_AUTO_TEST_CASE(storage_multiple_rejected_proofs)
{
    DoubleSpendProofStorage storage;
    DspId id1 = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    DspId id2 = uint256S("2222222222222222222222222222222222222222222222222222222222222222");

    storage.markProofRejected(id1);
    storage.markProofRejected(id2);
    BOOST_CHECK(storage.isRecentlyRejectedProof(id1));
    BOOST_CHECK(storage.isRecentlyRejectedProof(id2));

    // newBlockFound clears both
    storage.newBlockFound();
    BOOST_CHECK(!storage.isRecentlyRejectedProof(id1));
    BOOST_CHECK(!storage.isRecentlyRejectedProof(id2));
}

BOOST_AUTO_TEST_CASE(storage_getall_empty)
{
    DoubleSpendProofStorage storage;
    auto all = storage.getAll(true);
    BOOST_CHECK(all.empty());
}

BOOST_AUTO_TEST_CASE(storage_find_orphans_after_claim)
{
    // After claiming an orphan, findOrphans should no longer return it
    DoubleSpendProofStorage storage;
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);
    auto proof = MakeTestProof(prevout);

    storage.addOrphan(proof, 42);
    auto orphans = storage.findOrphans(prevout);
    BOOST_CHECK_EQUAL(orphans.size(), 1U);

    storage.claimOrphan(proof.GetId());
    orphans = storage.findOrphans(prevout);
    BOOST_CHECK(orphans.empty());
}

BOOST_AUTO_TEST_CASE(storage_orphan_existing_nonexistent_noop)
{
    // orphanExisting on non-existent proof is a no-op
    DoubleSpendProofStorage storage;
    DspId fakeId = uint256S("dead0000000000000000000000000000000000000000000000000000deadbeef");
    storage.orphanExisting(fakeId);
    BOOST_CHECK_EQUAL(storage.numOrphans(), 0U);
    BOOST_CHECK_EQUAL(storage.size(), 0U);
}

BOOST_AUTO_TEST_SUITE_END()
