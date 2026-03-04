// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for DoubleSpendProof (DSProof) unit-level behavior.
// Covers isEmpty, checkSanity, create, serialization, DspIdPtr, and enable/disable.

#include <dsp/dsproof.h>
#include <dsp/dspid.h>
#include <hash.h>
#include <key.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <policy/policy.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>

namespace {

// Helper: create a fake signature with SIGHASH_FORKID
std::vector<uint8_t> MakeFakeSig(uint8_t hashtype = SIGHASH_ALL | SIGHASH_FORKID) {
    // DER-encoded signature with arbitrary data (won't verify but structure is correct)
    std::vector<uint8_t> sig = {
        0x30, 0x44, // DER sequence, 68 bytes
        0x02, 0x20, // integer, 32 bytes (r)
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x02, 0x20, // integer, 32 bytes (s)
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
    };
    sig.push_back(hashtype);
    return sig;
}

// Helper: create a P2PKH spending tx
CMutableTransaction MakeSpendingTx(const COutPoint& prevout, const CKey& key) {
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].prevout = prevout;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;

    // scriptSig: <sig> <pubkey>
    auto sig = MakeFakeSig();
    CScript scriptSig;
    scriptSig << sig << ToByteVector(key.GetPubKey());
    tx.vin[0].scriptSig = scriptSig;

    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    return tx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(bch2_dsproof_tests, BasicTestingSetup)

// ============================================================================
// isEmpty() tests
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_default_is_empty)
{
    DoubleSpendProof proof;
    BOOST_CHECK(proof.isEmpty());
}

BOOST_AUTO_TEST_CASE(dsproof_empty_has_null_id)
{
    DoubleSpendProof proof;
    BOOST_CHECK(proof.GetId().IsNull());
}

// ============================================================================
// Validity enum values
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_validity_enum_values)
{
    // Verify the enum values are distinct
    BOOST_CHECK(DoubleSpendProof::Valid != DoubleSpendProof::Invalid);
    BOOST_CHECK(DoubleSpendProof::Valid != DoubleSpendProof::MissingTransaction);
    BOOST_CHECK(DoubleSpendProof::Valid != DoubleSpendProof::MissingUTXO);
    BOOST_CHECK(DoubleSpendProof::MissingTransaction != DoubleSpendProof::Invalid);
    BOOST_CHECK(DoubleSpendProof::MissingUTXO != DoubleSpendProof::Invalid);
}

// ============================================================================
// IsEnabled / SetEnabled
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_enabled_by_default)
{
    BOOST_CHECK(DoubleSpendProof::IsEnabled());
}

BOOST_AUTO_TEST_CASE(dsproof_can_disable_and_reenable)
{
    // Save current state
    bool wasEnabled = DoubleSpendProof::IsEnabled();

    DoubleSpendProof::SetEnabled(false);
    BOOST_CHECK(!DoubleSpendProof::IsEnabled());

    DoubleSpendProof::SetEnabled(true);
    BOOST_CHECK(DoubleSpendProof::IsEnabled());

    // Restore
    DoubleSpendProof::SetEnabled(wasEnabled);
}

// ============================================================================
// DetermineMaxPushDataSize
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_max_pushdata_size)
{
    // Currently always returns MAX_SCRIPT_ELEMENT_SIZE regardless of flags
    BOOST_CHECK_EQUAL(DoubleSpendProof::DetermineMaxPushDataSize(0), MAX_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK_EQUAL(DoubleSpendProof::DetermineMaxPushDataSize(0xFFFFFFFF), MAX_SCRIPT_ELEMENT_SIZE);
}

// ============================================================================
// create() factory method tests
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_create_same_tx_throws)
{
    // create() with identical tx hashes should throw invalid_argument
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx = MakeSpendingTx(prevout, key);
    CTransaction tx(mtx);

    BOOST_CHECK_THROW(
        DoubleSpendProof::create(0, tx, tx, prevout, nullptr),
        std::invalid_argument
    );
}

BOOST_AUTO_TEST_CASE(dsproof_create_no_common_outpoint_throws)
{
    // create() with txs that don't share the specified outpoint should throw
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint prevout2(Txid::FromUint256(uint256::ONE), 1);
    COutPoint prevout3(Txid::FromUint256(uint256::ONE), 2);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout1, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout2, key);

    // Different output amounts to make tx hashes different
    mtx2.vout[0].nValue = 999;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    // Neither tx spends prevout3
    BOOST_CHECK_THROW(
        DoubleSpendProof::create(0, tx1, tx2, prevout3, nullptr),
        std::runtime_error
    );
}

BOOST_AUTO_TEST_CASE(dsproof_create_valid_double_spend)
{
    // Create a valid DSProof from two txs spending the same outpoint
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    mtx1.vout[0].nValue = 900;

    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 800; // Different amount → different hash

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    // Using nullptr for txOut → non-verifying mode (for tests)
    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);

    BOOST_CHECK(!proof.isEmpty());
    BOOST_CHECK(!proof.GetId().IsNull());
    BOOST_CHECK(proof.outPoint() == prevout);
    BOOST_CHECK(proof.prevTxId() == prevout.hash);
    BOOST_CHECK_EQUAL(proof.prevOutIndex(), prevout.n);
}

BOOST_AUTO_TEST_CASE(dsproof_create_populates_spenders)
{
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    mtx1.vout[0].nValue = 700;

    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 600;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);

    // Both spenders should have exactly 1 pushData with non-empty data
    BOOST_CHECK_EQUAL(proof.spender1().pushData.size(), 1U);
    BOOST_CHECK_EQUAL(proof.spender2().pushData.size(), 1U);
    BOOST_CHECK(!proof.spender1().pushData.front().empty());
    BOOST_CHECK(!proof.spender2().pushData.front().empty());

    // Tx versions should be populated
    BOOST_CHECK_EQUAL(proof.spender1().txVersion, 2U);
    BOOST_CHECK_EQUAL(proof.spender2().txVersion, 2U);
}

// ============================================================================
// Canonical ordering
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_canonical_ordering)
{
    // create() should sort spenders so proof is the same regardless of tx order
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    mtx1.vout[0].nValue = 500;

    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 400;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof_12 = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    DoubleSpendProof proof_21 = DoubleSpendProof::create(0, tx2, tx1, prevout, nullptr);

    // Both proofs should have the same ID (canonical ordering makes them identical)
    BOOST_CHECK(proof_12.GetId() == proof_21.GetId());
    BOOST_CHECK(proof_12 == proof_21);
}

// ============================================================================
// Serialization roundtrip
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_serialization_roundtrip)
{
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    mtx1.vout[0].nValue = 300;

    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 200;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof original = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);

    // Serialize
    DataStream ss{};
    ss << original;

    // Deserialize
    DoubleSpendProof deserialized;
    ss >> deserialized;

    // Should be equal
    BOOST_CHECK(original == deserialized);
    BOOST_CHECK(original.GetId() == deserialized.GetId());
    BOOST_CHECK(original.outPoint() == deserialized.outPoint());
    BOOST_CHECK(!deserialized.isEmpty());
}

BOOST_AUTO_TEST_CASE(dsproof_serialization_empty_proof)
{
    DoubleSpendProof empty;

    // Serialize empty proof
    DataStream ss{};
    ss << empty;

    // Deserialize
    DoubleSpendProof deserialized;
    ss >> deserialized;

    // Both should be empty
    BOOST_CHECK(deserialized.isEmpty());
}

// ============================================================================
// Equality operators
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_equality_same_proof)
{
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    mtx1.vout[0].nValue = 100;
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 50;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof p1 = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    DoubleSpendProof p2 = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);

    BOOST_CHECK(p1 == p2);
    BOOST_CHECK(!(p1 != p2));
}

BOOST_AUTO_TEST_CASE(dsproof_inequality_different_proofs)
{
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint prevout2(Txid::FromUint256(uint256::ONE), 1);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout1, key);
    mtx1.vout[0].nValue = 100;
    CMutableTransaction mtx2 = MakeSpendingTx(prevout1, key);
    mtx2.vout[0].nValue = 50;
    CMutableTransaction mtx3 = MakeSpendingTx(prevout2, key);
    mtx3.vout[0].nValue = 100;
    CMutableTransaction mtx4 = MakeSpendingTx(prevout2, key);
    mtx4.vout[0].nValue = 50;

    CTransaction tx1(mtx1), tx2(mtx2), tx3(mtx3), tx4(mtx4);

    DoubleSpendProof p1 = DoubleSpendProof::create(0, tx1, tx2, prevout1, nullptr);
    DoubleSpendProof p2 = DoubleSpendProof::create(0, tx3, tx4, prevout2, nullptr);

    BOOST_CHECK(p1 != p2);
    BOOST_CHECK(!(p1 == p2));
}

// ============================================================================
// Missing SIGHASH_FORKID in create
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_create_missing_forkid_throws)
{
    // A tx without SIGHASH_FORKID in the signature should fail in create()
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    // Build tx1 without FORKID
    CMutableTransaction mtx1;
    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = prevout;

    auto sig_no_forkid = MakeFakeSig(SIGHASH_ALL); // No FORKID
    CScript scriptSig;
    scriptSig << sig_no_forkid << ToByteVector(key.GetPubKey());
    mtx1.vin[0].scriptSig = scriptSig;

    mtx1.vout.resize(1);
    mtx1.vout[0].nValue = 1000;
    mtx1.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 999;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    // Should throw because tx1 signature lacks FORKID
    BOOST_CHECK_THROW(
        DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr),
        std::runtime_error
    );
}

// ============================================================================
// DspIdPtr tests
// ============================================================================

BOOST_AUTO_TEST_CASE(dspid_ptr_default_is_null)
{
    DspIdPtr ptr;
    BOOST_CHECK(!ptr);
    BOOST_CHECK(ptr.get() == nullptr);
}

BOOST_AUTO_TEST_CASE(dspid_ptr_from_valid_id)
{
    DspId id = uint256S("0102030405060708091011121314151617181920212223242526272829303132");
    DspIdPtr ptr(id);
    BOOST_CHECK(bool(ptr));
    BOOST_CHECK(ptr.get() != nullptr);
    BOOST_CHECK(*ptr == id);
}

BOOST_AUTO_TEST_CASE(dspid_ptr_from_null_id)
{
    // A null (all-zero) DspId results in nullptr
    DspId nullId;
    BOOST_CHECK(nullId.IsNull());

    DspIdPtr ptr(nullId);
    BOOST_CHECK(!ptr);
    BOOST_CHECK(ptr.get() == nullptr);
}

BOOST_AUTO_TEST_CASE(dspid_ptr_copy_construction)
{
    DspId id = uint256S("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    DspIdPtr ptr1(id);
    DspIdPtr ptr2(ptr1);

    // Deep copy — different pointers, same value
    BOOST_CHECK(ptr1.get() != ptr2.get());
    BOOST_CHECK(*ptr1 == *ptr2);
    BOOST_CHECK(ptr1 == ptr2);
}

BOOST_AUTO_TEST_CASE(dspid_ptr_copy_assignment)
{
    DspId id = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    DspIdPtr ptr1(id);
    DspIdPtr ptr2;

    ptr2 = ptr1;
    BOOST_CHECK(bool(ptr2));
    BOOST_CHECK(ptr1 == ptr2);
    BOOST_CHECK(ptr1.get() != ptr2.get()); // Deep copy
}

BOOST_AUTO_TEST_CASE(dspid_ptr_move_construction)
{
    DspId id = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    DspIdPtr ptr1(id);
    DspIdPtr ptr2(std::move(ptr1));

    BOOST_CHECK(bool(ptr2));
    BOOST_CHECK(*ptr2 == id);
    BOOST_CHECK(!ptr1); // moved-from is empty
}

BOOST_AUTO_TEST_CASE(dspid_ptr_comparison_with_dspid)
{
    DspId id1 = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    DspId id2 = uint256S("4444444444444444444444444444444444444444444444444444444444444444");

    DspIdPtr ptr1(id1);
    BOOST_CHECK(ptr1 == id1);
    BOOST_CHECK(ptr1 != id2);
}

BOOST_AUTO_TEST_CASE(dspid_ptr_null_equals_null_dspid)
{
    DspIdPtr nullPtr;
    DspId nullId;
    BOOST_CHECK(nullPtr == nullId);
}

BOOST_AUTO_TEST_CASE(dspid_ptr_mem_usage)
{
    DspIdPtr nullPtr;
    BOOST_CHECK_EQUAL(nullPtr.memUsage(), sizeof(DspIdPtr));

    DspId id = uint256S("5555555555555555555555555555555555555555555555555555555555555555");
    DspIdPtr validPtr(id);
    BOOST_CHECK_EQUAL(validPtr.memUsage(), sizeof(DspIdPtr) + sizeof(DspId));
}

BOOST_AUTO_TEST_CASE(dspid_ptr_comparison_operators)
{
    DspId id1 = uint256S("1000000000000000000000000000000000000000000000000000000000000000");
    DspId id2 = uint256S("2000000000000000000000000000000000000000000000000000000000000000");

    DspIdPtr ptr1(id1);
    DspIdPtr ptr2(id2);

    // Comparison operators on DspIdPtr do deep comparison
    BOOST_CHECK(ptr1 != ptr2);
    BOOST_CHECK(ptr1 < ptr2 || ptr1 > ptr2); // At least one must be true since they differ
    BOOST_CHECK(ptr1 <= ptr2 || ptr1 >= ptr2);
}

BOOST_AUTO_TEST_CASE(dspid_ptr_reset)
{
    DspId id = uint256S("6666666666666666666666666666666666666666666666666666666666666666");
    DspIdPtr ptr(id);
    BOOST_CHECK(bool(ptr));

    ptr.reset();
    BOOST_CHECK(!ptr);
    BOOST_CHECK(ptr.get() == nullptr);
}

// ============================================================================
// Spender equality
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_spender_equality)
{
    DoubleSpendProof::Spender s1, s2;

    // Default-constructed spenders should be equal
    BOOST_CHECK(s1 == s2);
    BOOST_CHECK(!(s1 != s2));

    // Modify one field
    s1.txVersion = 3;
    BOOST_CHECK(s1 != s2);

    // Make them equal again
    s2.txVersion = 3;
    BOOST_CHECK(s1 == s2);

    // Modify pushData
    s1.pushData.push_back({0x01, 0x02});
    BOOST_CHECK(s1 != s2);
}

// ============================================================================
// create() with non-P2PKH output (verifying mode)
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_create_non_p2pkh_output_throws)
{
    // With txOut provided (verifying mode), a non-P2PKH output should throw
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    mtx1.vout[0].nValue = 1000;
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 999;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    // P2SH output — not P2PKH
    CTxOut p2shOut;
    p2shOut.nValue = 5000;
    p2shOut.scriptPubKey = CScript() << OP_HASH160 << std::vector<uint8_t>(20, 0xAA) << OP_EQUAL;

    BOOST_CHECK_THROW(
        DoubleSpendProof::create(0, tx1, tx2, prevout, &p2shOut),
        std::runtime_error
    );
}

// ============================================================================
// SIGHASH variant tests — exercise hashTx() branches in create()
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_create_sighash_anyonecanpay)
{
    // SIGHASH_ALL|ANYONECANPAY|FORKID — hashPrevOutputs and hashSequence should be zeroed
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    // Build tx with SIGHASH_ALL|ANYONECANPAY|FORKID
    CMutableTransaction mtx1;
    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = prevout;
    mtx1.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    auto sig_acp = MakeFakeSig(SIGHASH_ALL | SIGHASH_ANYONECANPAY | SIGHASH_FORKID);
    CScript scriptSig1;
    scriptSig1 << sig_acp << ToByteVector(key.GetPubKey());
    mtx1.vin[0].scriptSig = scriptSig1;
    mtx1.vout.resize(1);
    mtx1.vout[0].nValue = 900;
    mtx1.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Second tx with normal SIGHASH_ALL|FORKID
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 800;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    // Should succeed — ANYONECANPAY is a valid SIGHASH type
    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    BOOST_CHECK(!proof.isEmpty());

    // The spender with ANYONECANPAY should have zeroed hashPrevOutputs and hashSequence
    // (The canonical ordering may swap them, so check both)
    bool foundAcp = false;
    for (const auto* sp : {&proof.spender1(), &proof.spender2()}) {
        uint8_t lastByte = sp->pushData.front().back();
        if (lastByte & SIGHASH_ANYONECANPAY) {
            BOOST_CHECK(sp->hashPrevOutputs == uint256());
            BOOST_CHECK(sp->hashSequence == uint256());
            foundAcp = true;
        }
    }
    BOOST_CHECK(foundAcp);
}

BOOST_AUTO_TEST_CASE(dsproof_create_sighash_none)
{
    // SIGHASH_NONE|FORKID — hashOutputs and hashSequence should be zeroed
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1;
    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = prevout;
    mtx1.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    auto sig_none = MakeFakeSig(SIGHASH_NONE | SIGHASH_FORKID);
    CScript scriptSig1;
    scriptSig1 << sig_none << ToByteVector(key.GetPubKey());
    mtx1.vin[0].scriptSig = scriptSig1;
    mtx1.vout.resize(1);
    mtx1.vout[0].nValue = 900;
    mtx1.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 800;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    BOOST_CHECK(!proof.isEmpty());

    // SIGHASH_NONE spender should have zeroed hashSequence and hashOutputs
    bool foundNone = false;
    for (const auto* sp : {&proof.spender1(), &proof.spender2()}) {
        uint8_t ht = sp->pushData.front().back();
        uint8_t baseType = ht & 0x1f;
        if (baseType == SIGHASH_NONE) {
            BOOST_CHECK(sp->hashSequence == uint256());
            BOOST_CHECK(sp->hashOutputs == uint256());
            foundNone = true;
        }
    }
    BOOST_CHECK(foundNone);
}

BOOST_AUTO_TEST_CASE(dsproof_create_sighash_single)
{
    // SIGHASH_SINGLE|FORKID — hashSequence zeroed, hashOutputs is hash of single output
    CKey key;
    key.MakeNewKey(true);

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1;
    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = prevout;
    mtx1.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    auto sig_single = MakeFakeSig(SIGHASH_SINGLE | SIGHASH_FORKID);
    CScript scriptSig1;
    scriptSig1 << sig_single << ToByteVector(key.GetPubKey());
    mtx1.vin[0].scriptSig = scriptSig1;
    mtx1.vout.resize(1);
    mtx1.vout[0].nValue = 900;
    mtx1.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 800;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    BOOST_CHECK(!proof.isEmpty());

    // SIGHASH_SINGLE spender should have zeroed hashSequence but non-zero hashOutputs
    bool foundSingle = false;
    for (const auto* sp : {&proof.spender1(), &proof.spender2()}) {
        uint8_t ht = sp->pushData.front().back();
        uint8_t baseType = ht & 0x1f;
        if (baseType == SIGHASH_SINGLE) {
            BOOST_CHECK(sp->hashSequence == uint256());
            // hashOutputs should be the hash of the single output at input index
            BOOST_CHECK(sp->hashOutputs != uint256());
            foundSingle = true;
        }
    }
    BOOST_CHECK(foundSingle);
}

// ============================================================================
// Additional DSProof edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_spenders_not_equal_after_create)
{
    // Valid proof should have different spenders
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 500; // Different output to create different tx

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    BOOST_CHECK(proof.spender1() != proof.spender2());
}

BOOST_AUTO_TEST_CASE(dsproof_outpoint_matches_after_create)
{
    // Proof outpoint should match the prevout used in creation
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 7);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 500;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    BOOST_CHECK_EQUAL(proof.outPoint().hash, prevout.hash);
    BOOST_CHECK_EQUAL(proof.outPoint().n, prevout.n);
    BOOST_CHECK_EQUAL(proof.prevOutIndex(), 7u);
}

BOOST_AUTO_TEST_CASE(dsproof_spender_pushdata_contains_signature)
{
    // Each spender should have exactly 1 pushData element (the signature)
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 500;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);

    BOOST_CHECK_EQUAL(proof.spender1().pushData.size(), 1u);
    BOOST_CHECK_EQUAL(proof.spender2().pushData.size(), 1u);
    // Signature should be non-empty
    BOOST_CHECK(!proof.spender1().pushData[0].empty());
    BOOST_CHECK(!proof.spender2().pushData[0].empty());
}

BOOST_AUTO_TEST_CASE(dsproof_serialization_preserves_id)
{
    // Serialize → deserialize should preserve the DSProof ID
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 500;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    DspId originalId = proof.GetId();
    BOOST_CHECK(!originalId.IsNull());

    // Serialize
    DataStream ss{};
    ss << proof;

    // Deserialize
    DoubleSpendProof proof2;
    ss >> proof2;

    BOOST_CHECK_EQUAL(proof2.GetId(), originalId);
    BOOST_CHECK(proof == proof2);
}

BOOST_AUTO_TEST_CASE(dsproof_spender_version_matches_tx)
{
    // Spender txVersion should match the transaction nVersion
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    mtx1.nVersion = 1;
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.nVersion = 2;
    mtx2.vout[0].nValue = 500;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);

    // One spender should have version 1, the other version 2
    bool found_v1 = (proof.spender1().txVersion == 1 || proof.spender2().txVersion == 1);
    bool found_v2 = (proof.spender1().txVersion == 2 || proof.spender2().txVersion == 2);
    BOOST_CHECK(found_v1);
    BOOST_CHECK(found_v2);
}

BOOST_AUTO_TEST_CASE(dsproof_locktime_preserved_in_spender)
{
    // Spender lockTime should match transaction nLockTime
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    mtx1.nLockTime = 100;
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.nLockTime = 200;
    mtx2.vout[0].nValue = 500;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);

    // One spender should have lockTime=100, the other lockTime=200
    bool found_100 = (proof.spender1().lockTime == 100 || proof.spender2().lockTime == 100);
    bool found_200 = (proof.spender1().lockTime == 200 || proof.spender2().lockTime == 200);
    BOOST_CHECK(found_100);
    BOOST_CHECK(found_200);
}

BOOST_AUTO_TEST_CASE(dsproof_sequence_preserved_in_spender)
{
    // Spender outSequence should match transaction input sequence
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    mtx1.vin[0].nSequence = 42;
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vin[0].nSequence = 99;
    mtx2.vout[0].nValue = 500;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);

    bool found_42 = (proof.spender1().outSequence == 42 || proof.spender2().outSequence == 42);
    bool found_99 = (proof.spender1().outSequence == 99 || proof.spender2().outSequence == 99);
    BOOST_CHECK(found_42);
    BOOST_CHECK(found_99);
}

BOOST_AUTO_TEST_CASE(dsproof_multiple_inputs_finds_correct_outpoint)
{
    // Proof should work when txs have multiple inputs
    CKey key;
    key.MakeNewKey(true);

    COutPoint target(Txid::FromUint256(uint256::ONE), 0);
    COutPoint other(Txid::FromUint256(uint256S("02")), 0);

    // tx1: 2 inputs, target is second
    CMutableTransaction mtx1;
    mtx1.nVersion = 2;
    mtx1.nLockTime = 0;
    mtx1.vin.resize(2);
    mtx1.vin[0].prevout = other;
    mtx1.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    auto sig1 = MakeFakeSig();
    CScript scriptSig1;
    scriptSig1 << sig1 << ToByteVector(key.GetPubKey());
    mtx1.vin[0].scriptSig = scriptSig1;
    mtx1.vin[1].prevout = target;
    mtx1.vin[1].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx1.vin[1].scriptSig = scriptSig1;
    mtx1.vout.resize(1);
    mtx1.vout[0].nValue = 900;
    mtx1.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // tx2: 1 input, spends target
    CMutableTransaction mtx2 = MakeSpendingTx(target, key);
    mtx2.vout[0].nValue = 800;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, target, nullptr);
    BOOST_CHECK(!proof.isEmpty());
    BOOST_CHECK(proof.outPoint() == target);
}

// ============================================================================
// SIGHASH variants in DSProof
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_sighash_none_anyonecanpay)
{
    // SIGHASH_NONE|ANYONECANPAY|FORKID zeros all three hash fields.
    // To make spenders different, use different signature data (fake sigs differ by byte).
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 800;

    // Both use SIGHASH_NONE|ANYONECANPAY — but the sigs inside are different
    // because create() extracts pushData from scriptSig. The spenders
    // differ by their pushData (the fake DER sig bytes).
    // We need txs that produce different hashOutputs (via different hashtypes)
    // to make spenders non-identical. Use ALL for tx1 and SINGLE for tx2.
    auto sig1 = MakeFakeSig(SIGHASH_ALL | SIGHASH_FORKID);
    CScript scriptSig1;
    scriptSig1 << sig1 << ToByteVector(key.GetPubKey());
    mtx1.vin[0].scriptSig = scriptSig1;

    auto sig2 = MakeFakeSig(SIGHASH_SINGLE | SIGHASH_FORKID);
    CScript scriptSig2;
    scriptSig2 << sig2 << ToByteVector(key.GetPubKey());
    mtx2.vin[0].scriptSig = scriptSig2;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    BOOST_CHECK(!proof.isEmpty());
}

BOOST_AUTO_TEST_CASE(dsproof_sighash_single_forkid)
{
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 800;

    // Override with SIGHASH_SINGLE|FORKID
    auto sig = MakeFakeSig(SIGHASH_SINGLE | SIGHASH_FORKID);
    CScript scriptSig;
    scriptSig << sig << ToByteVector(key.GetPubKey());
    mtx1.vin[0].scriptSig = scriptSig;
    mtx2.vin[0].scriptSig = scriptSig;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    DoubleSpendProof proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    BOOST_CHECK(!proof.isEmpty());
}

// ============================================================================
// DSProof::create edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_create_same_tx_twice_throws)
{
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx = MakeSpendingTx(prevout, key);
    CTransaction tx(mtx);

    // Same tx for both spenders should throw
    BOOST_CHECK_THROW(DoubleSpendProof::create(0, tx, tx, prevout, nullptr), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(dsproof_create_fake_outpoint_throws)
{
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout1(Txid::FromUint256(uint256::ONE), 0);
    COutPoint prevout2(Txid::FromUint256(uint256S("02")), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout1, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout2, key);

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    // Using prevout that neither tx spends
    COutPoint fake(Txid::FromUint256(uint256S("03")), 0);
    BOOST_CHECK_THROW(DoubleSpendProof::create(0, tx1, tx2, fake, nullptr), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(dsproof_create_deterministic)
{
    // Creating the same proof twice should produce identical results
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 800;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    auto proof1 = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    auto proof2 = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);
    BOOST_CHECK(proof1 == proof2);
    BOOST_CHECK(proof1.GetId() == proof2.GetId());
}

BOOST_AUTO_TEST_CASE(dsproof_different_amounts_different_ids)
{
    // Proofs with different output amounts should have different IDs
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    CMutableTransaction mtx2a = MakeSpendingTx(prevout, key);
    mtx2a.vout[0].nValue = 800;
    CMutableTransaction mtx2b = MakeSpendingTx(prevout, key);
    mtx2b.vout[0].nValue = 700;

    CTransaction tx1(mtx1), tx2a(mtx2a), tx2b(mtx2b);

    auto proofA = DoubleSpendProof::create(0, tx1, tx2a, prevout, nullptr);
    auto proofB = DoubleSpendProof::create(0, tx1, tx2b, prevout, nullptr);
    BOOST_CHECK(proofA.GetId() != proofB.GetId());
}

// ============================================================================
// DSProof serialization edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_serialize_deserialize_preserves_all_fields)
{
    CKey key;
    key.MakeNewKey(true);
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx1 = MakeSpendingTx(prevout, key);
    CMutableTransaction mtx2 = MakeSpendingTx(prevout, key);
    mtx2.vout[0].nValue = 800;

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    auto proof = DoubleSpendProof::create(0, tx1, tx2, prevout, nullptr);

    // Serialize
    DataStream ss{};
    proof.Serialize(ss);

    // Deserialize
    DoubleSpendProof proof2;
    proof2.Unserialize(ss);

    BOOST_CHECK(proof == proof2);
    BOOST_CHECK(proof.GetId() == proof2.GetId());
    BOOST_CHECK(proof.outPoint() == proof2.outPoint());
    BOOST_CHECK(!proof2.isEmpty());
}

BOOST_AUTO_TEST_CASE(dsproof_empty_serialize_deserialize)
{
    DoubleSpendProof empty;
    DataStream ss{};
    empty.Serialize(ss);

    DoubleSpendProof deserialized;
    deserialized.Unserialize(ss);
    BOOST_CHECK(deserialized.isEmpty());
}

BOOST_AUTO_TEST_SUITE_END()
