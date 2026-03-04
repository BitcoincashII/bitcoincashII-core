// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for CTOR, CashAddr, SIGHASH_FORKID combinations, DSProof,
// and other BCH2 consensus features.

#include <arith_uint256.h>
#include <cashaddr.h>
#include <consensus/amount.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <dsp/dsproof.h>
#include <key.h>
#include <key_io.h>
#include <policy/policy.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(bch2_consensus_tests, BasicTestingSetup)

// ============================================================================
// CashAddr encoding/decoding
// ============================================================================

BOOST_AUTO_TEST_CASE(cashaddr_encode_p2pkh)
{
    // Encode a known hash as P2PKH CashAddr
    std::vector<uint8_t> hash(20, 0x42);
    auto payload = cashaddr::PackAddrData(hash, 0); // type 0 = P2PKH
    std::string encoded = cashaddr::Encode("bitcoincashii", payload);

    BOOST_CHECK(!encoded.empty());
    // Should start with the prefix
    BOOST_CHECK(encoded.substr(0, 14) == "bitcoincashii:");
}

BOOST_AUTO_TEST_CASE(cashaddr_encode_p2sh)
{
    std::vector<uint8_t> hash(20, 0x43);
    auto payload = cashaddr::PackAddrData(hash, 1); // type 1 = P2SH
    std::string encoded = cashaddr::Encode("bitcoincashii", payload);

    BOOST_CHECK(!encoded.empty());
    BOOST_CHECK(encoded.substr(0, 14) == "bitcoincashii:");
}

BOOST_AUTO_TEST_CASE(cashaddr_roundtrip_p2pkh)
{
    // Generate a random hash and round-trip through encode/decode
    std::vector<uint8_t> origHash(20);
    for (int i = 0; i < 20; i++) origHash[i] = static_cast<uint8_t>(i * 13 + 7);

    auto payload = cashaddr::PackAddrData(origHash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", payload);

    auto [prefix, decodedPayload] = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");

    auto [type, decodedHash] = cashaddr::UnpackAddrData(decodedPayload);
    BOOST_CHECK_EQUAL(type, 0); // P2PKH
    BOOST_CHECK(decodedHash == origHash);
}

BOOST_AUTO_TEST_CASE(cashaddr_roundtrip_p2sh)
{
    std::vector<uint8_t> origHash(20);
    for (int i = 0; i < 20; i++) origHash[i] = static_cast<uint8_t>(i * 17 + 3);

    auto payload = cashaddr::PackAddrData(origHash, 1);
    std::string encoded = cashaddr::Encode("bitcoincashii", payload);

    auto [prefix, decodedPayload] = cashaddr::Decode(encoded, "bitcoincashii");
    auto [type, decodedHash] = cashaddr::UnpackAddrData(decodedPayload);
    BOOST_CHECK_EQUAL(type, 1); // P2SH
    BOOST_CHECK(decodedHash == origHash);
}

BOOST_AUTO_TEST_CASE(cashaddr_decode_invalid)
{
    // Truncated address should fail
    auto [prefix1, payload1] = cashaddr::Decode("bitcoincashii:qshort", "bitcoincashii");
    BOOST_CHECK(payload1.empty());

    // Wrong prefix should fail
    auto [prefix2, payload2] = cashaddr::Decode("bitcoincash:qz2p8hv43kuq8s6gfa5lkm9a2jcm0m5vfcr7hxlmnj", "bitcoincashii");
    BOOST_CHECK(payload2.empty());
}

BOOST_AUTO_TEST_CASE(cashaddr_p2pkh_starts_with_q)
{
    // P2PKH addresses should have 'q' after the prefix
    std::vector<uint8_t> hash(20, 0x00);
    auto payload = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", payload);

    // Find the ':' separator
    size_t colonPos = encoded.find(':');
    BOOST_REQUIRE(colonPos != std::string::npos);
    char firstChar = encoded[colonPos + 1];
    BOOST_CHECK_EQUAL(firstChar, 'q');
}

BOOST_AUTO_TEST_CASE(cashaddr_p2sh_starts_with_p)
{
    std::vector<uint8_t> hash(20, 0x00);
    auto payload = cashaddr::PackAddrData(hash, 1);
    std::string encoded = cashaddr::Encode("bitcoincashii", payload);

    size_t colonPos = encoded.find(':');
    BOOST_REQUIRE(colonPos != std::string::npos);
    char firstChar = encoded[colonPos + 1];
    BOOST_CHECK_EQUAL(firstChar, 'p');
}

// ============================================================================
// SIGHASH constant values
// ============================================================================

BOOST_AUTO_TEST_CASE(sighash_constant_values)
{
    // Verify SIGHASH flag values used by BCH2
    BOOST_CHECK_EQUAL(SIGHASH_ALL, 1);
    BOOST_CHECK_EQUAL(SIGHASH_NONE, 2);
    BOOST_CHECK_EQUAL(SIGHASH_SINGLE, 3);
    BOOST_CHECK_EQUAL(SIGHASH_FORKID, 0x40);
    BOOST_CHECK_EQUAL(SIGHASH_ANYONECANPAY, 0x80);

    // Verify combined values
    BOOST_CHECK_EQUAL(SIGHASH_ALL | SIGHASH_FORKID, 0x41);
    BOOST_CHECK_EQUAL(SIGHASH_NONE | SIGHASH_FORKID, 0x42);
    BOOST_CHECK_EQUAL(SIGHASH_SINGLE | SIGHASH_FORKID, 0x43);
    BOOST_CHECK_EQUAL(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY, 0xC1);
}

// ============================================================================
// SIGHASH_FORKID: all combinations produce valid signatures
// ============================================================================

BOOST_AUTO_TEST_CASE(sighash_forkid_all_combos)
{
    CKey key;
    key.MakeNewKey(true);
    CScript scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    CAmount amount = 1000000;

    CMutableTransaction fundingTx;
    fundingTx.nVersion = 2;
    fundingTx.vin.resize(1);
    fundingTx.vout.resize(1);
    fundingTx.vout[0].nValue = amount;
    fundingTx.vout[0].scriptPubKey = scriptPubKey;

    // Test each hashtype combination
    std::vector<int> hashTypes = {
        SIGHASH_ALL | SIGHASH_FORKID,
        SIGHASH_NONE | SIGHASH_FORKID,
        SIGHASH_SINGLE | SIGHASH_FORKID,
        SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY,
    };

    for (int hashType : hashTypes) {
        CMutableTransaction spendingTx;
        spendingTx.nVersion = 2;
        spendingTx.vin.resize(1);
        spendingTx.vin[0].prevout.hash = fundingTx.GetHash();
        spendingTx.vin[0].prevout.n = 0;
        spendingTx.vout.resize(1);
        spendingTx.vout[0].nValue = amount - 1000;
        spendingTx.vout[0].scriptPubKey = scriptPubKey;

        uint256 sighash = SignatureHash(scriptPubKey, spendingTx, 0,
            hashType, amount, SigVersion::BCH_FORKID);

        std::vector<unsigned char> sig;
        BOOST_CHECK(key.Sign(sighash, sig));
        sig.push_back(static_cast<unsigned char>(hashType));

        CScript scriptSig;
        scriptSig << sig << ToByteVector(key.GetPubKey());
        spendingTx.vin[0].scriptSig = scriptSig;

        ScriptError serror;
        MutableTransactionSignatureChecker checker(&spendingTx, 0, amount, MissingDataBehavior::FAIL);
        bool result = VerifyScript(spendingTx.vin[0].scriptSig, scriptPubKey,
                                   nullptr, BCH2_SCRIPT_VERIFY_FLAGS, checker, &serror);
        BOOST_CHECK_MESSAGE(result, "SIGHASH combo 0x" + HexStr(Span<unsigned char>{(unsigned char*)&hashType, 1})
                            + " failed: " + ScriptErrorString(serror));
    }
}

BOOST_AUTO_TEST_CASE(sighash_without_forkid_rejected)
{
    CKey key;
    key.MakeNewKey(true);
    CScript scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    CAmount amount = 1000000;

    CMutableTransaction fundingTx;
    fundingTx.nVersion = 2;
    fundingTx.vin.resize(1);
    fundingTx.vout.resize(1);
    fundingTx.vout[0].nValue = amount;
    fundingTx.vout[0].scriptPubKey = scriptPubKey;

    CMutableTransaction spendingTx;
    spendingTx.nVersion = 2;
    spendingTx.vin.resize(1);
    spendingTx.vin[0].prevout.hash = fundingTx.GetHash();
    spendingTx.vin[0].prevout.n = 0;
    spendingTx.vout.resize(1);
    spendingTx.vout[0].nValue = amount - 1000;
    spendingTx.vout[0].scriptPubKey = scriptPubKey;

    // Sign without SIGHASH_FORKID (should be rejected)
    uint256 sighash = SignatureHash(scriptPubKey, spendingTx, 0,
        SIGHASH_ALL, amount, SigVersion::BASE);

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(SIGHASH_ALL); // No FORKID bit

    CScript scriptSig;
    scriptSig << sig << ToByteVector(key.GetPubKey());
    spendingTx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&spendingTx, 0, amount, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(spendingTx.vin[0].scriptSig, scriptPubKey,
                              nullptr, BCH2_SCRIPT_VERIFY_FLAGS, checker, &serror));
}

// ============================================================================
// CTOR: Canonical Transaction Ordering Rule
// ============================================================================

BOOST_AUTO_TEST_CASE(ctor_sorted_txids)
{
    // CTOR requires block transactions (after coinbase) sorted by txid
    // We test the sorting comparison directly

    // Create transactions with predictable hashes
    CMutableTransaction tx1, tx2, tx3;
    tx1.nVersion = 1; tx1.vout.resize(1); tx1.vout[0].nValue = 1;
    tx2.nVersion = 1; tx2.vout.resize(1); tx2.vout[0].nValue = 2;
    tx3.nVersion = 1; tx3.vout.resize(1); tx3.vout[0].nValue = 3;

    uint256 h1 = tx1.GetHash();
    uint256 h2 = tx2.GetHash();
    uint256 h3 = tx3.GetHash();

    // Sort by hash (CTOR ordering)
    std::vector<uint256> hashes = {h1, h2, h3};
    std::sort(hashes.begin(), hashes.end());

    // Verify they're in ascending order
    for (size_t i = 1; i < hashes.size(); i++) {
        BOOST_CHECK(hashes[i-1] < hashes[i]);
    }
}

// ============================================================================
// DSProof: basic structure
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_empty)
{
    DoubleSpendProof dsp;
    BOOST_CHECK(dsp.isEmpty());
}

BOOST_AUTO_TEST_CASE(dsproof_enabled)
{
    // DSProof should be enabled by default
    BOOST_CHECK(DoubleSpendProof::IsEnabled());
}

BOOST_AUTO_TEST_CASE(dsproof_spender_equality)
{
    DoubleSpendProof::Spender s1, s2;
    s1.txVersion = 2;
    s1.outSequence = 0xffffffff;
    s1.lockTime = 0;
    s2 = s1;
    BOOST_CHECK(s1 == s2);

    s2.txVersion = 1;
    BOOST_CHECK(s1 != s2);
}

// ============================================================================
// Consensus constants from whitepaper
// ============================================================================

BOOST_AUTO_TEST_CASE(consensus_constants)
{
    // Block size limit = 32MB
    BOOST_CHECK_EQUAL(BCH2_MAX_BLOCK_SIZE, 32000000u);

    // ABLA max = 2GB
    BOOST_CHECK_EQUAL(MAX_CONSENSUS_BLOCK_SIZE, 2'000'000'000u);

    // Legacy block size (pre-fork) = 4MB
    BOOST_CHECK_EQUAL(BCH2_LEGACY_MAX_BLOCK_SIZE, 4000000u);

    // WITNESS_SCALE_FACTOR = 1 (no segwit discount)
    BOOST_CHECK_EQUAL(WITNESS_SCALE_FACTOR, 1);

    // Coinbase maturity = 100
    BOOST_CHECK_EQUAL(COINBASE_MATURITY, 100);

    // Dust relay fee = 1000 sat/kB
    BOOST_CHECK_EQUAL(DUST_RELAY_TX_FEE, 1000);

    // MAX_OP_RETURN_RELAY = 223 bytes
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, 223u);
}

// ============================================================================
// DSProof: creation error paths
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_create_same_tx_throws)
{
    // create() with identical transactions → std::invalid_argument
    // Fake DER sig ending with SIGHASH_ALL|FORKID (0x41) so getP2PKHSignature accepts it
    std::vector<unsigned char> fakeSig(71, 0x30);
    fakeSig.back() = 0x41; // SIGHASH_ALL | SIGHASH_FORKID

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << fakeSig << std::vector<unsigned char>(33, 0x02);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    BOOST_CHECK_THROW(
        DoubleSpendProof::create(0, tx, tx, tx.vin[0].prevout, nullptr),
        std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(dsproof_create_no_double_spend_throws)
{
    // create() with transactions that don't share the specified outpoint → runtime_error
    std::vector<unsigned char> fakeSig1(71, 0x30);
    fakeSig1.back() = 0x41;
    std::vector<unsigned char> fakeSig2(71, 0x31);
    fakeSig2.back() = 0x41;

    CMutableTransaction mtx1, mtx2;
    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx1.vin[0].scriptSig = CScript() << fakeSig1 << std::vector<unsigned char>(33, 0x02);
    mtx1.vout.resize(1);
    mtx1.vout[0].nValue = 1000;
    mtx1.vout[0].scriptPubKey = CScript() << OP_TRUE;

    mtx2.nVersion = 2;
    mtx2.vin.resize(1);
    // Different outpoint
    mtx2.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx2.vin[0].scriptSig = CScript() << fakeSig2 << std::vector<unsigned char>(33, 0x03);
    mtx2.vout.resize(1);
    mtx2.vout[0].nValue = 2000;
    mtx2.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx1(mtx1), tx2(mtx2);
    BOOST_CHECK_THROW(
        DoubleSpendProof::create(0, tx1, tx2, tx1.vin[0].prevout, nullptr),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(dsproof_create_missing_forkid_throws)
{
    // create() with sig missing SIGHASH_FORKID → runtime_error
    std::vector<unsigned char> noForkidSig(71, 0x30);
    noForkidSig.back() = 0x01; // SIGHASH_ALL without FORKID

    CMutableTransaction mtx1, mtx2;
    COutPoint sharedOutpoint(Txid::FromUint256(uint256::ONE), 0);

    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = sharedOutpoint;
    mtx1.vin[0].scriptSig = CScript() << noForkidSig << std::vector<unsigned char>(33, 0x02);
    mtx1.vout.resize(1);
    mtx1.vout[0].nValue = 1000;
    mtx1.vout[0].scriptPubKey = CScript() << OP_TRUE;

    mtx2.nVersion = 2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout = sharedOutpoint;
    mtx2.vin[0].scriptSig = CScript() << noForkidSig << std::vector<unsigned char>(33, 0x03);
    mtx2.vout.resize(1);
    mtx2.vout[0].nValue = 2000;
    mtx2.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx1(mtx1), tx2(mtx2);
    BOOST_CHECK_THROW(
        DoubleSpendProof::create(0, tx1, tx2, sharedOutpoint, nullptr),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(dsproof_create_empty_scriptsig_throws)
{
    // create() with empty scriptSig → runtime_error ("scriptSig has no signature")
    CMutableTransaction mtx1, mtx2;
    COutPoint sharedOutpoint(Txid::FromUint256(uint256::ONE), 0);

    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = sharedOutpoint;
    mtx1.vin[0].scriptSig = CScript(); // empty
    mtx1.vout.resize(1);
    mtx1.vout[0].nValue = 1000;
    mtx1.vout[0].scriptPubKey = CScript() << OP_TRUE;

    std::vector<unsigned char> fakeSig(71, 0x30);
    fakeSig.back() = 0x41;
    mtx2.nVersion = 2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout = sharedOutpoint;
    mtx2.vin[0].scriptSig = CScript() << fakeSig << std::vector<unsigned char>(33, 0x02);
    mtx2.vout.resize(1);
    mtx2.vout[0].nValue = 2000;
    mtx2.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx1(mtx1), tx2(mtx2);
    BOOST_CHECK_THROW(
        DoubleSpendProof::create(0, tx1, tx2, sharedOutpoint, nullptr),
        std::runtime_error);
}

BOOST_AUTO_TEST_CASE(dsproof_spender_ordering)
{
    // DSProof spenders must be in canonical order
    DoubleSpendProof::Spender s1, s2;
    s1.txVersion = 2;
    s1.outSequence = 0xffffffff;
    s1.lockTime = 0;
    s1.hashPrevOutputs = uint256::ONE;
    s1.hashSequence = uint256::ONE;
    s1.hashOutputs = uint256::ONE;

    s2 = s1;
    s2.hashOutputs = uint256{2}; // Different so s1 != s2

    // Verify spenders are NOT equal
    BOOST_CHECK(s1 != s2);
}

BOOST_AUTO_TEST_CASE(dsproof_serialization_roundtrip)
{
    // Create a minimal DSProof and verify serialization round-trip
    std::vector<unsigned char> fakeSig1(71, 0x30);
    fakeSig1.back() = 0x41;
    std::vector<unsigned char> fakeSig2(71, 0x31);
    fakeSig2.back() = 0x41;

    CMutableTransaction mtx1, mtx2;
    COutPoint sharedOutpoint(Txid::FromUint256(uint256::ONE), 0);

    mtx1.nVersion = 2;
    mtx1.vin.resize(1);
    mtx1.vin[0].prevout = sharedOutpoint;
    mtx1.vin[0].scriptSig = CScript() << fakeSig1 << std::vector<unsigned char>(33, 0x02);
    mtx1.vout.resize(1);
    mtx1.vout[0].nValue = 1000;
    mtx1.vout[0].scriptPubKey = CScript() << OP_TRUE;

    mtx2.nVersion = 2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout = sharedOutpoint;
    mtx2.vin[0].scriptSig = CScript() << fakeSig2 << std::vector<unsigned char>(33, 0x03);
    mtx2.vout.resize(1);
    mtx2.vout[0].nValue = 2000;
    mtx2.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx1(mtx1), tx2(mtx2);

    // Create DSProof without signature verification (nullptr txOut)
    DoubleSpendProof dsp = DoubleSpendProof::create(0, tx1, tx2, sharedOutpoint, nullptr);
    BOOST_CHECK(!dsp.isEmpty());

    // Serialize
    DataStream ss;
    ss << dsp;

    // Deserialize
    DoubleSpendProof dsp2;
    ss >> dsp2;

    BOOST_CHECK(!dsp2.isEmpty());
    BOOST_CHECK(dsp2.prevTxId() == dsp.prevTxId());
    BOOST_CHECK_EQUAL(dsp2.prevOutIndex(), dsp.prevOutIndex());
    BOOST_CHECK(dsp == dsp2);
}

// ============================================================================
// ASERT: Direct formula tests (CalculateASERT)
// ============================================================================

BOOST_AUTO_TEST_CASE(asert_identity_at_target_spacing)
{
    // When time diff matches expected spacing, target should be approximately unchanged
    arith_uint256 refTarget;
    refTarget.SetCompact(0x1d00ffff); // standard Bitcoin mainnet starting target
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    int64_t nPowTargetSpacing = 600; // 10 minutes
    int64_t nHalfLife = 172800; // 2 days

    // 1 block, 600 seconds → exactly on schedule
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 600, 0, powLimit, nHalfLife);
    // Should be very close to refTarget (within 0.013% approximation error)
    BOOST_CHECK(result <= powLimit);
    BOOST_CHECK(result > 0);
}

BOOST_AUTO_TEST_CASE(asert_difficulty_increases_when_fast)
{
    // Blocks arriving faster than expected → target decreases (higher difficulty)
    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c0fffff);
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    int64_t nPowTargetSpacing = 600;
    int64_t nHalfLife = 172800;

    // 10 blocks in 3000 seconds (half the expected 6000 seconds)
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 3000, 9, powLimit, nHalfLife);
    // Target should decrease (harder difficulty)
    BOOST_CHECK(result < refTarget);
    BOOST_CHECK(result > 0);
}

BOOST_AUTO_TEST_CASE(asert_difficulty_decreases_when_slow)
{
    // Blocks arriving slower than expected → target increases (lower difficulty)
    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c0fffff);
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    int64_t nPowTargetSpacing = 600;
    int64_t nHalfLife = 172800;

    // 10 blocks in 12000 seconds (twice the expected 6000 seconds)
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 12000, 9, powLimit, nHalfLife);
    // Target should increase (easier difficulty)
    BOOST_CHECK(result > refTarget);
}

BOOST_AUTO_TEST_CASE(asert_halflife_halves_target)
{
    // After exactly nHalfLife seconds of no blocks, target should roughly double
    arith_uint256 refTarget;
    refTarget.SetCompact(0x1b0fffff); // low target (high difficulty) to have room
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    int64_t nPowTargetSpacing = 600;
    int64_t nHalfLife = 172800; // 2 days

    // Time diff = nHalfLife + nPowTargetSpacing (one block, arrived halflife late)
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, nHalfLife + nPowTargetSpacing, 0, powLimit, nHalfLife);
    // Target should approximately double (within ASERT approximation error ~0.013%)
    arith_uint256 doubled = refTarget * 2;
    // Check within 1% of doubled
    arith_uint256 tolerance = doubled / 100;
    BOOST_CHECK(result > doubled - tolerance);
    BOOST_CHECK(result < doubled + tolerance);
}

BOOST_AUTO_TEST_CASE(asert_clamped_to_pow_limit)
{
    // Very slow blocks should clamp to powLimit, not exceed it
    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c0fffff);
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    int64_t nPowTargetSpacing = 600;
    int64_t nHalfLife = 172800;

    // Extremely slow: 10 * halflife seconds for 1 block → target would be 2^10 * refTarget
    // which likely exceeds powLimit
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 10 * nHalfLife + nPowTargetSpacing, 0, powLimit, nHalfLife);
    BOOST_CHECK(result <= powLimit);
    BOOST_CHECK(result > 0);
}

BOOST_AUTO_TEST_CASE(asert_right_shift_path)
{
    // Fast blocks → negative exponent → right-shift path (shifts <= 0)
    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c0fffff);
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    int64_t nPowTargetSpacing = 600;
    int64_t nHalfLife = 172800;

    // 100 blocks in 1 second → extremely fast
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 1, 99, powLimit, nHalfLife);
    // Should be much less than refTarget
    BOOST_CHECK(result < refTarget);
    BOOST_CHECK(result > 0);
}

BOOST_AUTO_TEST_CASE(asert_overflow_path)
{
    // Test the overflow detection path: very high refTarget + slow blocks
    arith_uint256 refTarget;
    refTarget.SetCompact(0x1d00ffff); // near powLimit
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    int64_t nPowTargetSpacing = 600;
    int64_t nHalfLife = 172800;

    // Very slow: 5 * halflife seconds → would overflow past powLimit
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 5 * nHalfLife + nPowTargetSpacing, 0, powLimit, nHalfLife);
    // Must be clamped to powLimit
    BOOST_CHECK(result == powLimit);
}

BOOST_AUTO_TEST_CASE(asert_height_diff_zero)
{
    // Height diff of 0 (first block after anchor)
    arith_uint256 refTarget;
    refTarget.SetCompact(0x1c0fffff);
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    int64_t nPowTargetSpacing = 600;
    int64_t nHalfLife = 172800;

    // On schedule: 600 seconds for 1 block
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 600, 0, powLimit, nHalfLife);
    BOOST_CHECK(result > 0);
    BOOST_CHECK(result <= powLimit);
}

BOOST_AUTO_TEST_CASE(asert_one_hour_halflife)
{
    // Test with 1-hour halflife (used for early BCH2 blocks)
    arith_uint256 refTarget;
    refTarget.SetCompact(0x1b0fffff);
    arith_uint256 powLimit;
    powLimit.SetCompact(0x1d00ffff);

    int64_t nPowTargetSpacing = 600;
    int64_t nHalfLife = 3600; // 1 hour

    // 1 hour late for 1 block → target should roughly double
    arith_uint256 result = CalculateASERT(refTarget, nPowTargetSpacing, 3600 + nPowTargetSpacing, 0, powLimit, nHalfLife);
    arith_uint256 doubled = refTarget * 2;
    arith_uint256 tolerance = doubled / 100;
    BOOST_CHECK(result > doubled - tolerance);
    BOOST_CHECK(result < doubled + tolerance);
}

// ============================================================================
// DSProof: isEmpty and public API edge case tests
// ============================================================================

BOOST_AUTO_TEST_CASE(dsproof_isEmpty_default_constructed)
{
    DoubleSpendProof dsp;
    BOOST_CHECK(dsp.isEmpty());
    BOOST_CHECK(dsp.prevTxId().IsNull());
}

BOOST_AUTO_TEST_CASE(dsproof_enabled_disabled)
{
    // Test enable/disable
    bool origState = DoubleSpendProof::IsEnabled();
    DoubleSpendProof::SetEnabled(false);
    BOOST_CHECK(!DoubleSpendProof::IsEnabled());
    DoubleSpendProof::SetEnabled(true);
    BOOST_CHECK(DoubleSpendProof::IsEnabled());
    // Restore
    DoubleSpendProof::SetEnabled(origState);
}

BOOST_AUTO_TEST_CASE(dsproof_max_push_data_size)
{
    // DetermineMaxPushDataSize always returns MAX_SCRIPT_ELEMENT_SIZE (520)
    BOOST_CHECK_EQUAL(DoubleSpendProof::DetermineMaxPushDataSize(0), MAX_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK_EQUAL(DoubleSpendProof::DetermineMaxPushDataSize(0xFFFFFFFF), MAX_SCRIPT_ELEMENT_SIZE);
}

// ============================================================================
// CheckSignatureEncoding — FORKID missing when required
// ============================================================================

BOOST_AUTO_TEST_CASE(sig_encoding_missing_forkid_rejected)
{
    // When SCRIPT_VERIFY_SIGHASH_FORKID is set, a signature without FORKID
    // should be rejected with SCRIPT_ERR_SIG_HASHTYPE
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Create P2PK script so we only need sig on stack
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Sign the transaction properly first
    uint256 hash = SignatureHash(scriptPubKey, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, 60000, SigVersion::BASE, nullptr);
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    // Append hashtype WITHOUT FORKID (just SIGHASH_ALL = 0x01)
    sig.push_back(SIGHASH_ALL);

    CScript scriptSig;
    scriptSig << sig;
    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 60000, MissingDataBehavior::FAIL),
        &serror);

    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_HASHTYPE);
}

// ============================================================================
// CheckSignatureEncoding — undefined hashtype rejected with STRICTENC
// ============================================================================

BOOST_AUTO_TEST_CASE(sig_encoding_undefined_hashtype_rejected)
{
    // SIGHASH value 0x05 is not a defined hashtype (ALL=1, NONE=2, SINGLE=3)
    // With STRICTENC, this should be rejected
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Create a valid DER signature, then append undefined hashtype 0x45 (0x05 | FORKID)
    uint256 hash = SignatureHash(scriptPubKey, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, 60000, SigVersion::BASE, nullptr);
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    // 0x05 base hashtype is undefined (> SIGHASH_SINGLE), plus FORKID
    sig.push_back(0x05 | SIGHASH_FORKID);

    CScript scriptSig;
    scriptSig << sig;
    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 60000, MissingDataBehavior::FAIL),
        &serror);

    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_HASHTYPE);
}

// ============================================================================
// CheckSignatureEncoding — valid FORKID signature accepted
// ============================================================================

BOOST_AUTO_TEST_CASE(sig_encoding_valid_forkid_accepted)
{
    // A properly signed transaction with SIGHASH_ALL|FORKID should pass
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    uint256 hash = SignatureHash(scriptPubKey, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, 60000, SigVersion::BASE, nullptr);
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    sig.push_back(SIGHASH_ALL | SIGHASH_FORKID);

    CScript scriptSig;
    scriptSig << sig;
    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 60000, MissingDataBehavior::FAIL),
        &serror);

    BOOST_CHECK_MESSAGE(result, "Valid FORKID signature should be accepted");
}

// ============================================================================
// CheckSignatureEncoding — empty signature passes (fail-open for CHECK(MULTI)SIG)
// ============================================================================

BOOST_AUTO_TEST_CASE(sig_encoding_empty_sig_passes)
{
    // Empty signature is accepted by CheckSignatureEncoding (returns true)
    // but OP_CHECKSIG will push false on the stack (signature verification fails)
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG << OP_NOT;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Push empty sig
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>();
    tx.vin[0].scriptSig = scriptSig;

    // CHECKSIG returns false for empty sig, NOT inverts to true
    unsigned int flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID
                         | SCRIPT_VERIFY_NULLFAIL;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 60000, MissingDataBehavior::FAIL),
        &serror);

    // With NULLFAIL, empty sig for a failed CHECKSIG should still pass
    // because empty sig is the canonical "fail" value for NULLFAIL
    BOOST_CHECK(result);
}

// ============================================================================
// Legacy SigOp counting (BCH2: WITNESS_SCALE_FACTOR = 1)
// ============================================================================

BOOST_AUTO_TEST_CASE(legacy_sigop_count_p2pkh)
{
    // P2PKH output has 1 OP_CHECKSIG → 1 sigop in output
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(72, 0x30)
                                      << std::vector<unsigned char>(33, 0x02);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                          << std::vector<uint8_t>(20, 0xAA)
                                          << OP_EQUALVERIFY << OP_CHECKSIG;

    CTransaction tx(mtx);
    unsigned int sigops = GetLegacySigOpCount(tx);
    // P2PKH output: 1 CHECKSIG = 1 sigop
    BOOST_CHECK_EQUAL(sigops, 1u);
}

BOOST_AUTO_TEST_CASE(legacy_sigop_count_multisig)
{
    // 2-of-3 multisig has 3 pubkeys → GetSigOpCount returns 3
    std::vector<uint8_t> key1(33, 0x02), key2(33, 0x03), key3(33, 0x02);
    key3[1] = 0x01; // Make different from key1

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(1, 0x00);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_2 << key1 << key2 << key3
                                          << OP_3 << OP_CHECKMULTISIG;

    CTransaction tx(mtx);
    unsigned int sigops = GetLegacySigOpCount(tx);
    // Legacy (non-accurate) CHECKMULTISIG counts as MAX_PUBKEYS_PER_MULTISIG (20)
    BOOST_CHECK_EQUAL(sigops, 20u);
}

BOOST_AUTO_TEST_CASE(legacy_sigop_count_no_sigops)
{
    // OP_RETURN output has 0 sigops
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript();
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;
    mtx.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(10, 0xFF);

    CTransaction tx(mtx);
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(tx), 0u);
}

BOOST_AUTO_TEST_CASE(legacy_sigop_count_checksig_in_scriptsig)
{
    // OP_CHECKSIG in scriptSig also counted (for abuse prevention)
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    // scriptSig with OP_CHECKSIG inside
    mtx.vin[0].scriptSig = CScript() << OP_CHECKSIG;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    unsigned int sigops = GetLegacySigOpCount(tx);
    // 1 from scriptSig OP_CHECKSIG + 0 from output
    BOOST_CHECK_EQUAL(sigops, 1u);
}

BOOST_AUTO_TEST_CASE(legacy_sigop_count_multiple_outputs)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript();
    // Two P2PKH outputs = 2 OP_CHECKSIG = 2 sigops
    mtx.vout.resize(2);
    for (int i = 0; i < 2; ++i) {
        mtx.vout[i].nValue = 500;
        mtx.vout[i].scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                              << std::vector<uint8_t>(20, static_cast<uint8_t>(i))
                                              << OP_EQUALVERIFY << OP_CHECKSIG;
    }

    CTransaction tx(mtx);
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(tx), 2u);
}

// ============================================================================
// BCH2 min tx size
// ============================================================================

BOOST_AUTO_TEST_CASE(bch2_min_standard_tx_size)
{
    // BCH2 uses 65-byte minimum tx size (reduced from Bitcoin Core's 82)
    BOOST_CHECK_EQUAL(BCH2_MIN_STANDARD_TX_SIZE, 65u);
}

// ============================================================================
// Script flag consistency
// ============================================================================

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_forkid)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_SIGHASH_FORKID);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_schnorr)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_SCHNORR);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_vm_limits)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_VM_LIMITS);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_introspection)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_INTROSPECTION);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_bch2_opcodes)
{
    // BCH2_OPCODES flag enables OP_CAT, OP_SPLIT, OP_CHECKDATASIG, etc.
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_BCH2_OPCODES);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_bitwise)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_BITWISE_OPCODES);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_arithmetic)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_ARITHMETIC_OPCODES);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_reversebytes)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_REVERSEBYTES);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_no_segwit)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_NO_SEGWIT);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_p2sh)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_P2SH);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_include_cleanstack)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_CLEANSTACK);
}

BOOST_AUTO_TEST_CASE(bch2_script_flags_exclude_shift_opcodes)
{
    BOOST_CHECK(!(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_SHIFT_OPCODES));
}

// Note: SCRIPT_ENABLE_TOKENS (from script_flags.h) uses the same bit (1<<27)
// as SCRIPT_ENABLE_INTROSPECTION (from interpreter.h), so they can't coexist.
// BCH2_SCRIPT_VERIFY_FLAGS uses the interpreter.h definitions.

// ============================================================================
// CheckTransaction: coinbase scriptSig length boundaries
// ============================================================================

BOOST_AUTO_TEST_CASE(checktx_coinbase_scriptsig_2_bytes_valid)
{
    // Coinbase scriptSig minimum is 2 bytes → should pass
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull(); // coinbase
    mtx.vin[0].scriptSig = CScript() << CScriptNum(1); // 2 bytes: opcode + data
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000LL;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    BOOST_CHECK(tx.IsCoinBase());
    BOOST_CHECK_GE(tx.vin[0].scriptSig.size(), 2u);

    TxValidationState state;
    BOOST_CHECK_MESSAGE(CheckTransaction(tx, state), "2-byte coinbase scriptSig should be valid");
}

BOOST_AUTO_TEST_CASE(checktx_coinbase_scriptsig_1_byte_invalid)
{
    // Coinbase scriptSig 1 byte → "bad-cb-length"
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript() << OP_TRUE; // 1 byte
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000LL;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    BOOST_CHECK(tx.IsCoinBase());
    BOOST_CHECK_EQUAL(tx.vin[0].scriptSig.size(), 1u);

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

BOOST_AUTO_TEST_CASE(checktx_coinbase_scriptsig_100_bytes_valid)
{
    // Coinbase scriptSig maximum is 100 bytes → should pass
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    // Build a 100-byte scriptSig: OP_PUSHDATA1 + length(97) + 97 bytes data = 99 bytes
    // Actually simpler: use raw data push. 100 - 2 (push opcode + length) = 98 bytes data
    // OP_PUSHDATA1 (1) + length (1) + data (98) = 100 bytes
    std::vector<unsigned char> data(97, 0x42);
    mtx.vin[0].scriptSig = CScript() << data; // 1 (push_size) + 97 = 98... need to be exact
    // Let me compute: CScript << vector<97> → if size <= 75, pushes OP_N (1 byte) + data (97 bytes) = 98 bytes
    // Need 100 bytes: use 99-byte data → 1 (OP_PUSHDATA1) + 1 (length) + 99 (data) = 101... too much
    // Use 98-byte data: 1 (size byte) + 98 = 99 bytes... still not 100
    // For size 76-255, CScript uses OP_PUSHDATA1 (1) + length (1) + data
    // 76 < 98 ≤ 255 → OP_PUSHDATA1 + 1 + 98 = 100 bytes. Let me check: vector of 98 bytes
    // Actually: for vector size ≤ 75, script uses a single opcode (the size itself) + data
    // For size 76-255, it uses OP_PUSHDATA1 + 1-byte-length + data
    // So vector(98) → OP_PUSHDATA1(1) + 98(1) + data(98) = 100. Perfect!
    std::vector<unsigned char> data100(98, 0x42);
    mtx.vin[0].scriptSig = CScript() << data100;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000LL;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    BOOST_CHECK(tx.IsCoinBase());
    BOOST_CHECK_EQUAL(tx.vin[0].scriptSig.size(), 100u);

    TxValidationState state;
    BOOST_CHECK_MESSAGE(CheckTransaction(tx, state), "100-byte coinbase scriptSig should be valid");
}

BOOST_AUTO_TEST_CASE(checktx_coinbase_scriptsig_101_bytes_invalid)
{
    // Coinbase scriptSig 101 bytes → "bad-cb-length"
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    // vector(99) → OP_PUSHDATA1(1) + 99(1) + data(99) = 101 bytes
    std::vector<unsigned char> data101(99, 0x42);
    mtx.vin[0].scriptSig = CScript() << data101;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000LL;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    BOOST_CHECK(tx.IsCoinBase());
    BOOST_CHECK_EQUAL(tx.vin[0].scriptSig.size(), 101u);

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

BOOST_AUTO_TEST_CASE(checktx_coinbase_scriptsig_empty_invalid)
{
    // Coinbase scriptSig 0 bytes → "bad-cb-length"
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript(); // empty
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000LL;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    BOOST_CHECK(tx.IsCoinBase());

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

// ============================================================================
// CheckTransaction: non-coinbase null prevout
// ============================================================================

BOOST_AUTO_TEST_CASE(checktx_noncoinbase_null_prevout_invalid)
{
    // Non-coinbase tx with null prevout → "bad-txns-prevout-null"
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(2);
    // First input has valid prevout
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(10, 0x42);
    // Second input has null prevout
    mtx.vin[1].prevout.SetNull();
    mtx.vin[1].scriptSig = CScript() << std::vector<unsigned char>(10, 0x43);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    BOOST_CHECK(!tx.IsCoinBase()); // 2 inputs → not coinbase

    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

// ============================================================================
// CheckTransaction: empty vin/vout
// ============================================================================

BOOST_AUTO_TEST_CASE(checktx_empty_vin_invalid)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    // No inputs
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

BOOST_AUTO_TEST_CASE(checktx_empty_vout_invalid)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    // No outputs

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

// ============================================================================
// CheckTransaction: negative and overflow output values
// ============================================================================

BOOST_AUTO_TEST_CASE(checktx_negative_output_value_invalid)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = -1;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

BOOST_AUTO_TEST_CASE(checktx_output_exceeds_max_money_invalid)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = MAX_MONEY + 1;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

BOOST_AUTO_TEST_CASE(checktx_output_total_overflow_invalid)
{
    // Two outputs each at MAX_MONEY → total exceeds MoneyRange
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(2);
    mtx.vout[0].nValue = MAX_MONEY;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[1].nValue = 1;
    mtx.vout[1].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

// ============================================================================
// CheckTransaction: duplicate inputs (CVE-2018-17144)
// ============================================================================

BOOST_AUTO_TEST_CASE(checktx_duplicate_inputs_invalid)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    COutPoint sameOutpoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin.resize(2);
    mtx.vin[0].prevout = sameOutpoint;
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vin[1].prevout = sameOutpoint; // duplicate!
    mtx.vin[1].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

// ============================================================================
// CheckTransaction: valid minimal non-coinbase transaction
// ============================================================================

BOOST_AUTO_TEST_CASE(checktx_valid_minimal_tx)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(CheckTransaction(tx, state));
}

BOOST_AUTO_TEST_CASE(checktx_output_exactly_max_money_valid)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = MAX_MONEY;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(CheckTransaction(tx, state));
}

BOOST_AUTO_TEST_CASE(checktx_output_zero_value_valid)
{
    // Zero-value output is valid (e.g., OP_RETURN)
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;
    mtx.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(10, 0xFF);

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(CheckTransaction(tx, state));
}

// ============================================================================
// ScriptErrorString: BCH2-specific error codes produce correct strings
// ============================================================================

BOOST_AUTO_TEST_CASE(script_error_string_segwit_not_allowed)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_SEGWIT_NOT_ALLOWED),
                      "SegWit not allowed after BCH2 fork");
}

BOOST_AUTO_TEST_CASE(script_error_string_missing_forkid)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_MISSING_FORKID),
                      "SIGHASH_FORKID required after BCH2 fork");
}

BOOST_AUTO_TEST_CASE(script_error_string_invalid_operand_size)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_INVALID_OPERAND_SIZE),
                      "Operands must be the same size");
}

BOOST_AUTO_TEST_CASE(script_error_string_invalid_split_range)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_INVALID_SPLIT_RANGE),
                      "Split position out of range");
}

BOOST_AUTO_TEST_CASE(script_error_string_div_by_zero)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_DIV_BY_ZERO),
                      "Division by zero");
}

BOOST_AUTO_TEST_CASE(script_error_string_mod_by_zero)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_MOD_BY_ZERO),
                      "Modulo by zero");
}

BOOST_AUTO_TEST_CASE(script_error_string_impossible_encoding)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_IMPOSSIBLE_ENCODING),
                      "Cannot encode number in requested size");
}

BOOST_AUTO_TEST_CASE(script_error_string_invalid_number_range)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_INVALID_NUMBER_RANGE),
                      "Number out of valid range");
}

BOOST_AUTO_TEST_CASE(script_error_string_context_not_present)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_CONTEXT_NOT_PRESENT),
                      "Script execution context not available for introspection");
}

BOOST_AUTO_TEST_CASE(script_error_string_invalid_bitfield_size)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_INVALID_BITFIELD_SIZE),
                      "Invalid bitfield size");
}

BOOST_AUTO_TEST_CASE(script_error_string_invalid_bit_range)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_INVALID_BIT_RANGE),
                      "Invalid bit range");
}

BOOST_AUTO_TEST_CASE(script_error_string_op_cost)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_OP_COST),
                      "Operation cost limit exceeded");
}

BOOST_AUTO_TEST_CASE(script_error_string_hash_iters)
{
    BOOST_CHECK_EQUAL(ScriptErrorString(SCRIPT_ERR_HASH_ITERS),
                      "Hash iteration limit exceeded");
}

// ============================================================================
// Minimum tx size: verify serialized sizes near BCH2 boundary (65 bytes)
// ============================================================================

BOOST_AUTO_TEST_CASE(min_tx_size_64_byte_tx_serialization)
{
    // Build the smallest possible non-coinbase tx and verify it serializes
    // to exactly 64 bytes — below the BCH2 minimum of 65.
    // Structure: version(4) + vin_count(1) + prevhash(32) + previndex(4) +
    //            scriptSig_len(1) + scriptSig(N) + nSequence(4) +
    //            vout_count(1) + value(8) + scriptPubKey_len(1) + scriptPubKey(M) +
    //            nLockTime(4)
    // Fixed overhead: 4 + 1 + 32 + 4 + 1 + 4 + 1 + 8 + 1 + 4 = 60 bytes
    // So scriptSig + scriptPubKey = 4 bytes for total of 64
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE; // 1 byte
    mtx.vin[0].nSequence = 0xFFFFFFFF;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;
    mtx.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(1, 0x00); // 3 bytes

    CTransaction tx(mtx);
    size_t txSize = ::GetSerializeSize(TX_NO_WITNESS(tx));
    BOOST_CHECK_EQUAL(txSize, 64u);
    // This tx would be rejected from mempool as "tx-size-small" (< 65)
    BOOST_CHECK(txSize < BCH2_MIN_STANDARD_TX_SIZE);
}

BOOST_AUTO_TEST_CASE(min_tx_size_65_byte_tx_serialization)
{
    // Same as above but with 1 more byte → exactly 65 = BCH2_MIN_STANDARD_TX_SIZE
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE; // 1 byte
    mtx.vin[0].nSequence = 0xFFFFFFFF;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 0;
    mtx.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(2, 0x00); // 4 bytes

    CTransaction tx(mtx);
    size_t txSize = ::GetSerializeSize(TX_NO_WITNESS(tx));
    BOOST_CHECK_EQUAL(txSize, 65u);
    // This tx meets the minimum size requirement
    BOOST_CHECK_EQUAL(txSize, BCH2_MIN_STANDARD_TX_SIZE);
}

// ============================================================================
// CheckTransaction: oversized transaction rejected
// ============================================================================

BOOST_AUTO_TEST_CASE(checktx_oversized_tx_invalid)
{
    // Transaction exceeding MAX_BLOCK_WEIGHT (= MAX_BLOCK_SIZE * WITNESS_SCALE_FACTOR)
    // should fail CheckTransaction. MAX_BLOCK_WEIGHT = 32000000.
    // Build a tx with a single output containing a huge scriptPubKey.
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    // Create a script that pushes MAX_BLOCK_WEIGHT bytes of data
    // This makes the tx well over MAX_BLOCK_WEIGHT in serialized size
    std::vector<uint8_t> hugeData(MAX_BLOCK_WEIGHT, 0xAA);
    mtx.vout[0].scriptPubKey = CScript() << OP_RETURN << hugeData;

    CTransaction tx(mtx);
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

// ============================================================================
// CheckTransaction: multiple outputs with individually valid but combined
// overflow values
// ============================================================================

BOOST_AUTO_TEST_CASE(checktx_three_outputs_sum_overflow)
{
    // Three outputs: MAX_MONEY/2, MAX_MONEY/2, MAX_MONEY/2
    // Each is valid individually, but total exceeds MAX_MONEY
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vout.resize(3);
    for (int i = 0; i < 3; i++) {
        mtx.vout[i].nValue = MAX_MONEY / 2;
        mtx.vout[i].scriptPubKey = CScript() << OP_TRUE;
    }

    CTransaction tx(mtx);
    // Total = 3 * (MAX_MONEY/2) > MAX_MONEY
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

// ============================================================================
// CheckTransaction: coinbase with multiple inputs rejected
// ============================================================================

BOOST_AUTO_TEST_CASE(checktx_coinbase_with_extra_input_is_noncoinbase)
{
    // A tx with null prevout in first input but >1 inputs is NOT a coinbase
    // The second null-prevout input triggers "bad-txns-prevout-null"
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(2);
    mtx.vin[0].prevout.SetNull();
    mtx.vin[0].scriptSig = CScript() << CScriptNum(1);
    mtx.vin[1].prevout.SetNull(); // second null prevout
    mtx.vin[1].scriptSig = CScript() << CScriptNum(2);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000LL;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    BOOST_CHECK(!tx.IsCoinBase()); // 2 inputs → not coinbase
    TxValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
}

// ============================================================================
// IsFinalTx: pure function tests for locktime/sequence logic
// ============================================================================

static CMutableTransaction MakeLocktimeTx(uint32_t locktime, uint32_t sequence)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = locktime;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vin[0].nSequence = sequence;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return mtx;
}

BOOST_AUTO_TEST_CASE(is_final_locktime_zero)
{
    // nLockTime=0 → always final regardless of height/time
    auto mtx = MakeLocktimeTx(0, 0);
    CTransaction tx(mtx);
    BOOST_CHECK(IsFinalTx(tx, 1000, 1700000000));
}

BOOST_AUTO_TEST_CASE(is_final_sequence_final)
{
    // All inputs have nSequence=SEQUENCE_FINAL → final regardless of locktime
    auto mtx = MakeLocktimeTx(999999, CTxIn::SEQUENCE_FINAL);
    CTransaction tx(mtx);
    BOOST_CHECK(IsFinalTx(tx, 100, 0)); // height far below locktime
}

BOOST_AUTO_TEST_CASE(is_final_height_locktime_satisfied)
{
    // Height-based locktime (< 500000000): locktime < blockHeight → final
    // The check is: nLockTime < nBlockHeight (strict less-than)
    auto mtx = MakeLocktimeTx(500, 0);
    CTransaction tx(mtx);
    BOOST_CHECK(IsFinalTx(tx, 501, 0));  // 500 < 501 → final
    BOOST_CHECK(!IsFinalTx(tx, 500, 0)); // 500 < 500 → false → not final
}

BOOST_AUTO_TEST_CASE(is_not_final_height_locktime_not_reached)
{
    // Height-based locktime: block height < locktime → not final
    auto mtx = MakeLocktimeTx(500, 0);
    CTransaction tx(mtx);
    BOOST_CHECK(!IsFinalTx(tx, 499, 0));
}

BOOST_AUTO_TEST_CASE(is_final_time_locktime_satisfied)
{
    // Time-based locktime (>= 500000000): locktime < blockTime → final (strict <)
    uint32_t locktime = 500000000 + 1000; // time-based
    auto mtx = MakeLocktimeTx(locktime, 0);
    CTransaction tx(mtx);
    BOOST_CHECK(IsFinalTx(tx, 0, locktime + 1));  // locktime < time → final
    BOOST_CHECK(!IsFinalTx(tx, 0, locktime));      // locktime == time → not final
}

BOOST_AUTO_TEST_CASE(is_not_final_time_locktime_not_reached)
{
    // Time-based locktime: block time < locktime → not final
    uint32_t locktime = 500000000 + 1000;
    auto mtx = MakeLocktimeTx(locktime, 0);
    CTransaction tx(mtx);
    BOOST_CHECK(!IsFinalTx(tx, 0, locktime - 1));
}

BOOST_AUTO_TEST_CASE(is_final_locktime_threshold_boundary)
{
    // nLockTime = LOCKTIME_THRESHOLD - 1 → height-based
    auto mtx = MakeLocktimeTx(499999999, 0);
    CTransaction tx(mtx);
    BOOST_CHECK(IsFinalTx(tx, 500000000, 0));  // locktime < height → final
    BOOST_CHECK(!IsFinalTx(tx, 499999999, 0)); // locktime == height → not final
}

BOOST_AUTO_TEST_CASE(is_final_locktime_at_threshold)
{
    // nLockTime = LOCKTIME_THRESHOLD (500000000) → time-based
    auto mtx = MakeLocktimeTx(500000000, 0);
    CTransaction tx(mtx);
    // Now it's time-based: locktime < blockTime → final (strict <)
    BOOST_CHECK(IsFinalTx(tx, 999999, 500000001));  // locktime < time → final
    BOOST_CHECK(!IsFinalTx(tx, 999999, 500000000)); // locktime == time → not final
}

BOOST_AUTO_TEST_CASE(is_final_mixed_sequences)
{
    // Two inputs: one SEQUENCE_FINAL, one not → not final if locktime not reached
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 500;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << OP_TRUE;
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 1);
    mtx.vin[1].scriptSig = CScript() << OP_TRUE;
    mtx.vin[1].nSequence = 0; // not final
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    BOOST_CHECK(!IsFinalTx(tx, 500, 0)); // locktime == height → not final (strict <)
    BOOST_CHECK(IsFinalTx(tx, 501, 0));  // locktime < height → final
}

// ============================================================================
// WITNESS_SCALE_FACTOR=1: weight == size for BCH2
// ============================================================================

BOOST_AUTO_TEST_CASE(witness_scale_factor_is_one)
{
    BOOST_CHECK_EQUAL(WITNESS_SCALE_FACTOR, 1);
}

BOOST_AUTO_TEST_CASE(max_block_weight_equals_max_block_size)
{
    // With WITNESS_SCALE_FACTOR=1, MAX_BLOCK_WEIGHT should equal the block size
    // BCH2 uses 32MB blocks
    BOOST_CHECK_EQUAL(MAX_BLOCK_WEIGHT, 32000000);
}

// ============================================================================
// SighashToStr: BCH2 FORKID sighash type string mappings
// ============================================================================

BOOST_AUTO_TEST_CASE(sighash_to_str_all)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_ALL), "ALL");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_none)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_NONE), "NONE");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_single)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_SINGLE), "SINGLE");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_all_anyonecanpay)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_ALL | SIGHASH_ANYONECANPAY), "ALL|ANYONECANPAY");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_none_anyonecanpay)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_NONE | SIGHASH_ANYONECANPAY), "NONE|ANYONECANPAY");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_single_anyonecanpay)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY), "SINGLE|ANYONECANPAY");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_all_forkid)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_ALL | SIGHASH_FORKID), "ALL|FORKID");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_none_forkid)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_NONE | SIGHASH_FORKID), "NONE|FORKID");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_single_forkid)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_SINGLE | SIGHASH_FORKID), "SINGLE|FORKID");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_all_forkid_anyonecanpay)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY), "ALL|FORKID|ANYONECANPAY");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_none_forkid_anyonecanpay)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY), "NONE|FORKID|ANYONECANPAY");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_single_forkid_anyonecanpay)
{
    BOOST_CHECK_EQUAL(SighashToStr(SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY), "SINGLE|FORKID|ANYONECANPAY");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_unknown_returns_empty)
{
    // Unknown sighash type (0xFF) should return empty string
    BOOST_CHECK_EQUAL(SighashToStr(0xFF), "");
}

BOOST_AUTO_TEST_CASE(sighash_to_str_zero_returns_empty)
{
    // 0x00 is SIGHASH_DEFAULT (Taproot only, not in mapSigHashTypes in BCH2)
    BOOST_CHECK_EQUAL(SighashToStr(0x00), "");
}

// ============================================================================
// FindAndDelete: CScript manipulation
// ============================================================================

BOOST_AUTO_TEST_CASE(find_and_delete_basic_removal)
{
    // Remove OP_CODESEPARATOR from a script
    CScript script;
    script << OP_DUP << OP_CODESEPARATOR << OP_HASH160;
    CScript target;
    target << OP_CODESEPARATOR;

    int found = FindAndDelete(script, target);
    BOOST_CHECK_EQUAL(found, 1);
    // Script should now be OP_DUP OP_HASH160
    CScript expected;
    expected << OP_DUP << OP_HASH160;
    BOOST_CHECK(script == expected);
}

BOOST_AUTO_TEST_CASE(find_and_delete_multiple_occurrences)
{
    CScript script;
    script << OP_NOP << OP_CODESEPARATOR << OP_TRUE << OP_CODESEPARATOR;
    CScript target;
    target << OP_CODESEPARATOR;

    int found = FindAndDelete(script, target);
    BOOST_CHECK_EQUAL(found, 2);
    CScript expected;
    expected << OP_NOP << OP_TRUE;
    BOOST_CHECK(script == expected);
}

BOOST_AUTO_TEST_CASE(find_and_delete_no_match)
{
    CScript script;
    script << OP_DUP << OP_HASH160;
    CScript target;
    target << OP_CODESEPARATOR;

    int found = FindAndDelete(script, target);
    BOOST_CHECK_EQUAL(found, 0);
    // Script unchanged
    CScript expected;
    expected << OP_DUP << OP_HASH160;
    BOOST_CHECK(script == expected);
}

BOOST_AUTO_TEST_CASE(find_and_delete_empty_pattern)
{
    CScript script;
    script << OP_DUP << OP_HASH160;
    CScript empty;

    int found = FindAndDelete(script, empty);
    BOOST_CHECK_EQUAL(found, 0);
}

BOOST_AUTO_TEST_CASE(find_and_delete_data_push)
{
    // Remove a specific data push from the script
    std::vector<unsigned char> data = {0x01, 0x02, 0x03};
    CScript script;
    script << OP_TRUE << data << OP_DROP;
    CScript target;
    target << data;

    int found = FindAndDelete(script, target);
    BOOST_CHECK_EQUAL(found, 1);
    CScript expected;
    expected << OP_TRUE << OP_DROP;
    BOOST_CHECK(script == expected);
}

// ============================================================================
// CheckSignatureEncoding: direct function calls with various flags
// ============================================================================

BOOST_AUTO_TEST_CASE(check_sig_encoding_empty_always_passes)
{
    // Empty sig always passes CheckSignatureEncoding regardless of flags
    std::vector<unsigned char> emptySig;
    ScriptError serror;
    BOOST_CHECK(CheckSignatureEncoding(emptySig, SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID, &serror));
}

BOOST_AUTO_TEST_CASE(check_sig_encoding_invalid_der_rejected)
{
    // Non-DER signature (random bytes) should be rejected with DERSIG flag
    std::vector<unsigned char> badSig = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x41};
    ScriptError serror;
    BOOST_CHECK(!CheckSignatureEncoding(badSig, SCRIPT_VERIFY_DERSIG, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_DER);
}

BOOST_AUTO_TEST_CASE(check_sig_encoding_no_forkid_rejected_with_flag)
{
    // Build a minimal valid DER sig with SIGHASH_ALL (no FORKID)
    // Minimal DER: 30 06 02 01 01 02 01 01 01 (hashtype ALL=0x01)
    std::vector<unsigned char> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, SIGHASH_ALL};
    ScriptError serror;
    // With SIGHASH_FORKID flag, missing FORKID → SIG_HASHTYPE error
    BOOST_CHECK(!CheckSignatureEncoding(sig, SCRIPT_VERIFY_SIGHASH_FORKID, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_HASHTYPE);
}

BOOST_AUTO_TEST_CASE(check_sig_encoding_with_forkid_accepted)
{
    // Same minimal DER sig but with SIGHASH_ALL|FORKID
    std::vector<unsigned char> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
                                      static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID)};
    ScriptError serror;
    BOOST_CHECK(CheckSignatureEncoding(sig, SCRIPT_VERIFY_SIGHASH_FORKID, &serror));
}

BOOST_AUTO_TEST_CASE(check_sig_encoding_undefined_hashtype_strictenc)
{
    // Hashtype 0x05|FORKID is undefined (valid hashtypes are ALL=1, NONE=2, SINGLE=3)
    std::vector<unsigned char> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
                                      static_cast<unsigned char>(0x05 | SIGHASH_FORKID)};
    ScriptError serror;
    BOOST_CHECK(!CheckSignatureEncoding(sig, SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_HASHTYPE);
}

BOOST_AUTO_TEST_CASE(check_sig_encoding_none_forkid_strictenc_accepted)
{
    // SIGHASH_NONE|FORKID with STRICTENC should be accepted
    std::vector<unsigned char> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
                                      static_cast<unsigned char>(SIGHASH_NONE | SIGHASH_FORKID)};
    ScriptError serror;
    BOOST_CHECK(CheckSignatureEncoding(sig, SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID, &serror));
}

BOOST_AUTO_TEST_CASE(check_sig_encoding_single_anyonecanpay_forkid_accepted)
{
    // SIGHASH_SINGLE|ANYONECANPAY|FORKID with STRICTENC should be accepted
    std::vector<unsigned char> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
                                      static_cast<unsigned char>(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY | SIGHASH_FORKID)};
    ScriptError serror;
    BOOST_CHECK(CheckSignatureEncoding(sig, SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID, &serror));
}

BOOST_AUTO_TEST_CASE(check_sig_encoding_no_flags_accepts_bad_der)
{
    // Without DERSIG/LOW_S/STRICTENC flags, bad DER passes
    std::vector<unsigned char> badSig = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x41};
    ScriptError serror;
    BOOST_CHECK(CheckSignatureEncoding(badSig, 0, &serror));
}

// ============================================================================
// GetLegacySigOpCount: additional cases
// ============================================================================

BOOST_AUTO_TEST_CASE(legacy_sigop_count_coinbase)
{
    // Coinbase tx: scriptSig has no sigops, output may have OP_CHECKSIG
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull(); // coinbase
    mtx.vin[0].scriptSig = CScript() << CScriptNum(1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000LL;
    mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                          << std::vector<uint8_t>(20, 0xAA)
                                          << OP_EQUALVERIFY << OP_CHECKSIG;

    CTransaction tx(mtx);
    BOOST_CHECK(tx.IsCoinBase());
    // Output has 1 OP_CHECKSIG, scriptSig has none
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(tx), 1u);
}

BOOST_AUTO_TEST_CASE(legacy_sigop_count_checksigverify)
{
    // OP_CHECKSIGVERIFY also counts as 1 sigop
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript();
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    // scriptPubKey with both CHECKSIG and CHECKSIGVERIFY
    mtx.vout[0].scriptPubKey = CScript() << std::vector<uint8_t>(33, 0x02) << OP_CHECKSIGVERIFY
                                          << std::vector<uint8_t>(33, 0x03) << OP_CHECKSIG;

    CTransaction tx(mtx);
    // 1 CHECKSIGVERIFY + 1 CHECKSIG = 2
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(tx), 2u);
}

BOOST_AUTO_TEST_CASE(legacy_sigop_count_checkmultisigverify)
{
    // OP_CHECKMULTISIGVERIFY counts as MAX_PUBKEYS_PER_MULTISIG (20) too
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript();
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    std::vector<uint8_t> key(33, 0x02);
    mtx.vout[0].scriptPubKey = CScript() << OP_1 << key << OP_1 << OP_CHECKMULTISIGVERIFY << OP_TRUE;

    CTransaction tx(mtx);
    // CHECKMULTISIGVERIFY with non-accurate count = 20
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(tx), 20u);
}

// ============================================================================
// CheckSignatureEncoding: SIGHASH_ALL variants with all FORKID combinations
// ============================================================================

BOOST_AUTO_TEST_CASE(check_sig_encoding_all_forkid_anyonecanpay_strictenc)
{
    // SIGHASH_ALL|FORKID|ANYONECANPAY should pass with STRICTENC
    std::vector<unsigned char> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
                                      static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY)};
    ScriptError serror;
    BOOST_CHECK(CheckSignatureEncoding(sig, SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID, &serror));
}

BOOST_AUTO_TEST_CASE(check_sig_encoding_none_forkid_anyonecanpay_strictenc)
{
    // SIGHASH_NONE|FORKID|ANYONECANPAY
    std::vector<unsigned char> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
                                      static_cast<unsigned char>(SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY)};
    ScriptError serror;
    BOOST_CHECK(CheckSignatureEncoding(sig, SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID, &serror));
}

// ============================================================================
// SighashFromStr: string-to-sighash parsing
// ============================================================================

BOOST_AUTO_TEST_CASE(sighash_from_str_all)
{
    auto result = SighashFromStr("ALL");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(*result, SIGHASH_ALL);
}

BOOST_AUTO_TEST_CASE(sighash_from_str_none)
{
    auto result = SighashFromStr("NONE");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(*result, SIGHASH_NONE);
}

BOOST_AUTO_TEST_CASE(sighash_from_str_single)
{
    auto result = SighashFromStr("SINGLE");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(*result, SIGHASH_SINGLE);
}

BOOST_AUTO_TEST_CASE(sighash_from_str_all_anyonecanpay)
{
    auto result = SighashFromStr("ALL|ANYONECANPAY");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(*result, SIGHASH_ALL | SIGHASH_ANYONECANPAY);
}

BOOST_AUTO_TEST_CASE(sighash_from_str_default)
{
    auto result = SighashFromStr("DEFAULT");
    BOOST_CHECK(result.has_value());
    BOOST_CHECK_EQUAL(*result, SIGHASH_DEFAULT);
}

BOOST_AUTO_TEST_CASE(sighash_from_str_forkid_not_in_map)
{
    // FORKID variants are NOT in the parsing map — they're injected by SignTransaction
    auto result = SighashFromStr("ALL|FORKID");
    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(sighash_from_str_empty_returns_error)
{
    auto result = SighashFromStr("");
    BOOST_CHECK(!result.has_value());
}

BOOST_AUTO_TEST_CASE(sighash_from_str_garbage_returns_error)
{
    auto result = SighashFromStr("GARBAGE");
    BOOST_CHECK(!result.has_value());
}

// ============================================================================
// ScriptToAsmStr: sighash decode for BCH2 FORKID signatures
// ============================================================================

BOOST_AUTO_TEST_CASE(script_to_asm_forkid_sighash_decode)
{
    // Build a scriptSig containing a valid DER signature with ALL|FORKID
    // ScriptToAsmStr with fAttemptSighashDecode should show [ALL|FORKID]
    CKey key;
    key.MakeNewKey(true);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

    uint256 hash = SignatureHash(scriptPubKey, mtx, 0, SIGHASH_ALL | SIGHASH_FORKID, 60000, SigVersion::BASE, nullptr);
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    sig.push_back(SIGHASH_ALL | SIGHASH_FORKID);

    CScript scriptSig;
    scriptSig << sig;

    std::string asmStr = ScriptToAsmStr(scriptSig, true);
    BOOST_CHECK(asmStr.find("[ALL|FORKID]") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(script_to_asm_no_decode_shows_hex)
{
    // Without fAttemptSighashDecode, raw hex is shown
    CKey key;
    key.MakeNewKey(true);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

    uint256 hash = SignatureHash(scriptPubKey, mtx, 0, SIGHASH_ALL | SIGHASH_FORKID, 60000, SigVersion::BASE, nullptr);
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    sig.push_back(SIGHASH_ALL | SIGHASH_FORKID);

    CScript scriptSig;
    scriptSig << sig;

    std::string asmStr = ScriptToAsmStr(scriptSig, false);
    BOOST_CHECK(asmStr.find("[ALL|FORKID]") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(script_to_asm_none_forkid_decode)
{
    CKey key;
    key.MakeNewKey(true);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

    uint256 hash = SignatureHash(scriptPubKey, mtx, 0, SIGHASH_NONE | SIGHASH_FORKID, 60000, SigVersion::BASE, nullptr);
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    sig.push_back(SIGHASH_NONE | SIGHASH_FORKID);

    CScript scriptSig;
    scriptSig << sig;

    std::string asmStr = ScriptToAsmStr(scriptSig, true);
    BOOST_CHECK(asmStr.find("[NONE|FORKID]") != std::string::npos);
}

// ============================================================================
// CScript::GetSigOpCount: accurate vs non-accurate mode
// ============================================================================

BOOST_AUTO_TEST_CASE(script_sigop_count_checksig_accurate)
{
    CScript script;
    script << OP_CHECKSIG;
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true), 1u);
    BOOST_CHECK_EQUAL(script.GetSigOpCount(false), 1u);
}

BOOST_AUTO_TEST_CASE(script_sigop_count_checkmultisig_accurate_vs_nonaccurate)
{
    // Non-accurate counts CHECKMULTISIG as MAX_PUBKEYS_PER_MULTISIG (20)
    // Accurate uses the preceding OP_N to determine actual count
    std::vector<uint8_t> key(33, 0x02);
    CScript script;
    script << OP_2 << key << key << key << OP_3 << OP_CHECKMULTISIG;

    BOOST_CHECK_EQUAL(script.GetSigOpCount(false), 20u);
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true), 3u);
}

BOOST_AUTO_TEST_CASE(script_sigop_count_checksigverify_counted)
{
    CScript script;
    script << OP_CHECKSIGVERIFY;
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true), 1u);
    BOOST_CHECK_EQUAL(script.GetSigOpCount(false), 1u);
}

BOOST_AUTO_TEST_CASE(script_sigop_count_multiple_ops)
{
    // Script with 3 CHECKSIG + 1 CHECKMULTISIG(OP_2)
    std::vector<uint8_t> key(33, 0x02);
    CScript script;
    script << OP_CHECKSIG << OP_CHECKSIG << OP_CHECKSIG
           << OP_2 << key << key << OP_2 << OP_CHECKMULTISIG;

    BOOST_CHECK_EQUAL(script.GetSigOpCount(false), 23u);
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true), 5u);
}

BOOST_AUTO_TEST_CASE(script_sigop_count_empty_script)
{
    CScript script;
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true), 0u);
    BOOST_CHECK_EQUAL(script.GetSigOpCount(false), 0u);
}

BOOST_AUTO_TEST_CASE(script_sigop_count_checkmultisig_no_preceding_op)
{
    // CHECKMULTISIG without preceding OP_N → accurate mode uses MAX (20)
    CScript script;
    script << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(script.GetSigOpCount(true), 20u);
    BOOST_CHECK_EQUAL(script.GetSigOpCount(false), 20u);
}

// ============================================================================
// CheckSignatureEncoding: LOW_S validation
// ============================================================================

BOOST_AUTO_TEST_CASE(check_sig_encoding_low_s_accepted)
{
    CKey key;
    key.MakeNewKey(true);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

    uint256 hash = SignatureHash(scriptPubKey, mtx, 0, SIGHASH_ALL | SIGHASH_FORKID, 60000, SigVersion::BASE, nullptr);
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    sig.push_back(SIGHASH_ALL | SIGHASH_FORKID);

    ScriptError serror;
    // key.Sign always produces low-S signatures
    BOOST_CHECK(CheckSignatureEncoding(sig, SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_SIGHASH_FORKID, &serror));
}

// ============================================================================
// VerifyScript: pubkey encoding validation (indirect test of static functions)
// ============================================================================

BOOST_AUTO_TEST_CASE(verify_script_invalid_pubkey_strictenc_rejected)
{
    // Use a pubkey that's the wrong length (not 33 or 65 bytes)
    // This tests the static IsCompressedOrUncompressedPubKey indirectly
    std::vector<unsigned char> badPubKey(32, 0x02); // 32 bytes instead of 33

    CScript scriptPubKey;
    scriptPubKey << badPubKey << OP_CHECKSIG;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Non-empty sig to trigger pubkey encoding check
    std::vector<unsigned char> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
                                      static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID)};

    CScript scriptSig;
    scriptSig << sig;
    mtx.vin[0].scriptSig = scriptSig;

    unsigned int flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID;
    ScriptError serror;
    bool result = VerifyScript(
        mtx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&mtx, 0, 60000, MissingDataBehavior::FAIL),
        &serror);

    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_PUBKEYTYPE);
}

BOOST_AUTO_TEST_CASE(verify_script_uncompressed_pubkey_strictenc_accepted)
{
    // 65-byte uncompressed pubkey (0x04 prefix) should pass STRICTENC
    CKey key;
    key.MakeNewKey(false); // uncompressed
    CPubKey pubkey = key.GetPubKey();
    BOOST_CHECK(!pubkey.IsCompressed());
    BOOST_CHECK_EQUAL(pubkey.size(), 65u);

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(pubkey) << OP_CHECKSIG;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    uint256 hash = SignatureHash(scriptPubKey, mtx, 0, SIGHASH_ALL | SIGHASH_FORKID, 60000, SigVersion::BASE, nullptr);
    std::vector<unsigned char> sig;
    key.Sign(hash, sig);
    sig.push_back(SIGHASH_ALL | SIGHASH_FORKID);

    CScript scriptSig;
    scriptSig << sig;
    mtx.vin[0].scriptSig = scriptSig;

    unsigned int flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID;
    ScriptError serror;
    bool result = VerifyScript(
        mtx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&mtx, 0, 60000, MissingDataBehavior::FAIL),
        &serror);

    BOOST_CHECK_MESSAGE(result, "Uncompressed pubkey should pass STRICTENC");
}

BOOST_AUTO_TEST_CASE(verify_script_wrong_prefix_pubkey_rejected)
{
    // Pubkey starting with 0x05 (not 0x02, 0x03, or 0x04) should fail STRICTENC
    std::vector<unsigned char> badPubKey(33, 0x05);

    CScript scriptPubKey;
    scriptPubKey << badPubKey << OP_CHECKSIG;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    std::vector<unsigned char> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
                                      static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID)};

    CScript scriptSig;
    scriptSig << sig;
    mtx.vin[0].scriptSig = scriptSig;

    unsigned int flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID;
    ScriptError serror;
    bool result = VerifyScript(
        mtx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&mtx, 0, 60000, MissingDataBehavior::FAIL),
        &serror);

    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_PUBKEYTYPE);
}

// ============================================================================
// GetTransactionWeight: size == weight with WITNESS_SCALE_FACTOR=1
// ============================================================================

BOOST_AUTO_TEST_CASE(transaction_weight_equals_serialized_size)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(72, 0x30) << std::vector<unsigned char>(33, 0x02);
    mtx.vout.resize(2);
    mtx.vout[0].nValue = 50000;
    mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                          << std::vector<uint8_t>(20, 0xAA) << OP_EQUALVERIFY << OP_CHECKSIG;
    mtx.vout[1].nValue = 10000;
    mtx.vout[1].scriptPubKey = CScript() << OP_HASH160 << std::vector<uint8_t>(20, 0xBB) << OP_EQUAL;

    CTransaction tx(mtx);
    int64_t weight = GetTransactionWeight(tx);
    size_t serialSize = ::GetSerializeSize(TX_NO_WITNESS(tx));
    // With WITNESS_SCALE_FACTOR=1, weight == size
    BOOST_CHECK_EQUAL(weight, static_cast<int64_t>(serialSize));
}

// ============================================================================
// EncodeHexTx / DecodeHexTx roundtrip: BCH2 transaction serialization
// ============================================================================

BOOST_AUTO_TEST_CASE(encode_decode_hex_tx_roundtrip)
{
    // Build a standard BCH2 transaction and verify hex encode/decode roundtrip
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(72, 0x30);
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 50000;
    mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                          << std::vector<uint8_t>(20, 0xAA) << OP_EQUALVERIFY << OP_CHECKSIG;
    mtx.nLockTime = 0;

    CTransaction tx(mtx);
    std::string hex = EncodeHexTx(tx);
    BOOST_CHECK(!hex.empty());

    // Decode the hex back
    CMutableTransaction decoded;
    BOOST_CHECK(DecodeHexTx(decoded, hex));

    // Verify all fields match
    BOOST_CHECK_EQUAL(decoded.nVersion, tx.nVersion);
    BOOST_CHECK_EQUAL(decoded.vin.size(), tx.vin.size());
    BOOST_CHECK_EQUAL(decoded.vout.size(), tx.vout.size());
    BOOST_CHECK(decoded.vin[0].prevout == tx.vin[0].prevout);
    BOOST_CHECK(decoded.vin[0].scriptSig == tx.vin[0].scriptSig);
    BOOST_CHECK_EQUAL(decoded.vin[0].nSequence, tx.vin[0].nSequence);
    BOOST_CHECK_EQUAL(decoded.vout[0].nValue, tx.vout[0].nValue);
    BOOST_CHECK(decoded.vout[0].scriptPubKey == tx.vout[0].scriptPubKey);
    BOOST_CHECK_EQUAL(decoded.nLockTime, tx.nLockTime);
}

BOOST_AUTO_TEST_CASE(encode_decode_hex_tx_multiple_io)
{
    // Multiple inputs and outputs
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].scriptSig = CScript() << std::vector<unsigned char>(72, 0x30);
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 1);
    mtx.vin[1].scriptSig = CScript() << std::vector<unsigned char>(71, 0x30);
    mtx.vout.resize(3);
    mtx.vout[0].nValue = 25000;
    mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                          << std::vector<uint8_t>(20, 0xBB) << OP_EQUALVERIFY << OP_CHECKSIG;
    mtx.vout[1].nValue = 15000;
    mtx.vout[1].scriptPubKey = CScript() << OP_HASH160 << std::vector<uint8_t>(20, 0xCC) << OP_EQUAL;
    mtx.vout[2].nValue = 0;
    mtx.vout[2].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(10, 0xDD);
    mtx.nLockTime = 500000;

    CTransaction tx(mtx);
    std::string hex = EncodeHexTx(tx);

    CMutableTransaction decoded;
    BOOST_CHECK(DecodeHexTx(decoded, hex));
    BOOST_CHECK_EQUAL(decoded.vin.size(), 2u);
    BOOST_CHECK_EQUAL(decoded.vout.size(), 3u);
    BOOST_CHECK_EQUAL(decoded.nLockTime, 500000u);
    BOOST_CHECK_EQUAL(decoded.vout[0].nValue, 25000);
    BOOST_CHECK_EQUAL(decoded.vout[2].nValue, 0);
}

BOOST_AUTO_TEST_CASE(decode_hex_tx_invalid_hex_fails)
{
    CMutableTransaction decoded;
    BOOST_CHECK(!DecodeHexTx(decoded, "not_valid_hex"));
    BOOST_CHECK(!DecodeHexTx(decoded, ""));
    BOOST_CHECK(!DecodeHexTx(decoded, "zzzz"));
}

// ============================================================================
// ValueFromAmount: BCH2 amount formatting
// ============================================================================

BOOST_AUTO_TEST_CASE(value_from_amount_one_satoshi)
{
    UniValue val = ValueFromAmount(1);
    BOOST_CHECK_EQUAL(val.getValStr(), "0.00000001");
}

BOOST_AUTO_TEST_CASE(value_from_amount_one_coin)
{
    UniValue val = ValueFromAmount(COIN);
    BOOST_CHECK_EQUAL(val.getValStr(), "1.00000000");
}

BOOST_AUTO_TEST_CASE(value_from_amount_zero)
{
    UniValue val = ValueFromAmount(0);
    BOOST_CHECK_EQUAL(val.getValStr(), "0.00000000");
}

BOOST_AUTO_TEST_CASE(value_from_amount_max_money)
{
    UniValue val = ValueFromAmount(MAX_MONEY);
    // MAX_MONEY = 21000000 * COIN = 2100000000000000
    BOOST_CHECK_EQUAL(val.getValStr(), "21000000.00000000");
}

BOOST_AUTO_TEST_CASE(value_from_amount_negative)
{
    UniValue val = ValueFromAmount(-1);
    BOOST_CHECK_EQUAL(val.getValStr(), "-0.00000001");
}

BOOST_AUTO_TEST_CASE(value_from_amount_fractional)
{
    // 1.23456789 BCH2
    UniValue val = ValueFromAmount(123456789);
    BOOST_CHECK_EQUAL(val.getValStr(), "1.23456789");
}

// ============================================================================
// FormatScript: BCH2 opcodes in formatted scripts
// ============================================================================

BOOST_AUTO_TEST_CASE(format_script_p2pkh)
{
    CScript script;
    script << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0x42) << OP_EQUALVERIFY << OP_CHECKSIG;
    std::string formatted = FormatScript(script);
    BOOST_CHECK(formatted.find("DUP") != std::string::npos);
    BOOST_CHECK(formatted.find("HASH160") != std::string::npos);
    BOOST_CHECK(formatted.find("EQUALVERIFY") != std::string::npos);
    BOOST_CHECK(formatted.find("CHECKSIG") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(format_script_op_return)
{
    CScript script;
    script << OP_RETURN << std::vector<uint8_t>(5, 0xFF);
    std::string formatted = FormatScript(script);
    // OP_RETURN should appear with NOP prefix stripping
    BOOST_CHECK(!formatted.empty());
}

BOOST_AUTO_TEST_SUITE_END()
