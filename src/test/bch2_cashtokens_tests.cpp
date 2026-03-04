// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for CashTokens (CHIP-2022-02-CashTokens).
// Covers token validation, introspection opcodes, and token data structures.

#include <coins.h>
#include <compressor.h>
#include <consensus/tokens.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/token.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_execution_context.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

namespace {

// Test fixture that builds a transaction with token-bearing UTXOs
struct TokenIntrospectionSetup {
    CMutableTransaction tx;
    std::vector<CTxOut> spentOutputs;

    // A dummy category ID
    uint256 catId;

    TokenIntrospectionSetup() {
        // Use a recognizable category ID
        catId = uint256S("aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb");

        tx.nVersion = 2;
        tx.nLockTime = 0;

        // One input, one output
        tx.vin.resize(1);
        tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
        tx.vin[0].nSequence = 0xffffffff;

        tx.vout.resize(1);
        tx.vout[0].nValue = 1000;
        tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

        // Spent output (UTXO being consumed) — no token by default
        spentOutputs.resize(1);
        spentOutputs[0].nValue = 2000;
        spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    }

    // Attach a fungible token to the UTXO at input 0
    void SetUtxoFungibleToken(int64_t amount) {
        spentOutputs[0].tokenData.emplace(OutputToken(catId, amount));
    }

    // Attach an NFT (with optional commitment) to the UTXO at input 0
    void SetUtxoNFT(token::Capability cap, const std::vector<uint8_t>& commitment = {}) {
        spentOutputs[0].tokenData.emplace(OutputToken(catId, cap, commitment));
    }

    // Attach an NFT with fungible amount to the UTXO at input 0
    void SetUtxoNFTWithAmount(token::Capability cap, const std::vector<uint8_t>& commitment, int64_t amount) {
        spentOutputs[0].tokenData.emplace(OutputToken(catId, cap, commitment, amount));
    }

    // Attach a fungible token to output 0
    void SetOutputFungibleToken(int64_t amount) {
        tx.vout[0].tokenData.emplace(OutputToken(catId, amount));
    }

    // Attach an NFT to output 0
    void SetOutputNFT(token::Capability cap, const std::vector<uint8_t>& commitment = {}) {
        tx.vout[0].tokenData.emplace(OutputToken(catId, cap, commitment));
    }

    // Evaluate script with introspection context
    bool Eval(const CScript& scriptSig, const CScript& scriptPubKey) {
        tx.vin[0].scriptSig = scriptSig;
        spentOutputs[0].scriptPubKey = scriptPubKey;

        CTransaction txConst(tx);
        ScriptExecutionContext context(0, txConst, spentOutputs);

        unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                             & ~SCRIPT_VERIFY_SIGPUSHONLY
                             & ~SCRIPT_VERIFY_MINIMALDATA;
        ScriptError serror;
        PrecomputedTransactionData txdata;
        txdata.Init(txConst, std::vector<CTxOut>(spentOutputs));
        TransactionSignatureChecker checker(&txConst, 0,
            spentOutputs[0].nValue, txdata, MissingDataBehavior::FAIL, &context);
        return VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(bch2_cashtokens_tests, BasicTestingSetup)

// ============================================================================
// OutputToken validation
// ============================================================================

BOOST_AUTO_TEST_CASE(token_valid_fungible)
{
    uint256 catId = uint256::ONE;
    OutputToken tok(catId, 1000);
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK(tok.HasAmount());
    BOOST_CHECK(!tok.HasNFT());
    BOOST_CHECK_EQUAL(tok.amount, 1000);
}

BOOST_AUTO_TEST_CASE(token_valid_immutable_nft)
{
    uint256 catId = uint256::ONE;
    std::vector<uint8_t> commitment = {0x01, 0x02, 0x03};
    OutputToken tok(catId, token::None, commitment);
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK(tok.HasNFT());
    BOOST_CHECK(tok.IsImmutableToken());
    BOOST_CHECK(!tok.IsMutableToken());
    BOOST_CHECK(!tok.IsMintingToken());
    BOOST_CHECK_EQUAL(tok.GetCapability(), token::None);
}

BOOST_AUTO_TEST_CASE(token_valid_mutable_nft)
{
    uint256 catId = uint256::ONE;
    OutputToken tok(catId, token::Mutable, {0xAA});
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK(tok.IsMutableToken());
    BOOST_CHECK_EQUAL(tok.GetCapability(), token::Mutable);
}

BOOST_AUTO_TEST_CASE(token_valid_minting_nft)
{
    uint256 catId = uint256::ONE;
    OutputToken tok(catId, token::Minting);
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK(tok.IsMintingToken());
    BOOST_CHECK_EQUAL(tok.GetCapability(), token::Minting);
}

BOOST_AUTO_TEST_CASE(token_valid_nft_with_fungible)
{
    uint256 catId = uint256::ONE;
    std::vector<uint8_t> commitment = {0xDE, 0xAD};
    OutputToken tok(catId, token::Mutable, commitment, 5000);
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK(tok.HasNFT());
    BOOST_CHECK(tok.HasAmount());
    BOOST_CHECK_EQUAL(tok.amount, 5000);
}

BOOST_AUTO_TEST_CASE(token_invalid_reserved_bit)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    tok.bitfield = token::BitfieldFlag::HasAmount | token::BitfieldFlag::Reserved;
    tok.amount = 100;
    BOOST_CHECK(!tok.IsValid());
}

BOOST_AUTO_TEST_CASE(token_invalid_capability_without_nft)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    tok.bitfield = token::BitfieldFlag::HasAmount | 0x01; // capability without HasNFT
    tok.amount = 100;
    BOOST_CHECK(!tok.IsValid());
}

BOOST_AUTO_TEST_CASE(token_invalid_commitment_without_nft)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    tok.bitfield = token::BitfieldFlag::HasAmount | token::BitfieldFlag::HasCommitmentLength;
    tok.commitment = {0x01};
    tok.amount = 100;
    BOOST_CHECK(!tok.IsValid());
}

BOOST_AUTO_TEST_CASE(token_invalid_commitment_too_long)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    tok.bitfield = token::BitfieldFlag::HasNFT | token::BitfieldFlag::HasCommitmentLength;
    tok.commitment.resize(41); // Exceeds MAX_COMMITMENT_LENGTH (40)
    BOOST_CHECK(!tok.IsValid());
}

BOOST_AUTO_TEST_CASE(token_max_commitment_length_valid)
{
    uint256 catId = uint256::ONE;
    std::vector<uint8_t> commitment(40, 0xFF); // Exactly MAX_COMMITMENT_LENGTH
    OutputToken tok(catId, token::None, commitment);
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK_EQUAL(tok.commitment.size(), 40u);
}

BOOST_AUTO_TEST_CASE(token_invalid_zero_amount)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    tok.bitfield = token::BitfieldFlag::HasAmount;
    tok.amount = 0; // Invalid: must be > 0
    BOOST_CHECK(!tok.IsValid());
}

BOOST_AUTO_TEST_CASE(token_invalid_no_nft_no_amount)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    tok.bitfield = 0; // No NFT, no amount
    BOOST_CHECK(!tok.IsValid());
}

BOOST_AUTO_TEST_CASE(token_max_amount)
{
    uint256 catId = uint256::ONE;
    OutputToken tok(catId, token::MAX_AMOUNT);
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK_EQUAL(tok.amount, 2099999997690000LL);
}

BOOST_AUTO_TEST_CASE(token_over_max_amount)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    tok.bitfield = token::BitfieldFlag::HasAmount;
    tok.amount = token::MAX_AMOUNT + 1;
    BOOST_CHECK(!tok.IsValid());
}

// ============================================================================
// Token introspection: OP_UTXOTOKENAMOUNT
// ============================================================================

BOOST_AUTO_TEST_CASE(utxo_token_amount_fungible)
{
    TokenIntrospectionSetup t;
    t.SetUtxoFungibleToken(42000);

    CScript scriptSig;
    scriptSig << OP_TRUE;
    // <0> OP_UTXOTOKENAMOUNT should push 42000
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENAMOUNT << CScriptNum(42000) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(utxo_token_amount_no_token)
{
    TokenIntrospectionSetup t;
    // No token attached — amount should be 0

    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENAMOUNT << CScriptNum(0) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(utxo_token_amount_nft_only)
{
    TokenIntrospectionSetup t;
    t.SetUtxoNFT(token::None, {0x01}); // NFT only, no fungible amount

    CScript scriptSig;
    scriptSig << OP_TRUE;
    // NFT without fungible amount → amount returns 0
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENAMOUNT << CScriptNum(0) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

// ============================================================================
// Token introspection: OP_UTXOTOKENCATEGORY
// ============================================================================

BOOST_AUTO_TEST_CASE(utxo_token_category_fungible)
{
    TokenIntrospectionSetup t;
    t.SetUtxoFungibleToken(1000);

    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Fungible-only: push 32-byte category ID
    std::vector<unsigned char> expectedCatId(t.catId.begin(), t.catId.end());
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCATEGORY
                 << expectedCatId << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(utxo_token_category_nft_appends_capability)
{
    TokenIntrospectionSetup t;
    t.SetUtxoNFT(token::Mutable, {0x01});

    CScript scriptSig;
    scriptSig << OP_TRUE;
    // NFT: push 32-byte category ID + 1 byte capability
    std::vector<unsigned char> expectedCatIdWithCap(t.catId.begin(), t.catId.end());
    expectedCatIdWithCap.push_back(static_cast<uint8_t>(token::Mutable)); // 0x01
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCATEGORY
                 << expectedCatIdWithCap << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(utxo_token_category_no_token)
{
    TokenIntrospectionSetup t;
    // No token → returns empty

    CScript scriptSig;
    scriptSig << OP_TRUE;
    std::vector<unsigned char> empty;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCATEGORY
                 << empty << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

// ============================================================================
// Token introspection: OP_UTXOTOKENCOMMITMENT
// ============================================================================

BOOST_AUTO_TEST_CASE(utxo_token_commitment_present)
{
    TokenIntrospectionSetup t;
    std::vector<uint8_t> commitment = {0xDE, 0xAD, 0xBE, 0xEF};
    t.SetUtxoNFT(token::Mutable, commitment);

    CScript scriptSig;
    scriptSig << OP_TRUE;
    std::vector<unsigned char> expectedCommitment(commitment.begin(), commitment.end());
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCOMMITMENT
                 << expectedCommitment << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(utxo_token_commitment_no_nft)
{
    TokenIntrospectionSetup t;
    t.SetUtxoFungibleToken(1000); // Fungible only, no NFT

    CScript scriptSig;
    scriptSig << OP_TRUE;
    std::vector<unsigned char> empty;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCOMMITMENT
                 << empty << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(utxo_token_commitment_empty_nft)
{
    TokenIntrospectionSetup t;
    t.SetUtxoNFT(token::Minting); // NFT with no commitment

    CScript scriptSig;
    scriptSig << OP_TRUE;
    std::vector<unsigned char> empty;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCOMMITMENT
                 << empty << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

// ============================================================================
// Token introspection: OUTPUT variants
// ============================================================================

BOOST_AUTO_TEST_CASE(output_token_amount)
{
    TokenIntrospectionSetup t;
    t.SetOutputFungibleToken(7777);

    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENAMOUNT << CScriptNum(7777) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(output_token_category)
{
    TokenIntrospectionSetup t;
    t.SetOutputFungibleToken(1000);

    CScript scriptSig;
    scriptSig << OP_TRUE;
    std::vector<unsigned char> expectedCatId(t.catId.begin(), t.catId.end());
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENCATEGORY
                 << expectedCatId << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(output_token_commitment)
{
    TokenIntrospectionSetup t;
    std::vector<uint8_t> commitment = {0xCA, 0xFE};
    t.SetOutputNFT(token::None, commitment);

    CScript scriptSig;
    scriptSig << OP_TRUE;
    std::vector<unsigned char> expectedCommitment(commitment.begin(), commitment.end());
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENCOMMITMENT
                 << expectedCommitment << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(output_token_no_token)
{
    TokenIntrospectionSetup t;
    // No token on output → amount returns 0, category returns empty

    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENAMOUNT << CScriptNum(0) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

// ============================================================================
// Token introspection: out-of-bounds index
// ============================================================================

BOOST_AUTO_TEST_CASE(utxo_token_amount_out_of_bounds)
{
    TokenIntrospectionSetup t;

    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_UTXOTOKENAMOUNT << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(output_token_category_out_of_bounds)
{
    TokenIntrospectionSetup t;

    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(10) << OP_OUTPUTTOKENCATEGORY << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

// ============================================================================
// Token constants
// ============================================================================

BOOST_AUTO_TEST_CASE(token_constants)
{
    BOOST_CHECK_EQUAL(token::MAX_COMMITMENT_LENGTH, 40u);
    BOOST_CHECK_EQUAL(token::MAX_AMOUNT, 2099999997690000LL);
    BOOST_CHECK_EQUAL(static_cast<int>(token::None), 0);
    BOOST_CHECK_EQUAL(static_cast<int>(token::Mutable), 1);
    BOOST_CHECK_EQUAL(static_cast<int>(token::Minting), 2);
}

// ============================================================================
// Token equality and comparison
// ============================================================================

BOOST_AUTO_TEST_CASE(token_equality)
{
    uint256 catId = uint256::ONE;
    OutputToken a(catId, 1000);
    OutputToken b(catId, 1000);
    BOOST_CHECK(a == b);

    OutputToken c(catId, 2000);
    BOOST_CHECK(a != c);
}

// ============================================================================
// Token Conservation: CheckTokens() validation
// ============================================================================

BOOST_AUTO_TEST_CASE(token_conservation_fungible_valid)
{
    // Input: 1000 fungible tokens of catId
    // Output: 500 fungible tokens (burning 500 is allowed)
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(catId, 500);

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, 1000);

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(result.valid, "Burning tokens (output < input) should be valid: " + result.error);
}

BOOST_AUTO_TEST_CASE(token_conservation_fungible_overflow)
{
    // Input: 500 fungible tokens
    // Output: 1000 fungible tokens → should FAIL
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(catId, 1000);

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, 500);

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Fungible output > input should be invalid");
    BOOST_CHECK(result.error.find("token-amount-exceeds-input") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_conservation_genesis_creates_tokens)
{
    // Genesis: input 0's outpoint txid matches output token category
    // This allows creating tokens from nothing
    uint256 genesisTxid = uint256{42};

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(genesisTxid), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    // Category = genesisTxid (matches input 0's outpoint txid → genesis)
    mtx.vout[0].tokenData = OutputToken(genesisTxid, 1000000);

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    // No tokens in input — genesis creates from nothing

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(result.valid, "Genesis transaction should create tokens: " + result.error);
}

BOOST_AUTO_TEST_CASE(token_conservation_no_genesis_no_inputs)
{
    // Output has tokens but no matching input tokens AND no genesis → fail
    uint256 catId = uint256::ONE;
    uint256 differentTxid = uint256{99}; // Different from catId, so no genesis

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(differentTxid), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(catId, 500);

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    // No tokens in input

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Tokens without genesis or input should fail");
    BOOST_CHECK(result.error.find("token-category-not-in-inputs") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_conservation_minting_creates_nfts)
{
    // Minting capability input → can create new immutable NFTs
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);

    // Output 0: new immutable NFT
    mtx.vout.resize(2);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(catId, token::None, std::vector<uint8_t>{0x42});
    // Output 1: preserve minting capability
    mtx.vout[1].nValue = 500;
    mtx.vout[1].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[1].tokenData = OutputToken(catId, token::Minting);

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, token::Minting);

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(result.valid, "Minting input should allow creating NFTs: " + result.error);
}

BOOST_AUTO_TEST_CASE(token_conservation_coinbase_with_tokens_fails)
{
    // Coinbase transactions cannot have token outputs
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull(); // Coinbase marker
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 5000000000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(uint256::ONE, 1000);

    std::vector<CTxOut> spentOutputs; // Empty for coinbase

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Coinbase with tokens should fail");
    BOOST_CHECK(result.error.find("coinbase-has-tokens") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_no_tokens_always_valid)
{
    // Transaction with no tokens at all should pass
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(result.valid, "No-token tx should always be valid: " + result.error);
}

// ============================================================================
// Token UTXO Serialization: CTxOut native round-trip
// ============================================================================

BOOST_AUTO_TEST_CASE(token_serialization_fungible_roundtrip)
{
    // Create a CTxOut with fungible token data
    CTxOut txout;
    txout.nValue = 100000;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0xAB) << OP_EQUALVERIFY << OP_CHECKSIG;
    txout.tokenData = OutputToken(uint256::ONE, 42000);

    // Serialize
    DataStream ss;
    ss << txout;

    // Deserialize
    CTxOut txout2;
    ss >> txout2;

    // Verify all fields preserved
    BOOST_CHECK_EQUAL(txout2.nValue, 100000);
    BOOST_CHECK(txout2.scriptPubKey == txout.scriptPubKey);
    BOOST_CHECK(txout2.HasTokenData());
    BOOST_CHECK(txout2.tokenData->HasAmount());
    BOOST_CHECK(!txout2.tokenData->HasNFT());
    BOOST_CHECK_EQUAL(txout2.tokenData->amount, 42000);
    BOOST_CHECK(txout2.tokenData->categoryId == uint256::ONE);
}

BOOST_AUTO_TEST_CASE(token_serialization_nft_roundtrip)
{
    // Create a CTxOut with NFT token data (mutable, with commitment)
    CTxOut txout;
    txout.nValue = 50000;
    txout.scriptPubKey = CScript() << OP_TRUE;
    std::vector<uint8_t> commitment = {0xDE, 0xAD, 0xBE, 0xEF};
    txout.tokenData = OutputToken(uint256::ONE, token::Mutable, commitment);

    DataStream ss;
    ss << txout;

    CTxOut txout2;
    ss >> txout2;

    BOOST_CHECK_EQUAL(txout2.nValue, 50000);
    BOOST_CHECK(txout2.HasTokenData());
    BOOST_CHECK(txout2.tokenData->HasNFT());
    BOOST_CHECK(txout2.tokenData->IsMutableToken());
    BOOST_CHECK_EQUAL(txout2.tokenData->GetCapability(), token::Mutable);
    BOOST_CHECK(txout2.tokenData->commitment == commitment);
    BOOST_CHECK(txout2.tokenData->categoryId == uint256::ONE);
}

BOOST_AUTO_TEST_CASE(token_serialization_nft_with_fungible_roundtrip)
{
    // NFT + fungible amount
    CTxOut txout;
    txout.nValue = 75000;
    txout.scriptPubKey = CScript() << OP_TRUE;
    std::vector<uint8_t> commitment = {0xCA, 0xFE};
    txout.tokenData = OutputToken(uint256::ONE, token::Minting, commitment, 99999);

    DataStream ss;
    ss << txout;

    CTxOut txout2;
    ss >> txout2;

    BOOST_CHECK(txout2.HasTokenData());
    BOOST_CHECK(txout2.tokenData->HasNFT());
    BOOST_CHECK(txout2.tokenData->HasAmount());
    BOOST_CHECK(txout2.tokenData->IsMintingToken());
    BOOST_CHECK_EQUAL(txout2.tokenData->amount, 99999);
    BOOST_CHECK(txout2.tokenData->commitment == commitment);
}

BOOST_AUTO_TEST_CASE(token_serialization_no_token_roundtrip)
{
    // CTxOut without tokens - backward compatibility
    CTxOut txout;
    txout.nValue = 200000;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0x42) << OP_EQUALVERIFY << OP_CHECKSIG;

    DataStream ss;
    ss << txout;

    CTxOut txout2;
    ss >> txout2;

    BOOST_CHECK_EQUAL(txout2.nValue, 200000);
    BOOST_CHECK(txout2.scriptPubKey == txout.scriptPubKey);
    BOOST_CHECK(!txout2.HasTokenData());
}

BOOST_AUTO_TEST_CASE(token_serialization_compressor_roundtrip)
{
    // Test TxOutCompression (UTXO database format)
    CTxOut txout;
    txout.nValue = 100000;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0xAB) << OP_EQUALVERIFY << OP_CHECKSIG;
    txout.tokenData = OutputToken(uint256::ONE, 42000);

    DataStream ss;
    ss << Using<TxOutCompression>(txout);

    CTxOut txout2;
    ss >> Using<TxOutCompression>(txout2);

    BOOST_CHECK_EQUAL(txout2.nValue, txout.nValue);
    BOOST_CHECK(txout2.scriptPubKey == txout.scriptPubKey);
    BOOST_CHECK(txout2.HasTokenData());
    BOOST_CHECK_EQUAL(txout2.tokenData->amount, 42000);
    BOOST_CHECK(txout2.tokenData->categoryId == uint256::ONE);
}

BOOST_AUTO_TEST_CASE(token_serialization_compressor_no_token)
{
    // TxOutCompression without tokens
    CTxOut txout;
    txout.nValue = 200000;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0x42) << OP_EQUALVERIFY << OP_CHECKSIG;

    DataStream ss;
    ss << Using<TxOutCompression>(txout);

    CTxOut txout2;
    ss >> Using<TxOutCompression>(txout2);

    BOOST_CHECK_EQUAL(txout2.nValue, 200000);
    BOOST_CHECK(txout2.scriptPubKey == txout.scriptPubKey);
    BOOST_CHECK(!txout2.HasTokenData());
}

BOOST_AUTO_TEST_CASE(token_serialization_ef_prefix_present)
{
    // Verify that serialized token data starts with 0xEF prefix
    CTxOut txout;
    txout.nValue = 100000;
    txout.scriptPubKey = CScript() << OP_TRUE;
    txout.tokenData = OutputToken(uint256::ONE, 1000);

    DataStream ss;
    ss << txout;

    // Read the serialized bytes
    auto bytes = ss.str();
    // Skip nValue (8 bytes), read compact size, then first byte should be 0xEF
    size_t offset = 8; // nValue
    // Next is compact size of the combined script+token data
    offset++; // skip compact size byte
    // First byte of the combined data should be 0xEF (SPECIAL_TOKEN_PREFIX)
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(bytes[offset]), 0xEF);
}

// ============================================================================
// Token Conservation: multi-category
// ============================================================================

BOOST_AUTO_TEST_CASE(token_conservation_multi_category)
{
    // Two categories, conservation must hold per-category
    uint256 catA = uint256::ONE;
    uint256 catB = uint256{2};

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{10}), 0);
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256{11}), 0);

    // Output: 500 of catA, 300 of catB
    mtx.vout.resize(2);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(catA, 500);
    mtx.vout[1].nValue = 500;
    mtx.vout[1].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[1].tokenData = OutputToken(catB, 300);

    std::vector<CTxOut> spentOutputs(2);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catA, 1000);
    spentOutputs[1].nValue = 2000;
    spentOutputs[1].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[1].tokenData = OutputToken(catB, 500);

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(result.valid, "Multi-category conservation should pass: " + result.error);
}

BOOST_AUTO_TEST_CASE(token_conservation_multi_category_overflow_one)
{
    // Two categories: catA conserves, catB overflows → fail
    uint256 catA = uint256::ONE;
    uint256 catB = uint256{2};

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{10}), 0);
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256{11}), 0);

    mtx.vout.resize(2);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(catA, 500);
    mtx.vout[1].nValue = 500;
    mtx.vout[1].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[1].tokenData = OutputToken(catB, 600); // > 500 input

    std::vector<CTxOut> spentOutputs(2);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catA, 1000);
    spentOutputs[1].nValue = 2000;
    spentOutputs[1].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[1].tokenData = OutputToken(catB, 500);

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Multi-category with one overflow should fail");
}

BOOST_AUTO_TEST_CASE(token_conservation_immutable_downgrade_fails)
{
    // Immutable NFT input cannot produce mutable/minting NFT output
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    // Try to output a mutable NFT from an immutable input
    mtx.vout[0].tokenData = OutputToken(catId, token::Mutable, std::vector<uint8_t>{0x01});

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, token::None, std::vector<uint8_t>{0x01});

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Immutable NFT cannot produce mutable output");
}

// ============================================================================
// CheckTokens() error paths — exhaustive coverage
// ============================================================================

BOOST_AUTO_TEST_CASE(token_inputs_mismatch)
{
    // tokens.cpp:83-85 — spentOutputs.size() != tx.vin.size()
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(2); // 2 inputs
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256{3}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(catId, 500);

    // Only 1 spent output for 2 inputs → mismatch
    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, 1000);

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Should fail with inputs mismatch");
    BOOST_CHECK(result.error.find("token-inputs-mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_invalid_input)
{
    // tokens.cpp:99-101 — !token->IsValid() on an input UTXO
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Create an invalid token on the spent output (reserved bit set)
    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    OutputToken invalidTok;
    invalidTok.categoryId = catId;
    invalidTok.bitfield = token::BitfieldFlag::HasAmount | token::BitfieldFlag::Reserved;
    invalidTok.amount = 100;
    spentOutputs[0].tokenData = invalidTok;

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Should fail with invalid token input");
    BOOST_CHECK(result.error.find("invalid-token-input") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_invalid_output)
{
    // tokens.cpp:135-137 — !token->IsValid() on an output
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    // Create an invalid token on the output (reserved bit set)
    OutputToken invalidTok;
    invalidTok.categoryId = catId;
    invalidTok.bitfield = token::BitfieldFlag::HasAmount | token::BitfieldFlag::Reserved;
    invalidTok.amount = 100;
    mtx.vout[0].tokenData = invalidTok;

    // Valid token on input to trigger the output validation path
    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, 500);

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Should fail with invalid token output");
    BOOST_CHECK(result.error.find("invalid-token-output") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_amount_overflow_input)
{
    // tokens.cpp:107-109 — fungible input amount overflow
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256{3}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(catId, 1000);

    // Two inputs with amounts that overflow when summed
    std::vector<CTxOut> spentOutputs(2);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, token::MAX_AMOUNT);
    spentOutputs[1].nValue = 2000;
    spentOutputs[1].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[1].tokenData = OutputToken(catId, 1); // MAX_AMOUNT + 1 overflows

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Should fail with input amount overflow");
    BOOST_CHECK(result.error.find("token-amount-overflow-input") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_amount_overflow_output)
{
    // tokens.cpp:153-155 — fungible output amount overflow
    uint256 genesisTxid = uint256{2};

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    // Use genesis so we can create arbitrary output amounts
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(genesisTxid), 0);
    mtx.vout.resize(2);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[0].tokenData = OutputToken(genesisTxid, token::MAX_AMOUNT);
    mtx.vout[1].nValue = 500;
    mtx.vout[1].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[1].tokenData = OutputToken(genesisTxid, 1); // overflow

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Should fail with output amount overflow");
    BOOST_CHECK(result.error.find("token-amount-overflow-output") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_minting_without_capability)
{
    // tokens.cpp:189-192 — minting NFT output without minting input (non-genesis)
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    // Use a different txid so this is NOT genesis
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    // Output has minting NFT
    mtx.vout[0].tokenData = OutputToken(catId, token::Minting);

    // Input has only mutable capability (not minting)
    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, token::Mutable, std::vector<uint8_t>{0x01});

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Should fail: minting output requires minting input");
    BOOST_CHECK(result.error.find("token-minting-without-capability") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_mutable_without_capability)
{
    // tokens.cpp:195-199 — mutable NFT output without minting/mutable input (non-genesis)
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    // Output has mutable NFT
    mtx.vout[0].tokenData = OutputToken(catId, token::Mutable, std::vector<uint8_t>{0x01});

    // Input has only immutable capability
    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, token::None, std::vector<uint8_t>{0x01});

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Should fail: mutable output requires minting/mutable input");
    BOOST_CHECK(result.error.find("token-mutable-without-capability") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_immutable_nft_mismatch)
{
    // tokens.cpp:208-211 — immutable NFT commitments don't match (no minting/mutable)
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    // Output: immutable NFT with DIFFERENT commitment
    mtx.vout[0].tokenData = OutputToken(catId, token::None, std::vector<uint8_t>{0xFF});

    // Input: immutable NFT with commitment {0x01}
    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, token::None, std::vector<uint8_t>{0x01});

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Should fail: immutable NFT commitment must match");
    BOOST_CHECK(result.error.find("token-immutable-nft-mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_immutable_nft_count_exceeded)
{
    // tokens.cpp:214-217 — with mutable capability, immutable output count > input+1
    uint256 catId = uint256::ONE;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256{2}), 0);
    // 3 immutable NFT outputs (input has 1 mutable → can convert to at most 1 immutable)
    mtx.vout.resize(3);
    for (int i = 0; i < 3; i++) {
        mtx.vout[i].nValue = 500;
        mtx.vout[i].scriptPubKey = CScript() << OP_TRUE;
        mtx.vout[i].tokenData = OutputToken(catId, token::None, std::vector<uint8_t>{static_cast<uint8_t>(i)});
    }

    // Input: 1 mutable NFT (can convert to at most 1 immutable, so 0+1=1 total)
    // Output: 3 immutable → 3 > 0+1 → exceeded
    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData = OutputToken(catId, token::Mutable, std::vector<uint8_t>{0xAA});

    CTransaction tx(mtx);
    auto result = CheckTokens(tx, spentOutputs);
    BOOST_CHECK_MESSAGE(!result.valid, "Should fail: immutable NFT count exceeded with mutable input");
    BOOST_CHECK(result.error.find("token-immutable-nft-count-exceeded") != std::string::npos);
}

// ============================================================================
// OutputToken::Unserialize error paths
// ============================================================================

BOOST_AUTO_TEST_CASE(token_unserialize_commitment_too_long)
{
    // Manually serialize a token with commitment length > MAX_COMMITMENT_LENGTH (40)
    DataStream ss{};

    // Category ID (32 bytes)
    uint256 catId = uint256::ONE;
    ss << catId;

    // Bitfield: HasNFT | HasCommitmentLength | capability=None
    uint8_t bitfield = token::BitfieldFlag::HasNFT | token::BitfieldFlag::HasCommitmentLength;
    ss << bitfield;

    // Commitment length = 41 (exceeds MAX_COMMITMENT_LENGTH=40)
    WriteCompactSize(ss, 41);
    // Write 41 bytes of commitment data
    std::vector<std::byte> commitData(41, std::byte{0x42});
    ss.write(commitData);

    OutputToken tok;
    BOOST_CHECK_THROW(tok.Unserialize(ss), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(token_unserialize_amount_zero)
{
    // Serialize a token with amount = 0 (invalid)
    DataStream ss{};

    uint256 catId = uint256::ONE;
    ss << catId;

    // Bitfield: HasAmount only
    uint8_t bitfield = token::BitfieldFlag::HasAmount;
    ss << bitfield;

    // Amount = 0 (invalid: must be > 0)
    WriteCompactSize(ss, 0);

    OutputToken tok;
    BOOST_CHECK_THROW(tok.Unserialize(ss), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(token_unserialize_amount_exceeds_max)
{
    // Serialize a token with amount > MAX_AMOUNT
    DataStream ss{};

    uint256 catId = uint256::ONE;
    ss << catId;

    uint8_t bitfield = token::BitfieldFlag::HasAmount;
    ss << bitfield;

    // Amount = MAX_AMOUNT + 1 (invalid)
    WriteCompactSize(ss, static_cast<uint64_t>(token::MAX_AMOUNT) + 1);

    OutputToken tok;
    BOOST_CHECK_THROW(tok.Unserialize(ss), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(token_unserialize_valid_roundtrip)
{
    // Verify a valid token survives serialize→unserialize roundtrip
    OutputToken orig(uint256::ONE, token::Minting, std::vector<uint8_t>{0x01, 0x02, 0x03}, 5000);
    BOOST_CHECK(orig.IsValid());

    DataStream ss{};
    orig.Serialize(ss);

    OutputToken restored;
    restored.Unserialize(ss);

    BOOST_CHECK(restored == orig);
    BOOST_CHECK(restored.IsValid());
    BOOST_CHECK_EQUAL(restored.amount, 5000);
    BOOST_CHECK_EQUAL(restored.commitment.size(), 3u);
}

BOOST_AUTO_TEST_CASE(token_unserialize_commitment_at_max_length)
{
    // Commitment at exactly MAX_COMMITMENT_LENGTH (40) should succeed
    OutputToken orig(uint256::ONE, token::Mutable, std::vector<uint8_t>(40, 0xBB));
    BOOST_CHECK(orig.IsValid());

    DataStream ss{};
    orig.Serialize(ss);

    OutputToken restored;
    BOOST_CHECK_NO_THROW(restored.Unserialize(ss));
    BOOST_CHECK(restored == orig);
}

// ============================================================================
// IsValid: capability > Minting (3+) is invalid
// ============================================================================

BOOST_AUTO_TEST_CASE(token_invalid_capability_above_minting)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    // Set HasNFT + capability 3 (invalid, max is Minting=2)
    tok.bitfield = token::BitfieldFlag::HasNFT | 0x03;
    BOOST_CHECK(!tok.IsValid());
}

// ============================================================================
// IsValid: HasCommitmentLength set but commitment empty
// ============================================================================

BOOST_AUTO_TEST_CASE(token_invalid_commitment_flag_but_empty)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    tok.bitfield = token::BitfieldFlag::HasNFT | token::BitfieldFlag::HasCommitmentLength;
    tok.commitment.clear(); // Empty but flag says HasCommitmentLength
    BOOST_CHECK(!tok.IsValid()); // commitment presence must match flag
}

// ============================================================================
// IsValid: commitment present but HasCommitmentLength flag NOT set
// ============================================================================

BOOST_AUTO_TEST_CASE(token_invalid_commitment_present_but_no_flag)
{
    OutputToken tok;
    tok.categoryId = uint256::ONE;
    tok.bitfield = token::BitfieldFlag::HasNFT; // no HasCommitmentLength
    tok.commitment = {0x01, 0x02}; // commitment exists
    BOOST_CHECK(!tok.IsValid()); // HasCommitment() != !commitment.empty()
}

// ============================================================================
// Token construction helpers
// ============================================================================

BOOST_AUTO_TEST_CASE(token_fungible_constructor)
{
    uint256 catId = uint256::ONE;
    OutputToken tok(catId, 42);
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK(tok.HasAmount());
    BOOST_CHECK(!tok.HasNFT());
    BOOST_CHECK_EQUAL(tok.amount, 42);
    BOOST_CHECK_EQUAL(tok.categoryId, catId);
}

BOOST_AUTO_TEST_CASE(token_nft_plus_fungible_constructor)
{
    uint256 catId = uint256::ONE;
    std::vector<uint8_t> commitment = {0xDE, 0xAD};
    OutputToken tok(catId, token::Mutable, commitment, 1000);
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK(tok.HasNFT());
    BOOST_CHECK(tok.HasAmount());
    BOOST_CHECK(tok.HasCommitment());
    BOOST_CHECK(tok.IsMutableToken());
    BOOST_CHECK(!tok.IsMintingToken());
    BOOST_CHECK(!tok.IsImmutableToken());
    BOOST_CHECK_EQUAL(tok.amount, 1000);
    BOOST_CHECK_EQUAL(tok.commitment.size(), 2u);
}

BOOST_AUTO_TEST_CASE(token_nft_type_predicates)
{
    uint256 catId = uint256::ONE;

    OutputToken immutable(catId, token::None, {0x01});
    BOOST_CHECK(immutable.IsImmutableToken());
    BOOST_CHECK(!immutable.IsMutableToken());
    BOOST_CHECK(!immutable.IsMintingToken());

    OutputToken mutable_(catId, token::Mutable, {0x01});
    BOOST_CHECK(!mutable_.IsImmutableToken());
    BOOST_CHECK(mutable_.IsMutableToken());
    BOOST_CHECK(!mutable_.IsMintingToken());

    OutputToken minting(catId, token::Minting, {});
    BOOST_CHECK(!minting.IsImmutableToken());
    BOOST_CHECK(!minting.IsMutableToken());
    BOOST_CHECK(minting.IsMintingToken());
}

// ===== Coin serialization roundtrip tests =====

BOOST_AUTO_TEST_CASE(coin_roundtrip_with_fungible_token)
{
    // Coin with fungible token should survive serialize/deserialize
    CTxOut out;
    out.nValue = 50000;
    out.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0xAA)
                                 << OP_EQUALVERIFY << OP_CHECKSIG;
    out.tokenData.emplace(OutputToken(uint256::ONE, 999));

    Coin coin(out, 12345, false);
    BOOST_CHECK(!coin.IsSpent());
    BOOST_CHECK(!coin.IsCoinBase());

    DataStream ss{};
    coin.Serialize(ss);

    Coin coin2;
    coin2.Unserialize(ss);

    BOOST_CHECK_EQUAL(coin2.nHeight, 12345u);
    BOOST_CHECK(!coin2.fCoinBase);
    BOOST_CHECK_EQUAL(coin2.out.nValue, 50000);
    BOOST_CHECK(coin2.out.HasTokenData());
    BOOST_CHECK(coin2.out.GetTokenData()->HasAmount());
    BOOST_CHECK_EQUAL(coin2.out.GetTokenData()->amount, 999);
    BOOST_CHECK(coin2.out.GetTokenData()->categoryId == uint256::ONE);
}

BOOST_AUTO_TEST_CASE(coin_roundtrip_with_nft_and_commitment)
{
    // Coin with minting NFT + commitment + fungible should survive roundtrip
    CTxOut out;
    out.nValue = 100000;
    out.scriptPubKey = CScript() << OP_TRUE;
    std::vector<uint8_t> commitment(40, 0xBB); // max-length commitment
    out.tokenData.emplace(OutputToken(uint256S("deadbeef"), token::Minting, commitment, 42));

    Coin coin(out, 999999, true); // coinbase
    DataStream ss{};
    coin.Serialize(ss);

    Coin coin2;
    coin2.Unserialize(ss);

    BOOST_CHECK_EQUAL(coin2.nHeight, 999999u);
    BOOST_CHECK(coin2.fCoinBase);
    BOOST_CHECK(coin2.out.HasTokenData());
    const OutputToken* tok = coin2.out.GetTokenData();
    BOOST_CHECK(tok->IsMintingToken());
    BOOST_CHECK(tok->HasCommitment());
    BOOST_CHECK_EQUAL(tok->commitment.size(), 40u);
    BOOST_CHECK_EQUAL(tok->commitment[0], 0xBB);
    BOOST_CHECK_EQUAL(tok->amount, 42);
}

BOOST_AUTO_TEST_CASE(coin_roundtrip_without_token)
{
    // Coin without token data (baseline)
    CTxOut out;
    out.nValue = 10000;
    out.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0x11)
                                 << OP_EQUALVERIFY << OP_CHECKSIG;

    Coin coin(out, 500, false);
    DataStream ss{};
    coin.Serialize(ss);

    Coin coin2;
    coin2.Unserialize(ss);

    BOOST_CHECK_EQUAL(coin2.nHeight, 500u);
    BOOST_CHECK(!coin2.fCoinBase);
    BOOST_CHECK_EQUAL(coin2.out.nValue, 10000);
    BOOST_CHECK(!coin2.out.HasTokenData());
    BOOST_CHECK(coin2.out.scriptPubKey == out.scriptPubKey);
}

BOOST_AUTO_TEST_CASE(coin_header_encoding)
{
    // Verify header encodes nHeight*2 + fCoinBase correctly
    CTxOut out;
    out.nValue = 1000;
    out.scriptPubKey = CScript() << OP_TRUE;

    // coinbase at height 0: code = 0*2+1 = 1
    Coin coin1(out, 0, true);
    DataStream ss1{};
    coin1.Serialize(ss1);
    Coin c1;
    c1.Unserialize(ss1);
    BOOST_CHECK_EQUAL(c1.nHeight, 0u);
    BOOST_CHECK(c1.fCoinBase);

    // non-coinbase at height 100: code = 100*2+0 = 200
    Coin coin2(out, 100, false);
    DataStream ss2{};
    coin2.Serialize(ss2);
    Coin c2;
    c2.Unserialize(ss2);
    BOOST_CHECK_EQUAL(c2.nHeight, 100u);
    BOOST_CHECK(!c2.fCoinBase);

    // coinbase at height 1000000: code = 1000000*2+1 = 2000001
    Coin coin3(out, 1000000, true);
    DataStream ss3{};
    coin3.Serialize(ss3);
    Coin c3;
    c3.Unserialize(ss3);
    BOOST_CHECK_EQUAL(c3.nHeight, 1000000u);
    BOOST_CHECK(c3.fCoinBase);
}

// ===== Additional CheckTokens validation paths =====

BOOST_AUTO_TEST_CASE(token_conservation_mutable_to_immutable_success)
{
    // Mutable input can be converted to one immutable output with different commitment
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = 0xFFFFFFFFU;

    uint256 catId = uint256S("aabb");

    // Input: mutable NFT with commitment {0x01}
    std::vector<CTxOut> spent(1);
    spent[0].nValue = 5000;
    spent[0].scriptPubKey = CScript() << OP_TRUE;
    spent[0].tokenData.emplace(OutputToken(catId, token::Mutable, {0x01}));

    // Output: immutable NFT with different commitment {0x02}
    tx.vout.resize(1);
    tx.vout[0].nValue = 4000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    tx.vout[0].tokenData.emplace(OutputToken(catId, token::None, {0x02}));

    CTransaction txConst(tx);
    auto result = CheckTokens(txConst, spent);
    BOOST_CHECK(result.valid);
}

BOOST_AUTO_TEST_CASE(token_burn_fungible_partial)
{
    // Burning some fungible tokens is allowed (output < input)
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = 0xFFFFFFFFU;

    uint256 catId = uint256S("beef");

    std::vector<CTxOut> spent(1);
    spent[0].nValue = 5000;
    spent[0].scriptPubKey = CScript() << OP_TRUE;
    spent[0].tokenData.emplace(OutputToken(catId, 1000));

    // Output only 500 of 1000 — burns 500
    tx.vout.resize(1);
    tx.vout[0].nValue = 4000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    tx.vout[0].tokenData.emplace(OutputToken(catId, 500));

    CTransaction txConst(tx);
    auto result = CheckTokens(txConst, spent);
    BOOST_CHECK(result.valid);
}

BOOST_AUTO_TEST_CASE(token_burn_all_fungible)
{
    // Burning ALL fungible tokens (no token output) is allowed
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = 0xFFFFFFFFU;

    uint256 catId = uint256S("cafe");

    std::vector<CTxOut> spent(1);
    spent[0].nValue = 5000;
    spent[0].scriptPubKey = CScript() << OP_TRUE;
    spent[0].tokenData.emplace(OutputToken(catId, 1000));

    // Output has no token — all burned
    tx.vout.resize(1);
    tx.vout[0].nValue = 4000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction txConst(tx);
    auto result = CheckTokens(txConst, spent);
    BOOST_CHECK(result.valid);
}

BOOST_AUTO_TEST_CASE(token_genesis_all_types_at_once)
{
    // Genesis creates minting + mutable + immutable + fungible in one tx
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    uint256 genesisCat = uint256S("aaaa");
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(genesisCat), 0);
    tx.vin[0].nSequence = 0xFFFFFFFFU;

    // No token on input (genesis creates from nothing)
    std::vector<CTxOut> spent(1);
    spent[0].nValue = 100000;
    spent[0].scriptPubKey = CScript() << OP_TRUE;

    tx.vout.resize(4);
    // Minting NFT
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    tx.vout[0].tokenData.emplace(OutputToken(genesisCat, token::Minting, {0x01}));
    // Mutable NFT
    tx.vout[1].nValue = 1000;
    tx.vout[1].scriptPubKey = CScript() << OP_TRUE;
    tx.vout[1].tokenData.emplace(OutputToken(genesisCat, token::Mutable, {0x02}));
    // Immutable NFT
    tx.vout[2].nValue = 1000;
    tx.vout[2].scriptPubKey = CScript() << OP_TRUE;
    tx.vout[2].tokenData.emplace(OutputToken(genesisCat, token::None, {0x03}));
    // Fungible only
    tx.vout[3].nValue = 1000;
    tx.vout[3].scriptPubKey = CScript() << OP_TRUE;
    tx.vout[3].tokenData.emplace(OutputToken(genesisCat, 500000));

    CTransaction txConst(tx);
    auto result = CheckTokens(txConst, spent);
    BOOST_CHECK(result.valid);
}

BOOST_AUTO_TEST_CASE(token_genesis_category_id_helper)
{
    // GetGenesisCategoryId returns input 0's outpoint txid
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(2);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256S("1234")), 0);
    tx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256S("5678")), 0);

    CTransaction txConst(tx);
    BOOST_CHECK(GetGenesisCategoryId(txConst) == uint256S("1234"));

    // Empty vin returns zero
    CMutableTransaction empty;
    empty.nVersion = 2;
    CTransaction emptyConst(empty);
    BOOST_CHECK(GetGenesisCategoryId(emptyConst) == uint256());
}

BOOST_AUTO_TEST_CASE(token_is_genesis_helper)
{
    // IsTokenGenesis returns true only when output category matches input 0 txid
    uint256 genesisCat = uint256S("face");

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(genesisCat), 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    tx.vout[0].tokenData.emplace(OutputToken(genesisCat, 100));

    CTransaction txConst(tx);
    BOOST_CHECK(IsTokenGenesis(txConst));

    // Different category ID → not genesis
    CMutableTransaction tx2;
    tx2.nVersion = 2;
    tx2.vin.resize(1);
    tx2.vin[0].prevout = COutPoint(Txid::FromUint256(uint256S("1111")), 0);
    tx2.vout.resize(1);
    tx2.vout[0].nValue = 1000;
    tx2.vout[0].scriptPubKey = CScript() << OP_TRUE;
    tx2.vout[0].tokenData.emplace(OutputToken(uint256S("2222"), 100));

    CTransaction tx2Const(tx2);
    BOOST_CHECK(!IsTokenGenesis(tx2Const));
}

BOOST_AUTO_TEST_CASE(token_has_token_outputs_helper)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vout.resize(2);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    tx.vout[1].nValue = 2000;
    tx.vout[1].scriptPubKey = CScript() << OP_TRUE;

    // No tokens
    CTransaction tx1(tx);
    BOOST_CHECK(!HasTokenOutputs(tx1));

    // Add token to second output
    tx.vout[1].tokenData.emplace(OutputToken(uint256::ONE, 100));
    CTransaction tx2(tx);
    BOOST_CHECK(HasTokenOutputs(tx2));
}

BOOST_AUTO_TEST_CASE(token_has_token_inputs_helper)
{
    std::vector<CTxOut> spent(2);
    spent[0].nValue = 1000;
    spent[0].scriptPubKey = CScript() << OP_TRUE;
    spent[1].nValue = 2000;
    spent[1].scriptPubKey = CScript() << OP_TRUE;

    BOOST_CHECK(!HasTokenInputs(spent));

    spent[1].tokenData.emplace(OutputToken(uint256::ONE, 100));
    BOOST_CHECK(HasTokenInputs(spent));
}

BOOST_AUTO_TEST_CASE(token_minting_downgrade_to_mutable)
{
    // Minting capability can be downgraded to mutable
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = 0xFFFFFFFFU;

    uint256 catId = uint256S("dddd");

    std::vector<CTxOut> spent(1);
    spent[0].nValue = 5000;
    spent[0].scriptPubKey = CScript() << OP_TRUE;
    spent[0].tokenData.emplace(OutputToken(catId, token::Minting, {0x01}));

    // Output: mutable NFT (downgrade from minting)
    tx.vout.resize(1);
    tx.vout[0].nValue = 4000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    tx.vout[0].tokenData.emplace(OutputToken(catId, token::Mutable, {0x02}));

    CTransaction txConst(tx);
    auto result = CheckTokens(txConst, spent);
    BOOST_CHECK(result.valid);
}

BOOST_AUTO_TEST_CASE(token_ordering_operators)
{
    uint256 cat1 = uint256S("0001");
    uint256 cat2 = uint256S("0002");

    OutputToken a(cat1, 100);
    OutputToken b(cat2, 100);
    OutputToken c(cat1, 200);

    // Different category
    BOOST_CHECK(a < b);

    // Same category, different amount
    BOOST_CHECK(a < c);

    // Equal tokens
    OutputToken d(cat1, 100);
    BOOST_CHECK(!(a < d));
    BOOST_CHECK(!(d < a));
}

// ============================================================================
// OutputToken::ToString()
// ============================================================================

BOOST_AUTO_TEST_CASE(token_to_string_fungible_only)
{
    OutputToken tok(uint256::ONE, 42);
    std::string s = tok.ToString();
    // Should contain "OutputToken(category="
    BOOST_CHECK(s.find("OutputToken(category=") != std::string::npos);
    // Should contain "amount=42"
    BOOST_CHECK(s.find("amount=42") != std::string::npos);
    // Should NOT contain "nft=" (no NFT)
    BOOST_CHECK(s.find("nft=") == std::string::npos);
    // Should end with ")"
    BOOST_CHECK_EQUAL(s.back(), ')');
}

BOOST_AUTO_TEST_CASE(token_to_string_nft_minting)
{
    OutputToken tok(uint256::ONE, token::Minting, {});
    std::string s = tok.ToString();
    BOOST_CHECK(s.find("nft=minting") != std::string::npos);
    // No commitment
    BOOST_CHECK(s.find("commitment=") == std::string::npos);
    // No amount
    BOOST_CHECK(s.find("amount=") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_to_string_nft_mutable_with_commitment)
{
    OutputToken tok(uint256::ONE, token::Mutable, {0xDE, 0xAD});
    std::string s = tok.ToString();
    BOOST_CHECK(s.find("nft=mutable") != std::string::npos);
    BOOST_CHECK(s.find("commitment=dead") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_to_string_nft_immutable)
{
    OutputToken tok(uint256::ONE, token::None, {0x01});
    std::string s = tok.ToString();
    BOOST_CHECK(s.find("nft=none") != std::string::npos);
    BOOST_CHECK(s.find("commitment=01") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_to_string_nft_and_fungible)
{
    OutputToken tok(uint256::ONE, token::Minting, {0xCA, 0xFE}, 999);
    std::string s = tok.ToString();
    BOOST_CHECK(s.find("nft=minting") != std::string::npos);
    BOOST_CHECK(s.find("commitment=cafe") != std::string::npos);
    BOOST_CHECK(s.find("amount=999") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(token_to_string_contains_category_hex)
{
    uint256 catId = uint256S("deadbeef");
    OutputToken tok(catId, 100);
    std::string s = tok.ToString();
    // The category hex should appear in the string
    BOOST_CHECK(s.find(catId.GetHex()) != std::string::npos);
}

// ============================================================================
// ScriptExecutionContext: limited vs full context
// ============================================================================

BOOST_AUTO_TEST_CASE(context_full_is_not_limited)
{
    // Full context constructed with all spent outputs
    TokenIntrospectionSetup setup;
    setup.SetUtxoFungibleToken(5000);
    CTransaction txConst(setup.tx);
    ScriptExecutionContext ctx(0, txConst, setup.spentOutputs);

    BOOST_CHECK(!ctx.isLimited());
    BOOST_CHECK_EQUAL(ctx.inputIndex(), 0u);
    BOOST_CHECK_EQUAL(ctx.inputCount(), 1u);
    BOOST_CHECK_EQUAL(ctx.outputCount(), 1u);
    BOOST_CHECK_EQUAL(ctx.txVersion(), 2);
    BOOST_CHECK_EQUAL(ctx.txLockTime(), 0u);
}

BOOST_AUTO_TEST_CASE(context_limited_is_limited)
{
    // Limited context constructed with single spent output
    TokenIntrospectionSetup setup;
    CTransaction txConst(setup.tx);
    ScriptExecutionContext ctx(0, txConst, setup.spentOutputs[0]);

    BOOST_CHECK(ctx.isLimited());
    BOOST_CHECK_EQUAL(ctx.inputIndex(), 0u);
    // Can still access current input's UTXO
    BOOST_CHECK_EQUAL(ctx.spentOutput().nValue, 2000);
}

BOOST_AUTO_TEST_CASE(context_full_multiple_inputs)
{
    // Full context with 3 inputs, verify all UTXOs accessible
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 42;
    mtx.vin.resize(3);
    for (int i = 0; i < 3; i++) {
        mtx.vin[i].prevout = COutPoint(Txid::FromUint256(uint256::ONE), i);
        mtx.vin[i].nSequence = 0xffffffff;
    }
    mtx.vout.resize(2);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[1].nValue = 300;
    mtx.vout[1].scriptPubKey = CScript() << OP_TRUE;

    std::vector<CTxOut> spentOutputs(3);
    spentOutputs[0].nValue = 1000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[1].nValue = 2000;
    spentOutputs[1].scriptPubKey = CScript() << OP_DUP;
    spentOutputs[2].nValue = 3000;
    spentOutputs[2].scriptPubKey = CScript() << OP_NOP;

    CTransaction txConst(mtx);
    ScriptExecutionContext ctx(1, txConst, spentOutputs);

    BOOST_CHECK(!ctx.isLimited());
    BOOST_CHECK_EQUAL(ctx.inputIndex(), 1u);
    BOOST_CHECK_EQUAL(ctx.inputCount(), 3u);
    BOOST_CHECK_EQUAL(ctx.outputCount(), 2u);
    BOOST_CHECK_EQUAL(ctx.txLockTime(), 42u);

    // Access all UTXOs
    BOOST_CHECK_EQUAL(ctx.utxoValue(0), 1000);
    BOOST_CHECK_EQUAL(ctx.utxoValue(1), 2000);
    BOOST_CHECK_EQUAL(ctx.utxoValue(2), 3000);

    // Access output values
    BOOST_CHECK_EQUAL(ctx.outputValue(0), 500);
    BOOST_CHECK_EQUAL(ctx.outputValue(1), 300);

    // Access outpoint data
    BOOST_CHECK_EQUAL(ctx.outpointIndex(0), 0u);
    BOOST_CHECK_EQUAL(ctx.outpointIndex(1), 1u);
    BOOST_CHECK_EQUAL(ctx.outpointIndex(2), 2u);

    // Sequence number
    BOOST_CHECK_EQUAL(ctx.inputSequenceNumber(0), 0xffffffff);
}

BOOST_AUTO_TEST_CASE(context_limited_other_input_utxo_empty)
{
    // Limited context: non-current input UTXOs have default (zero) values
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 0;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTxOut spentOutput;
    spentOutput.nValue = 9999;
    spentOutput.scriptPubKey = CScript() << OP_DUP;

    CTransaction txConst(mtx);
    ScriptExecutionContext ctx(0, txConst, spentOutput);

    BOOST_CHECK(ctx.isLimited());
    // Current input's UTXO is populated
    BOOST_CHECK_EQUAL(ctx.utxoValue(0), 9999);
    // Other input's UTXO is default-constructed (nValue = -1 for CTxOut())
    BOOST_CHECK_EQUAL(ctx.utxoValue(1), -1);
}

BOOST_AUTO_TEST_CASE(context_token_data_via_utxo)
{
    // Token data accessible through context
    TokenIntrospectionSetup setup;
    setup.SetUtxoFungibleToken(42000);
    CTransaction txConst(setup.tx);
    ScriptExecutionContext ctx(0, txConst, setup.spentOutputs);

    BOOST_CHECK(ctx.utxoHasToken(0));
    const OutputToken* tok = ctx.utxoToken(0);
    BOOST_CHECK(tok != nullptr);
    BOOST_CHECK_EQUAL(tok->amount, 42000);
}

BOOST_AUTO_TEST_CASE(context_no_token_returns_nullptr)
{
    TokenIntrospectionSetup setup;
    // No token set
    CTransaction txConst(setup.tx);
    ScriptExecutionContext ctx(0, txConst, setup.spentOutputs);

    BOOST_CHECK(!ctx.utxoHasToken(0));
    BOOST_CHECK(ctx.utxoToken(0) == nullptr);
}

BOOST_AUTO_TEST_CASE(context_output_token_data)
{
    TokenIntrospectionSetup setup;
    setup.SetOutputFungibleToken(7777);
    CTransaction txConst(setup.tx);
    ScriptExecutionContext ctx(0, txConst, setup.spentOutputs);

    BOOST_CHECK(ctx.outputHasToken(0));
    const OutputToken* tok = ctx.outputToken(0);
    BOOST_CHECK(tok != nullptr);
    BOOST_CHECK_EQUAL(tok->amount, 7777);
}

BOOST_AUTO_TEST_CASE(context_out_of_range_throws)
{
    TokenIntrospectionSetup setup;
    CTransaction txConst(setup.tx);
    ScriptExecutionContext ctx(0, txConst, setup.spentOutputs);

    // Access beyond valid range should throw
    BOOST_CHECK_THROW(ctx.utxoValue(99), std::out_of_range);
    BOOST_CHECK_THROW(ctx.outputValue(99), std::out_of_range);
    BOOST_CHECK_THROW(ctx.inputBytecode(99), std::out_of_range);
}

// ============================================================================
// Token: MAX_AMOUNT boundary
// ============================================================================

BOOST_AUTO_TEST_CASE(token_max_amount_boundary)
{
    // MAX_AMOUNT = 2099999997690000 should be valid
    uint256 catId = uint256::ONE;
    OutputToken tok(catId, token::MAX_AMOUNT);
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK_EQUAL(tok.amount, token::MAX_AMOUNT);
}

BOOST_AUTO_TEST_CASE(token_above_max_amount_invalid)
{
    // MAX_AMOUNT + 1 should be invalid
    uint256 catId = uint256::ONE;
    OutputToken tok(catId, token::MAX_AMOUNT + 1);
    BOOST_CHECK(!tok.IsValid());
}

BOOST_AUTO_TEST_CASE(token_zero_amount_with_nft_valid)
{
    // Amount = 0 is valid if NFT is present
    uint256 catId = uint256::ONE;
    OutputToken tok(catId, token::None, {0x01});
    BOOST_CHECK(tok.IsValid());
    BOOST_CHECK_EQUAL(tok.amount, 0);
}

// ============================================================================
// Token: commitment boundary at MAX_COMMITMENT_LENGTH
// ============================================================================

BOOST_AUTO_TEST_CASE(token_max_commitment_serialization_roundtrip)
{
    // Exactly 40-byte commitment should round-trip through serialization
    uint256 catId = uint256::ONE;
    std::vector<uint8_t> maxCommit(token::MAX_COMMITMENT_LENGTH, 0xAB);
    OutputToken tok(catId, token::Mutable, maxCommit, 500);
    BOOST_CHECK(tok.IsValid());

    // Serialize
    DataStream ss{};
    tok.Serialize(ss);

    // Deserialize
    OutputToken tok2;
    tok2.Unserialize(ss);

    BOOST_CHECK_EQUAL(tok2.amount, 500);
    BOOST_CHECK(tok2.HasNFT());
    BOOST_CHECK_EQUAL(tok2.commitment.size(), token::MAX_COMMITMENT_LENGTH);
    BOOST_CHECK(tok2.commitment == maxCommit);
}

BOOST_AUTO_TEST_CASE(token_oversized_commitment_deserialization_throws)
{
    // Manually construct a serialized token with commitment > 40 bytes
    uint256 catId = uint256::ONE;
    // Valid token with 40-byte commitment
    std::vector<uint8_t> validCommit(token::MAX_COMMITMENT_LENGTH, 0xCC);
    OutputToken validTok(catId, token::Mutable, validCommit);

    DataStream ss{};
    validTok.Serialize(ss);

    // Tamper with the stream: change commitment length byte to 41
    // The serialization layout is: categoryId(32) + bitfield(1) + compactSize(commitment_len) + commitment
    std::string data = ss.str();
    // CompactSize for 40 is a single byte: 0x28. Change to 0x29 (41).
    // But we need to also add one more byte of commitment data.
    // Instead, construct from scratch:
    DataStream tampered{};
    tampered << catId;
    // Bitfield with HasNFT + HasCommitmentLength + Mutable capability
    uint8_t bitfield = 0x61; // HasNFT(0x20) | HasCommitmentLength(0x40) | Mutable(0x01)
    tampered << bitfield;
    // Commitment length = 41 (exceeds max)
    WriteCompactSize(tampered, 41);
    std::vector<uint8_t> oversizedCommit(41, 0xDD);
    tampered.write(MakeByteSpan(oversizedCommit));

    OutputToken badTok;
    BOOST_CHECK_THROW(badTok.Unserialize(tampered), std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(token_max_commitment_coin_roundtrip)
{
    // Max-size commitment through Coin serialization (simulates UTXO DB)
    uint256 catId = uint256::ONE;
    std::vector<uint8_t> maxCommit(token::MAX_COMMITMENT_LENGTH, 0xFE);
    // Use a moderate amount (large amounts hit CompactSize MAX_SIZE limit in deserialization)
    OutputToken tok(catId, token::Minting, maxCommit, 1000000);

    CTxOut out(5000, CScript() << OP_TRUE, tok);
    Coin coin(out, 200, false);

    DataStream ss{};
    ss << coin;

    Coin deserialized;
    ss >> deserialized;

    BOOST_CHECK(deserialized.out.HasTokenData());
    const OutputToken* dtok = deserialized.out.GetTokenData();
    BOOST_CHECK(dtok != nullptr);
    BOOST_CHECK_EQUAL(dtok->amount, 1000000);
    BOOST_CHECK(dtok->commitment == maxCommit);
    BOOST_CHECK_EQUAL(dtok->commitment.size(), token::MAX_COMMITMENT_LENGTH);
    BOOST_CHECK(dtok->HasNFT());
}

BOOST_AUTO_TEST_SUITE_END()
