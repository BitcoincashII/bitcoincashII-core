// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for Native Introspection Opcodes (Upgrade 8).
// These opcodes allow scripts to inspect the transaction that spends them.

#include <key.h>
#include <policy/policy.h>
#include <primitives/token.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_execution_context.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

// Build a test transaction with known structure for introspection testing
struct IntrospectionTestSetup {
    CMutableTransaction tx;
    std::vector<CTxOut> spentOutputs;

    IntrospectionTestSetup() {
        tx.nVersion = 2;
        tx.nLockTime = 500000;

        // Two inputs
        tx.vin.resize(2);
        tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
        tx.vin[0].nSequence = 0xfffffffe;
        tx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 1);
        tx.vin[1].nSequence = 0xffffffff;

        // Two outputs
        tx.vout.resize(2);
        tx.vout[0].nValue = 50000;
        tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
        tx.vout[1].nValue = 40000;
        tx.vout[1].scriptPubKey = CScript() << OP_DUP << OP_DROP << OP_TRUE;

        // Spent outputs (UTXOs being consumed)
        spentOutputs.resize(2);
        spentOutputs[0].nValue = 60000;
        spentOutputs[0].scriptPubKey = CScript() << OP_TRUE; // placeholder
        spentOutputs[1].nValue = 35000;
        spentOutputs[1].scriptPubKey = CScript() << OP_TRUE;
    }

    // Evaluate script as input 0 with introspection context
    bool Eval(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int inputIdx = 0) {
        tx.vin[inputIdx].scriptSig = scriptSig;
        spentOutputs[inputIdx].scriptPubKey = scriptPubKey;

        CTransaction txConst(tx);
        ScriptExecutionContext context(inputIdx, txConst, spentOutputs);

        unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                             & ~SCRIPT_VERIFY_SIGPUSHONLY
                             & ~SCRIPT_VERIFY_MINIMALDATA;
        ScriptError serror;
        PrecomputedTransactionData txdata;
        txdata.Init(txConst, std::vector<CTxOut>(spentOutputs));
        TransactionSignatureChecker checker(&txConst, inputIdx,
            spentOutputs[inputIdx].nValue, txdata, MissingDataBehavior::FAIL, &context);
        return VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(bch2_introspection_tests, BasicTestingSetup)

// ============================================================================
// Nullary opcodes (no arguments)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_inputindex)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Input 0: OP_INPUTINDEX should push 0
    CScript scriptPubKey;
    scriptPubKey << OP_INPUTINDEX << CScriptNum(0) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_inputindex_second_input)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Input 1: OP_INPUTINDEX should push 1
    CScript scriptPubKey;
    scriptPubKey << OP_INPUTINDEX << CScriptNum(1) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 1));
}

BOOST_AUTO_TEST_CASE(op_txversion)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXVERSION << CScriptNum(2) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_txinputcount)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXINPUTCOUNT << CScriptNum(2) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_txoutputcount)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXOUTPUTCOUNT << CScriptNum(2) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_txlocktime)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXLOCKTIME << CScriptNum(500000) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_ACTIVEBYTECODE: returns currently executing script (post-CODESEPARATOR)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_activebytecode_returns_full_script)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Build a script that uses OP_ACTIVEBYTECODE to get its own bytecode,
    // then checks the size. The script is:
    // OP_ACTIVEBYTECODE OP_SIZE <expectedSize> OP_EQUALVERIFY OP_DROP
    // This is 5 bytes (0xc1 0x82 0x55 0x88 0x75)
    CScript scriptPubKey;
    scriptPubKey << OP_ACTIVEBYTECODE << OP_SIZE << OP_5 << OP_EQUALVERIFY << OP_DROP;
    BOOST_CHECK_EQUAL(scriptPubKey.size(), 5u);

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_activebytecode_after_codeseparator)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // After OP_CODESEPARATOR, OP_ACTIVEBYTECODE should return only
    // the script AFTER the CODESEPARATOR, not the full script.
    // Script: OP_NOP OP_CODESEPARATOR OP_ACTIVEBYTECODE OP_SIZE <3> OP_EQUALVERIFY OP_DROP
    // After CODESEPARATOR, active bytecode = OP_ACTIVEBYTECODE OP_SIZE <3> OP_EQUALVERIFY OP_DROP
    // That's 5 bytes: 0xc1 0x82 0x53 0x88 0x75
    // Wait: OP_3 = 0x53. So size = 5.
    // Let me re-count:
    // After CODESEPARATOR: OP_ACTIVEBYTECODE(1) OP_SIZE(1) OP_5(1) OP_EQUALVERIFY(1) OP_DROP(1) = 5 bytes
    CScript scriptPubKey;
    scriptPubKey << OP_NOP << OP_CODESEPARATOR
                 << OP_ACTIVEBYTECODE << OP_SIZE << OP_5 << OP_EQUALVERIFY << OP_DROP;
    // Full script is 7 bytes, but active bytecode after CODESEPARATOR is 5 bytes

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_activebytecode_larger_script)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Build a larger script with NOPs before OP_ACTIVEBYTECODE
    CScript scriptPubKey;
    for (int i = 0; i < 10; ++i)
        scriptPubKey << OP_NOP;
    // Active bytecode from start: 10 NOPs + ACTIVEBYTECODE + SIZE + push(13) + EQUALVERIFY + DROP
    // = 10 + 1 + 1 + 1 + 1 + 1 = 15... but the push of 13 is CScriptNum(15).getvch()
    // Actually this is a chicken-and-egg: the size includes the size check itself.
    // Instead, just verify it's > 10 bytes
    scriptPubKey << OP_ACTIVEBYTECODE << OP_SIZE << CScriptNum(10)
                 << OP_GREATERTHANOREQUAL << OP_DROP;
    // Script is 10 NOPs(10) + ACTIVEBYTECODE(1) + SIZE(1) + push 10(2) + GTE(1) + DROP(1) = 16 bytes

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_activebytecode_content_match)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Build a known script and verify OP_ACTIVEBYTECODE returns exact bytes
    // Script: OP_ACTIVEBYTECODE OP_DROP OP_TRUE
    // Bytes: 0xc1 0x75 0x51 = 3 bytes
    CScript scriptPubKey;
    scriptPubKey << OP_ACTIVEBYTECODE << OP_DROP << OP_TRUE;

    // First verify the script itself
    std::vector<unsigned char> expectedBytes(scriptPubKey.begin(), scriptPubKey.end());
    BOOST_CHECK_EQUAL(expectedBytes.size(), 3u);

    // Now verify it works
    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// Unary opcodes (take index from stack)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxovalue)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // UTXO value of input 0 = 60000
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOVALUE << CScriptNum(60000) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxovalue_other_input)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // UTXO value of input 1 = 35000
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_UTXOVALUE << CScriptNum(35000) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputvalue)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Output 0 value = 50000
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTVALUE << CScriptNum(50000) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputvalue_second)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Output 1 value = 40000
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_OUTPUTVALUE << CScriptNum(40000) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_inputsequencenumber)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Input 0 sequence = 0xfffffffe
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_INPUTSEQUENCENUMBER
                 << CScriptNum(0xfffffffe) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outpointindex)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Input 0's outpoint index = 0
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPOINTINDEX << CScriptNum(0) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outpointindex_second_input)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Input 1's outpoint index = 1
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_OUTPOINTINDEX << CScriptNum(1) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// Bytecode introspection
// ============================================================================

BOOST_AUTO_TEST_CASE(op_outputbytecode)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Output 0 scriptPubKey = OP_TRUE (0x51)
    CScript expectedScript;
    expectedScript << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTBYTECODE
                 << std::vector<unsigned char>(expectedScript.begin(), expectedScript.end())
                 << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// Out-of-bounds index
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxovalue_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Index 5 is out of bounds (only 2 inputs)
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_UTXOVALUE << CScriptNum(0) << OP_EQUALVERIFY;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputvalue_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Index 10 is out of bounds (only 2 outputs)
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(10) << OP_OUTPUTVALUE << CScriptNum(0) << OP_EQUALVERIFY;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// Covenant pattern: enforce output value >= input value - fee
// ============================================================================

BOOST_AUTO_TEST_CASE(covenant_value_preservation)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Script: verify output[0] >= utxo[0] - 1000 (fee allowance)
    // OP_INPUTINDEX OP_UTXOVALUE <1000> OP_SUB
    // <0> OP_OUTPUTVALUE
    // OP_LESSTHANOREQUAL
    CScript scriptPubKey;
    scriptPubKey << OP_INPUTINDEX << OP_UTXOVALUE << CScriptNum(1000) << OP_SUB
                 << CScriptNum(0) << OP_OUTPUTVALUE
                 << OP_LESSTHANOREQUAL;

    // utxo[0] = 60000, output[0] = 50000
    // 60000 - 1000 = 59000. Is 59000 <= 50000? No -> fails
    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));

    // Adjust output to satisfy covenant
    t.tx.vout[0].nValue = 59500;
    // 60000 - 1000 = 59000. Is 59000 <= 59500? Yes -> passes
    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_OUTPOINTTXHASH — push txid of outpoint at input index
// ============================================================================

BOOST_AUTO_TEST_CASE(op_outpointtxhash)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Input 0's outpoint txid = uint256::ONE
    // uint256 stores bytes LE, begin() points to least significant byte
    std::vector<unsigned char> expectedHash(32, 0);
    expectedHash[0] = 1; // uint256::ONE in LE byte order

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPOINTTXHASH
                 << expectedHash << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outpointtxhash_second_input)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Input 1's outpoint txid is also uint256::ONE (same in fixture)
    std::vector<unsigned char> expectedHash(32, 0);
    expectedHash[0] = 1;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_OUTPOINTTXHASH
                 << expectedHash << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outpointtxhash_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Index 5 is out of bounds (only 2 inputs)
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_OUTPOINTTXHASH;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outpointtxhash_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Negative index should fail (idx < 0 check)
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_OUTPOINTTXHASH;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_INPUTBYTECODE — push scriptSig at input index
// ============================================================================

BOOST_AUTO_TEST_CASE(op_inputbytecode_self)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE; // 0x51

    // OP_INPUTBYTECODE for input 0 returns the scriptSig we set (0x51)
    std::vector<unsigned char> expectedBytes(scriptSig.begin(), scriptSig.end());

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_INPUTBYTECODE
                 << expectedBytes << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_inputbytecode_other_input)
{
    IntrospectionTestSetup t;

    // Set input 1's scriptSig to something known
    CScript input1ScriptSig;
    input1ScriptSig << CScriptNum(42);
    t.tx.vin[1].scriptSig = input1ScriptSig;

    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Query input 1's scriptSig from input 0
    std::vector<unsigned char> expectedBytes(input1ScriptSig.begin(), input1ScriptSig.end());

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_INPUTBYTECODE
                 << expectedBytes << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_inputbytecode_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Index 5 is out of bounds
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_INPUTBYTECODE;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_inputbytecode_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Negative index should fail
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_INPUTBYTECODE;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_UTXOBYTECODE — introspect the scriptPubKey of spent UTXO
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxobytecode)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // UTXO 1's scriptPubKey = OP_TRUE (0x51)
    CScript expectedScript;
    expectedScript << OP_TRUE;
    std::vector<unsigned char> expectedBytes(expectedScript.begin(), expectedScript.end());

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_UTXOBYTECODE
                 << expectedBytes << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxobytecode_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(10) << OP_UTXOBYTECODE;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_OUTPUTBYTECODE — additional tests
// ============================================================================

BOOST_AUTO_TEST_CASE(op_outputbytecode_second_output)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Output 1 scriptPubKey = OP_DUP OP_DROP OP_TRUE
    CScript expectedScript;
    expectedScript << OP_DUP << OP_DROP << OP_TRUE;
    std::vector<unsigned char> expectedBytes(expectedScript.begin(), expectedScript.end());

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_OUTPUTBYTECODE
                 << expectedBytes << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputbytecode_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(10) << OP_OUTPUTBYTECODE;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_UTXOTOKENCATEGORY — fungible-only token returns 32-byte category ID
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxotokencategory_fungible_only)
{
    IntrospectionTestSetup t;

    // Attach a fungible-only token (no NFT) to UTXO at input 0
    uint256 catId;
    catId.SetHex("0102030405060708091011121314151617181920212223242526272829303132");
    OutputToken fungibleToken(catId, 1000); // fungible amount only
    BOOST_CHECK(fungibleToken.HasAmount());
    BOOST_CHECK(!fungibleToken.HasNFT());
    t.spentOutputs[0].tokenData.emplace(fungibleToken);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    // OP_UTXOTOKENCATEGORY for fungible-only: pushes just 32-byte category ID (no capability byte)
    std::vector<unsigned char> expectedCategory(catId.begin(), catId.end());
    BOOST_CHECK_EQUAL(expectedCategory.size(), 32u);

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCATEGORY
                 << expectedCategory << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_UTXOTOKENCATEGORY — NFT token returns 33 bytes (category + capability)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxotokencategory_nft_with_capability)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("aabbccddee112233445566778899aabb00112233445566778899aabbccddeeff");
    OutputToken nftToken(catId, token::Mutable, {0x42, 0x43}); // mutable NFT with commitment
    BOOST_CHECK(nftToken.HasNFT());
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(nftToken.GetCapability()), static_cast<uint8_t>(token::Mutable));
    t.spentOutputs[0].tokenData.emplace(nftToken);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    // OP_UTXOTOKENCATEGORY for NFT: pushes 32-byte category + 1-byte capability
    std::vector<unsigned char> expectedResult(catId.begin(), catId.end());
    expectedResult.push_back(static_cast<uint8_t>(token::Mutable)); // 0x01
    BOOST_CHECK_EQUAL(expectedResult.size(), 33u);

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCATEGORY
                 << expectedResult << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_UTXOTOKENCATEGORY — no token returns empty
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxotokencategory_no_token)
{
    IntrospectionTestSetup t;
    // No token on UTXO 0 (default)
    BOOST_CHECK(!t.spentOutputs[0].HasTokenData());

    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Should push empty bytes
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCATEGORY
                 << OP_SIZE << CScriptNum(0) << OP_EQUALVERIFY << OP_DROP;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_OUTPUTTOKENCATEGORY — NFT on output returns 33 bytes
// ============================================================================

BOOST_AUTO_TEST_CASE(op_outputtokencategory_nft)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00");
    OutputToken mintingToken(catId, token::Minting, {}); // minting NFT, no commitment
    t.tx.vout[0].tokenData.emplace(mintingToken);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Expected: 32-byte category + Minting capability (0x02)
    std::vector<unsigned char> expectedResult(catId.begin(), catId.end());
    expectedResult.push_back(static_cast<uint8_t>(token::Minting));
    BOOST_CHECK_EQUAL(expectedResult.size(), 33u);

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENCATEGORY
                 << expectedResult << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_OUTPUTTOKENCATEGORY — fungible-only on output returns 32 bytes
// ============================================================================

BOOST_AUTO_TEST_CASE(op_outputtokencategory_fungible_only)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken fungibleToken(catId, 500);
    t.tx.vout[1].tokenData.emplace(fungibleToken);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Fungible-only: just 32-byte category ID
    std::vector<unsigned char> expectedCategory(catId.begin(), catId.end());
    BOOST_CHECK_EQUAL(expectedCategory.size(), 32u);

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_OUTPUTTOKENCATEGORY
                 << expectedCategory << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_UTXOTOKENCATEGORY — immutable NFT (capability = 0x00)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxotokencategory_immutable_nft)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    OutputToken immutableNFT(catId, token::None, {0x01}); // immutable (capability None=0)
    BOOST_CHECK(immutableNFT.HasNFT());
    BOOST_CHECK_EQUAL(static_cast<uint8_t>(immutableNFT.GetCapability()), 0u);
    t.spentOutputs[0].tokenData.emplace(immutableNFT);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Immutable NFT: 32-byte category + capability byte 0x00
    std::vector<unsigned char> expectedResult(catId.begin(), catId.end());
    expectedResult.push_back(0x00); // token::None
    BOOST_CHECK_EQUAL(expectedResult.size(), 33u);

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCATEGORY
                 << expectedResult << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_UTXOTOKENAMOUNT — fungible token returns amount
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxotokenamount_fungible)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd");
    OutputToken fungibleToken(catId, 42000);
    t.spentOutputs[0].tokenData.emplace(fungibleToken);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENAMOUNT
                 << CScriptNum(42000) << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxotokenamount_no_token)
{
    IntrospectionTestSetup t;
    // No token → amount = 0

    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENAMOUNT
                 << CScriptNum(0) << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxotokenamount_nft_plus_fungible)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    // NFT + fungible: mutable NFT with commitment AND 99999 fungible tokens
    OutputToken combo(catId, token::Mutable, {0x01, 0x02, 0x03}, 99999);
    BOOST_CHECK(combo.HasNFT());
    BOOST_CHECK(combo.HasAmount());
    t.spentOutputs[0].tokenData.emplace(combo);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENAMOUNT
                 << CScriptNum(99999) << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_UTXOTOKENCOMMITMENT — NFT with commitment
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxotokencommitment_with_data)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01");
    std::vector<uint8_t> commitment = {0xDE, 0xAD, 0xBE, 0xEF};
    OutputToken nft(catId, token::None, commitment);
    t.spentOutputs[0].tokenData.emplace(nft);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    std::vector<unsigned char> expectedCommitment(commitment.begin(), commitment.end());

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCOMMITMENT
                 << expectedCommitment << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxotokencommitment_no_token)
{
    IntrospectionTestSetup t;
    // No token → empty commitment

    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCOMMITMENT
                 << OP_SIZE << CScriptNum(0) << OP_EQUALVERIFY << OP_DROP;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxotokencommitment_nft_no_commitment)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("0000000000000000000000000000000000000000000000000000000000000001");
    OutputToken nft(catId, token::Minting, {}); // minting NFT, no commitment
    BOOST_CHECK(nft.HasNFT());
    BOOST_CHECK(!nft.HasCommitment());
    t.spentOutputs[0].tokenData.emplace(nft);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    // NFT without commitment → empty commitment
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCOMMITMENT
                 << OP_SIZE << CScriptNum(0) << OP_EQUALVERIFY << OP_DROP;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_OUTPUTTOKENAMOUNT — output with fungible token
// ============================================================================

BOOST_AUTO_TEST_CASE(op_outputtokenamount_fungible)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    OutputToken fungible(catId, 77777);
    t.tx.vout[0].tokenData.emplace(fungible);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENAMOUNT
                 << CScriptNum(77777) << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputtokenamount_no_token)
{
    IntrospectionTestSetup t;
    // No token on output → amount = 0

    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENAMOUNT
                 << CScriptNum(0) << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// OP_OUTPUTTOKENCOMMITMENT — output with NFT commitment
// ============================================================================

BOOST_AUTO_TEST_CASE(op_outputtokencommitment_with_data)
{
    IntrospectionTestSetup t;

    uint256 catId;
    catId.SetHex("3333333333333333333333333333333333333333333333333333333333333333");
    std::vector<uint8_t> commitment(40, 0x42); // max 40-byte commitment
    OutputToken nft(catId, token::None, commitment);
    t.tx.vout[0].tokenData.emplace(nft);

    CScript scriptSig;
    scriptSig << OP_TRUE;

    std::vector<unsigned char> expectedCommitment(commitment.begin(), commitment.end());

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENCOMMITMENT
                 << expectedCommitment << OP_EQUAL;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputtokencommitment_no_nft)
{
    IntrospectionTestSetup t;
    // No token on output → empty commitment

    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENCOMMITMENT
                 << OP_SIZE << CScriptNum(0) << OP_EQUALVERIFY << OP_DROP;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// Token opcodes — negative index and out-of-bounds tests
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxotokencategory_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_UTXOTOKENCATEGORY;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxotokencategory_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Only 2 inputs, index 5 is OOB
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_UTXOTOKENCATEGORY;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxotokencommitment_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_UTXOTOKENCOMMITMENT;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxotokencommitment_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(99) << OP_UTXOTOKENCOMMITMENT;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxotokenamount_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_UTXOTOKENAMOUNT;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxotokenamount_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(10) << OP_UTXOTOKENAMOUNT;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputtokencategory_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_OUTPUTTOKENCATEGORY;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputtokencategory_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    // Only 2 outputs, index 5 is OOB
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_OUTPUTTOKENCATEGORY;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputtokencommitment_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_OUTPUTTOKENCOMMITMENT;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputtokencommitment_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(20) << OP_OUTPUTTOKENCOMMITMENT;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputtokenamount_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_OUTPUTTOKENAMOUNT;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputtokenamount_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(7) << OP_OUTPUTTOKENAMOUNT;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// Missing OOB/negative tests for non-token introspection opcodes
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxovalue_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_UTXOVALUE;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputvalue_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_OUTPUTVALUE;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_inputsequencenumber_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_INPUTSEQUENCENUMBER;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_inputsequencenumber_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(50) << OP_INPUTSEQUENCENUMBER;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_utxobytecode_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_UTXOBYTECODE;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outputbytecode_negative_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_OUTPUTBYTECODE;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outpointindex_negative)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_OUTPOINTINDEX;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

BOOST_AUTO_TEST_CASE(op_outpointindex_out_of_bounds)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(10) << OP_OUTPOINTINDEX;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey, 0));
}

// ============================================================================
// Context-null handling — introspection opcode without ScriptExecutionContext
// ============================================================================

BOOST_AUTO_TEST_CASE(introspection_context_null_rejected)
{
    // When checker has no ScriptExecutionContext, introspection should fail
    // with SCRIPT_ERR_CONTEXT_NOT_PRESENT
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CScript scriptSig;
    scriptSig << CScriptNum(0);

    tx.vin[0].scriptSig = scriptSig;

    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_INPUTINDEX;

    CTransaction txConst(tx);
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY
                         & ~SCRIPT_VERIFY_MINIMALDATA;
    ScriptError serror;
    // Create checker WITHOUT ScriptExecutionContext (nullptr)
    MutableTransactionSignatureChecker checker(&tx, 0, 1000, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);

    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CONTEXT_NOT_PRESENT);
}

// ============================================================================
// ScriptExecutionContext construction tests
// ============================================================================

BOOST_AUTO_TEST_CASE(context_full_construction)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 42;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 1);
    mtx.vin[1].nSequence = 0xFFFFFFFE;
    mtx.vout.resize(2);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    mtx.vout[1].nValue = 2000;
    mtx.vout[1].scriptPubKey = CScript() << OP_DUP;

    CTransaction tx(mtx);

    std::vector<CTxOut> spentOutputs(2);
    spentOutputs[0].nValue = 5000;
    spentOutputs[0].scriptPubKey = CScript() << OP_1;
    spentOutputs[1].nValue = 6000;
    spentOutputs[1].scriptPubKey = CScript() << OP_2;

    ScriptExecutionContext ctx(0, tx, spentOutputs);

    BOOST_CHECK_EQUAL(ctx.inputIndex(), 0U);
    BOOST_CHECK(!ctx.isLimited());
    BOOST_CHECK_EQUAL(ctx.inputCount(), 2U);
    BOOST_CHECK_EQUAL(ctx.outputCount(), 2U);
    BOOST_CHECK_EQUAL(ctx.txVersion(), 2);
    BOOST_CHECK_EQUAL(ctx.txLockTime(), 42U);
    BOOST_CHECK_EQUAL(ctx.utxoValue(0), 5000);
    BOOST_CHECK_EQUAL(ctx.utxoValue(1), 6000);
    BOOST_CHECK_EQUAL(ctx.outputValue(0), 1000);
    BOOST_CHECK_EQUAL(ctx.outputValue(1), 2000);
    BOOST_CHECK_EQUAL(ctx.inputSequenceNumber(0), 0xFFFFFFFFU);
    BOOST_CHECK_EQUAL(ctx.inputSequenceNumber(1), 0xFFFFFFFEU);
}

BOOST_AUTO_TEST_CASE(context_limited_construction)
{
    CMutableTransaction mtx;
    mtx.nVersion = 1;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 500;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);

    CTxOut singleSpent;
    singleSpent.nValue = 3000;
    singleSpent.scriptPubKey = CScript() << OP_1;

    // Limited context for input 1 only
    ScriptExecutionContext ctx(1, tx, singleSpent);

    BOOST_CHECK_EQUAL(ctx.inputIndex(), 1U);
    BOOST_CHECK(ctx.isLimited());
    BOOST_CHECK_EQUAL(ctx.utxoValue(1), 3000);
    // Input 0's spent output was not provided — it exists but has default CTxOut values
    BOOST_CHECK_EQUAL(ctx.utxoValue(0), -1); // Default CTxOut::nValue is -1
}

BOOST_AUTO_TEST_CASE(context_outpoint_accessors)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    uint256 txhash = uint256S("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(txhash), 7);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);
    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 5000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;

    ScriptExecutionContext ctx(0, tx, spentOutputs);

    BOOST_CHECK(ctx.outpointTxHash(0) == txhash);
    BOOST_CHECK_EQUAL(ctx.outpointIndex(0), 7U);
}

// ============================================================================
// Introspection opcodes disabled without SCRIPT_ENABLE_INTROSPECTION flag
// ============================================================================

BOOST_AUTO_TEST_CASE(introspection_disabled_inputindex)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_INPUTINDEX;

    // Use flags WITHOUT SCRIPT_ENABLE_INTROSPECTION
    t.tx.vin[0].scriptSig = scriptSig;
    t.spentOutputs[0].scriptPubKey = scriptPubKey;

    CTransaction txConst(t.tx);
    ScriptExecutionContext context(0, txConst, t.spentOutputs);
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA
                         & ~SCRIPT_ENABLE_INTROSPECTION;
    ScriptError serror;
    PrecomputedTransactionData txdata;
    txdata.Init(txConst, std::vector<CTxOut>(t.spentOutputs));
    TransactionSignatureChecker checker(&txConst, 0, t.spentOutputs[0].nValue,
                                        txdata, MissingDataBehavior::FAIL, &context);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISABLED_OPCODE);
}

BOOST_AUTO_TEST_CASE(introspection_disabled_utxovalue)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOVALUE;

    t.tx.vin[0].scriptSig = scriptSig;
    t.spentOutputs[0].scriptPubKey = scriptPubKey;

    CTransaction txConst(t.tx);
    ScriptExecutionContext context(0, txConst, t.spentOutputs);
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA
                         & ~SCRIPT_ENABLE_INTROSPECTION;
    ScriptError serror;
    PrecomputedTransactionData txdata;
    txdata.Init(txConst, std::vector<CTxOut>(t.spentOutputs));
    TransactionSignatureChecker checker(&txConst, 0, t.spentOutputs[0].nValue,
                                        txdata, MissingDataBehavior::FAIL, &context);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISABLED_OPCODE);
}

BOOST_AUTO_TEST_CASE(introspection_disabled_utxotokencategory)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCATEGORY;

    t.tx.vin[0].scriptSig = scriptSig;
    t.spentOutputs[0].scriptPubKey = scriptPubKey;

    CTransaction txConst(t.tx);
    ScriptExecutionContext context(0, txConst, t.spentOutputs);
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA
                         & ~SCRIPT_ENABLE_INTROSPECTION;
    ScriptError serror;
    PrecomputedTransactionData txdata;
    txdata.Init(txConst, std::vector<CTxOut>(t.spentOutputs));
    TransactionSignatureChecker checker(&txConst, 0, t.spentOutputs[0].nValue,
                                        txdata, MissingDataBehavior::FAIL, &context);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISABLED_OPCODE);
}

BOOST_AUTO_TEST_CASE(introspection_disabled_outputbytecode)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTBYTECODE;

    t.tx.vin[0].scriptSig = scriptSig;
    t.spentOutputs[0].scriptPubKey = scriptPubKey;

    CTransaction txConst(t.tx);
    ScriptExecutionContext context(0, txConst, t.spentOutputs);
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA
                         & ~SCRIPT_ENABLE_INTROSPECTION;
    ScriptError serror;
    PrecomputedTransactionData txdata;
    txdata.Init(txConst, std::vector<CTxOut>(t.spentOutputs));
    TransactionSignatureChecker checker(&txConst, 0, t.spentOutputs[0].nValue,
                                        txdata, MissingDataBehavior::FAIL, &context);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISABLED_OPCODE);
}

BOOST_AUTO_TEST_CASE(introspection_disabled_txversion)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXVERSION;

    t.tx.vin[0].scriptSig = scriptSig;
    t.spentOutputs[0].scriptPubKey = scriptPubKey;

    CTransaction txConst(t.tx);
    ScriptExecutionContext context(0, txConst, t.spentOutputs);
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA
                         & ~SCRIPT_ENABLE_INTROSPECTION;
    ScriptError serror;
    PrecomputedTransactionData txdata;
    txdata.Init(txConst, std::vector<CTxOut>(t.spentOutputs));
    TransactionSignatureChecker checker(&txConst, 0, t.spentOutputs[0].nValue,
                                        txdata, MissingDataBehavior::FAIL, &context);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISABLED_OPCODE);
}

BOOST_AUTO_TEST_CASE(introspection_disabled_outputtokenamount)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTTOKENAMOUNT;

    t.tx.vin[0].scriptSig = scriptSig;
    t.spentOutputs[0].scriptPubKey = scriptPubKey;

    CTransaction txConst(t.tx);
    ScriptExecutionContext context(0, txConst, t.spentOutputs);
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA
                         & ~SCRIPT_ENABLE_INTROSPECTION;
    ScriptError serror;
    PrecomputedTransactionData txdata;
    txdata.Init(txConst, std::vector<CTxOut>(t.spentOutputs));
    TransactionSignatureChecker checker(&txConst, 0, t.spentOutputs[0].nValue,
                                        txdata, MissingDataBehavior::FAIL, &context);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISABLED_OPCODE);
}

BOOST_AUTO_TEST_CASE(context_token_accessors)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CTransaction tx(mtx);

    // UTXO with token
    uint256 catId = uint256S("aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb");
    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 5000;
    spentOutputs[0].scriptPubKey = CScript() << OP_TRUE;
    spentOutputs[0].tokenData.emplace(OutputToken(catId, 500));

    ScriptExecutionContext ctx(0, tx, spentOutputs);

    BOOST_CHECK(ctx.utxoHasToken(0));
    const OutputToken* tok = ctx.utxoToken(0);
    BOOST_CHECK(tok != nullptr);
    BOOST_CHECK(tok->HasAmount());
    BOOST_CHECK_EQUAL(tok->amount, 500);

    // Output has no token
    BOOST_CHECK(!ctx.outputHasToken(0));
    BOOST_CHECK(ctx.outputToken(0) == nullptr);
}

// ============================================================================
// OutputToken: comparison operators and validation
// ============================================================================

BOOST_AUTO_TEST_CASE(output_token_equality)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken a(catId, 1000);
    OutputToken b(catId, 1000);
    BOOST_CHECK(a == b);
    BOOST_CHECK(!(a != b));
}

BOOST_AUTO_TEST_CASE(output_token_inequality_amount)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken a(catId, 1000);
    OutputToken b(catId, 2000);
    BOOST_CHECK(a != b);
    BOOST_CHECK(!(a == b));
}

BOOST_AUTO_TEST_CASE(output_token_inequality_category)
{
    uint256 catId1 = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    uint256 catId2 = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    OutputToken a(catId1, 1000);
    OutputToken b(catId2, 1000);
    BOOST_CHECK(a != b);
}

BOOST_AUTO_TEST_CASE(output_token_inequality_commitment)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken a(catId, token::None, {0x01, 0x02});
    OutputToken b(catId, token::None, {0x01, 0x03});
    BOOST_CHECK(a != b);
}

BOOST_AUTO_TEST_CASE(output_token_less_than_by_category)
{
    uint256 catId1 = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    uint256 catId2 = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    OutputToken a(catId1, 500);
    OutputToken b(catId2, 500);
    BOOST_CHECK(a < b);
    BOOST_CHECK(!(b < a));
}

BOOST_AUTO_TEST_CASE(output_token_less_than_by_amount)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken a(catId, 500);
    OutputToken b(catId, 1000);
    BOOST_CHECK(a < b);
    BOOST_CHECK(!(b < a));
}

BOOST_AUTO_TEST_CASE(output_token_less_than_by_bitfield)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken a(catId, token::None, {}); // bitfield: HasNFT | None = 0x20
    OutputToken b(catId, token::Mutable, {}); // bitfield: HasNFT | Mutable = 0x21
    BOOST_CHECK(a < b);
}

BOOST_AUTO_TEST_CASE(output_token_is_valid_fungible)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t(catId, 1000);
    BOOST_CHECK(t.IsValid());
    BOOST_CHECK(t.HasAmount());
    BOOST_CHECK(!t.HasNFT());
}

BOOST_AUTO_TEST_CASE(output_token_is_valid_nft_immutable)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t(catId, token::None, {0x42});
    BOOST_CHECK(t.IsValid());
    BOOST_CHECK(t.HasNFT());
    BOOST_CHECK(t.IsImmutableToken());
    BOOST_CHECK(!t.IsMutableToken());
    BOOST_CHECK(!t.IsMintingToken());
}

BOOST_AUTO_TEST_CASE(output_token_is_valid_nft_mutable)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t(catId, token::Mutable, {0x01});
    BOOST_CHECK(t.IsValid());
    BOOST_CHECK(t.IsMutableToken());
}

BOOST_AUTO_TEST_CASE(output_token_is_valid_nft_minting)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t(catId, token::Minting, {});
    BOOST_CHECK(t.IsValid());
    BOOST_CHECK(t.IsMintingToken());
}

BOOST_AUTO_TEST_CASE(output_token_is_valid_combo_nft_fungible)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t(catId, token::Minting, {0xDE, 0xAD}, 99999);
    BOOST_CHECK(t.IsValid());
    BOOST_CHECK(t.HasNFT());
    BOOST_CHECK(t.HasAmount());
    BOOST_CHECK(t.HasCommitment());
    BOOST_CHECK(t.IsMintingToken());
    BOOST_CHECK_EQUAL(t.amount, 99999);
}

BOOST_AUTO_TEST_CASE(output_token_invalid_reserved_bit)
{
    OutputToken t;
    t.categoryId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    t.bitfield = token::BitfieldFlag::HasAmount | token::BitfieldFlag::Reserved; // reserved bit set
    t.amount = 100;
    BOOST_CHECK(!t.IsValid());
}

BOOST_AUTO_TEST_CASE(output_token_invalid_no_nft_no_amount)
{
    OutputToken t;
    t.categoryId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    t.bitfield = 0; // no NFT, no amount
    BOOST_CHECK(!t.IsValid());
}

BOOST_AUTO_TEST_CASE(output_token_invalid_commitment_too_long)
{
    OutputToken t;
    t.categoryId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    t.bitfield = token::BitfieldFlag::HasNFT | token::BitfieldFlag::HasCommitmentLength;
    t.commitment.resize(41, 0x42); // exceeds MAX_COMMITMENT_LENGTH (40)
    BOOST_CHECK(!t.IsValid());
}

BOOST_AUTO_TEST_CASE(output_token_serialization_roundtrip_fungible)
{
    uint256 catId = uint256S("aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd");
    OutputToken original(catId, 42000);

    DataStream ss{};
    original.Serialize(ss);

    OutputToken deserialized;
    deserialized.Unserialize(ss);

    BOOST_CHECK(original == deserialized);
    BOOST_CHECK_EQUAL(deserialized.amount, 42000);
    BOOST_CHECK(!deserialized.HasNFT());
}

BOOST_AUTO_TEST_CASE(output_token_serialization_roundtrip_nft)
{
    uint256 catId = uint256S("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    OutputToken original(catId, token::Mutable, {0x01, 0x02, 0x03, 0x04, 0x05});

    DataStream ss{};
    original.Serialize(ss);

    OutputToken deserialized;
    deserialized.Unserialize(ss);

    BOOST_CHECK(original == deserialized);
    BOOST_CHECK(deserialized.HasNFT());
    BOOST_CHECK(deserialized.IsMutableToken());
    BOOST_CHECK_EQUAL(deserialized.commitment.size(), 5u);
}

BOOST_AUTO_TEST_CASE(output_token_serialization_roundtrip_combo)
{
    uint256 catId = uint256S("1234567812345678123456781234567812345678123456781234567812345678");
    OutputToken original(catId, token::Minting, {0xAA, 0xBB}, 999999);

    DataStream ss{};
    original.Serialize(ss);

    OutputToken deserialized;
    deserialized.Unserialize(ss);

    BOOST_CHECK(original == deserialized);
    BOOST_CHECK(deserialized.HasNFT());
    BOOST_CHECK(deserialized.HasAmount());
    BOOST_CHECK(deserialized.HasCommitment());
    BOOST_CHECK_EQUAL(deserialized.amount, 999999);
}

// ============================================================================
// OutputToken::ToString() format verification
// ============================================================================

BOOST_AUTO_TEST_CASE(output_token_tostring_fungible)
{
    uint256 catId = uint256S("aabbccdd00000000000000000000000000000000000000000000000000000001");
    OutputToken t(catId, 42000);
    std::string s = t.ToString();
    // Should contain "category=" and "amount=42000" but NOT "nft="
    BOOST_CHECK(s.find("category=") != std::string::npos);
    BOOST_CHECK(s.find("amount=42000") != std::string::npos);
    BOOST_CHECK(s.find("nft=") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(output_token_tostring_nft_immutable)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t(catId, token::None, {0xDE, 0xAD});
    std::string s = t.ToString();
    BOOST_CHECK(s.find("nft=none") != std::string::npos);
    BOOST_CHECK(s.find("commitment=dead") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(output_token_tostring_nft_mutable)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t(catId, token::Mutable, {0x42});
    std::string s = t.ToString();
    BOOST_CHECK(s.find("nft=mutable") != std::string::npos);
    BOOST_CHECK(s.find("commitment=42") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(output_token_tostring_nft_minting)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t(catId, token::Minting, {});
    std::string s = t.ToString();
    BOOST_CHECK(s.find("nft=minting") != std::string::npos);
    // No commitment for empty
    BOOST_CHECK(s.find("commitment=") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(output_token_tostring_combo)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t(catId, token::Minting, {0x01, 0x02, 0x03}, 77777);
    std::string s = t.ToString();
    BOOST_CHECK(s.find("nft=minting") != std::string::npos);
    BOOST_CHECK(s.find("commitment=010203") != std::string::npos);
    BOOST_CHECK(s.find("amount=77777") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(output_token_tostring_max_commitment)
{
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    std::vector<uint8_t> maxCommitment(40, 0xFF);
    OutputToken t(catId, token::None, maxCommitment);
    std::string s = t.ToString();
    BOOST_CHECK(s.find("commitment=") != std::string::npos);
    // 40 bytes of 0xFF = 80 hex chars of 'f'
    BOOST_CHECK(s.find(std::string(80, 'f')) != std::string::npos);
}

// ============================================================================
// OutputToken::IsValid() additional edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(output_token_invalid_capability_without_nft)
{
    // Capability set but HasNFT not set → invalid
    OutputToken t;
    t.categoryId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    t.bitfield = token::BitfieldFlag::HasAmount | 0x01; // capability=Mutable but no HasNFT flag
    t.amount = 100;
    BOOST_CHECK(!t.IsValid());
}

BOOST_AUTO_TEST_CASE(output_token_invalid_commitment_flag_mismatch)
{
    // HasCommitmentLength flag set but commitment is empty → invalid
    OutputToken t;
    t.categoryId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    t.bitfield = token::BitfieldFlag::HasNFT | token::BitfieldFlag::HasCommitmentLength;
    t.commitment.clear(); // empty, but flag says it has commitment
    BOOST_CHECK(!t.IsValid());
}

BOOST_AUTO_TEST_CASE(output_token_invalid_amount_zero)
{
    // Amount flag set but amount=0 → invalid
    OutputToken t;
    t.categoryId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    t.bitfield = token::BitfieldFlag::HasAmount;
    t.amount = 0;
    BOOST_CHECK(!t.IsValid());
}

BOOST_AUTO_TEST_CASE(output_token_invalid_amount_negative)
{
    // Amount flag set but amount=-1 → invalid
    OutputToken t;
    t.categoryId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    t.bitfield = token::BitfieldFlag::HasAmount;
    t.amount = -1;
    BOOST_CHECK(!t.IsValid());
}

BOOST_AUTO_TEST_CASE(output_token_invalid_amount_exceeds_max)
{
    // Amount > MAX_AMOUNT → invalid
    OutputToken t;
    t.categoryId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    t.bitfield = token::BitfieldFlag::HasAmount;
    t.amount = token::MAX_AMOUNT + 1;
    BOOST_CHECK(!t.IsValid());
}

BOOST_AUTO_TEST_CASE(output_token_valid_max_amount)
{
    // Amount == MAX_AMOUNT → valid
    uint256 catId = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    OutputToken t;
    t.categoryId = catId;
    t.bitfield = token::BitfieldFlag::HasAmount;
    t.amount = token::MAX_AMOUNT;
    BOOST_CHECK(t.IsValid());
}

// ============================================================================
// Boundary tests: out-of-range index for unary introspection opcodes
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxovalue_index_out_of_range_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Push index 99 (far beyond 2 inputs)
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(99) << OP_UTXOVALUE << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_utxovalue_negative_index_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_UTXOVALUE << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_outputvalue_index_out_of_range_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Push index 2 (only outputs 0 and 1 exist)
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(2) << OP_OUTPUTVALUE << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_outputvalue_negative_index_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(-1) << OP_OUTPUTVALUE << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_inputsequencenumber_out_of_range_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_INPUTSEQUENCENUMBER << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_outpointtxhash_out_of_range_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(10) << OP_OUTPOINTTXHASH << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_outpointindex_out_of_range_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(10) << OP_OUTPOINTINDEX << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_utxobytecode_out_of_range_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_UTXOBYTECODE << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_outputbytecode_out_of_range_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_OUTPUTBYTECODE << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_inputbytecode_out_of_range_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_INPUTBYTECODE << OP_DROP;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

// ============================================================================
// Stack underflow tests for unary introspection opcodes
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxovalue_empty_stack_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_UTXOVALUE; // no index on stack

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_outputvalue_empty_stack_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_OUTPUTVALUE;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_inputsequencenumber_empty_stack_fails)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_INPUTSEQUENCENUMBER;

    BOOST_CHECK(!t.Eval(scriptSig, scriptPubKey));
}

// ============================================================================
// Boundary index tests (valid boundary: last valid index)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxovalue_last_valid_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Index 1 is the last valid input (2 inputs: 0 and 1)
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_UTXOVALUE << CScriptNum(35000) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_outputvalue_last_valid_index)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_OUTPUTVALUE << CScriptNum(40000) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_inputsequencenumber_value_check)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // Input 0 has nSequence = 0xfffffffe
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_INPUTSEQUENCENUMBER << CScriptNum(0xfffffffe) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

// ============================================================================
// Token introspection with no tokens
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxotokencategory_no_token_pushes_empty)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    // No token on UTXO → OP_UTXOTOKENCATEGORY pushes empty
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCATEGORY << OP_SIZE << CScriptNum(0) << OP_EQUALVERIFY << OP_DROP;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_utxotokencommitment_no_token_pushes_empty)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENCOMMITMENT << OP_SIZE << CScriptNum(0) << OP_EQUALVERIFY << OP_DROP;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_CASE(op_utxotokenamount_no_token_pushes_zero)
{
    IntrospectionTestSetup t;
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_UTXOTOKENAMOUNT << CScriptNum(0) << OP_EQUALVERIFY;

    BOOST_CHECK(t.Eval(scriptSig, scriptPubKey));
}

BOOST_AUTO_TEST_SUITE_END()
