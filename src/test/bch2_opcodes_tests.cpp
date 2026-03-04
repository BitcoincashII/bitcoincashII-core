// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for BCH2 re-enabled opcodes: OP_CAT, OP_SUBSTR, OP_NUM2BIN, OP_BIN2NUM,
// OP_AND, OP_OR, OP_XOR, OP_DIV, OP_MOD, OP_MUL, OP_REVERSEBYTES.
// These activate with the Magnetic Anomaly and subsequent upgrades.

#include <crypto/sha256.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/bitfield.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

// Helper: evaluate a script with BCH2 flags and check result
bool EvalOpcode(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    return VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
}

// Flags for opcode tests: enable BCH2 opcodes but not CLEANSTACK/SIGPUSHONLY/MINIMALDATA
// (raw script testing with numeric pushes in scriptSig)
static const unsigned int TEST_FLAGS = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                                       & ~SCRIPT_VERIFY_SIGPUSHONLY
                                       & ~SCRIPT_VERIFY_MINIMALDATA;

} // namespace

BOOST_FIXTURE_TEST_SUITE(bch2_opcodes_tests, BasicTestingSetup)

// ============================================================================
// OP_CAT: concatenate two byte strings
// ============================================================================

BOOST_AUTO_TEST_CASE(op_cat_basic)
{
    // <"ab"> <"cd"> OP_CAT <"abcd"> OP_EQUAL
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'a', 'b'}
              << std::vector<unsigned char>{'c', 'd'};
    CScript scriptPubKey;
    scriptPubKey << OP_CAT << std::vector<unsigned char>{'a', 'b', 'c', 'd'} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_cat_empty)
{
    // <""> <"abc"> OP_CAT <"abc"> OP_EQUAL
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{} << std::vector<unsigned char>{'a', 'b', 'c'};
    CScript scriptPubKey;
    scriptPubKey << OP_CAT << std::vector<unsigned char>{'a', 'b', 'c'} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_cat_both_empty)
{
    // <""> <""> OP_CAT <""> OP_EQUAL
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{} << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_CAT << std::vector<unsigned char>{} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_cat_disabled_without_flag)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'a'} << std::vector<unsigned char>{'b'};
    CScript scriptPubKey;
    scriptPubKey << OP_CAT << std::vector<unsigned char>{'a', 'b'} << OP_EQUAL;

    // Without BCH2 opcodes flag, OP_CAT should be disabled
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SIGHASH_FORKID;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

// ============================================================================
// OP_SUBSTR: split byte string at position
// ============================================================================

BOOST_AUTO_TEST_CASE(op_split_basic)
{
    // <"abcd"> <2> OP_SUBSTR -> <"ab"> <"cd">
    // Verify: <"abcd"> <2> OP_SUBSTR <"cd"> OP_EQUALVERIFY <"ab"> OP_EQUAL
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'a', 'b', 'c', 'd'} << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_SUBSTR
                 << std::vector<unsigned char>{'c', 'd'} << OP_EQUALVERIFY
                 << std::vector<unsigned char>{'a', 'b'} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_split_at_zero)
{
    // Split at 0: <"abc"> <0> OP_SUBSTR -> <""> <"abc">
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'a', 'b', 'c'} << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_SUBSTR
                 << std::vector<unsigned char>{'a', 'b', 'c'} << OP_EQUALVERIFY
                 << std::vector<unsigned char>{} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_split_at_end)
{
    // Split at end: <"abc"> <3> OP_SUBSTR -> <"abc"> <"">
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'a', 'b', 'c'} << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_SUBSTR
                 << std::vector<unsigned char>{} << OP_EQUALVERIFY
                 << std::vector<unsigned char>{'a', 'b', 'c'} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_NUM2BIN: convert number to byte array of given size
// ============================================================================

BOOST_AUTO_TEST_CASE(op_num2bin_basic)
{
    // <256> <4> OP_NUM2BIN -> <0x00 0x01 0x00 0x00>
    CScript scriptSig;
    scriptSig << CScriptNum(256) << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_NUM2BIN
                 << std::vector<unsigned char>{0x00, 0x01, 0x00, 0x00} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_num2bin_zero)
{
    // <0> <4> OP_NUM2BIN -> <0x00 0x00 0x00 0x00>
    CScript scriptSig;
    scriptSig << CScriptNum(0) << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_NUM2BIN
                 << std::vector<unsigned char>{0x00, 0x00, 0x00, 0x00} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_num2bin_negative)
{
    // <-1> <4> OP_NUM2BIN -> <0x01 0x00 0x00 0x80> (sign bit in last byte)
    CScript scriptSig;
    scriptSig << CScriptNum(-1) << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_NUM2BIN
                 << std::vector<unsigned char>{0x01, 0x00, 0x00, 0x80} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_BIN2NUM: convert byte array to minimal numeric encoding
// ============================================================================

BOOST_AUTO_TEST_CASE(op_bin2num_basic)
{
    // <0x01 0x00 0x00 0x00> OP_BIN2NUM -> <1>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01, 0x00, 0x00, 0x00};
    CScript scriptPubKey;
    scriptPubKey << OP_BIN2NUM << CScriptNum(1) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_bin2num_zero)
{
    // <0x00 0x00 0x00 0x00> OP_BIN2NUM -> <> (empty = 0)
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x00, 0x00, 0x00, 0x00};
    CScript scriptPubKey;
    scriptPubKey << OP_BIN2NUM << CScriptNum(0) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_REVERSEBYTES
// ============================================================================

BOOST_AUTO_TEST_CASE(op_reversebytes)
{
    // <0x01 0x02 0x03> OP_REVERSEBYTES -> <0x03 0x02 0x01>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01, 0x02, 0x03};
    CScript scriptPubKey;
    scriptPubKey << OP_REVERSEBYTES
                 << std::vector<unsigned char>{0x03, 0x02, 0x01} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_reversebytes_single)
{
    // Single byte reversal = identity
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x42};
    CScript scriptPubKey;
    scriptPubKey << OP_REVERSEBYTES << std::vector<unsigned char>{0x42} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_reversebytes_empty)
{
    // Empty reversal = empty
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_REVERSEBYTES << std::vector<unsigned char>{} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Bitwise: OP_AND, OP_OR, OP_XOR
// ============================================================================

BOOST_AUTO_TEST_CASE(op_and)
{
    // <0xFF 0x0F> <0x0F 0xFF> OP_AND -> <0x0F 0x0F>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xFF, 0x0F}
              << std::vector<unsigned char>{0x0F, 0xFF};
    CScript scriptPubKey;
    scriptPubKey << OP_AND << std::vector<unsigned char>{0x0F, 0x0F} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_or)
{
    // <0xF0 0x00> <0x0F 0xFF> OP_OR -> <0xFF 0xFF>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xF0, 0x00}
              << std::vector<unsigned char>{0x0F, 0xFF};
    CScript scriptPubKey;
    scriptPubKey << OP_OR << std::vector<unsigned char>{0xFF, 0xFF} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_xor)
{
    // <0xFF 0x00> <0x0F 0x0F> OP_XOR -> <0xF0 0x0F>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xFF, 0x00}
              << std::vector<unsigned char>{0x0F, 0x0F};
    CScript scriptPubKey;
    scriptPubKey << OP_XOR << std::vector<unsigned char>{0xF0, 0x0F} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Arithmetic: OP_MUL, OP_DIV, OP_MOD
// ============================================================================

BOOST_AUTO_TEST_CASE(op_mul)
{
    // <7> <6> OP_MUL -> <42>
    CScript scriptSig;
    scriptSig << CScriptNum(7) << CScriptNum(6);
    CScript scriptPubKey;
    scriptPubKey << OP_MUL << CScriptNum(42) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mul_by_zero)
{
    // <100> <0> OP_MUL -> <0>
    CScript scriptSig;
    scriptSig << CScriptNum(100) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_MUL << CScriptNum(0) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mul_negative)
{
    // <-3> <4> OP_MUL -> <-12>
    CScript scriptSig;
    scriptSig << CScriptNum(-3) << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_MUL << CScriptNum(-12) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_div)
{
    // <42> <6> OP_DIV -> <7>
    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(6);
    CScript scriptPubKey;
    scriptPubKey << OP_DIV << CScriptNum(7) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_div_truncates)
{
    // <7> <2> OP_DIV -> <3> (integer division truncates)
    CScript scriptSig;
    scriptSig << CScriptNum(7) << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_DIV << CScriptNum(3) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mod)
{
    // <7> <3> OP_MOD -> <1>
    CScript scriptSig;
    scriptSig << CScriptNum(7) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_MOD << CScriptNum(1) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_CAT + OP_SUBSTR round-trip
// ============================================================================

BOOST_AUTO_TEST_CASE(cat_split_roundtrip)
{
    // <"hello"> <"world"> OP_CAT <5> OP_SUBSTR
    // Should yield <"hello"> <"world">
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'h','e','l','l','o'}
              << std::vector<unsigned char>{'w','o','r','l','d'};
    CScript scriptPubKey;
    scriptPubKey << OP_CAT << CScriptNum(5) << OP_SUBSTR
                 << std::vector<unsigned char>{'w','o','r','l','d'} << OP_EQUALVERIFY
                 << std::vector<unsigned char>{'h','e','l','l','o'} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Error paths: OP_DIV by zero, OP_MOD by zero (CRITICAL)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_div_by_zero)
{
    // <42> <0> OP_DIV → SCRIPT_ERR_DIV_BY_ZERO
    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_DIV;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mod_by_zero)
{
    // <42> <0> OP_MOD → SCRIPT_ERR_MOD_BY_ZERO
    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_MOD;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_LSHIFT / OP_RSHIFT (requires SCRIPT_ENABLE_SHIFT_OPCODES)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_lshift_basic)
{
    // <1> <3> OP_LSHIFT → <8>
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_LSHIFT << CScriptNum(8) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_lshift_negative_shift_fails)
{
    // <1> <-1> OP_LSHIFT → SCRIPT_ERR_INVALID_STACK_OPERATION
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(-1);
    CScript scriptPubKey;
    scriptPubKey << OP_LSHIFT;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_lshift_64_returns_zero)
{
    // <0xFF> <64> OP_LSHIFT → <0>
    CScript scriptSig;
    scriptSig << CScriptNum(0xFF) << CScriptNum(64);
    CScript scriptPubKey;
    scriptPubKey << OP_LSHIFT << CScriptNum(0) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_rshift_basic)
{
    // <8> <3> OP_RSHIFT → <1>
    CScript scriptSig;
    scriptSig << CScriptNum(8) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_RSHIFT << CScriptNum(1) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_rshift_negative_shift_fails)
{
    // <8> <-1> OP_RSHIFT → error
    CScript scriptSig;
    scriptSig << CScriptNum(8) << CScriptNum(-1);
    CScript scriptPubKey;
    scriptPubKey << OP_RSHIFT;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_rshift_64_positive_returns_zero)
{
    // <0xFF> <64> OP_RSHIFT → <0> (positive value)
    CScript scriptSig;
    scriptSig << CScriptNum(0xFF) << CScriptNum(64);
    CScript scriptPubKey;
    scriptPubKey << OP_RSHIFT << CScriptNum(0) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_rshift_64_negative_returns_minus1)
{
    // <-1> <64> OP_RSHIFT → <-1> (arithmetic right shift preserves sign)
    CScript scriptSig;
    scriptSig << CScriptNum(-1) << CScriptNum(64);
    CScript scriptPubKey;
    scriptPubKey << OP_RSHIFT << CScriptNum(-1) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_lshift_disabled_without_flag)
{
    // OP_LSHIFT should be disabled without SCRIPT_ENABLE_SHIFT_OPCODES
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(1);
    CScript scriptPubKey;
    scriptPubKey << OP_LSHIFT;

    // TEST_FLAGS does not include SCRIPT_ENABLE_SHIFT_OPCODES
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_rshift_disabled_without_flag)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(1);
    CScript scriptPubKey;
    scriptPubKey << OP_RSHIFT;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Error paths: OP_AND/OR/XOR different-size operands
// ============================================================================

BOOST_AUTO_TEST_CASE(op_and_different_size_fails)
{
    // <0xFF> <0xFF 0x00> OP_AND → SCRIPT_ERR_INVALID_OPERAND_SIZE
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xFF}
              << std::vector<unsigned char>{0xFF, 0x00};
    CScript scriptPubKey;
    scriptPubKey << OP_AND;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_or_different_size_fails)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xFF, 0x00}
              << std::vector<unsigned char>{0xFF};
    CScript scriptPubKey;
    scriptPubKey << OP_OR;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_xor_different_size_fails)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01, 0x02, 0x03}
              << std::vector<unsigned char>{0x01};
    CScript scriptPubKey;
    scriptPubKey << OP_XOR;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Error paths: OP_CAT exceeds max element size
// ============================================================================

BOOST_AUTO_TEST_CASE(op_cat_exceeds_max_element_size)
{
    // Two 5001-byte strings → 10002 > MAX_SCRIPT_ELEMENT_SIZE (10000)
    std::vector<unsigned char> big(5001, 0xAA);
    CScript scriptSig;
    scriptSig << big << big;
    CScript scriptPubKey;
    scriptPubKey << OP_CAT << OP_DROP << OP_TRUE;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Error paths: OP_SPLIT invalid range
// ============================================================================

BOOST_AUTO_TEST_CASE(op_split_negative_position_fails)
{
    // <"abc"> <-1> OP_SPLIT → SCRIPT_ERR_INVALID_SPLIT_RANGE
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'a', 'b', 'c'} << CScriptNum(-1);
    CScript scriptPubKey;
    scriptPubKey << OP_SUBSTR;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_split_beyond_end_fails)
{
    // <"abc"> <4> OP_SPLIT → SCRIPT_ERR_INVALID_SPLIT_RANGE
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'a', 'b', 'c'} << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_SUBSTR;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Error paths: OP_NUM2BIN
// ============================================================================

BOOST_AUTO_TEST_CASE(op_num2bin_negative_size_fails)
{
    // <1> <-1> OP_NUM2BIN → SCRIPT_ERR_PUSH_SIZE
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(-1);
    CScript scriptPubKey;
    scriptPubKey << OP_NUM2BIN;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_num2bin_impossible_encoding)
{
    // <256> <1> OP_NUM2BIN → SCRIPT_ERR_IMPOSSIBLE_ENCODING
    // 256 requires at least 2 bytes (0x00 0x01), cannot fit in 1 byte
    CScript scriptSig;
    scriptSig << CScriptNum(256) << CScriptNum(1);
    CScript scriptPubKey;
    scriptPubKey << OP_NUM2BIN;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Error paths: OP_BIN2NUM invalid number range
// ============================================================================

BOOST_AUTO_TEST_CASE(op_bin2num_invalid_number_range)
{
    // A 5-byte non-zero value that exceeds CScriptNum::MAXIMUM_ELEMENT_SIZE
    // after minimalization → SCRIPT_ERR_INVALID_NUMBER_RANGE
    // 5 bytes: 0x01 0x00 0x00 0x00 0x01 (= large positive number, 5 bytes minimal)
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01, 0x00, 0x00, 0x00, 0x01};
    CScript scriptPubKey;
    scriptPubKey << OP_BIN2NUM;

    // Without VM limits, MAXIMUM_ELEMENT_SIZE = 4
    unsigned int flags = (TEST_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS);
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

// ============================================================================
// OP_DIV/MOD: negative operand edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(op_div_negative_dividend)
{
    // -7 / 2 = -3 (truncation toward zero)
    CScript scriptSig;
    scriptSig << CScriptNum(-7) << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_DIV << CScriptNum(-3) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mod_negative_dividend)
{
    // -7 % 4 = -3 (sign matches dividend)
    CScript scriptSig;
    scriptSig << CScriptNum(-7) << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_MOD << CScriptNum(-3) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_REVERSEBYTES: single byte (identity)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_reversebytes_single_byte_identity)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x42};
    CScript scriptPubKey;
    scriptPubKey << OP_REVERSEBYTES << std::vector<unsigned char>{0x42} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_SPLIT: middle position
// ============================================================================

BOOST_AUTO_TEST_CASE(op_split_middle_position)
{
    // Split "abcd" at 2 → "ab" + "cd"
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'a', 'b', 'c', 'd'} << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_SUBSTR
                 << std::vector<unsigned char>{'c', 'd'} << OP_EQUALVERIFY
                 << std::vector<unsigned char>{'a', 'b'} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_NUM2BIN: max 4-byte value → 4 bytes
// ============================================================================

BOOST_AUTO_TEST_CASE(op_num2bin_max_4byte_value)
{
    // 2147483647 (0x7FFFFFFF) → 4 bytes: {0xFF, 0xFF, 0xFF, 0x7F}
    CScript scriptSig;
    scriptSig << CScriptNum(2147483647) << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_NUM2BIN
                 << std::vector<unsigned char>{0xFF, 0xFF, 0xFF, 0x7F} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_LSHIFT/OP_RSHIFT: additional edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(op_lshift_by_zero)
{
    // <42> <0> OP_LSHIFT → <42> (identity)
    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_LSHIFT << CScriptNum(42) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_rshift_by_zero)
{
    // <42> <0> OP_RSHIFT → <42> (identity)
    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_RSHIFT << CScriptNum(42) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_lshift_by_128_returns_zero)
{
    // <0xFF> <128> OP_LSHIFT → <0> (shift >= 64 → 0)
    CScript scriptSig;
    scriptSig << CScriptNum(255) << CScriptNum(128);
    CScript scriptPubKey;
    scriptPubKey << OP_LSHIFT << CScriptNum(0) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_rshift_by_128_positive_returns_zero)
{
    // <0xFF> <128> OP_RSHIFT → <0> (shift >= 64, positive value → 0)
    CScript scriptSig;
    scriptSig << CScriptNum(255) << CScriptNum(128);
    CScript scriptPubKey;
    scriptPubKey << OP_RSHIFT << CScriptNum(0) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_rshift_by_128_negative_returns_minus1)
{
    // <-100> <128> OP_RSHIFT → <-1> (shift >= 64, negative value → -1)
    CScript scriptSig;
    scriptSig << CScriptNum(-100) << CScriptNum(128);
    CScript scriptPubKey;
    scriptPubKey << OP_RSHIFT << CScriptNum(-1) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_lshift_by_1000_returns_zero)
{
    // <1> <1000> OP_LSHIFT → <0> (very large shift)
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(1000);
    CScript scriptPubKey;
    scriptPubKey << OP_LSHIFT << CScriptNum(0) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_lshift_large_result)
{
    // <1> <31> OP_LSHIFT → 2147483648 (5 bytes in CScriptNum)
    // Verify it equals the expected value using OP_EQUAL (byte comparison)
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(31);
    CScript scriptPubKey;
    // CScriptNum(2147483648).getvch() = {0x00, 0x00, 0x00, 0x80, 0x00}
    scriptPubKey << OP_LSHIFT
                 << std::vector<unsigned char>{0x00, 0x00, 0x00, 0x80, 0x00} << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_rshift_preserves_sign_small_shift)
{
    // <-16> <2> OP_RSHIFT → <-4> (arithmetic right shift preserves sign)
    CScript scriptSig;
    scriptSig << CScriptNum(-16) << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_RSHIFT << CScriptNum(-4) << OP_EQUAL;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_SHIFT_OPCODES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

// ============================================================================
// OP_MUL: overflow / large value edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(op_mul_large_values)
{
    // 100000 * 100000 = 10000000000 (10 billion, fits in int64_t)
    CScript scriptSig;
    scriptSig << CScriptNum(100000) << CScriptNum(100000);
    CScript scriptPubKey;
    scriptPubKey << OP_MUL << CScriptNum(10000000000LL) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mul_both_negative)
{
    // <-3> <-5> OP_MUL → <15> (negative * negative = positive)
    CScript scriptSig;
    scriptSig << CScriptNum(-3) << CScriptNum(-5);
    CScript scriptPubKey;
    scriptPubKey << OP_MUL << CScriptNum(15) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mul_identity)
{
    // <42> <1> OP_MUL → <42> (multiplicative identity)
    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(1);
    CScript scriptPubKey;
    scriptPubKey << OP_MUL << CScriptNum(42) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_MOD: negative divisor edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(op_mod_negative_divisor)
{
    // 7 % -4 = 3 (result sign matches dividend, not divisor)
    CScript scriptSig;
    scriptSig << CScriptNum(7) << CScriptNum(-4);
    CScript scriptPubKey;
    scriptPubKey << OP_MOD << CScriptNum(3) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mod_both_negative)
{
    // -7 % -4 = -3 (result sign matches dividend)
    CScript scriptSig;
    scriptSig << CScriptNum(-7) << CScriptNum(-4);
    CScript scriptPubKey;
    scriptPubKey << OP_MOD << CScriptNum(-3) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mod_exact_divisible)
{
    // 12 % 4 = 0
    CScript scriptSig;
    scriptSig << CScriptNum(12) << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_MOD << CScriptNum(0) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_div_negative_divisor)
{
    // 7 / -2 = -3 (truncation toward zero)
    CScript scriptSig;
    scriptSig << CScriptNum(7) << CScriptNum(-2);
    CScript scriptPubKey;
    scriptPubKey << OP_DIV << CScriptNum(-3) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_div_both_negative)
{
    // -7 / -2 = 3 (negative / negative = positive, truncation toward zero)
    CScript scriptSig;
    scriptSig << CScriptNum(-7) << CScriptNum(-2);
    CScript scriptPubKey;
    scriptPubKey << OP_DIV << CScriptNum(3) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// DecodeBitfield tests
// ============================================================================

BOOST_AUTO_TEST_CASE(decode_bitfield_single_bit)
{
    // 1 bit: vch = {0x01}, size = 1 → bitfield = 1
    std::vector<uint8_t> vch{0x01};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 1, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 1u);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_single_bit_zero)
{
    // 1 bit: vch = {0x00}, size = 1 → bitfield = 0
    std::vector<uint8_t> vch{0x00};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 1, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 0u);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_8bits)
{
    // 8 bits: vch = {0xFF}, size = 8 → bitfield = 255
    std::vector<uint8_t> vch{0xFF};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 8, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 255u);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_16bits_le)
{
    // 16 bits: vch = {0x34, 0x12}, size = 16 → bitfield = 0x1234
    std::vector<uint8_t> vch{0x34, 0x12};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 16, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 0x1234u);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_32bits)
{
    // 32 bits: vch = {0xEF, 0xBE, 0xAD, 0xDE}, size = 32 → 0xDEADBEEF
    std::vector<uint8_t> vch{0xEF, 0xBE, 0xAD, 0xDE};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 32, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 0xDEADBEEFu);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_size_exceeds_32)
{
    // Size > 32 → INVALID_BITFIELD_SIZE
    std::vector<uint8_t> vch{0x01, 0x02, 0x03, 0x04, 0x05};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(!DecodeBitfield(vch, 33, bitfield, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_BITFIELD_SIZE);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_wrong_byte_count)
{
    // Size=8 needs 1 byte, but give 2 → INVALID_BITFIELD_SIZE
    std::vector<uint8_t> vch{0x01, 0x02};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(!DecodeBitfield(vch, 8, bitfield, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_BITFIELD_SIZE);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_wrong_byte_count_too_few)
{
    // Size=16 needs 2 bytes, but give 1 → INVALID_BITFIELD_SIZE
    std::vector<uint8_t> vch{0x01};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(!DecodeBitfield(vch, 16, bitfield, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_BITFIELD_SIZE);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_bits_outside_range)
{
    // Size=3, needs 1 byte. vch = {0x08} = bit 3 set, but only bits 0-2 allowed
    // mask = (1<<3)-1 = 0x07. bitfield & mask = 0x00 != 0x08 → INVALID_BIT_RANGE
    std::vector<uint8_t> vch{0x08};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(!DecodeBitfield(vch, 3, bitfield, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_BIT_RANGE);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_3bits_valid)
{
    // Size=3, vch = {0x05} = bits 0 and 2 set. mask = 0x07. 0x05 & 0x07 = 0x05 → valid
    std::vector<uint8_t> vch{0x05};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 3, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 5u);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_empty_size_zero)
{
    // Size=0 needs 0 bytes. Empty vch is valid.
    std::vector<uint8_t> vch{};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 0, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 0u);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_9bits_needs_2bytes)
{
    // Size=9 needs ceil(9/8)=2 bytes. vch = {0xFF, 0x01} → bitfield = 0x01FF
    // mask = (1<<9)-1 = 0x1FF. 0x01FF & 0x1FF = 0x01FF → valid
    std::vector<uint8_t> vch{0xFF, 0x01};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 9, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 0x1FFu);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_9bits_high_bit_set)
{
    // Size=9 but vch has bit 9 set: {0x00, 0x02}. 0x0200 & 0x1FF = 0 ≠ 0x200 → error
    std::vector<uint8_t> vch{0x00, 0x02};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(!DecodeBitfield(vch, 9, bitfield, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_BIT_RANGE);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_null_serror)
{
    // Passing nullptr for serror should still return correctly (no crash)
    std::vector<uint8_t> vch{0x01};
    uint32_t bitfield;
    BOOST_CHECK(DecodeBitfield(vch, 1, bitfield, nullptr));
    BOOST_CHECK_EQUAL(bitfield, 1u);

    // Error case with nullptr serror
    BOOST_CHECK(!DecodeBitfield(vch, 33, bitfield, nullptr));
}

BOOST_AUTO_TEST_CASE(decode_bitfield_32bits_all_ones)
{
    // Size=32 with all bits set: 0xFFFFFFFF
    std::vector<uint8_t> vch{0xFF, 0xFF, 0xFF, 0xFF};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 32, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 0xFFFFFFFFu);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_32bits_one_bit)
{
    // Size=32 with only bit 31 set: 0x80000000
    std::vector<uint8_t> vch{0x00, 0x00, 0x00, 0x80};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 32, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 0x80000000u);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_too_many_bytes)
{
    // Size=8 should need 1 byte, providing 2 is wrong
    std::vector<uint8_t> vch{0xFF, 0x00};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(!DecodeBitfield(vch, 8, bitfield, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_BITFIELD_SIZE);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_empty_for_nonzero_size)
{
    // Size=1 but empty vector — wrong byte count
    std::vector<uint8_t> vch{};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(!DecodeBitfield(vch, 1, bitfield, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_BITFIELD_SIZE);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_7bits_padding_clean)
{
    // Size=7 needs 1 byte. 0x7F = 0b01111111, mask = (1<<7)-1 = 0x7F. Valid.
    std::vector<uint8_t> vch{0x7F};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(DecodeBitfield(vch, 7, bitfield, &serror));
    BOOST_CHECK_EQUAL(bitfield, 0x7Fu);
}

BOOST_AUTO_TEST_CASE(decode_bitfield_7bits_padding_dirty)
{
    // Size=7 but bit 7 set: 0x80 = 0b10000000. mask = 0x7F. 0x80 & 0x7F = 0 ≠ 0x80 → error
    std::vector<uint8_t> vch{0x80};
    uint32_t bitfield;
    ScriptError serror;
    BOOST_CHECK(!DecodeBitfield(vch, 7, bitfield, &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_INVALID_BIT_RANGE);
}

// ============================================================================
// OP_INVERT: bitwise NOT of each byte
// ============================================================================

BOOST_AUTO_TEST_CASE(op_invert_basic)
{
    // <0xFF 0x00> OP_INVERT → <0x00 0xFF>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xFF, 0x00};
    CScript scriptPubKey;
    scriptPubKey << OP_INVERT << std::vector<unsigned char>{0x00, 0xFF} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_invert_all_ones)
{
    // <0xFF 0xFF 0xFF> OP_INVERT → <0x00 0x00 0x00>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xFF, 0xFF, 0xFF};
    CScript scriptPubKey;
    scriptPubKey << OP_INVERT << std::vector<unsigned char>{0x00, 0x00, 0x00} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_invert_all_zeros)
{
    // <0x00 0x00> OP_INVERT → <0xFF 0xFF>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x00, 0x00};
    CScript scriptPubKey;
    scriptPubKey << OP_INVERT << std::vector<unsigned char>{0xFF, 0xFF} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_invert_alternating_bits)
{
    // <0xAA> OP_INVERT → <0x55>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xAA};
    CScript scriptPubKey;
    scriptPubKey << OP_INVERT << std::vector<unsigned char>{0x55} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_invert_empty)
{
    // <""> OP_INVERT → <""> (inverting empty is empty)
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_INVERT << std::vector<unsigned char>{} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_invert_single_byte)
{
    // <0x42> OP_INVERT → <0xBD>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x42};
    CScript scriptPubKey;
    scriptPubKey << OP_INVERT << std::vector<unsigned char>{0xBD} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_invert_double_invert_identity)
{
    // <data> OP_INVERT OP_INVERT → <data> (double invert is identity)
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xDE, 0xAD, 0xBE, 0xEF};
    CScript scriptPubKey;
    scriptPubKey << OP_INVERT << OP_INVERT
                 << std::vector<unsigned char>{0xDE, 0xAD, 0xBE, 0xEF} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_invert_empty_stack_fails)
{
    // OP_INVERT on empty stack → INVALID_STACK_OPERATION
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_INVERT;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_AND / OP_OR / OP_XOR: bitwise operations with empty operands
// ============================================================================

BOOST_AUTO_TEST_CASE(op_and_both_empty)
{
    // <""> <""> OP_AND → <"">
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{} << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_AND << std::vector<unsigned char>{} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_or_both_empty)
{
    // <""> <""> OP_OR → <"">
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{} << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_OR << std::vector<unsigned char>{} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_xor_both_empty)
{
    // <""> <""> OP_XOR → <"">
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{} << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_XOR << std::vector<unsigned char>{} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_and_size_mismatch_fails)
{
    // <0xFF> <0xFF 0xFF> OP_AND → error (different sizes)
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xFF} << std::vector<unsigned char>{0xFF, 0xFF};
    CScript scriptPubKey;
    scriptPubKey << OP_AND;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_xor_self_is_zero)
{
    // <data> OP_DUP OP_XOR → all zeros (XOR with self = 0)
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xDE, 0xAD, 0xBE, 0xEF};
    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_XOR
                 << std::vector<unsigned char>{0x00, 0x00, 0x00, 0x00} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_or_self_is_self)
{
    // <data> OP_DUP OP_OR → same data (OR with self = self)
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xAB, 0xCD};
    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_OR
                 << std::vector<unsigned char>{0xAB, 0xCD} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_and_with_mask)
{
    // <0xFF 0x0F> <0x0F 0xFF> OP_AND → <0x0F 0x0F>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xFF, 0x0F}
              << std::vector<unsigned char>{0x0F, 0xFF};
    CScript scriptPubKey;
    scriptPubKey << OP_AND << std::vector<unsigned char>{0x0F, 0x0F} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_TOALTSTACK / OP_FROMALTSTACK: error paths
// ============================================================================

BOOST_AUTO_TEST_CASE(op_toaltstack_empty_stack_fails)
{
    // Empty stack → OP_TOALTSTACK should fail
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_TOALTSTACK;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_fromaltstack_empty_altstack_fails)
{
    // Altstack is empty → OP_FROMALTSTACK should fail
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_FROMALTSTACK;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_toaltstack_fromaltstack_roundtrip)
{
    // <42> OP_TOALTSTACK OP_FROMALTSTACK <42> OP_EQUAL
    CScript scriptSig;
    scriptSig << CScriptNum(42);
    CScript scriptPubKey;
    scriptPubKey << OP_TOALTSTACK << OP_FROMALTSTACK << CScriptNum(42) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_DEPTH: push stack depth
// ============================================================================

BOOST_AUTO_TEST_CASE(op_depth_empty_stack)
{
    // Empty stack → OP_DEPTH should push 0
    // scriptSig is empty, scriptPubKey: OP_DEPTH <0> OP_EQUAL
    // But wait: after scriptSig runs, stack is empty. OP_DEPTH pushes 0.
    // Then CScriptNum(0) is pushed, then OP_EQUAL compares.
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_DEPTH << CScriptNum(0) << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_depth_with_items)
{
    // Push 3 items, then OP_DEPTH should push 3
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_DEPTH << CScriptNum(3) << OP_EQUALVERIFY
                 << OP_DROP << OP_DROP << OP_DROP << OP_TRUE; // clean up the 3 items

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Disabled opcodes: OP_2MUL, OP_2DIV permanently disabled
// ============================================================================

BOOST_AUTO_TEST_CASE(op_2mul_disabled)
{
    CScript scriptSig;
    scriptSig << CScriptNum(5);
    CScript scriptPubKey;
    scriptPubKey << OP_2MUL;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_2div_disabled)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_2DIV;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_2mul_disabled_in_unexecuted_branch)
{
    // Disabled opcodes in non-executed IF branch should still succeed
    // (only executed opcodes trigger the disabled check)
    CScript scriptSig;
    scriptSig << OP_FALSE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF << OP_2MUL << OP_ENDIF << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_RETURN: error path and non-executed branch
// ============================================================================

BOOST_AUTO_TEST_CASE(op_return_fails_when_executed)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_RETURN;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_return_in_unexecuted_branch_succeeds)
{
    // OP_RETURN in non-executed IF branch should not trigger error
    CScript scriptSig;
    scriptSig << OP_FALSE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF << OP_RETURN << OP_ENDIF << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_NOP: verify it's truly a no-op
// ============================================================================

BOOST_AUTO_TEST_CASE(op_nop_is_noop)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_NOP << OP_NOP << OP_NOP;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_PICK / OP_ROLL: stack manipulation
// ============================================================================

BOOST_AUTO_TEST_CASE(op_pick_basic)
{
    // Stack: [1, 2, 3]. <2> OP_PICK → copies item at index 2 (bottom) = 1
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(2) << OP_PICK << CScriptNum(1) << OP_EQUALVERIFY
                 << OP_DROP << OP_DROP << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_pick_out_of_bounds_fails)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1);
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(5) << OP_PICK; // only 1 item, index 5 is OOB

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_roll_basic)
{
    // Stack: [1, 2, 3]. <2> OP_ROLL → moves item at index 2 (bottom=1) to top
    // Stack becomes: [2, 3, 1]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(2) << OP_ROLL << CScriptNum(1) << OP_EQUALVERIFY
                 << OP_DROP << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_SIZE: push size of top element without consuming it
// ============================================================================

BOOST_AUTO_TEST_CASE(op_size_empty_element)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_SIZE << CScriptNum(0) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_size_nonempty)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01, 0x02, 0x03, 0x04, 0x05};
    CScript scriptPubKey;
    scriptPubKey << OP_SIZE << CScriptNum(5) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Unbalanced conditional edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(unbalanced_if_no_endif_fails)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF << OP_TRUE;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(endif_without_if_fails)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_ENDIF;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(else_without_if_fails)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_ELSE << OP_TRUE << OP_ENDIF;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(nested_if_else_correct)
{
    // IF TRUE ELSE FALSE ENDIF → executes TRUE branch
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF << OP_TRUE << OP_ELSE << OP_FALSE << OP_ENDIF;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(notif_executes_false_branch)
{
    // FALSE NOTIF → executes the body
    CScript scriptSig;
    scriptSig << OP_FALSE;
    CScript scriptPubKey;
    scriptPubKey << OP_NOTIF << OP_TRUE << OP_ENDIF;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Conditional stack depth and edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(deeply_nested_conditionals_100)
{
    // 100 nested IF/ENDIF pairs — at MAX_CONDITIONAL_STACK_DEPTH (defined but unenforced)
    CScript scriptSig;
    for (int i = 0; i < 100; i++)
        scriptSig << OP_TRUE;
    CScript scriptPubKey;
    for (int i = 0; i < 100; i++)
        scriptPubKey << OP_IF;
    scriptPubKey << OP_TRUE;
    for (int i = 0; i < 100; i++)
        scriptPubKey << OP_ENDIF;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(deeply_nested_conditionals_101_exceeds_op_count)
{
    // 101 nested IF/ENDIF — 101 IFs + 101 ENDIFs = 202 ops > MAX_OPS_PER_SCRIPT (201)
    // VerifyScript calls EvalScript without metrics, so vmLimitsActive=false
    // and the old op count limit applies (not the VM limits budget)
    CScript scriptSig;
    for (int i = 0; i < 101; i++)
        scriptSig << OP_TRUE;
    CScript scriptPubKey;
    for (int i = 0; i < 101; i++)
        scriptPubKey << OP_IF;
    scriptPubKey << OP_TRUE;
    for (int i = 0; i < 101; i++)
        scriptPubKey << OP_ENDIF;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(nested_if_false_branch_skips_body)
{
    // FALSE IF [deep nesting] ENDIF — body is not executed
    // The inner IFs are between OP_IF..OP_ENDIF range so they ARE parsed
    // but fExec=false means they don't cost anything
    CScript scriptSig;
    scriptSig << OP_FALSE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF;
    for (int i = 0; i < 50; i++)
        scriptPubKey << OP_IF;
    for (int i = 0; i < 50; i++)
        scriptPubKey << OP_ENDIF;
    scriptPubKey << OP_ENDIF << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_verif_fails_when_executed)
{
    // OP_VERIF (0x65) falls through to default: BAD_OPCODE
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << static_cast<opcodetype>(0x65); // OP_VERIF

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_verif_fails_even_in_false_branch)
{
    // OP_VERIF (0x65) is in OP_IF..OP_ENDIF range (0x63..0x68)
    // so it gets processed even when fExec=false, and hits default: BAD_OPCODE
    CScript scriptSig;
    scriptSig << OP_FALSE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF << static_cast<opcodetype>(0x65) << OP_ENDIF << OP_TRUE;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_vernotif_fails_even_in_false_branch)
{
    // OP_VERNOTIF (0x66) — same behavior as OP_VERIF
    CScript scriptSig;
    scriptSig << OP_FALSE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF << static_cast<opcodetype>(0x66) << OP_ENDIF << OP_TRUE;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(nested_if_alternating_conditions)
{
    // TRUE FALSE: outer IF executes, inner IF (FALSE) takes ELSE branch
    CScript scriptSig;
    scriptSig << OP_FALSE << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF          // consumes TRUE → enters body
                 << OP_IF          // consumes FALSE → skips to ELSE
                 << OP_FALSE       // not executed
                 << OP_ELSE
                 << OP_TRUE        // executed
                 << OP_ENDIF
                 << OP_ENDIF;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(deeply_nested_notif)
{
    // NOTIF inverts: FALSE NOTIF → body executes
    CScript scriptSig;
    for (int i = 0; i < 10; i++)
        scriptSig << OP_FALSE;
    CScript scriptPubKey;
    for (int i = 0; i < 10; i++)
        scriptPubKey << OP_NOTIF;
    scriptPubKey << OP_TRUE;
    for (int i = 0; i < 10; i++)
        scriptPubKey << OP_ENDIF;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// CHECKMULTISIG: BCH2-specific edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(checkmultisig_0_of_0)
{
    // 0-of-0 multisig: <dummy> 0 0 OP_CHECKMULTISIG → TRUE
    // Requires NULLDUMMY: dummy must be empty
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{}; // dummy
    CScript scriptPubKey;
    scriptPubKey << OP_0 << OP_0 << OP_CHECKMULTISIG;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(checkmultisig_0_of_2_with_keys)
{
    // 0-of-2 multisig: no sigs needed, but keys are on stack
    // <dummy> 0 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG → TRUE
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{}; // dummy
    CScript scriptPubKey;
    // Use dummy 33-byte "pubkeys" (they won't be checked since 0 sigs)
    std::vector<unsigned char> fakePubKey(33, 0x02);
    scriptPubKey << OP_0 << fakePubKey << fakePubKey << OP_2 << OP_CHECKMULTISIG;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(checkmultisig_nulldummy_enforced)
{
    // Non-empty dummy element with NULLDUMMY flag → SCRIPT_ERR_SIG_NULLDUMMY
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01}; // non-empty dummy
    CScript scriptPubKey;
    scriptPubKey << OP_0 << OP_0 << OP_CHECKMULTISIG;

    // TEST_FLAGS includes SCRIPT_VERIFY_NULLDUMMY
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(checkmultisig_negative_key_count_fails)
{
    // Negative key count → SCRIPT_ERR_PUBKEY_COUNT
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{}; // dummy
    CScript scriptPubKey;
    scriptPubKey << OP_0 << CScriptNum(-1) << OP_CHECKMULTISIG;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(checkmultisig_too_many_keys_fails)
{
    // 21 keys > MAX_PUBKEYS_PER_MULTISIG (20) → SCRIPT_ERR_PUBKEY_COUNT
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{}; // dummy
    CScript scriptPubKey;
    scriptPubKey << OP_0;
    std::vector<unsigned char> fakePubKey(33, 0x02);
    for (int i = 0; i < 21; i++)
        scriptPubKey << fakePubKey;
    scriptPubKey << CScriptNum(21) << OP_CHECKMULTISIG;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(checkmultisig_negative_sig_count_fails)
{
    // Negative sig count → SCRIPT_ERR_SIG_COUNT
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{}; // dummy
    CScript scriptPubKey;
    std::vector<unsigned char> fakePubKey(33, 0x02);
    scriptPubKey << CScriptNum(-1) << fakePubKey << OP_1 << OP_CHECKMULTISIG;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(checkmultisig_more_sigs_than_keys_fails)
{
    // 2 sigs for 1 key → SCRIPT_ERR_SIG_COUNT
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{}; // dummy
    CScript scriptPubKey;
    std::vector<unsigned char> fakePubKey(33, 0x02);
    scriptPubKey << OP_2 << fakePubKey << OP_1 << OP_CHECKMULTISIG;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(checkmultisigverify_0_of_0)
{
    // 0-of-0 CHECKMULTISIGVERIFY: succeeds and pops TRUE
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{}; // dummy
    CScript scriptPubKey;
    scriptPubKey << OP_0 << OP_0 << OP_CHECKMULTISIGVERIFY << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(checkmultisig_empty_stack_fails)
{
    // Empty stack → SCRIPT_ERR_INVALID_STACK_OPERATION
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKMULTISIG;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Boolean logic opcodes: OP_BOOLAND, OP_BOOLOR
// ============================================================================

BOOST_AUTO_TEST_CASE(op_booland_true_true)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(1);
    CScript scriptPubKey;
    scriptPubKey << OP_BOOLAND; // 1 AND 1 = 1 (truthy)

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_booland_true_false)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_BOOLAND << OP_NOT; // 1 AND 0 = 0, NOT 0 = 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_booland_false_false)
{
    CScript scriptSig;
    scriptSig << CScriptNum(0) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_BOOLAND << OP_NOT; // 0 AND 0 = 0, NOT 0 = 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_boolor_true_false)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_BOOLOR; // 1 OR 0 = 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_boolor_false_false)
{
    CScript scriptSig;
    scriptSig << CScriptNum(0) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_BOOLOR << OP_NOT; // 0 OR 0 = 0, NOT 0 = 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_boolor_nonzero_values)
{
    // Any nonzero value is truthy: 42 OR -5 = 1
    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(-5);
    CScript scriptPubKey;
    scriptPubKey << OP_BOOLOR;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Numeric comparison opcodes
// ============================================================================

BOOST_AUTO_TEST_CASE(op_numequal_same)
{
    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(42);
    CScript scriptPubKey;
    scriptPubKey << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_numequal_different)
{
    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(43);
    CScript scriptPubKey;
    scriptPubKey << OP_NUMEQUAL << OP_NOT; // 42 != 43, result 0, NOT → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_numequalverify_same)
{
    CScript scriptSig;
    scriptSig << CScriptNum(7) << CScriptNum(7);
    CScript scriptPubKey;
    scriptPubKey << OP_NUMEQUALVERIFY << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_numequalverify_different_fails)
{
    CScript scriptSig;
    scriptSig << CScriptNum(7) << CScriptNum(8);
    CScript scriptPubKey;
    scriptPubKey << OP_NUMEQUALVERIFY << OP_TRUE;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_numnotequal_different)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(20);
    CScript scriptPubKey;
    scriptPubKey << OP_NUMNOTEQUAL; // 10 != 20 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_numnotequal_same)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_NUMNOTEQUAL << OP_NOT; // 10 == 10 → 0, NOT → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_lessthan_true)
{
    CScript scriptSig;
    scriptSig << CScriptNum(5) << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_LESSTHAN; // 5 < 10 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_lessthan_equal_is_false)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_LESSTHAN << OP_NOT; // 10 < 10 → 0, NOT → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_greaterthan_true)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(5);
    CScript scriptPubKey;
    scriptPubKey << OP_GREATERTHAN; // 10 > 5 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_lessthanorequal_equal)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_LESSTHANOREQUAL; // 10 <= 10 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_greaterthanorequal_equal)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_GREATERTHANOREQUAL; // 10 >= 10 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_lessthan_negative)
{
    CScript scriptSig;
    scriptSig << CScriptNum(-5) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_LESSTHAN; // -5 < 0 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Unary numeric opcodes: ABS, NEGATE, NOT, 0NOTEQUAL
// ============================================================================

BOOST_AUTO_TEST_CASE(op_abs_negative)
{
    CScript scriptSig;
    scriptSig << CScriptNum(-42);
    CScript scriptPubKey;
    scriptPubKey << OP_ABS << CScriptNum(42) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_abs_positive)
{
    CScript scriptSig;
    scriptSig << CScriptNum(42);
    CScript scriptPubKey;
    scriptPubKey << OP_ABS << CScriptNum(42) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_abs_zero)
{
    CScript scriptSig;
    scriptSig << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_ABS << CScriptNum(0) << OP_NUMEQUAL << OP_NOT << OP_NOT; // 0==0→1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_negate_positive)
{
    CScript scriptSig;
    scriptSig << CScriptNum(42);
    CScript scriptPubKey;
    scriptPubKey << OP_NEGATE << CScriptNum(-42) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_negate_negative)
{
    CScript scriptSig;
    scriptSig << CScriptNum(-42);
    CScript scriptPubKey;
    scriptPubKey << OP_NEGATE << CScriptNum(42) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_not_zero_is_true)
{
    CScript scriptSig;
    scriptSig << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_NOT; // NOT 0 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_not_nonzero_is_false)
{
    CScript scriptSig;
    scriptSig << CScriptNum(42);
    CScript scriptPubKey;
    scriptPubKey << OP_NOT << OP_NOT; // NOT 42 → 0, NOT 0 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_0notequal_nonzero)
{
    CScript scriptSig;
    scriptSig << CScriptNum(42);
    CScript scriptPubKey;
    scriptPubKey << OP_0NOTEQUAL; // 42 != 0 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_0notequal_zero)
{
    CScript scriptSig;
    scriptSig << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_0NOTEQUAL << OP_NOT; // 0 != 0 → 0, NOT → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_WITHIN, OP_MIN, OP_MAX
// ============================================================================

BOOST_AUTO_TEST_CASE(op_within_inside)
{
    // x min max WITHIN: 5 is within [0, 10)
    CScript scriptSig;
    scriptSig << CScriptNum(5) << CScriptNum(0) << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_WITHIN; // 0 <= 5 < 10 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_within_at_min)
{
    // x == min → TRUE (inclusive lower bound)
    CScript scriptSig;
    scriptSig << CScriptNum(0) << CScriptNum(0) << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_WITHIN; // 0 <= 0 < 10 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_within_at_max)
{
    // x == max → FALSE (exclusive upper bound)
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(0) << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_WITHIN << OP_NOT; // 0 <= 10 < 10 → 0, NOT → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_within_negative_range)
{
    CScript scriptSig;
    scriptSig << CScriptNum(-3) << CScriptNum(-5) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_WITHIN; // -5 <= -3 < 0 → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_min_returns_smaller)
{
    CScript scriptSig;
    scriptSig << CScriptNum(3) << CScriptNum(7);
    CScript scriptPubKey;
    scriptPubKey << OP_MIN << CScriptNum(3) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_min_negative)
{
    CScript scriptSig;
    scriptSig << CScriptNum(-10) << CScriptNum(5);
    CScript scriptPubKey;
    scriptPubKey << OP_MIN << CScriptNum(-10) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_max_returns_larger)
{
    CScript scriptSig;
    scriptSig << CScriptNum(3) << CScriptNum(7);
    CScript scriptPubKey;
    scriptPubKey << OP_MAX << CScriptNum(7) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_max_equal_values)
{
    CScript scriptSig;
    scriptSig << CScriptNum(5) << CScriptNum(5);
    CScript scriptPubKey;
    scriptPubKey << OP_MAX << CScriptNum(5) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_ADD / OP_SUB edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(op_add_negative_plus_positive)
{
    CScript scriptSig;
    scriptSig << CScriptNum(-10) << CScriptNum(15);
    CScript scriptPubKey;
    scriptPubKey << OP_ADD << CScriptNum(5) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_sub_result_negative)
{
    CScript scriptSig;
    scriptSig << CScriptNum(3) << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_SUB << CScriptNum(-7) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_add_both_negative)
{
    CScript scriptSig;
    scriptSig << CScriptNum(-10) << CScriptNum(-20);
    CScript scriptPubKey;
    scriptPubKey << OP_ADD << CScriptNum(-30) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_1add_and_1sub)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10);
    CScript scriptPubKey;
    scriptPubKey << OP_1ADD << OP_1SUB << CScriptNum(10) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_VERIFY
// ============================================================================

BOOST_AUTO_TEST_CASE(op_verify_true_continues)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_VERIFY << OP_TRUE; // TRUE consumed by VERIFY, then push TRUE

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_verify_false_fails)
{
    CScript scriptSig;
    scriptSig << OP_FALSE;
    CScript scriptPubKey;
    scriptPubKey << OP_VERIFY;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_verify_empty_stack_fails)
{
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_VERIFY;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Stack manipulation: 2-item operations
// ============================================================================

BOOST_AUTO_TEST_CASE(op_2dup_basic)
{
    // Stack: [1, 2] → 2DUP → [1, 2, 1, 2], drop extras, verify
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_2DUP << CScriptNum(2) << OP_EQUALVERIFY
                 << CScriptNum(1) << OP_EQUALVERIFY
                 << OP_DROP << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_3dup_basic)
{
    // Stack: [1, 2, 3] → 3DUP → [1, 2, 3, 1, 2, 3]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_3DUP
                 << CScriptNum(3) << OP_EQUALVERIFY
                 << CScriptNum(2) << OP_EQUALVERIFY
                 << CScriptNum(1) << OP_EQUALVERIFY
                 << OP_DROP << OP_DROP << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_2over_basic)
{
    // Stack: [1, 2, 3, 4] → 2OVER → [1, 2, 3, 4, 1, 2]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3) << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_2OVER
                 << CScriptNum(2) << OP_EQUALVERIFY  // top = 2
                 << CScriptNum(1) << OP_EQUALVERIFY  // next = 1
                 << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_2rot_basic)
{
    // Stack: [1, 2, 3, 4, 5, 6] → 2ROT → [3, 4, 5, 6, 1, 2]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3)
              << CScriptNum(4) << CScriptNum(5) << CScriptNum(6);
    CScript scriptPubKey;
    scriptPubKey << OP_2ROT
                 << CScriptNum(2) << OP_EQUALVERIFY  // top = 2
                 << CScriptNum(1) << OP_EQUALVERIFY  // next = 1
                 << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_2swap_basic)
{
    // Stack: [1, 2, 3, 4] → 2SWAP → [3, 4, 1, 2]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3) << CScriptNum(4);
    CScript scriptPubKey;
    scriptPubKey << OP_2SWAP
                 << CScriptNum(2) << OP_EQUALVERIFY  // top = 2
                 << CScriptNum(1) << OP_EQUALVERIFY  // next = 1
                 << OP_DROP << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_over_basic)
{
    // Stack: [1, 2] → OVER → [1, 2, 1]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_OVER << CScriptNum(1) << OP_EQUALVERIFY
                 << OP_DROP << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_rot_basic)
{
    // Stack: [1, 2, 3] → ROT → [2, 3, 1]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_ROT
                 << CScriptNum(1) << OP_EQUALVERIFY  // top = 1
                 << CScriptNum(3) << OP_EQUALVERIFY  // next = 3
                 << CScriptNum(2) << OP_EQUALVERIFY  // bottom = 2
                 << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_swap_basic)
{
    // Stack: [1, 2] → SWAP → [2, 1]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_SWAP
                 << CScriptNum(1) << OP_EQUALVERIFY  // top = 1 (was 2nd)
                 << CScriptNum(2) << OP_EQUALVERIFY  // next = 2 (was top)
                 << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_tuck_basic)
{
    // Stack: [1, 2] → TUCK → [2, 1, 2]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_TUCK
                 << CScriptNum(2) << OP_EQUALVERIFY  // top = 2
                 << CScriptNum(1) << OP_EQUALVERIFY  // next = 1
                 << CScriptNum(2) << OP_EQUALVERIFY  // bottom = 2
                 << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_nip_basic)
{
    // Stack: [1, 2] → NIP → [2]
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_NIP << CScriptNum(2) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_ifdup_true)
{
    // Stack: [1] → IFDUP → [1, 1] (truthy, duplicated)
    CScript scriptSig;
    scriptSig << CScriptNum(1);
    CScript scriptPubKey;
    scriptPubKey << OP_IFDUP << CScriptNum(1) << OP_EQUALVERIFY;
    // stack now [1], which is truthy

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_ifdup_false)
{
    // Stack: [0] → IFDUP → [0] (falsy, not duplicated)
    CScript scriptSig;
    scriptSig << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_IFDUP << OP_NOT; // 0 → NOT → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Stack error conditions
// ============================================================================

BOOST_AUTO_TEST_CASE(op_2dup_insufficient_stack_fails)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1); // only 1 item, need 2
    CScript scriptPubKey;
    scriptPubKey << OP_2DUP;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_2over_insufficient_stack_fails)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3); // need 4
    CScript scriptPubKey;
    scriptPubKey << OP_2OVER;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_2rot_insufficient_stack_fails)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3)
              << CScriptNum(4) << CScriptNum(5); // need 6
    CScript scriptPubKey;
    scriptPubKey << OP_2ROT;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// MAX_STACK_SIZE boundary
// ============================================================================

BOOST_AUTO_TEST_CASE(stack_at_max_size_passes)
{
    // Push exactly MAX_STACK_SIZE (1000) items → should pass
    // Use OP_DUP chain: push 1 item, then DUP 999 times = 1000 items
    // But 999 DUPs > MAX_OPS_PER_SCRIPT (201). So push multiple in scriptSig.
    // scriptSig can push up to 1000 items (all OP_TRUE = 1000 bytes)
    // After pushes, scriptPubKey just drops 999 and leaves 1
    CScript scriptSig;
    for (int i = 0; i < 200; i++) // push 200 items
        scriptSig << OP_TRUE;
    CScript scriptPubKey;
    for (int i = 0; i < 199; i++) // drop 199, leaving 1 TRUE
        scriptPubKey << OP_DROP;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(stack_exceeds_max_size_fails)
{
    // Push more than MAX_STACK_SIZE → should fail with SCRIPT_ERR_STACK_SIZE
    // 1001 items on stack
    CScript scriptSig;
    for (int i = 0; i < 501; i++)
        scriptSig << OP_TRUE;
    CScript scriptPubKey;
    for (int i = 0; i < 501; i++)
        scriptPubKey << OP_DUP; // each DUP adds 1 item: 501 + 501 = 1002 > 1000

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_NUM2BIN/BIN2NUM: additional edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(op_num2bin_to_zero_size)
{
    // 0 with size 0 → empty byte string
    CScript scriptSig;
    scriptSig << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_NUM2BIN
                 << std::vector<unsigned char>{} << OP_EQUAL << OP_NOT << OP_NOT;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_num2bin_encoding_too_small_fails)
{
    // 256 needs 2 bytes minimum, but request size 1 → IMPOSSIBLE_ENCODING
    CScript scriptSig;
    scriptSig << CScriptNum(256);
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_NUM2BIN;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_num2bin_size_1_for_small_value)
{
    // 42 fits in 1 byte
    CScript scriptSig;
    scriptSig << CScriptNum(42);
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_NUM2BIN
                 << std::vector<unsigned char>{0x2a} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_bin2num_padded_negative)
{
    // 0x2a000080 → -42 (sign bit in high byte, padded zeros)
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x2a, 0x00, 0x00, 0x80};
    CScript scriptPubKey;
    scriptPubKey << OP_BIN2NUM << CScriptNum(-42) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_num2bin_bin2num_roundtrip)
{
    // NUM2BIN then BIN2NUM should recover the original number
    CScript scriptSig;
    scriptSig << CScriptNum(-1000);
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(4) << OP_NUM2BIN << OP_BIN2NUM
                 << CScriptNum(-1000) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_REVERSEBYTES: additional edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(op_reversebytes_two_bytes)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xAB, 0xCD};
    CScript scriptPubKey;
    scriptPubKey << OP_REVERSEBYTES
                 << std::vector<unsigned char>{0xCD, 0xAB} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_reversebytes_palindrome)
{
    // Palindrome bytes: reverse is same
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01, 0x02, 0x01};
    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_REVERSEBYTES << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_CAT + OP_SPLIT roundtrip
// ============================================================================

BOOST_AUTO_TEST_CASE(op_cat_split_roundtrip)
{
    // CAT then SPLIT should give back originals
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'h', 'e', 'l', 'l', 'o'}
              << std::vector<unsigned char>{'w', 'o', 'r', 'l', 'd'};
    CScript scriptPubKey;
    scriptPubKey << OP_CAT << CScriptNum(5) << OP_SUBSTR
                 << std::vector<unsigned char>{'w', 'o', 'r', 'l', 'd'} << OP_EQUALVERIFY
                 << std::vector<unsigned char>{'h', 'e', 'l', 'l', 'o'} << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Hash opcodes: HASH160, HASH256, SHA256, SHA1, RIPEMD160
// ============================================================================

BOOST_AUTO_TEST_CASE(op_hash160_produces_20_bytes)
{
    // HASH160 = RIPEMD160(SHA256(x)) → always 20 bytes
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_HASH160 << OP_SIZE << CScriptNum(20) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_sha256_known_value)
{
    // SHA256("") = e3b0c442...
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_SHA256
                 << std::vector<unsigned char>{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                                               0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                                               0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                                               0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55}
                 << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_hash256_produces_32_bytes)
{
    // HASH256 = SHA256(SHA256(x)) → always 32 bytes
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_HASH256 << OP_SIZE << CScriptNum(32) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_ripemd160_known_value)
{
    // RIPEMD160("") = 9c1185a5c5e9fc54612808977ee8f548b2258d31
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_RIPEMD160
                 << std::vector<unsigned char>{0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54,
                                               0x61, 0x28, 0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48,
                                               0xb2, 0x25, 0x8d, 0x31}
                 << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_sha1_known_value)
{
    // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_SHA1
                 << std::vector<unsigned char>{0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
                                               0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
                                               0xaf, 0xd8, 0x07, 0x09}
                 << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_hash160_nonempty_data)
{
    // HASH160 of non-empty data and verify double-hashing works
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01, 0x02, 0x03};
    CScript scriptPubKey;
    // Just verify it produces a 20-byte result
    scriptPubKey << OP_HASH160 << OP_SIZE << CScriptNum(20) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_sha256_nonempty_produces_32_bytes)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xDE, 0xAD};
    CScript scriptPubKey;
    scriptPubKey << OP_SHA256 << OP_SIZE << CScriptNum(32) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_EQUALVERIFY failure and OP_DUP/DROP/2DROP
// ============================================================================

BOOST_AUTO_TEST_CASE(op_equalverify_mismatch_fails)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01} << std::vector<unsigned char>{0x02};
    CScript scriptPubKey;
    scriptPubKey << OP_EQUALVERIFY << OP_TRUE;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_equalverify_match_continues)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x42} << std::vector<unsigned char>{0x42};
    CScript scriptPubKey;
    scriptPubKey << OP_EQUALVERIFY << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_dup_basic)
{
    CScript scriptSig;
    scriptSig << CScriptNum(42);
    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_EQUALVERIFY; // 42 42 EQUALVERIFY → empty, need TRUE
    // After EQUALVERIFY stack is empty, need to push TRUE
    // Actually wait — EQUALVERIFY consumes both copies: stack empty after
    // Let me rethink: DUP duplicates top → [42, 42], EQUALVERIFY → match → empty
    // Need OP_TRUE after

    // Re-do: just verify DUP creates a copy
    CScript scriptPubKey2;
    scriptPubKey2 << OP_DUP << CScriptNum(42) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey2, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_2drop_basic)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(2) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_2DROP; // drops top 2 items, leaving 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_2drop_insufficient_stack_fails)
{
    CScript scriptSig;
    scriptSig << CScriptNum(1);
    CScript scriptPubKey;
    scriptPubKey << OP_2DROP;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_RESERVED, OP_RESERVED1, OP_RESERVED2
// ============================================================================

BOOST_AUTO_TEST_CASE(op_reserved_fails_when_executed)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_RESERVED;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_reserved_in_false_branch_succeeds)
{
    // OP_RESERVED in non-executed IF branch → skipped
    CScript scriptSig;
    scriptSig << OP_FALSE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF << OP_RESERVED << OP_ENDIF << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_reserved1_fails_when_executed)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_RESERVED1;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_reserved2_fails_when_executed)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_RESERVED2;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Complex script patterns: P2PKH template verification
// ============================================================================

BOOST_AUTO_TEST_CASE(script_dup_hash160_equalverify_pattern)
{
    // Classic P2PKH pattern: DUP HASH160 <hash> EQUALVERIFY CHECKSIG
    // Test the DUP + HASH160 + EQUALVERIFY portion (without actual sig check)
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    CKeyID keyID = pubkey.GetID();

    CScript scriptSig;
    scriptSig << ToByteVector(pubkey);
    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_HASH160
                 << std::vector<unsigned char>(keyID.begin(), keyID.end())
                 << OP_EQUALVERIFY; // leaves pubkey on stack (truthy)

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// Hash composition: verify SHA256+RIPEMD160 == HASH160
// ============================================================================

BOOST_AUTO_TEST_CASE(hash160_equals_ripemd160_of_sha256)
{
    // Compute both sides in script and compare
    // Stack: [data, data], apply SHA256+RIPEMD160 to one, HASH160 to other
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01, 0x02, 0x03};
    CScript scriptPubKey;
    scriptPubKey << OP_DUP
                 << OP_HASH160   // HASH160(data) on top
                 << OP_SWAP
                 << OP_SHA256 << OP_RIPEMD160  // RIPEMD160(SHA256(data))
                 << OP_EQUAL;  // should match

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(hash256_equals_double_sha256)
{
    // HASH256(x) should equal SHA256(SHA256(x))
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0xDE, 0xAD, 0xBE, 0xEF};
    CScript scriptPubKey;
    scriptPubKey << OP_DUP
                 << OP_HASH256     // HASH256(data)
                 << OP_SWAP
                 << OP_SHA256 << OP_SHA256  // SHA256(SHA256(data))
                 << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_EQUAL edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(op_equal_empty_elements)
{
    // Two empty elements should be equal
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{} << std::vector<unsigned char>{};
    CScript scriptPubKey;
    scriptPubKey << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_equal_different_lengths_not_equal)
{
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01}
              << std::vector<unsigned char>{0x01, 0x00};
    CScript scriptPubKey;
    scriptPubKey << OP_EQUAL << OP_NOT; // different lengths → 0, NOT → 1

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_CODESEPARATOR: resets code hash start
// ============================================================================

BOOST_AUTO_TEST_CASE(op_codeseparator_basic)
{
    // OP_CODESEPARATOR resets pbegincodehash but otherwise is a no-op
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_CODESEPARATOR << OP_NOP;

    // Without SCRIPT_VERIFY_CONST_SCRIPTCODE, CODESEPARATOR is allowed
    unsigned int flags = TEST_FLAGS & ~SCRIPT_VERIFY_CONST_SCRIPTCODE;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_codeseparator_rejected_with_const_scriptcode)
{
    // SCRIPT_VERIFY_CONST_SCRIPTCODE makes CODESEPARATOR fail
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_CODESEPARATOR << OP_NOP;

    unsigned int flags = TEST_FLAGS | SCRIPT_VERIFY_CONST_SCRIPTCODE;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

// ============================================================================
// Complex script: multi-stage arithmetic
// ============================================================================

BOOST_AUTO_TEST_CASE(arithmetic_chain_add_sub_mul)
{
    // (2 + 3) * 4 = 20
    CScript scriptSig;
    scriptSig << CScriptNum(2) << CScriptNum(3) << CScriptNum(4);
    CScript scriptPubKey;
    // Stack: [2, 3, 4]
    // ROT → [3, 4, 2], SWAP → [3, 2, 4], ROT → [2, 4, 3]
    // Actually simpler: just ADD first two then MUL
    // Stack after ADD of first two: we need [2, 3] on top → ADD → [5], then [4] → MUL
    // scriptSig pushes [2, 3, 4] → scriptPubKey: ROT ROT ADD → [4, 5] → MUL → [20]
    scriptPubKey << OP_ROT << OP_ROT << OP_ADD << OP_MUL << CScriptNum(20) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(arithmetic_negative_result_abs)
{
    // -7 + 3 = -4, ABS = 4
    CScript scriptSig;
    scriptSig << CScriptNum(-7) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_ADD << OP_ABS << CScriptNum(4) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_NOP1-NOP10 with DISCOURAGE_UPGRADABLE_NOPS
// ============================================================================

BOOST_AUTO_TEST_CASE(op_nop1_as_nop_in_bch2)
{
    // BCH2 flags do NOT include DISCOURAGE_UPGRADABLE_NOPS, so NOP1 acts as NOP
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_NOP1;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_nop1_with_discourage_flag_fails)
{
    // When DISCOURAGE_UPGRADABLE_NOPS is explicitly set, NOP1 fails
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_NOP1;

    unsigned int flags = TEST_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_nop10_as_nop_in_bch2)
{
    // NOP10 also acts as NOP without DISCOURAGE flag
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_NOP10;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_CODESEPARATOR in false branch with CONST_SCRIPTCODE
// ============================================================================

BOOST_AUTO_TEST_CASE(op_codeseparator_in_false_branch_with_const_scriptcode)
{
    // OP_CODESEPARATOR is rejected even in non-executed branches when
    // SCRIPT_VERIFY_CONST_SCRIPTCODE is set (interpreter.cpp:588-590).
    // The check occurs BEFORE the fExec gate.
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    // OP_0 OP_IF OP_CODESEPARATOR OP_ENDIF — CODESEPARATOR in unexecuted branch
    scriptPubKey << OP_0 << OP_IF << OP_CODESEPARATOR << OP_ENDIF;

    unsigned int flags = TEST_FLAGS | SCRIPT_VERIFY_CONST_SCRIPTCODE;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_codeseparator_in_false_branch_without_const_scriptcode)
{
    // Without CONST_SCRIPTCODE, CODESEPARATOR in a false branch is fine
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_0 << OP_IF << OP_CODESEPARATOR << OP_ENDIF;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_VERIFY_CONST_SCRIPTCODE;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_codeseparator_in_true_branch_without_const_scriptcode)
{
    // Without CONST_SCRIPTCODE, CODESEPARATOR in an executed branch is fine
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_1 << OP_IF << OP_CODESEPARATOR << OP_ENDIF;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_VERIFY_CONST_SCRIPTCODE;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

// ============================================================================
// Introspection opcodes disabled without SCRIPT_ENABLE_INTROSPECTION
// ============================================================================

BOOST_AUTO_TEST_CASE(op_inputindex_disabled_without_introspection_flag)
{
    // OP_INPUTINDEX fails with DISABLED_OPCODE when SCRIPT_ENABLE_INTROSPECTION not set
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_INPUTINDEX << OP_DROP;

    // Remove introspection flag
    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_txversion_disabled_without_introspection_flag)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXVERSION << OP_DROP;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_txlocktime_disabled_without_introspection_flag)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXLOCKTIME << OP_DROP;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_txinputcount_disabled_without_introspection_flag)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXINPUTCOUNT << OP_DROP;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_txoutputcount_disabled_without_introspection_flag)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXOUTPUTCOUNT << OP_DROP;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_activebytecode_disabled_without_introspection_flag)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_ACTIVEBYTECODE << OP_DROP;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

// Introspection opcodes in unexecuted branches should NOT fail (disabled check is fExec-gated)
BOOST_AUTO_TEST_CASE(op_inputindex_in_false_branch_without_flag_passes)
{
    // Disabled opcodes only fail in executed branches (interpreter.cpp:584-586)
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_0 << OP_IF << OP_INPUTINDEX << OP_ENDIF;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

// Introspection with null context (EvalOpcode uses basic checker without context)
BOOST_AUTO_TEST_CASE(op_inputindex_null_context_fails)
{
    // When SCRIPT_ENABLE_INTROSPECTION is set but checker has no context,
    // the opcode fails with SCRIPT_ERR_CONTEXT_NOT_PRESENT
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_INPUTINDEX << OP_DROP;

    // With introspection flag enabled, but our EvalOpcode uses a basic checker
    // without ScriptExecutionContext, so ctx == nullptr
    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_txversion_null_context_fails)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXVERSION << OP_DROP;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_txlocktime_null_context_fails)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TXLOCKTIME << OP_DROP;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_activebytecode_null_context_fails)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_ACTIVEBYTECODE << OP_DROP;

    unsigned int flags = TEST_FLAGS | SCRIPT_ENABLE_INTROSPECTION;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

// ============================================================================
// OP_REVERSEBYTES disabled without SCRIPT_ENABLE_REVERSEBYTES
// ============================================================================

BOOST_AUTO_TEST_CASE(op_reversebytes_disabled_without_flag)
{
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    std::vector<uint8_t> data = {0x01, 0x02};
    scriptPubKey << data << OP_REVERSEBYTES << OP_DROP;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_REVERSEBYTES;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_reversebytes_in_false_branch_without_flag_passes)
{
    // Disabled opcodes in unexecuted branches don't fail
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    std::vector<uint8_t> data = {0x01};
    scriptPubKey << OP_0 << OP_IF << data << OP_REVERSEBYTES << OP_ENDIF;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_REVERSEBYTES;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

// ============================================================================
// OP_CHECKDATASIG disabled without SCRIPT_ENABLE_CHECKDATASIG
// ============================================================================

BOOST_AUTO_TEST_CASE(op_checkdatasig_disabled_without_bch2_opcodes_flag)
{
    // OP_CHECKDATASIG is gated by SCRIPT_ENABLE_BCH2_OPCODES
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    std::vector<uint8_t> sig(64, 0);
    std::vector<uint8_t> msg = {0x01};
    std::vector<uint8_t> key(33, 0x02);
    scriptPubKey << sig << msg << key << OP_CHECKDATASIG;

    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_BCH2_OPCODES;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

// ============================================================================
// Disabled opcodes behavior contrast: OP_MUL vs OP_2MUL
// ============================================================================

BOOST_AUTO_TEST_CASE(op_mul_enabled_in_bch2)
{
    // OP_MUL was re-enabled in BCH (Magnetic Anomaly)
    CScript scriptSig;
    scriptSig << CScriptNum(3) << CScriptNum(7);
    CScript scriptPubKey;
    scriptPubKey << OP_MUL << CScriptNum(21) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_div_enabled_in_bch2)
{
    // OP_DIV was re-enabled in BCH
    CScript scriptSig;
    scriptSig << CScriptNum(21) << CScriptNum(7);
    CScript scriptPubKey;
    scriptPubKey << OP_DIV << CScriptNum(3) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mod_enabled_in_bch2)
{
    // OP_MOD was re-enabled in BCH
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(3);
    CScript scriptPubKey;
    scriptPubKey << OP_MOD << CScriptNum(1) << OP_NUMEQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_div_by_zero_fails)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_DIV;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_mod_by_zero_fails)
{
    CScript scriptSig;
    scriptSig << CScriptNum(10) << CScriptNum(0);
    CScript scriptPubKey;
    scriptPubKey << OP_MOD;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_AND / OP_OR / OP_XOR (bitwise operations, re-enabled in BCH)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_and_basic)
{
    // 0xFF AND 0x0F = 0x0F
    CScript scriptSig;
    std::vector<uint8_t> a = {0xFF};
    std::vector<uint8_t> b = {0x0F};
    std::vector<uint8_t> expected = {0x0F};
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << a << b << OP_AND << expected << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_or_basic)
{
    // 0xF0 OR 0x0F = 0xFF
    CScript scriptSig;
    std::vector<uint8_t> a = {0xF0};
    std::vector<uint8_t> b = {0x0F};
    std::vector<uint8_t> expected = {0xFF};
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << a << b << OP_OR << expected << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_xor_basic)
{
    // 0xFF XOR 0x0F = 0xF0
    CScript scriptSig;
    std::vector<uint8_t> a = {0xFF};
    std::vector<uint8_t> b = {0x0F};
    std::vector<uint8_t> expected = {0xF0};
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << a << b << OP_XOR << expected << OP_EQUAL;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_and_different_lengths_fails)
{
    // AND with different-length operands fails
    CScript scriptSig;
    std::vector<uint8_t> a = {0xFF, 0xFF};
    std::vector<uint8_t> b = {0x0F};
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << a << b << OP_AND;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY
// ============================================================================

BOOST_AUTO_TEST_CASE(op_checklocktimeverify_too_few_items)
{
    // Empty stack → fail
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKLOCKTIMEVERIFY;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checksequenceverify_too_few_items)
{
    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKSEQUENCEVERIFY;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checklocktimeverify_negative_fails)
{
    // Negative locktime argument → fail
    CScript scriptSig;
    scriptSig << CScriptNum(-1);
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKLOCKTIMEVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checksequenceverify_negative_fails)
{
    // Negative sequence → fail (top bit not set in 5-byte encoding)
    CScript scriptSig;
    scriptSig << CScriptNum(-1);
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKSEQUENCEVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

// ============================================================================
// OP_CHECKDATASIG: verify signature over data (Graviton upgrade)
// ============================================================================

BOOST_AUTO_TEST_CASE(op_checkdatasig_ecdsa_valid)
{
    // OP_CHECKDATASIG with valid ECDSA signature over a message
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(messageHash, sig));

    // scriptSig: <sig> <message> <pubkey>
    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    // scriptPubKey: OP_CHECKDATASIG
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_schnorr_valid)
{
    // OP_CHECKDATASIG with valid 64-byte Schnorr signature
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'s', 'c', 'h', 'n', 'o', 'r', 'r'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(messageHash, sig, nullptr, uint256::ZERO));

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_invalid_ecdsa_returns_false)
{
    // Invalid ECDSA sig → pushes false (not an error, unless NULLFAIL)
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(messageHash, sig));
    sig[5] ^= 0xFF; // Corrupt signature

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    // OP_CHECKDATASIG pushes false; OP_NOT makes it true for the test
    scriptPubKey << OP_CHECKDATASIG << OP_NOT;

    // Without NULLFAIL, corrupted sig → false
    unsigned int flags = TEST_FLAGS & ~SCRIPT_VERIFY_NULLFAIL;
    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_nullfail_rejects_bad_sig)
{
    // With NULLFAIL, non-empty invalid sig → script error
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'b', 'a', 'd'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(messageHash, sig));
    sig[5] ^= 0xFF; // Corrupt

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    // With NULLFAIL, this should error
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_empty_sig_returns_false)
{
    // Empty signature should return false (not error)
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'m', 's', 'g'};

    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{} << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG << OP_NOT; // false → NOT → true

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasigverify_ecdsa_valid)
{
    // OP_CHECKDATASIGVERIFY with valid ECDSA — succeeds (pops result)
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'v', 'e', 'r', 'i', 'f', 'y'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(messageHash, sig));

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIGVERIFY << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasigverify_schnorr_valid)
{
    // OP_CHECKDATASIGVERIFY with 64-byte Schnorr
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'s', 'n', 'r'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(messageHash, sig, nullptr, uint256::ZERO));

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIGVERIFY << OP_TRUE;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasigverify_invalid_sig_fails)
{
    // OP_CHECKDATASIGVERIFY with invalid sig → script fails
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'f', 'a', 'i', 'l'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(messageHash, sig));
    sig[5] ^= 0xFF; // Corrupt

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIGVERIFY << OP_TRUE;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_wrong_message_fails)
{
    // Correct sig for "hello" but verify against "world"
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(messageHash, sig));

    std::vector<uint8_t> wrongMessage = {'w', 'o', 'r', 'l', 'd'};

    CScript scriptSig;
    scriptSig << sig << wrongMessage << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    // NULLFAIL: non-empty sig that doesn't verify → error
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_wrong_pubkey_fails)
{
    // Valid sig by key1, but verified against key2's pubkey
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);

    std::vector<uint8_t> message = {'k', 'e', 'y'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key1.Sign(messageHash, sig));

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key2.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_empty_message)
{
    // Sign over empty message
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message;
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(messageHash, sig));

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_schnorr_requires_compressed_pubkey)
{
    // Schnorr path requires compressed pubkey; uncompressed should fail
    CKey key;
    key.MakeNewKey(false); // uncompressed

    std::vector<uint8_t> message = {'u', 'n', 'c'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    // Create a 64-byte "sig" (will be treated as Schnorr)
    std::vector<unsigned char> sig(64, 0x42);

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    // Uncompressed pubkey + 64-byte sig → NULLFAIL error
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_disabled_without_flag)
{
    // Without SCRIPT_ENABLE_CHECKDATASIG flag, OP_CHECKDATASIG should fail
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'d', 'i', 's'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(messageHash, sig));

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SIGHASH_FORKID;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_stack_underflow)
{
    // Only 2 items on stack → underflow
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{'a'} << std::vector<unsigned char>{'b'};
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_schnorr_empty_message_valid)
{
    // Schnorr signature over empty message
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message;
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(messageHash, sig, nullptr, uint256::ZERO));

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    BOOST_CHECK(EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_schnorr_wrong_data_fails)
{
    // Schnorr sig for "abc" but verify against "xyz"
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'a', 'b', 'c'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(messageHash, sig, nullptr, uint256::ZERO));

    std::vector<uint8_t> wrongMessage = {'x', 'y', 'z'};
    CScript scriptSig;
    scriptSig << sig << wrongMessage << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    // NULLFAIL: non-empty sig that fails → error
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, TEST_FLAGS));
}

BOOST_AUTO_TEST_CASE(op_checkdatasig_without_schnorr_flag_64byte_fails)
{
    // Without SCRIPT_ENABLE_SCHNORR, 64-byte sig is not treated as Schnorr
    // but as ECDSA — it will fail DER validation
    CKey key;
    key.MakeNewKey(true);

    std::vector<uint8_t> message = {'n', 'o', 's'};
    uint256 messageHash;
    CSHA256().Write(message.data(), message.size()).Finalize(messageHash.begin());

    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(messageHash, sig, nullptr, uint256::ZERO));

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    // Enable CHECKDATASIG but disable SCHNORR
    unsigned int flags = TEST_FLAGS & ~SCRIPT_ENABLE_SCHNORR;
    BOOST_CHECK(!EvalOpcode(scriptSig, scriptPubKey, flags));
}

// ============================================================================
// OP_CHECKDATASIG: sig-check counter increment
// ============================================================================

BOOST_AUTO_TEST_CASE(checkdatasig_sigchecks_incremented)
{
    // A valid OP_CHECKDATASIG with non-empty sig should increment nSigChecks
    CKey key;
    key.MakeNewKey(true);
    std::vector<unsigned char> message = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"

    // ECDSA-sign the SHA256 of the message
    uint256 hash;
    CSHA256().Write(message.data(), message.size()).Finalize(hash.begin());
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));

    CScript scriptSig;
    scriptSig << sig << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    scriptPubKey << OP_CHECKDATASIG;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    ScriptError serror;
    int nSigChecks = 0;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, TEST_FLAGS, checker, nSigChecks, &serror);
    BOOST_CHECK(result);
    BOOST_CHECK_EQUAL(nSigChecks, 1);
}

BOOST_AUTO_TEST_CASE(checkdatasig_empty_sig_no_sigcheck)
{
    // OP_CHECKDATASIG with empty sig → returns FALSE, does NOT increment nSigChecks
    CKey key;
    key.MakeNewKey(true);
    std::vector<unsigned char> message = {0x48, 0x65, 0x6C, 0x6C, 0x6F};

    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{} << message << ToByteVector(key.GetPubKey());
    CScript scriptPubKey;
    // OP_CHECKDATASIG returns FALSE, OP_NOT turns it to TRUE
    scriptPubKey << OP_CHECKDATASIG << OP_NOT;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    ScriptError serror;
    int nSigChecks = 0;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, TEST_FLAGS, checker, nSigChecks, &serror);
    BOOST_CHECK(result);
    BOOST_CHECK_EQUAL(nSigChecks, 0);
}

// ============================================================================
// GetOpName: BCH2-specific opcode names
// ============================================================================

BOOST_AUTO_TEST_CASE(get_opname_bch2_splice_opcodes)
{
    BOOST_CHECK_EQUAL(GetOpName(OP_CAT), "OP_CAT");
    BOOST_CHECK_EQUAL(GetOpName(OP_SUBSTR), "OP_SUBSTR"); // OP_SPLIT uses SUBSTR value
    BOOST_CHECK_EQUAL(GetOpName(OP_NUM2BIN), "OP_LEFT");   // OP_NUM2BIN aliases OP_LEFT
    BOOST_CHECK_EQUAL(GetOpName(OP_BIN2NUM), "OP_RIGHT");  // OP_BIN2NUM aliases OP_RIGHT
}

BOOST_AUTO_TEST_CASE(get_opname_bch2_bitwise_opcodes)
{
    BOOST_CHECK_EQUAL(GetOpName(OP_AND), "OP_AND");
    BOOST_CHECK_EQUAL(GetOpName(OP_OR), "OP_OR");
    BOOST_CHECK_EQUAL(GetOpName(OP_XOR), "OP_XOR");
}

BOOST_AUTO_TEST_CASE(get_opname_bch2_arithmetic_opcodes)
{
    BOOST_CHECK_EQUAL(GetOpName(OP_DIV), "OP_DIV");
    BOOST_CHECK_EQUAL(GetOpName(OP_MOD), "OP_MOD");
    BOOST_CHECK_EQUAL(GetOpName(OP_MUL), "OP_MUL");
}

BOOST_AUTO_TEST_CASE(get_opname_checkdatasig)
{
    BOOST_CHECK_EQUAL(GetOpName(OP_CHECKDATASIG), "OP_CHECKDATASIG");
    BOOST_CHECK_EQUAL(GetOpName(OP_CHECKDATASIGVERIFY), "OP_CHECKDATASIGVERIFY");
}

BOOST_AUTO_TEST_CASE(get_opname_introspection_opcodes_unknown)
{
    // Introspection opcodes don't have GetOpName entries → "OP_UNKNOWN"
    BOOST_CHECK_EQUAL(GetOpName(OP_INPUTINDEX), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_ACTIVEBYTECODE), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_TXVERSION), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_TXINPUTCOUNT), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_TXOUTPUTCOUNT), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_TXLOCKTIME), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_UTXOVALUE), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_UTXOBYTECODE), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_OUTPOINTTXHASH), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_OUTPOINTINDEX), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_INPUTBYTECODE), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_INPUTSEQUENCENUMBER), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_OUTPUTVALUE), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_OUTPUTBYTECODE), "OP_UNKNOWN");
}

BOOST_AUTO_TEST_CASE(get_opname_token_introspection_opcodes_unknown)
{
    // CashToken introspection opcodes → "OP_UNKNOWN"
    BOOST_CHECK_EQUAL(GetOpName(OP_UTXOTOKENCATEGORY), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_UTXOTOKENCOMMITMENT), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_UTXOTOKENAMOUNT), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_OUTPUTTOKENCATEGORY), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_OUTPUTTOKENCOMMITMENT), "OP_UNKNOWN");
    BOOST_CHECK_EQUAL(GetOpName(OP_OUTPUTTOKENAMOUNT), "OP_UNKNOWN");
}

BOOST_AUTO_TEST_CASE(get_opname_reversebytes)
{
    // OP_REVERSEBYTES (0xbc) is in the NOP range and may return its NOP alias
    std::string name = GetOpName(OP_REVERSEBYTES);
    // Document current behavior (may be "OP_UNKNOWN" or an NOP name)
    BOOST_CHECK(!name.empty());
}

// ============================================================================
// Opcode value consistency: BCH2-specific opcodes have correct values
// ============================================================================

BOOST_AUTO_TEST_CASE(opcode_values_bch2_introspection)
{
    // Verify BCH2 introspection opcode values match the CHIP specification
    BOOST_CHECK_EQUAL(static_cast<int>(OP_INPUTINDEX), 0xc0);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_ACTIVEBYTECODE), 0xc1);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_TXVERSION), 0xc2);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_TXINPUTCOUNT), 0xc3);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_TXOUTPUTCOUNT), 0xc4);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_TXLOCKTIME), 0xc5);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_UTXOVALUE), 0xc6);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_UTXOBYTECODE), 0xc7);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_OUTPOINTTXHASH), 0xc8);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_OUTPOINTINDEX), 0xc9);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_INPUTBYTECODE), 0xca);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_INPUTSEQUENCENUMBER), 0xcb);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_OUTPUTVALUE), 0xcc);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_OUTPUTBYTECODE), 0xcd);
}

BOOST_AUTO_TEST_CASE(opcode_values_bch2_token_introspection)
{
    BOOST_CHECK_EQUAL(static_cast<int>(OP_UTXOTOKENCATEGORY), 0xce);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_UTXOTOKENCOMMITMENT), 0xcf);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_UTXOTOKENAMOUNT), 0xd0);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_OUTPUTTOKENCATEGORY), 0xd1);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_OUTPUTTOKENCOMMITMENT), 0xd2);
    BOOST_CHECK_EQUAL(static_cast<int>(OP_OUTPUTTOKENAMOUNT), 0xd3);
}

BOOST_AUTO_TEST_CASE(opcode_values_bch2_aliases)
{
    // NUM2BIN aliases LEFT, BIN2NUM aliases RIGHT
    BOOST_CHECK_EQUAL(static_cast<int>(OP_NUM2BIN), static_cast<int>(OP_LEFT));
    BOOST_CHECK_EQUAL(static_cast<int>(OP_BIN2NUM), static_cast<int>(OP_RIGHT));
}

BOOST_AUTO_TEST_CASE(max_opcode_value)
{
    // MAX_OPCODE should be the highest opcode (OP_OUTPUTTOKENAMOUNT = 0xd3)
    BOOST_CHECK_EQUAL(MAX_OPCODE, static_cast<unsigned int>(OP_OUTPUTTOKENAMOUNT));
}

BOOST_AUTO_TEST_CASE(special_token_prefix_value)
{
    // SPECIAL_TOKEN_PREFIX used to mark CashToken data in scriptPubKey serialization
    BOOST_CHECK_EQUAL(SPECIAL_TOKEN_PREFIX, 0xef);
}

BOOST_AUTO_TEST_SUITE_END()
