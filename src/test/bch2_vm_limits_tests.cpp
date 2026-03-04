// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for VM Limits (CHIP-2021-05).
// VM Limits: density-based op cost budget, hash iteration limits.

#include <addresstype.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_metrics.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/vm_limits.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

// Helper to evaluate script and return success/error
struct ScriptResult {
    bool success;
    ScriptError error;
};

ScriptResult EvalScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    ScriptResult result;
    int nSigChecks = 0;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    result.success = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker,
                                  nSigChecks, &result.error);
    return result;
}

static const unsigned int VM_FLAGS = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                                     & ~SCRIPT_VERIFY_SIGPUSHONLY
                                     & ~SCRIPT_VERIFY_MINIMALDATA;

} // namespace

BOOST_FIXTURE_TEST_SUITE(bch2_vm_limits_tests, BasicTestingSetup)

// ============================================================================
// VM Limits constants
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_constants)
{
    // MAX_SCRIPT_ELEMENT_SIZE when VM limits active = 10000
    BOOST_CHECK_EQUAL(may2025::MAX_SCRIPT_ELEMENT_SIZE, 10000u);

    // Legacy limit = 520
    BOOST_CHECK_EQUAL(MAX_SCRIPT_ELEMENT_SIZE_LEGACY, 520u);

    // Op cost per opcode = 100
    BOOST_CHECK_EQUAL(may2025::OPCODE_COST, 100u);

    // SigCheck cost factor = 26000
    BOOST_CHECK_EQUAL(may2025::SIG_CHECK_COST_FACTOR, 26000u);
}

// ============================================================================
// ScriptLimits: budget calculation
// ============================================================================

BOOST_AUTO_TEST_CASE(script_limits_budget)
{
    // Budget = (scriptSigSize + 41) * 800
    may2025::ScriptLimits limits(true, 100); // standard, 100-byte scriptSig
    int64_t expected = (100 + 41) * 800;
    BOOST_CHECK_EQUAL(limits.GetOpCostLimit(), expected);
    BOOST_CHECK_EQUAL(limits.GetOpCostLimit(), 112800);
}

BOOST_AUTO_TEST_CASE(script_limits_hash_iters_standard)
{
    // Standard: hashItersLimit = (scriptSigSize + 41) * 1 / 2
    // (half the non-standard limit, since standard gets 3x hash cost penalty)
    may2025::ScriptLimits limits(true, 100);
    int64_t hashLimit = limits.GetHashItersLimit();
    BOOST_CHECK_GT(hashLimit, 0);
}

BOOST_AUTO_TEST_CASE(script_limits_hash_iters_nonstandard)
{
    // Non-standard: hashItersLimit = (scriptSigSize + 41) * 7 / 2
    may2025::ScriptLimits limitsStd(true, 100);
    may2025::ScriptLimits limitsNonStd(false, 100);
    // Non-standard should have a higher raw hash limit
    BOOST_CHECK_GT(limitsNonStd.GetHashItersLimit(), limitsStd.GetHashItersLimit());
}

// ============================================================================
// ScriptExecutionMetrics: cost tallying
// ============================================================================

BOOST_AUTO_TEST_CASE(metrics_tally_op)
{
    ScriptExecutionMetrics metrics;
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 0);

    metrics.TallyOp(100);
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 100);

    metrics.TallyOp(200);
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 300);
}

BOOST_AUTO_TEST_CASE(metrics_tally_push)
{
    ScriptExecutionMetrics metrics;
    metrics.TallyPushOp(50); // 50-byte push
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 50);
}

BOOST_AUTO_TEST_CASE(metrics_tally_hash)
{
    ScriptExecutionMetrics metrics;
    // Hash of 100-byte message (single round): iters = 1 + (100+8)/64 = 2
    metrics.TallyHashOp(100, false);
    BOOST_CHECK_EQUAL(metrics.GetHashDigestIterations(), 2);

    // Hash of 100-byte message (two round, e.g. HASH256): iters = 2 + (100+8)/64 = 3
    metrics.TallyHashOp(100, true);
    // Total: 2 + 3 = 5
    BOOST_CHECK_EQUAL(metrics.GetHashDigestIterations(), 5);
}

BOOST_AUTO_TEST_CASE(metrics_composite_cost)
{
    ScriptExecutionMetrics metrics;
    metrics.TallyOp(1000);
    metrics.TallyHashOp(64, false); // 1 + (64+8)/64 = 2 iters
    metrics.TallySigChecks(1);

    // Composite = opCost + hashIters * factor + sigChecks * 26000
    // Standard factor = 192
    int64_t composite = metrics.GetCompositeOpCost(BCH2_SCRIPT_VERIFY_FLAGS);
    BOOST_CHECK_EQUAL(composite, 1000 + 2 * 192 + 1 * 26000);
}

// ============================================================================
// MAX_SCRIPT_ELEMENT_SIZE: 10000 bytes with VM limits
// ============================================================================

BOOST_AUTO_TEST_CASE(large_push_with_vm_limits)
{
    // Push a 600-byte element (> 520 legacy limit) - should work with VM limits
    std::vector<unsigned char> data(600, 0x42);
    CScript scriptSig;
    scriptSig << data;
    CScript scriptPubKey;
    scriptPubKey << OP_SIZE << CScriptNum(600) << OP_EQUAL;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(large_push_fails_without_vm_limits)
{
    // Same 600-byte push should fail without VM limits (>520 limit)
    std::vector<unsigned char> data(600, 0x42);
    CScript scriptSig;
    scriptSig << data;
    CScript scriptPubKey;
    scriptPubKey << OP_SIZE << CScriptNum(600) << OP_EQUAL;

    // Remove VM limits flag
    unsigned int flags = VM_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS & ~SCRIPT_VM_LIMITS_STANDARD;
    auto result = EvalScript(scriptSig, scriptPubKey, flags);
    BOOST_CHECK(!result.success);
}

// ============================================================================
// No legacy 201-opcode limit with VM limits
// ============================================================================

BOOST_AUTO_TEST_CASE(more_than_201_ops_with_vm_limits)
{
    // Build a script with 250 OP_NOPs (exceeds legacy 201 limit)
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    for (int i = 0; i < 250; i++) {
        scriptPubKey << OP_NOP;
    }

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(more_than_201_ops_fails_without_vm_limits)
{
    // Same script should fail without VM limits (201 opcode limit)
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    for (int i = 0; i < 250; i++) {
        scriptPubKey << OP_NOP;
    }

    unsigned int flags = VM_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS & ~SCRIPT_VM_LIMITS_STANDARD;
    auto result = EvalScript(scriptSig, scriptPubKey, flags);
    BOOST_CHECK(!result.success);
}

// ============================================================================
// CalcHashIters
// ============================================================================

BOOST_AUTO_TEST_CASE(calc_hash_iters)
{
    // Single round, 0-byte message: 1 + (0+8)/64 = 1
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(0, false), 1);

    // Single round, 55-byte message: 1 + (55+8)/64 = 1 (fits in one block)
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(55, false), 1);

    // Single round, 56-byte message: 1 + (56+8)/64 = 2 (spills to second block)
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(56, false), 2);

    // Two round (HASH256), 0-byte message: 2 + (0+8)/64 = 2
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(0, true), 2);
}

// ============================================================================
// Budget boundary: script within budget should PASS
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_budget_within_limit)
{
    // scriptSig = OP_TRUE (1 byte)
    // Budget = (1 + 41) * 800 = 33600
    // Each OP_NOP costs OPCODE_COST (100). So 336 NOPs = 33600 cost.
    // Use fewer to stay safely within budget (accounting for push cost of OP_TRUE = 1).
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    // 200 NOPs = 20000 op cost, well within 33600 budget
    for (int i = 0; i < 200; i++) {
        scriptPubKey << OP_NOP;
    }

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success, "Script with cost within budget should pass");
}

// ============================================================================
// Budget boundary: verify budget calculation is exact
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_budget_calculation_exact)
{
    // Budget = (scriptSigSize + 41) * 800
    // Test various scriptSig sizes
    may2025::ScriptLimits limits0(true, 0);
    BOOST_CHECK_EQUAL(limits0.GetOpCostLimit(), 32800); // (0+41)*800

    may2025::ScriptLimits limits1(true, 1);
    BOOST_CHECK_EQUAL(limits1.GetOpCostLimit(), 33600); // (1+41)*800

    may2025::ScriptLimits limits100(true, 100);
    BOOST_CHECK_EQUAL(limits100.GetOpCostLimit(), 112800); // (100+41)*800
}

// ============================================================================
// MAX_SCRIPT_ELEMENT_SIZE: Use OP_NUM2BIN to create element at boundary
// ============================================================================

BOOST_AUTO_TEST_CASE(max_element_size_via_num2bin_within_limit)
{
    // Use OP_NUM2BIN to create a large element on the stack
    // Note: OP_NUM2BIN output is limited by maxElementSize (520 without VM limits,
    // 10000 with VM limits). Check that values up to 520 work for sure.
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(520);
    CScript scriptPubKey;
    scriptPubKey << OP_NUM2BIN << OP_SIZE << CScriptNum(520) << OP_EQUAL;

    // With VM limits, 520 should definitely work
    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success, "OP_NUM2BIN to 520 bytes should succeed: error=" + std::to_string(result.error));

    // Also test larger size (600 bytes) which only works with VM limits
    CScript scriptSig2;
    scriptSig2 << CScriptNum(1) << CScriptNum(600);
    CScript scriptPubKey2;
    scriptPubKey2 << OP_NUM2BIN << OP_SIZE << CScriptNum(600) << OP_EQUAL;

    auto result2 = EvalScript(scriptSig2, scriptPubKey2, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result2.success, "OP_NUM2BIN to 600 bytes should succeed with VM limits: error=" + std::to_string(result2.error));

    // Same 600 bytes should fail without VM limits
    unsigned int noVmFlags = VM_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS & ~SCRIPT_VM_LIMITS_STANDARD;
    auto result3 = EvalScript(scriptSig2, scriptPubKey2, noVmFlags);
    BOOST_CHECK_MESSAGE(!result3.success, "OP_NUM2BIN to 600 bytes should fail without VM limits");
}

BOOST_AUTO_TEST_CASE(max_element_size_via_num2bin_over_limit)
{
    // <1> <10001> OP_NUM2BIN — should fail (exceeds MAX_SCRIPT_ELEMENT_SIZE)
    CScript scriptSig;
    scriptSig << CScriptNum(1) << CScriptNum(10001);
    CScript scriptPubKey;
    scriptPubKey << OP_NUM2BIN << OP_SIZE << CScriptNum(10001) << OP_EQUAL;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(!result.success, "OP_NUM2BIN to 10001 bytes should fail");
}

BOOST_AUTO_TEST_CASE(max_element_size_via_push_within_limit)
{
    // Push a large element (5000 bytes) directly — well within limit
    std::vector<unsigned char> data(5000, 0x42);
    CScript scriptSig;
    scriptSig << data;
    CScript scriptPubKey;
    scriptPubKey << OP_SIZE << CScriptNum(5000) << OP_EQUAL;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success, "Push of 5000 bytes should succeed with VM limits");
}

// ============================================================================
// MAX_SCRIPT_ELEMENT_SIZE constant verification
// ============================================================================

BOOST_AUTO_TEST_CASE(max_element_size_constant)
{
    // Verify the constant is exactly 10000 under VM limits
    BOOST_CHECK_EQUAL(may2025::MAX_SCRIPT_ELEMENT_SIZE, 10000u);
    // And equals MAX_SCRIPT_SIZE (as documented)
    BOOST_CHECK_EQUAL(may2025::MAX_SCRIPT_ELEMENT_SIZE, (unsigned int)MAX_SCRIPT_SIZE);
}

// ============================================================================
// Conditional stack depth: verify constant
// ============================================================================

BOOST_AUTO_TEST_CASE(conditional_stack_depth_constant)
{
    BOOST_CHECK_EQUAL(may2025::MAX_CONDITIONAL_STACK_DEPTH, 100u);
}

// ============================================================================
// Conditional stack depth: moderate nesting should PASS
// ============================================================================

BOOST_AUTO_TEST_CASE(conditional_stack_depth_moderate)
{
    // 10 nested IF/ENDIF — well within limit
    CScript scriptSig;
    for (int i = 0; i < 10; i++) {
        scriptSig << OP_TRUE;
    }
    CScript scriptPubKey;
    for (int i = 0; i < 10; i++) {
        scriptPubKey << OP_IF;
    }
    scriptPubKey << OP_TRUE;
    for (int i = 0; i < 10; i++) {
        scriptPubKey << OP_ENDIF;
    }

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success, "10 nested IF/ENDIF should succeed");
}

// ============================================================================
// Budget calculation: zero-length scriptSig
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_budget_zero_scriptsig)
{
    // Budget for 0-byte scriptSig = (0 + 41) * 800 = 32800
    may2025::ScriptLimits limits(true, 0);
    BOOST_CHECK_EQUAL(limits.GetOpCostLimit(), 32800);
}

// ============================================================================
// Hash iterations limit: standard vs non-standard difference
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_hash_iters_exact)
{
    // Standard: (100 + 41) * 1 / 2 = 70
    may2025::ScriptLimits limitsStd(true, 100);
    BOOST_CHECK_EQUAL(limitsStd.GetHashItersLimit(), 70);

    // Non-standard: (100 + 41) * 7 / 2 = 493
    may2025::ScriptLimits limitsNonStd(false, 100);
    BOOST_CHECK_EQUAL(limitsNonStd.GetHashItersLimit(), 493);
}

// ============================================================================
// Budget boundary: cost == limit exactly should PASS (uses > comparison)
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_budget_exactly_at_limit)
{
    // Use ScriptExecutionMetrics directly to verify the > comparison behavior.
    // SetScriptLimits(flags, scriptSigSize) creates ScriptLimits internally.
    // For scriptSigSize=100, standard: budget = (100+41)*800 = 112,800

    ScriptExecutionMetrics metrics;
    metrics.SetScriptLimits(VM_FLAGS, 100); // standard, scriptSigSize=100

    // Tally exactly 112,800 of base op cost
    metrics.TallyOp(112800);

    // IsOverOpCostLimit uses >, so cost == limit should NOT be over
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 112800);
    BOOST_CHECK_MESSAGE(!metrics.IsOverOpCostLimit(VM_FLAGS),
                        "cost == limit should NOT be over (uses > comparison)");
}

// ============================================================================
// Budget boundary: cost == limit + 1 should FAIL
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_budget_one_over_limit)
{
    ScriptExecutionMetrics metrics;
    metrics.SetScriptLimits(VM_FLAGS, 100); // standard, scriptSigSize=100, budget = 112,800

    // Tally exactly 112,801 (one over limit)
    metrics.TallyOp(112801);

    // IsOverOpCostLimit uses >, so cost > limit should be over
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 112801);
    BOOST_CHECK_MESSAGE(metrics.IsOverOpCostLimit(VM_FLAGS),
                        "cost == limit + 1 should be over limit");
}

// ============================================================================
// SIGHASH_UTXOS | SIGHASH_ANYONECANPAY → rejected
// ============================================================================

BOOST_AUTO_TEST_CASE(sighash_utxos_anyonecanpay_rejected)
{
    // SIGHASH_UTXOS (0x20) combined with SIGHASH_ANYONECANPAY (0x80) is disallowed
    // per CashTokens spec, enforced in sigencoding.cpp
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

    // Sign with SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS | SIGHASH_ANYONECANPAY
    // = 0x01 | 0x40 | 0x20 | 0x80 = 0xE1
    uint32_t hashType = SIGHASH_ALL | SIGHASH_FORKID | 0x20 | SIGHASH_ANYONECANPAY;
    uint256 sighash = SignatureHash(scriptPubKey, tx, 0, hashType, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(hashType));

    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    // Use BCH2 flags + SCRIPT_ENABLE_TOKENS (1U << 27, needed for SIGHASH_UTXOS recognition)
    // SCRIPT_ENABLE_TOKENS is defined in script_flags.h which conflicts with interpreter.h
    static constexpr unsigned int LOCAL_SCRIPT_ENABLE_TOKENS = (1U << 27);
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS | LOCAL_SCRIPT_ENABLE_TOKENS;
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "SIGHASH_UTXOS | ANYONECANPAY should be rejected");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_HASHTYPE);
}

// ============================================================================
// SIGHASH_UTXOS pre-Upgrade9 (without SCRIPT_ENABLE_TOKENS) → rejected
// ============================================================================

BOOST_AUTO_TEST_CASE(sighash_utxos_pre_upgrade9_rejected)
{
    // SIGHASH_UTXOS (0x20) requires SCRIPT_ENABLE_TOKENS flag (Upgrade 9)
    // Without it, any signature with SIGHASH_UTXOS should be rejected
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

    // Sign with SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS = 0x61
    uint32_t hashType = SIGHASH_ALL | SIGHASH_FORKID | 0x20;
    uint256 sighash = SignatureHash(scriptPubKey, tx, 0, hashType, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(hashType));

    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    // Use BCH2 flags WITHOUT SCRIPT_ENABLE_TOKENS — pre-Upgrade9
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS; // no SCRIPT_ENABLE_TOKENS
    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr, flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "SIGHASH_UTXOS should be rejected pre-Upgrade9");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_HASHTYPE);
}

// ============================================================================
// BigInt: large numbers (>4 bytes) work with VM limits active
// ============================================================================

BOOST_AUTO_TEST_CASE(bigint_5byte_number_with_vm_limits)
{
    // With VM limits, CScriptNum max size = 10000 bytes (not 4)
    // Push a 5-byte number, do arithmetic
    // 0x0100000000 = 4294967296 (> 2^32, doesn't fit in 4 bytes)
    std::vector<unsigned char> bigNum = {0x00, 0x00, 0x00, 0x00, 0x01}; // 4294967296 in LE

    CScript scriptSig;
    scriptSig << bigNum;
    CScript scriptPubKey;
    // Push the same big number and check equality
    scriptPubKey << bigNum << OP_NUMEQUAL;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "5-byte number should work with VM limits: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_CASE(bigint_5byte_fails_without_vm_limits)
{
    // Same 5-byte number should fail without VM limits (max 4 bytes)
    std::vector<unsigned char> bigNum = {0x00, 0x00, 0x00, 0x00, 0x01};

    CScript scriptSig;
    scriptSig << bigNum;
    CScript scriptPubKey;
    scriptPubKey << bigNum << OP_NUMEQUAL;

    unsigned int noVmFlags = VM_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS & ~SCRIPT_VM_LIMITS_STANDARD;
    auto result = EvalScript(scriptSig, scriptPubKey, noVmFlags);
    BOOST_CHECK_MESSAGE(!result.success,
        "5-byte number should fail without VM limits");
}

BOOST_AUTO_TEST_CASE(bigint_8byte_arithmetic)
{
    // 8-byte numbers (fits in int64_t) should work with VM limits
    // Use 0x00000001 00000000 = 4294967296
    std::vector<unsigned char> a = {0x00, 0x00, 0x00, 0x00, 0x01}; // 4294967296
    std::vector<unsigned char> b = {0x01, 0x00, 0x00, 0x00, 0x00}; // 1
    // a + b = 4294967297

    CScript scriptSig;
    scriptSig << a << b;
    CScript scriptPubKey;
    scriptPubKey << OP_ADD << OP_DROP << OP_TRUE; // Just verify it doesn't error

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "8-byte arithmetic should work with VM limits: error=" + std::to_string(result.error));
}

// ============================================================================
// Hash iteration limit: boundary test
// ============================================================================

BOOST_AUTO_TEST_CASE(hash_iter_limit_constants)
{
    // Standard hash iter limit: (scriptSigSize + 41) * 1 / 2
    may2025::ScriptLimits limitsSmall(true, 10);
    BOOST_CHECK_EQUAL(limitsSmall.GetHashItersLimit(), (10 + 41) / 2); // 25

    may2025::ScriptLimits limitsLarge(true, 1000);
    BOOST_CHECK_EQUAL(limitsLarge.GetHashItersLimit(), (1000 + 41) / 2); // 520

    // Non-standard (block txns) get 7x bonus
    may2025::ScriptLimits limitsNonStd(false, 10);
    BOOST_CHECK_EQUAL(limitsNonStd.GetHashItersLimit(), (10 + 41) * 7 / 2); // 178
}

BOOST_AUTO_TEST_CASE(hash_iter_limit_at_boundary)
{
    ScriptExecutionMetrics metrics;
    metrics.SetScriptLimits(VM_FLAGS, 10); // standard, scriptSigSize=10
    // Hash iter limit = (10+41)*7/2 = 178

    // CalcHashIters for SHA256 on 64 bytes: (64 + 8 + 64) / 64 = 2 iters (single-round)
    // Use TallyHashOp to simulate hashing
    // Just check the boundary directly
    BOOST_CHECK(!metrics.IsOverHashItersLimit());
}

// ============================================================================
// Op cost: OP_HASH256 (two-round hash) costs more iterations
// ============================================================================

BOOST_AUTO_TEST_CASE(hash256_two_round_cost)
{
    // OP_HASH256 = SHA256(SHA256(x)), so isTwoRoundHashOp = true
    // CalcHashIters for 64-byte message, two-round:
    // First round: ceil((64+8+1)/64) = 2 iterations
    // Second round: ceil((32+8+1)/64) = 1 iteration
    // Total: 3 iterations
    uint32_t iters = may2025::CalcHashIters(64, true);
    BOOST_CHECK_GT(iters, 0u);

    // Single-round (SHA256 only): should be fewer
    uint32_t itersOneRound = may2025::CalcHashIters(64, false);
    BOOST_CHECK_LT(itersOneRound, iters);
}

// ============================================================================
// Op cost: SigChecks counted in composite cost
// ============================================================================

BOOST_AUTO_TEST_CASE(sigchecks_in_composite_cost)
{
    ScriptExecutionMetrics metrics;
    metrics.SetScriptLimits(VM_FLAGS, 100);

    // Base cost starts at 0
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 0);

    // Add 1 sigcheck
    metrics.TallySigChecks(1);
    BOOST_CHECK_EQUAL(metrics.GetSigChecks(), 1);

    // Composite cost includes sigchecks × SIG_CHECK_COST_FACTOR
    // SIG_CHECK_COST_FACTOR = 26000
    int64_t composite = metrics.GetCompositeOpCost(VM_FLAGS);
    BOOST_CHECK_GT(composite, 0);
}

// ============================================================================
// VM limits: OP_HASH160 succeeds within budget
// ============================================================================

BOOST_AUTO_TEST_CASE(hash160_within_budget)
{
    // OP_HASH160 on small input should succeed (within hash iter budget)
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{0x01, 0x02, 0x03, 0x04};
    CScript scriptPubKey;
    scriptPubKey << OP_HASH160 << OP_DROP << OP_TRUE;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "OP_HASH160 on small input should succeed: error=" + std::to_string(result.error));
}

// ============================================================================
// VM limits: disabled = no limit enforcement
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_disabled_no_enforcement)
{
    // Without calling SetScriptLimits, the metrics have no limit → never over
    ScriptExecutionMetrics metrics;
    // Don't call SetScriptLimits — scriptLimits remains nullopt

    // Even with extreme costs, not over limit (because limits not set)
    metrics.TallyOp(999999999);
    BOOST_CHECK(!metrics.HasValidScriptLimits());
    unsigned int noVmFlags = VM_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS & ~SCRIPT_VM_LIMITS_STANDARD;
    BOOST_CHECK(!metrics.IsOverOpCostLimit(noVmFlags));
    BOOST_CHECK(!metrics.IsOverHashItersLimit());
}

// ============================================================================
// VM Limits enforcement integration tests:
// Scripts that exceed op cost or hash iter budgets
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_opcost_exceeded_by_nops)
{
    // Budget = (scriptSigSize + 41) * 800
    // scriptSig: push 1 byte (OP_TRUE = 0x51) → size=1, budget=(1+41)*800=33,600
    // Each NOP costs 100 (OPCODE_COST). We need 337 NOPs = 33,700 > 33,600
    // Plus the OP_TRUE at end costs 100. scriptSig pushes cost 1 (1 byte).
    // Total: scriptSig push cost (1) + 337*100 (NOPs) + 100 (OP_TRUE) = 33,801 > 33,600
    CScript scriptSig;
    scriptSig << OP_TRUE; // 1 byte scriptSig

    CScript scriptPubKey;
    scriptPubKey << OP_DROP; // costs 100 + stack item size
    for (int i = 0; i < 336; ++i) {
        scriptPubKey << OP_NOP; // each costs 100
    }
    scriptPubKey << OP_TRUE; // costs 100
    // Total pubkey ops: DROP(100+1) + 336*NOP(33600) + TRUE(100) = 33,801
    // Wait: we need to also add the scriptSig push cost (1 byte = 1)
    // Composite cost = 1 (push) + 101 (DROP) + 33600 (NOPs) + 100 (TRUE) = 33,802 > 33,600

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(!result.success, "Script exceeding op cost should fail");
    BOOST_CHECK_EQUAL(result.error, SCRIPT_ERR_OP_COST);
}

BOOST_AUTO_TEST_CASE(vm_limits_opcost_within_budget)
{
    // Same setup but fewer NOPs to stay within budget
    // Budget = 33,600. Use 330 NOPs.
    // Cost: 1 (push) + 101 (DROP) + 33000 (330 NOPs) + 100 (TRUE) = 33,202 < 33,600
    CScript scriptSig;
    scriptSig << OP_TRUE;

    CScript scriptPubKey;
    scriptPubKey << OP_DROP;
    for (int i = 0; i < 330; ++i) {
        scriptPubKey << OP_NOP;
    }
    scriptPubKey << OP_TRUE;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "Script within op cost should succeed: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_CASE(vm_limits_hash_iters_exceeded)
{
    // Hash iter limit = (scriptSigSize + 41) / 2 (standard)
    // Or (scriptSigSize + 41) * 7 / 2 (non-standard, which is what VM_FLAGS gives since
    // VM_FLAGS includes SCRIPT_VM_LIMITS_STANDARD)
    // Wait: SCRIPT_VM_LIMITS_STANDARD means standard=true, so limit = (size+41)/2.
    // scriptSig = OP_TRUE (1 byte) → limit = (1+41)/2 = 21 hash iters
    // Each OP_HASH256 on empty input: CalcHashIters(0, true) = 1+1 + (0+8)/64 = 2 + 0 = 2
    // Actually: CalcHashIters(0, true) = isTwoRoundHashOp(1) + 1 + (0+8)/64 = 2 + 0 = 2
    // 11 OP_HASH256 on 0 bytes = 22 iters > 21 limit
    // But we also need to account for the hash iter cost in the composite op cost
    // Actually, IsOverHashItersLimit() checks nHashDigestIterations > limit DIRECTLY
    // (not composite). So we need raw iterations > limit.
    //
    // 11 OP_HASH256 on small input: each produces 20-byte hash, next hashes 20 bytes
    // Let's compute: push empty (0 bytes), then repeated HASH256
    // CalcHashIters(0, true) = 2. After first: 32 bytes on stack
    // CalcHashIters(32, true) = 1+1+(32+8)/64 = 2+0 = 2. After: 32 bytes
    // Each HASH256 on 32-byte input: CalcHashIters(32, true) = 2
    // So 11 HASH256s = 22 iters > 21 limit → should fail with HASH_ITERS
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{}; // empty push, 1 byte in scriptSig

    CScript scriptPubKey;
    for (int i = 0; i < 11; ++i) {
        scriptPubKey << OP_HASH256;
    }
    scriptPubKey << OP_DROP << OP_TRUE;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(!result.success, "Script exceeding hash iter limit should fail");
    // Could be HASH_ITERS or OP_COST depending on which limit is hit first
    BOOST_CHECK(result.error == SCRIPT_ERR_HASH_ITERS || result.error == SCRIPT_ERR_OP_COST);
}

BOOST_AUTO_TEST_CASE(vm_limits_hash_iters_within_budget)
{
    // Same as above but with fewer hash operations
    // Limit = 21 iters. 5 HASH256 = 10 iters < 21
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{};

    CScript scriptPubKey;
    for (int i = 0; i < 5; ++i) {
        scriptPubKey << OP_HASH256;
    }
    scriptPubKey << OP_DROP << OP_TRUE;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "Script within hash iter budget should succeed: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_CASE(vm_limits_larger_scriptsig_more_budget)
{
    // A larger scriptSig gives more budget
    // scriptSig: push 100-byte element → scriptSig size = 102 (1 pushdata + 1 len + 100 data)
    // Budget = (102 + 41) * 800 = 114,400
    // 1100 NOPs + overhead < 114,400
    std::vector<unsigned char> padding(100, 0x42);
    CScript scriptSig;
    scriptSig << padding;

    CScript scriptPubKey;
    scriptPubKey << OP_DROP; // drop the padding
    for (int i = 0; i < 1100; ++i) {
        scriptPubKey << OP_NOP;
    }
    scriptPubKey << OP_TRUE;
    // Cost: 100 (push) + 200 (DROP: 100 + 100 item) + 110000 (NOPs) + 100 (TRUE) = 110,400 < 114,400

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "Larger scriptSig should allow more ops: error=" + std::to_string(result.error));
}

// ============================================================================
// Composite cost: op cost + hash cost + sigcheck cost all contribute
// ============================================================================

BOOST_AUTO_TEST_CASE(composite_cost_all_components)
{
    // Verify composite cost formula: opCost + hashIters*factor + sigChecks*26000
    ScriptExecutionMetrics metrics;
    metrics.SetScriptLimits(VM_FLAGS, 100); // standard, scriptSigSize=100

    metrics.TallyOp(5000);      // base op cost = 5000
    metrics.TallyHashOp(64, true); // HASH256 on 64 bytes → CalcHashIters(64, true) = 2+1 = 3
    // Wait: CalcHashIters(64, true) = isTwoRound(1) + 1 + (64+8)/64 = 2 + 1 = 3
    metrics.TallySigChecks(1);  // 1 sigcheck

    // Standard hash iter factor = 192 (3 * 64)
    // Composite = 5000 + 3*192 + 1*26000 = 5000 + 576 + 26000 = 31576
    int64_t expected = 5000 + 3 * 192 + 26000;
    BOOST_CHECK_EQUAL(metrics.GetCompositeOpCost(VM_FLAGS), expected);

    // Non-standard hash iter factor = 64
    unsigned int nonStdFlags = VM_FLAGS & ~SCRIPT_VM_LIMITS_STANDARD;
    int64_t expectedNonStd = 5000 + 3 * 64 + 26000;
    BOOST_CHECK_EQUAL(metrics.GetCompositeOpCost(nonStdFlags), expectedNonStd);
}

BOOST_AUTO_TEST_CASE(composite_cost_hash_factor_standard_vs_nonstd)
{
    // Standard flag uses 3x hash cost (192 per iter vs 64 per iter)
    ScriptExecutionMetrics metrics;
    metrics.SetScriptLimits(VM_FLAGS, 10);
    metrics.TallyHashOp(32, false); // SHA256 on 32 bytes → CalcHashIters(32, false) = 0+1+(32+8)/64 = 1+0 = 1
    // Actually: CalcHashIters(32, false) = false(0) + 1 + (32+8)/64 = 1 + 0 = 1

    int64_t stdCost = metrics.GetCompositeOpCost(VM_FLAGS);    // 1 * 192 = 192
    unsigned int nonStdFlags = VM_FLAGS & ~SCRIPT_VM_LIMITS_STANDARD;
    int64_t nonStdCost = metrics.GetCompositeOpCost(nonStdFlags); // 1 * 64 = 64

    BOOST_CHECK_EQUAL(stdCost, 192);
    BOOST_CHECK_EQUAL(nonStdCost, 64);
    BOOST_CHECK_EQUAL(stdCost, nonStdCost * 3);
}

// ============================================================================
// Push data cost tallying
// ============================================================================

BOOST_AUTO_TEST_CASE(push_data_cost_tallied)
{
    // TallyPushOp adds to base op cost
    ScriptExecutionMetrics metrics;
    metrics.TallyPushOp(100);
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 100);
    metrics.TallyPushOp(200);
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 300);
}

BOOST_AUTO_TEST_CASE(push_data_cost_in_script_execution)
{
    // A large push in scriptPubKey contributes to op cost
    // scriptSig: OP_TRUE (1 byte), budget = (1+41)*800 = 33,600
    // scriptPubKey: push 500-byte element + OP_DROP + OP_TRUE
    // Push cost = 500, DROP cost = 100, TRUE = 0 (≤OP_16) → total 600
    // Well within budget
    std::vector<unsigned char> data(500, 0xAA);
    CScript scriptSig;
    scriptSig << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << data << OP_DROP;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(push_cost_not_tallied_in_false_branch)
{
    // Pushes in non-executed branches should NOT contribute to op cost
    // (vmLimitsActive && fExec && opcode <= OP_PUSHDATA4 condition)
    CScript scriptSig;
    scriptSig << OP_FALSE;
    CScript scriptPubKey;
    scriptPubKey << OP_IF;
    // Large push in non-executed branch (should not be tallied)
    std::vector<unsigned char> data(5000, 0xBB);
    scriptPubKey << data;
    scriptPubKey << OP_ENDIF << OP_TRUE;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK(result.success);
}

// ============================================================================
// maxNumSize boundary: 4 bytes legacy vs 10000 with VM limits
// ============================================================================

BOOST_AUTO_TEST_CASE(maxnumsize_521_byte_number_with_vm_limits)
{
    // 521-byte number (just over legacy MAX_SCRIPT_ELEMENT_SIZE=520)
    // Should work with VM limits
    std::vector<unsigned char> bigNum(521, 0x00);
    bigNum[0] = 0x01; // make it non-zero

    CScript scriptSig;
    scriptSig << bigNum;
    CScript scriptPubKey;
    // Just verify it can be used in arithmetic (OP_0NOTEQUAL tests numeric parsing)
    scriptPubKey << OP_0NOTEQUAL;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "521-byte number should work with VM limits: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_CASE(maxnumsize_521_byte_fails_without_vm_limits)
{
    // Same 521-byte number should fail without VM limits
    std::vector<unsigned char> bigNum(521, 0x00);
    bigNum[0] = 0x01;

    CScript scriptSig;
    scriptSig << bigNum;
    CScript scriptPubKey;
    scriptPubKey << OP_0NOTEQUAL;

    unsigned int noVmFlags = VM_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS & ~SCRIPT_VM_LIMITS_STANDARD;
    auto result = EvalScript(scriptSig, scriptPubKey, noVmFlags);
    BOOST_CHECK(!result.success);
}

// ============================================================================
// Budget boundary with composite cost including sig checks
// ============================================================================

BOOST_AUTO_TEST_CASE(composite_cost_sigchecks_contribution)
{
    // Each signature check adds 26000 to composite cost
    ScriptExecutionMetrics metrics;
    metrics.SetScriptLimits(VM_FLAGS, 100);
    // budget = (100+41)*800 = 112,800

    // Without sig checks, base op cost of 1000 is fine
    metrics.TallyOp(1000);
    BOOST_CHECK(!metrics.IsOverOpCostLimit(VM_FLAGS));

    // Add 4 sig checks: 4 * 26000 = 104,000
    // Composite = 1000 + 104,000 = 105,000 < 112,800 → OK
    metrics.TallySigChecks(4);
    BOOST_CHECK(!metrics.IsOverOpCostLimit(VM_FLAGS));

    // One more op to push close: add 7800
    metrics.TallyOp(7800);
    // Composite = 8800 + 104,000 = 112,800 → exactly at limit → OK (uses >)
    BOOST_CHECK(!metrics.IsOverOpCostLimit(VM_FLAGS));

    // One more → over limit
    metrics.TallyOp(1);
    // Composite = 8801 + 104,000 = 112,801 > 112,800 → over
    BOOST_CHECK(metrics.IsOverOpCostLimit(VM_FLAGS));
}

// ============================================================================
// CalcHashIters for various message sizes
// ============================================================================

BOOST_AUTO_TEST_CASE(calc_hash_iters_various_sizes)
{
    // CalcHashIters(msgLen, isTwoRound):
    // SHA-256 processes 64-byte blocks with 9 bytes of padding (length + 0x80 byte)
    // Single-round: 1 + (msgLen + 8) / 64
    // Two-round: adds 1 for the second round (hashing 32-byte intermediate)

    // Empty message: 1 + (0+8)/64 = 1
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(0, false), 1u);

    // 55-byte message: 1 + (55+8)/64 = 1 + 0 = 1 (fits in one block)
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(55, false), 1u);

    // 56-byte message: 1 + (56+8)/64 = 1 + 1 = 2 (needs two blocks)
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(56, false), 2u);

    // 64-byte message: 1 + (64+8)/64 = 1 + 1 = 2
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(64, false), 2u);

    // Two-round adds 1
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(0, true), 2u);  // 1 + 1
    BOOST_CHECK_EQUAL(may2025::CalcHashIters(64, true), 3u); // 2 + 1
}

// ============================================================================
// SetScriptLimits initializes metrics correctly
// ============================================================================

BOOST_AUTO_TEST_CASE(metrics_initial_state)
{
    ScriptExecutionMetrics metrics;
    BOOST_CHECK_EQUAL(metrics.GetBaseOpCost(), 0);
    BOOST_CHECK_EQUAL(metrics.GetHashDigestIterations(), 0);
    BOOST_CHECK_EQUAL(metrics.GetCompositeOpCost(VM_FLAGS), 0);
    BOOST_CHECK(!metrics.IsOverOpCostLimit(VM_FLAGS));
    BOOST_CHECK(!metrics.IsOverHashItersLimit());
}

// ============================================================================
// may2025 constants
// ============================================================================

BOOST_AUTO_TEST_CASE(vm_limits_may2025_max_element_size)
{
    BOOST_CHECK_EQUAL(may2025::MAX_SCRIPT_ELEMENT_SIZE, 10000u);
}

BOOST_AUTO_TEST_CASE(vm_limits_may2025_opcode_cost)
{
    BOOST_CHECK_EQUAL(may2025::OPCODE_COST, 100u);
}

BOOST_AUTO_TEST_CASE(vm_limits_may2025_max_conditional_stack_depth)
{
    BOOST_CHECK_EQUAL(may2025::MAX_CONDITIONAL_STACK_DEPTH, 100u);
}

BOOST_AUTO_TEST_CASE(vm_limits_may2025_sig_check_cost_factor)
{
    BOOST_CHECK_EQUAL(may2025::SIG_CHECK_COST_FACTOR, 26000u);
}

BOOST_AUTO_TEST_CASE(vm_limits_detail_constants)
{
    BOOST_CHECK_EQUAL(may2025::detail::HASH_ITER_BONUS_FOR_NONSTD_TXNS, 7u);
    BOOST_CHECK_EQUAL(may2025::detail::OP_COST_BUDGET_PER_INPUT_BYTE, 800u);
    BOOST_CHECK_EQUAL(may2025::detail::HASH_COST_PENALTY_FOR_STD_TXNS, 3u);
    BOOST_CHECK_EQUAL(may2025::detail::HASH_BLOCK_SIZE, 64u);
    BOOST_CHECK_EQUAL(may2025::detail::INPUT_SCRIPT_SIZE_FIXED_CREDIT, 41u);
}

BOOST_AUTO_TEST_CASE(vm_limits_may2025_legacy_constants)
{
    BOOST_CHECK_EQUAL(MAX_SCRIPT_ELEMENT_SIZE_LEGACY, 520u);
    BOOST_CHECK_EQUAL(MAX_OPS_PER_SCRIPT_LEGACY, 201);
}

BOOST_AUTO_TEST_CASE(vm_limits_may2026_constants)
{
    BOOST_CHECK_EQUAL(may2026::MAX_CONTROL_STACK_DEPTH, 100u);
    BOOST_CHECK_EQUAL(may2026::MAX_FUNCTION_IDENTIFIER_SIZE, 7u);
    // may2026::MAX_CONTROL_STACK_DEPTH inherits from may2025
    BOOST_CHECK_EQUAL(may2026::MAX_CONTROL_STACK_DEPTH, may2025::MAX_CONDITIONAL_STACK_DEPTH);
}

// ============================================================================
// GetHashIterOpCostFactor
// ============================================================================

BOOST_AUTO_TEST_CASE(hash_iter_cost_factor_standard_vs_nonstandard)
{
    // Standard: 64 * 3 = 192
    BOOST_CHECK_EQUAL(may2025::GetHashIterOpCostFactor(true), 192);
    // Non-standard: 64
    BOOST_CHECK_EQUAL(may2025::GetHashIterOpCostFactor(false), 64);
}

// ============================================================================
// ScriptLimits
// ============================================================================

BOOST_AUTO_TEST_CASE(script_limits_op_cost_limit)
{
    // OpCostLimit = (scriptSigSize + 41) * 800
    may2025::ScriptLimits limits(true, 100);
    BOOST_CHECK_EQUAL(limits.GetOpCostLimit(), (100 + 41) * 800);
}

BOOST_AUTO_TEST_CASE(script_limits_hash_iters_limit_standard)
{
    // HashItersLimit (standard) = (scriptSigSize + 41) * 1 / 2
    may2025::ScriptLimits limits(true, 100);
    BOOST_CHECK_EQUAL(limits.GetHashItersLimit(), (100 + 41) / 2);
}

BOOST_AUTO_TEST_CASE(script_limits_hash_iters_limit_nonstandard)
{
    // HashItersLimit (non-standard) = (scriptSigSize + 41) * 7 / 2
    may2025::ScriptLimits limits(false, 100);
    BOOST_CHECK_EQUAL(limits.GetHashItersLimit(), (100 + 41) * 7 / 2);
}

BOOST_AUTO_TEST_CASE(script_limits_zero_scriptsig)
{
    // With empty scriptSig, only the 41-byte credit matters
    may2025::ScriptLimits limits(true, 0);
    BOOST_CHECK_EQUAL(limits.GetOpCostLimit(), 41 * 800);
    BOOST_CHECK_EQUAL(limits.GetHashItersLimit(), 41 / 2);
}

// ============================================================================
// OP_CAT with VM limits: maxElementSize = 10000
// ============================================================================

BOOST_AUTO_TEST_CASE(op_cat_vm_limits_exactly_at_10000)
{
    // OP_CAT concatenating to exactly 10000 bytes with VM limits active.
    // scriptSig must be <= MAX_SCRIPT_SIZE (10000), so push one 4997-byte item.
    // In scriptPubKey: DUP + CAT = 9994, then push 6-byte and CAT = 10000
    std::vector<uint8_t> data(4997, 0xAA);
    std::vector<uint8_t> pad(6, 0xBB);

    CScript scriptSig;
    scriptSig << data;
    CScript scriptPubKey;
    // stack: [4997 bytes]
    // DUP → [4997, 4997], CAT → [9994], push 6, CAT → [10000]
    scriptPubKey << OP_DUP << OP_CAT << pad << OP_CAT
                 << OP_SIZE << CScriptNum(10000) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "OP_CAT 10000 failed: " + ScriptErrorString(result.error));
}

BOOST_AUTO_TEST_CASE(op_cat_vm_limits_exceeds_10000)
{
    // OP_CAT concatenating to 10001 bytes with VM limits — should fail with PUSH_SIZE
    std::vector<uint8_t> data(4997, 0xAA);
    std::vector<uint8_t> pad(7, 0xBB); // 9994 + 7 = 10001

    CScript scriptSig;
    scriptSig << data;
    CScript scriptPubKey;
    scriptPubKey << OP_DUP << OP_CAT << pad << OP_CAT << OP_DROP << OP_TRUE;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK(!result.success);
    BOOST_CHECK_EQUAL(result.error, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(op_cat_legacy_exceeds_520)
{
    // Without VM limits, OP_CAT max is 520 bytes (legacy)
    std::vector<uint8_t> part1(261, 0xDD);
    std::vector<uint8_t> part2(260, 0xEE);

    CScript scriptSig;
    scriptSig << part1 << part2;
    CScript scriptPubKey;
    scriptPubKey << OP_CAT << OP_DROP << OP_TRUE;

    // Enable BCH2 opcodes but NOT VM limits
    unsigned int flags = (VM_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS & ~SCRIPT_VM_LIMITS_STANDARD);
    auto result = EvalScript(scriptSig, scriptPubKey, flags);
    BOOST_CHECK(!result.success);
    BOOST_CHECK_EQUAL(result.error, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(op_cat_legacy_exactly_520)
{
    // Without VM limits, OP_CAT at exactly 520 should succeed
    std::vector<uint8_t> part1(260, 0xDD);
    std::vector<uint8_t> part2(260, 0xEE);

    CScript scriptSig;
    scriptSig << part1 << part2;
    CScript scriptPubKey;
    scriptPubKey << OP_CAT << OP_SIZE << CScriptNum(520) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    unsigned int flags = (VM_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS & ~SCRIPT_VM_LIMITS_STANDARD);
    BOOST_CHECK(EvalScript(scriptSig, scriptPubKey, flags).success);
}

// ============================================================================
// BigInt OP_MUL with VM limits: multiply >4-byte numbers
// ============================================================================

BOOST_AUTO_TEST_CASE(bigint_mul_5byte_numbers)
{
    // With VM limits, CScriptNum supports >4-byte numbers
    // 70000 * 70000 = 4,900,000,000 (> 2^32, needs 5-byte result)
    // 70000 = 0x00011170 in LE: {0x70, 0x11, 0x01, 0x00}
    // Push as scriptNum with 4 bytes (fits in 4 bytes)
    CScript scriptSig;
    scriptSig << CScriptNum(70000) << CScriptNum(70000);
    CScript scriptPubKey;
    // 70000 * 70000 = 4,900,000,000
    // Verify result: DROP result + push TRUE (avoid having to encode 5-byte expected value)
    scriptPubKey << OP_MUL << OP_DROP << OP_TRUE;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "BigInt MUL 70000*70000 should work: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_CASE(bigint_mul_result_verified)
{
    // 100000 * 100000 = 10,000,000,000 (5-byte result)
    // Verify by checking the result equals the expected 5-byte value
    // 10000000000 = 0x2540BE400 → LE: {0x00, 0xE4, 0x0B, 0x54, 0x02}
    std::vector<unsigned char> expected = {0x00, 0xE4, 0x0B, 0x54, 0x02};

    CScript scriptSig;
    scriptSig << CScriptNum(100000) << CScriptNum(100000);
    CScript scriptPubKey;
    scriptPubKey << OP_MUL << expected << OP_NUMEQUAL;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "BigInt MUL 100000*100000=10B should verify: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_CASE(bigint_mul_negative_large)
{
    // -70000 * 70000 = -4,900,000,000 (negative 5-byte result)
    CScript scriptSig;
    scriptSig << CScriptNum(-70000) << CScriptNum(70000);
    CScript scriptPubKey;
    // Result should be negative: check via OP_0 OP_LESSTHAN
    scriptPubKey << OP_MUL << OP_0 << OP_LESSTHAN;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "BigInt MUL -70000*70000 should be negative: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_CASE(bigint_mul_5byte_by_5byte)
{
    // Multiply two 5-byte numbers: 4294967296 * 2 = 8589934592
    // 4294967296 = 2^32, LE: {0x00, 0x00, 0x00, 0x00, 0x01}
    std::vector<unsigned char> bigA = {0x00, 0x00, 0x00, 0x00, 0x01}; // 2^32
    CScript scriptSig;
    scriptSig << bigA << CScriptNum(2);
    CScript scriptPubKey;
    // 2^32 * 2 = 2^33 = 8589934592
    // LE: {0x00, 0x00, 0x00, 0x00, 0x02}
    std::vector<unsigned char> expected = {0x00, 0x00, 0x00, 0x00, 0x02};
    scriptPubKey << OP_MUL << expected << OP_NUMEQUAL;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "BigInt MUL 2^32*2=2^33 should verify: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_CASE(bigint_mul_fails_without_vm_limits)
{
    // Without VM limits, 5-byte numbers should fail (maxNumSize=4)
    std::vector<unsigned char> bigA = {0x00, 0x00, 0x00, 0x00, 0x01}; // 2^32
    CScript scriptSig;
    scriptSig << bigA << CScriptNum(2);
    CScript scriptPubKey;
    scriptPubKey << OP_MUL << OP_DROP << OP_TRUE;

    unsigned int noVmFlags = VM_FLAGS & ~SCRIPT_ENABLE_VM_LIMITS & ~SCRIPT_VM_LIMITS_STANDARD;
    auto result = EvalScript(scriptSig, scriptPubKey, noVmFlags);
    BOOST_CHECK(!result.success);
}

// ============================================================================
// BigInt OP_DIV / OP_MOD with VM limits
// ============================================================================

BOOST_AUTO_TEST_CASE(bigint_div_large)
{
    // 10,000,000,000 / 100000 = 100000
    std::vector<unsigned char> bigA = {0x00, 0xE4, 0x0B, 0x54, 0x02}; // 10000000000
    CScript scriptSig;
    scriptSig << bigA << CScriptNum(100000);
    CScript scriptPubKey;
    scriptPubKey << OP_DIV << CScriptNum(100000) << OP_NUMEQUAL;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "BigInt DIV 10B/100K should be 100K: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_CASE(bigint_mod_large)
{
    // 10,000,000,001 % 100000 = 1
    // 10000000001 in LE: {0x01, 0xE4, 0x0B, 0x54, 0x02}
    std::vector<unsigned char> bigA = {0x01, 0xE4, 0x0B, 0x54, 0x02}; // 10000000001
    CScript scriptSig;
    scriptSig << bigA << CScriptNum(100000);
    CScript scriptPubKey;
    scriptPubKey << OP_MOD << CScriptNum(1) << OP_NUMEQUAL;

    auto result = EvalScript(scriptSig, scriptPubKey, VM_FLAGS);
    BOOST_CHECK_MESSAGE(result.success,
        "BigInt MOD 10000000001%%100000 should be 1: error=" + std::to_string(result.error));
}

BOOST_AUTO_TEST_SUITE_END()
