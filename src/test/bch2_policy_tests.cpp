// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for BCH2-specific policy rules: dust threshold, fee constants, script flags.

#include <policy/policy.h>
#include <policy/feerate.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/interpreter.h>
#include <script/solver.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(bch2_policy_tests)

// ===== BCH2 fee constants =====

BOOST_AUTO_TEST_CASE(dust_relay_fee_is_1000)
{
    // BCH2 uses 1000 sat/kvB dust relay fee (not 3000 as in BTC)
    BOOST_CHECK_EQUAL(DUST_RELAY_TX_FEE, 1000u);
}

BOOST_AUTO_TEST_CASE(default_min_relay_fee_is_1000)
{
    BOOST_CHECK_EQUAL(DEFAULT_MIN_RELAY_TX_FEE, 1000u);
}

BOOST_AUTO_TEST_CASE(default_block_min_tx_fee_is_1000)
{
    BOOST_CHECK_EQUAL(DEFAULT_BLOCK_MIN_TX_FEE, 1000u);
}

// ===== GetDustThreshold =====

BOOST_AUTO_TEST_CASE(dust_threshold_p2pkh)
{
    // P2PKH output: 34 bytes (8 amount + 1 scriptLen + 25 scriptPubKey)
    // Input size: 148 bytes (32 prevhash + 4 index + 1 scriptLen + 107 scriptSig + 4 nSequence)
    // Total: 34 + 148 = 182 bytes
    // At 1000 sat/kvB: 182 * 1000 / 1000 = 182 sat
    CTxOut txout;
    txout.nValue = 1000;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);
    CAmount threshold = GetDustThreshold(txout, dustRelayFee);

    // Verify it's based on the 1000 sat/kvB rate
    BOOST_CHECK(threshold > 0);
    BOOST_CHECK(threshold < 1000); // Should be ~182 at 1000 sat/kvB

    // At BTC's 3000 rate it would be ~546; at BCH2's 1000 rate it should be ~182
    BOOST_CHECK(threshold < 300);
}

BOOST_AUTO_TEST_CASE(dust_threshold_unspendable_is_zero)
{
    // OP_RETURN outputs are unspendable → threshold = 0
    CTxOut txout;
    txout.nValue = 0;
    txout.scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(10, 0x00);

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);
    CAmount threshold = GetDustThreshold(txout, dustRelayFee);
    BOOST_CHECK_EQUAL(threshold, 0);
}

BOOST_AUTO_TEST_CASE(dust_threshold_p2sh)
{
    // P2SH output is slightly smaller than P2PKH
    CTxOut txout;
    txout.nValue = 1000;
    txout.scriptPubKey = CScript() << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUAL;

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);
    CAmount threshold = GetDustThreshold(txout, dustRelayFee);
    BOOST_CHECK(threshold > 0);
    BOOST_CHECK(threshold < 300);
}

BOOST_AUTO_TEST_CASE(dust_threshold_with_zero_fee)
{
    // Zero fee rate → zero dust threshold
    CTxOut txout;
    txout.nValue = 1;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;

    CFeeRate zeroFee(0);
    CAmount threshold = GetDustThreshold(txout, zeroFee);
    BOOST_CHECK_EQUAL(threshold, 0);
}

// ===== IsDust =====

BOOST_AUTO_TEST_CASE(is_dust_below_threshold)
{
    CTxOut txout;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);
    CAmount threshold = GetDustThreshold(txout, dustRelayFee);

    // Below threshold → dust
    txout.nValue = threshold - 1;
    BOOST_CHECK(IsDust(txout, dustRelayFee));
}

BOOST_AUTO_TEST_CASE(is_dust_at_threshold)
{
    CTxOut txout;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);
    CAmount threshold = GetDustThreshold(txout, dustRelayFee);

    // Exactly at threshold → NOT dust (nValue < threshold is dust)
    txout.nValue = threshold;
    BOOST_CHECK(!IsDust(txout, dustRelayFee));
}

BOOST_AUTO_TEST_CASE(is_dust_above_threshold)
{
    CTxOut txout;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);
    CAmount threshold = GetDustThreshold(txout, dustRelayFee);

    // Above threshold → NOT dust
    txout.nValue = threshold + 1;
    BOOST_CHECK(!IsDust(txout, dustRelayFee));
}

BOOST_AUTO_TEST_CASE(is_dust_op_return_never_dust)
{
    CTxOut txout;
    txout.nValue = 0;
    txout.scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(20, 0x00);

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);
    // OP_RETURN with 0 value: threshold is 0, so 0 < 0 = false → NOT dust
    BOOST_CHECK(!IsDust(txout, dustRelayFee));
}

// ===== BCH2 script verification flags =====

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_include_forkid)
{
    BOOST_CHECK(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_SIGHASH_FORKID);
}

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_include_no_segwit)
{
    BOOST_CHECK(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_NO_SEGWIT);
}

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_no_witness)
{
    // Post-fork mandatory flags should NOT include WITNESS or TAPROOT
    BOOST_CHECK(!(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_WITNESS));
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_schnorr)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_SCHNORR);
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_introspection)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_INTROSPECTION);
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_vm_limits)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_VM_LIMITS);
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_bch2_opcodes)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_BCH2_OPCODES);
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_arithmetic_opcodes)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_ARITHMETIC_OPCODES);
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_bitwise_opcodes)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_BITWISE_OPCODES);
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_reversebytes)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_REVERSEBYTES);
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_cleanstack)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_CLEANSTACK);
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_sigpushonly)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_SIGPUSHONLY);
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_include_vm_limits_standard)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VM_LIMITS_STANDARD);
}

// ===== BCH2 minimum tx size =====

BOOST_AUTO_TEST_CASE(bch2_min_tx_size_is_65)
{
    // BCH2 post-fork minimum is 65 bytes (Magnetic Anomaly)
    BOOST_CHECK_EQUAL(BCH2_MIN_STANDARD_TX_SIZE, 65u);
}

// ===== Other BCH2-specific policy constants =====

BOOST_AUTO_TEST_CASE(max_op_return_relay_is_223)
{
    // BCH2 matches BCH: 220 data bytes + OP_RETURN + 2 pushdata opcodes = 223
    BOOST_CHECK_EQUAL(MAX_OP_RETURN_RELAY, 223u);
}

BOOST_AUTO_TEST_CASE(tx_max_standard_version_is_2)
{
    BOOST_CHECK_EQUAL(TX_MAX_STANDARD_VERSION, 2);
}

// ===== Consensus constants =====

BOOST_AUTO_TEST_CASE(max_block_sigops_cost_is_640000)
{
    BOOST_CHECK_EQUAL(MAX_BLOCK_SIGOPS_COST, 640000);
}

BOOST_AUTO_TEST_CASE(max_standard_tx_sigops_cost_is_128000)
{
    // MAX_BLOCK_SIGOPS_COST / 5
    BOOST_CHECK_EQUAL(MAX_STANDARD_TX_SIGOPS_COST, 128000u);
}

BOOST_AUTO_TEST_CASE(witness_scale_factor_is_1)
{
    // BCH2 has no SegWit discount — weight == size
    BOOST_CHECK_EQUAL(WITNESS_SCALE_FACTOR, 1);
}

BOOST_AUTO_TEST_CASE(max_standard_tx_weight_is_100000)
{
    BOOST_CHECK_EQUAL(MAX_STANDARD_TX_WEIGHT, 100000);
}

BOOST_AUTO_TEST_CASE(max_standard_scriptsig_size_is_1650)
{
    BOOST_CHECK_EQUAL(MAX_STANDARD_SCRIPTSIG_SIZE, 1650u);
}

BOOST_AUTO_TEST_CASE(max_p2sh_sigops_is_15)
{
    BOOST_CHECK_EQUAL(MAX_P2SH_SIGOPS, 15u);
}

BOOST_AUTO_TEST_CASE(bch2_max_block_size_is_32mb)
{
    BOOST_CHECK_EQUAL(BCH2_MAX_BLOCK_SIZE, 32000000u);
}

BOOST_AUTO_TEST_CASE(max_consensus_block_size_is_2gb)
{
    BOOST_CHECK_EQUAL(MAX_CONSENSUS_BLOCK_SIZE, uint64_t{2'000'000'000});
}

BOOST_AUTO_TEST_CASE(default_bytes_per_sigop_is_20)
{
    BOOST_CHECK_EQUAL(DEFAULT_BYTES_PER_SIGOP, 20u);
}

BOOST_AUTO_TEST_CASE(default_permit_baremultisig_is_true)
{
    BOOST_CHECK(DEFAULT_PERMIT_BAREMULTISIG);
}

BOOST_AUTO_TEST_CASE(coinbase_maturity_is_100)
{
    BOOST_CHECK_EQUAL(COINBASE_MATURITY, 100);
}

// ===== IsStandardTx version boundary tests =====

static CMutableTransaction MakeSimpleStandardTx()
{
    // Build a minimal standard transaction: 1 input, 1 P2PKH output
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    // Push-only scriptSig (just a dummy push)
    tx.vin[0].scriptSig = CScript() << std::vector<uint8_t>(72, 0x30);
    tx.vout.resize(1);
    tx.vout[0].nValue = 50000;
    tx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                        << std::vector<uint8_t>(20, 0xAA)
                                        << OP_EQUALVERIFY << OP_CHECKSIG;
    return tx;
}

BOOST_AUTO_TEST_CASE(is_standard_tx_version_1_accepted)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    tx.nVersion = 1;
    std::string reason;
    BOOST_CHECK(IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                             CFeeRate(DUST_RELAY_TX_FEE), reason));
}

BOOST_AUTO_TEST_CASE(is_standard_tx_version_2_accepted)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    tx.nVersion = 2;
    std::string reason;
    BOOST_CHECK(IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                             CFeeRate(DUST_RELAY_TX_FEE), reason));
}

BOOST_AUTO_TEST_CASE(is_standard_tx_version_3_rejected)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    tx.nVersion = 3;
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                              CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "version");
}

BOOST_AUTO_TEST_CASE(is_standard_tx_version_0_rejected)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    tx.nVersion = 0;
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                              CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "version");
}

BOOST_AUTO_TEST_CASE(is_standard_tx_version_negative_rejected)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    tx.nVersion = -1;
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                              CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "version");
}

// ===== IsStandardTx scriptsig boundary tests =====

BOOST_AUTO_TEST_CASE(is_standard_tx_scriptsig_at_max_accepted)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    // ScriptSig exactly at MAX_STANDARD_SCRIPTSIG_SIZE (1650)
    // Use push-only: OP_PUSHDATA2 <1647 bytes> = 1 + 2 + 1647 = 1650
    std::vector<uint8_t> data(1647, 0x42);
    tx.vin[0].scriptSig = CScript() << data;
    std::string reason;
    BOOST_CHECK_EQUAL(tx.vin[0].scriptSig.size(), 1650u);
    BOOST_CHECK(IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                             CFeeRate(DUST_RELAY_TX_FEE), reason));
}

BOOST_AUTO_TEST_CASE(is_standard_tx_scriptsig_one_over_max_rejected)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    // ScriptSig at MAX_STANDARD_SCRIPTSIG_SIZE + 1 (1651)
    std::vector<uint8_t> data(1648, 0x42);
    tx.vin[0].scriptSig = CScript() << data;
    std::string reason;
    BOOST_CHECK_EQUAL(tx.vin[0].scriptSig.size(), 1651u);
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                              CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "scriptsig-size");
}

BOOST_AUTO_TEST_CASE(is_standard_tx_scriptsig_not_pushonly_rejected)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    // scriptSig with a non-push opcode (OP_NOP)
    tx.vin[0].scriptSig = CScript() << std::vector<uint8_t>(10, 0x42) << OP_NOP;
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                              CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "scriptsig-not-pushonly");
}

// ===== IsStandard output type: multisig boundary tests =====

BOOST_AUTO_TEST_CASE(is_standard_output_multisig_1_of_1_accepted)
{
    CScript script;
    script << OP_1 << std::vector<uint8_t>(33, 0x02) << OP_1 << OP_CHECKMULTISIG;
    TxoutType whichType;
    BOOST_CHECK(IsStandard(script, MAX_OP_RETURN_RELAY, whichType));
    BOOST_CHECK(whichType == TxoutType::MULTISIG);
}

BOOST_AUTO_TEST_CASE(is_standard_output_multisig_1_of_3_accepted)
{
    // All compressed pubkeys must start with 0x02 or 0x03
    std::vector<uint8_t> key1(33, 0x11); key1[0] = 0x02;
    std::vector<uint8_t> key2(33, 0x22); key2[0] = 0x03;
    std::vector<uint8_t> key3(33, 0x33); key3[0] = 0x02;
    CScript script;
    script << OP_1 << key1 << key2 << key3 << OP_3 << OP_CHECKMULTISIG;
    TxoutType whichType;
    BOOST_CHECK(IsStandard(script, MAX_OP_RETURN_RELAY, whichType));
    BOOST_CHECK(whichType == TxoutType::MULTISIG);
}

BOOST_AUTO_TEST_CASE(is_standard_output_multisig_3_of_3_accepted)
{
    std::vector<uint8_t> key1(33, 0x11); key1[0] = 0x02;
    std::vector<uint8_t> key2(33, 0x22); key2[0] = 0x03;
    std::vector<uint8_t> key3(33, 0x33); key3[0] = 0x02;
    CScript script;
    script << OP_3 << key1 << key2 << key3 << OP_3 << OP_CHECKMULTISIG;
    TxoutType whichType;
    BOOST_CHECK(IsStandard(script, MAX_OP_RETURN_RELAY, whichType));
    BOOST_CHECK(whichType == TxoutType::MULTISIG);
}

BOOST_AUTO_TEST_CASE(is_standard_output_multisig_1_of_4_rejected)
{
    // n > 3 → nonstandard multisig
    std::vector<uint8_t> key1(33, 0x11); key1[0] = 0x02;
    std::vector<uint8_t> key2(33, 0x22); key2[0] = 0x03;
    std::vector<uint8_t> key3(33, 0x33); key3[0] = 0x02;
    std::vector<uint8_t> key4(33, 0x44); key4[0] = 0x03;
    CScript script;
    script << OP_1 << key1 << key2 << key3 << key4 << OP_4 << OP_CHECKMULTISIG;
    TxoutType whichType;
    BOOST_CHECK(!IsStandard(script, MAX_OP_RETURN_RELAY, whichType));
}

// ===== IsStandard output: NULL_DATA size boundary =====

BOOST_AUTO_TEST_CASE(is_standard_output_null_data_at_223_accepted)
{
    // Exactly MAX_OP_RETURN_RELAY (223 bytes total)
    // OP_RETURN (1) + OP_PUSHDATA1 (1) + length byte (1) + data (220) = 223
    CScript script;
    script << OP_RETURN << std::vector<uint8_t>(220, 0xFF);
    TxoutType whichType;
    BOOST_CHECK_EQUAL(script.size(), 223u);
    BOOST_CHECK(IsStandard(script, MAX_OP_RETURN_RELAY, whichType));
    BOOST_CHECK(whichType == TxoutType::NULL_DATA);
}

BOOST_AUTO_TEST_CASE(is_standard_output_null_data_at_224_rejected)
{
    // One byte over MAX_OP_RETURN_RELAY → rejected
    CScript script;
    script << OP_RETURN << std::vector<uint8_t>(221, 0xFF);
    TxoutType whichType;
    BOOST_CHECK(script.size() > MAX_OP_RETURN_RELAY);
    BOOST_CHECK(!IsStandard(script, MAX_OP_RETURN_RELAY, whichType));
}

BOOST_AUTO_TEST_CASE(is_standard_output_empty_null_data_accepted)
{
    // Just OP_RETURN with no data — valid NULL_DATA, size 1 ≤ 223
    CScript script;
    script << OP_RETURN;
    TxoutType whichType;
    BOOST_CHECK(IsStandard(script, MAX_OP_RETURN_RELAY, whichType));
    BOOST_CHECK(whichType == TxoutType::NULL_DATA);
}

BOOST_AUTO_TEST_CASE(is_standard_output_null_data_disabled)
{
    // If max_datacarrier_bytes is nullopt → NULL_DATA rejected
    CScript script;
    script << OP_RETURN << std::vector<uint8_t>(10, 0xFF);
    TxoutType whichType;
    BOOST_CHECK(!IsStandard(script, std::nullopt, whichType));
}

// ===== IsStandardTx multi-OP_RETURN =====

BOOST_AUTO_TEST_CASE(is_standard_tx_one_op_return_accepted)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    // Add one OP_RETURN output (keep P2PKH output too)
    CTxOut opRetOut;
    opRetOut.nValue = 0;
    opRetOut.scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(10, 0x00);
    tx.vout.push_back(opRetOut);
    std::string reason;
    BOOST_CHECK(IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                             CFeeRate(DUST_RELAY_TX_FEE), reason));
}

BOOST_AUTO_TEST_CASE(is_standard_tx_two_op_returns_rejected)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    // Add two OP_RETURN outputs
    CTxOut opRetOut;
    opRetOut.nValue = 0;
    opRetOut.scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(10, 0x00);
    tx.vout.push_back(opRetOut);
    tx.vout.push_back(opRetOut);
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                              CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "multi-op-return");
}

// ===== IsStandardTx bare-multisig with permit=false =====

BOOST_AUTO_TEST_CASE(is_standard_tx_bare_multisig_permitted)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    tx.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<uint8_t>(33, 0x02) << OP_1 << OP_CHECKMULTISIG;
    tx.vout[0].nValue = 50000;
    std::string reason;
    BOOST_CHECK(IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                             CFeeRate(DUST_RELAY_TX_FEE), reason));
}

BOOST_AUTO_TEST_CASE(is_standard_tx_bare_multisig_not_permitted)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    tx.vout[0].scriptPubKey = CScript() << OP_1 << std::vector<uint8_t>(33, 0x02) << OP_1 << OP_CHECKMULTISIG;
    tx.vout[0].nValue = 50000;
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, false,
                              CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "bare-multisig");
}

// ===== IsStandardTx dust rejection =====

BOOST_AUTO_TEST_CASE(is_standard_tx_dust_output_rejected)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    tx.vout[0].nValue = 1; // 1 satoshi — below dust threshold
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                              CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "dust");
}

BOOST_AUTO_TEST_CASE(is_standard_tx_nonstandard_output_rejected)
{
    CMutableTransaction tx = MakeSimpleStandardTx();
    // Nonstandard scriptPubKey: raw opcode sequence
    tx.vout[0].scriptPubKey = CScript() << OP_NOP << OP_NOP << OP_TRUE;
    tx.vout[0].nValue = 50000;
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx), MAX_OP_RETURN_RELAY, true,
                              CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");
}

// ===== BCH2 mandatory flags negative tests =====

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_no_taproot)
{
    BOOST_CHECK(!(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_TAPROOT));
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_no_witness)
{
    BOOST_CHECK(!(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_WITNESS));
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_no_taproot)
{
    BOOST_CHECK(!(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_TAPROOT));
}

BOOST_AUTO_TEST_CASE(bch2_full_flags_no_shift_opcodes)
{
    // Shift opcodes (upgrade12) deliberately omitted — NEVER_ACTIVE_HEIGHT
    BOOST_CHECK(!(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_SHIFT_OPCODES));
}

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_include_p2sh)
{
    BOOST_CHECK(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_P2SH);
}

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_include_dersig)
{
    BOOST_CHECK(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_DERSIG);
}

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_include_cltv)
{
    BOOST_CHECK(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY);
}

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_include_csv)
{
    BOOST_CHECK(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY);
}

// ===== GetVirtualTransactionSize with WITNESS_SCALE_FACTOR=1 =====

BOOST_AUTO_TEST_CASE(virtual_tx_size_equals_weight)
{
    // With WITNESS_SCALE_FACTOR=1, vsize == weight == serialized size
    CMutableTransaction tx = MakeSimpleStandardTx();
    CTransaction ctx(tx);
    int64_t weight = GetTransactionWeight(ctx);
    int64_t vsize = GetVirtualTransactionSize(ctx);
    BOOST_CHECK_EQUAL(weight, vsize);
}

BOOST_AUTO_TEST_CASE(incremental_relay_fee_is_1000)
{
    BOOST_CHECK_EQUAL(DEFAULT_INCREMENTAL_RELAY_FEE, 1000u);
}

BOOST_AUTO_TEST_CASE(extra_descendant_tx_size_limit_is_10000)
{
    BOOST_CHECK_EQUAL(EXTRA_DESCENDANT_TX_SIZE_LIMIT, 10000u);
}

BOOST_AUTO_TEST_CASE(default_ancestor_limit_is_25)
{
    BOOST_CHECK_EQUAL(DEFAULT_ANCESTOR_LIMIT, 25u);
}

BOOST_AUTO_TEST_CASE(default_descendant_limit_is_25)
{
    BOOST_CHECK_EQUAL(DEFAULT_DESCENDANT_LIMIT, 25u);
}

// ===== GetDustThreshold exact value verification =====

BOOST_AUTO_TEST_CASE(dust_threshold_p2pkh_exact_value)
{
    // P2PKH output: 34 bytes serialized (8 value + 1 scriptLen + 25 scriptPubKey)
    // Input cost: 32 (prevhash) + 4 (index) + 1 (scriptLen) + 107 (scriptSig) + 4 (nSequence) = 148
    // Total: 34 + 148 = 182 bytes
    // At 1000 sat/kvB: ceil(182 * 1000 / 1000) = 182 sat
    CTxOut txout;
    txout.nValue = 1000;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);
    CAmount threshold = GetDustThreshold(txout, dustRelayFee);
    BOOST_CHECK_EQUAL(threshold, 182);
}

BOOST_AUTO_TEST_CASE(dust_threshold_p2sh_exact_value)
{
    // P2SH output: 32 bytes serialized (8 value + 1 scriptLen + 23 scriptPubKey)
    // Input cost: same 148 for non-witness
    // Total: 32 + 148 = 180 bytes
    // At 1000 sat/kvB: 180 sat
    CTxOut txout;
    txout.nValue = 1000;
    txout.scriptPubKey = CScript() << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUAL;

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);
    CAmount threshold = GetDustThreshold(txout, dustRelayFee);
    BOOST_CHECK_EQUAL(threshold, 180);
}

BOOST_AUTO_TEST_CASE(is_dust_at_exact_p2pkh_threshold)
{
    // Verify IsDust boundary at exactly 182 sat for P2PKH
    CTxOut txout;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;

    CFeeRate dustRelayFee(DUST_RELAY_TX_FEE);

    txout.nValue = 181;
    BOOST_CHECK(IsDust(txout, dustRelayFee)); // 181 < 182 → dust

    txout.nValue = 182;
    BOOST_CHECK(!IsDust(txout, dustRelayFee)); // 182 == 182 → NOT dust
}

// ===== IsStandardTx tx weight boundary =====

BOOST_AUTO_TEST_CASE(is_standard_tx_weight_at_max_accepted)
{
    // Build a tx whose weight == MAX_STANDARD_TX_WEIGHT (100000)
    // With WITNESS_SCALE_FACTOR=1, weight == serialized size
    // Strategy: iteratively adjust data size until exact match
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].scriptSig = CScript() << std::vector<uint8_t>(72, 0x30); // push-only
    tx.vout.resize(1);
    tx.vout[0].nValue = 0; // OP_RETURN can have 0 value

    // Start with a rough estimate, then adjust
    size_t dataSize = 99900; // start large, will adjust down
    for (int i = 0; i < 5; ++i) {
        tx.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(dataSize, 0xAA);
        CTransaction ctx(tx);
        int64_t currentWeight = GetTransactionWeight(ctx);
        int64_t diff = currentWeight - MAX_STANDARD_TX_WEIGHT;
        if (diff == 0) break;
        dataSize -= static_cast<size_t>(diff);
    }

    CTransaction finalTx(tx);
    BOOST_CHECK_EQUAL(GetTransactionWeight(finalTx), MAX_STANDARD_TX_WEIGHT);

    std::string reason;
    // Pass large max_datacarrier_bytes to allow the big OP_RETURN
    BOOST_CHECK(IsStandardTx(finalTx, std::optional<unsigned>(200000), true, CFeeRate(0), reason));
}

BOOST_AUTO_TEST_CASE(is_standard_tx_weight_one_over_max_rejected)
{
    // Build a tx with weight > MAX_STANDARD_TX_WEIGHT → "tx-size"
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].scriptSig = CScript() << std::vector<uint8_t>(72, 0x30);
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    size_t dataSize = 99901;
    for (int i = 0; i < 5; ++i) {
        tx.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<uint8_t>(dataSize, 0xAA);
        CTransaction ctx(tx);
        int64_t currentWeight = GetTransactionWeight(ctx);
        int64_t diff = currentWeight - (MAX_STANDARD_TX_WEIGHT + 1);
        if (diff == 0) break;
        dataSize -= static_cast<size_t>(diff);
    }

    CTransaction finalTx(tx);
    BOOST_CHECK_GT(GetTransactionWeight(finalTx), MAX_STANDARD_TX_WEIGHT);

    std::string reason;
    BOOST_CHECK(!IsStandardTx(finalTx, std::nullopt, true, CFeeRate(DUST_RELAY_TX_FEE), reason));
    BOOST_CHECK_EQUAL(reason, "tx-size");
}

// ===== IsDust with various fee rates =====

BOOST_AUTO_TEST_CASE(is_dust_with_high_fee_rate)
{
    // At higher fee rate (e.g., 10000 sat/kvB), dust threshold rises proportionally
    CTxOut txout;
    txout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<uint8_t>(20, 0x00)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;

    CFeeRate highFee(10000);
    CAmount threshold = GetDustThreshold(txout, highFee);
    // 182 * 10 = 1820
    BOOST_CHECK_EQUAL(threshold, 1820);

    txout.nValue = 1819;
    BOOST_CHECK(IsDust(txout, highFee));

    txout.nValue = 1820;
    BOOST_CHECK(!IsDust(txout, highFee));
}

// ============================================================================
// BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS excludes witness/taproot
// ============================================================================

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_exclude_witness)
{
    BOOST_CHECK(!(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_WITNESS));
}

BOOST_AUTO_TEST_CASE(bch2_mandatory_flags_exclude_taproot)
{
    BOOST_CHECK(!(BCH2_MANDATORY_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_TAPROOT));
}

// ============================================================================
// BCH2_SCRIPT_VERIFY_FLAGS vs STANDARD_SCRIPT_VERIFY_FLAGS
// ============================================================================

BOOST_AUTO_TEST_CASE(bch2_flags_include_schnorr_not_standard)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_SCHNORR);
    // STANDARD flags do NOT include Schnorr (pre-fork BTC standard)
    BOOST_CHECK(!(STANDARD_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_SCHNORR));
}

BOOST_AUTO_TEST_CASE(bch2_flags_vm_limits_with_standard)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_VM_LIMITS);
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VM_LIMITS_STANDARD);
}

BOOST_AUTO_TEST_CASE(bch2_flags_exclude_witness_taproot)
{
    BOOST_CHECK(!(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_WITNESS));
    BOOST_CHECK(!(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_TAPROOT));
}

BOOST_AUTO_TEST_CASE(bch2_flags_include_sigpushonly_cleanstack)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_SIGPUSHONLY);
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_VERIFY_CLEANSTACK);
}

BOOST_AUTO_TEST_CASE(standard_not_mandatory_composition)
{
    BOOST_CHECK_EQUAL(STANDARD_NOT_MANDATORY_VERIFY_FLAGS,
                      STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS);
}

BOOST_AUTO_TEST_CASE(bch2_flags_all_bch_opcodes)
{
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_BCH2_OPCODES);
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_BITWISE_OPCODES);
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_ARITHMETIC_OPCODES);
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_REVERSEBYTES);
    BOOST_CHECK(BCH2_SCRIPT_VERIFY_FLAGS & SCRIPT_ENABLE_INTROSPECTION);
}

BOOST_AUTO_TEST_SUITE_END()
