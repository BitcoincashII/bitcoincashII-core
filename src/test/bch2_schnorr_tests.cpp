// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for BCH-style Schnorr signatures (Graviton upgrade).
// BCH Schnorr: 64-byte sig, implicit SIGHASH_ALL|SIGHASH_FORKID (0x41),
// BIP143-style sighash, XOnlyPubKey verification.

#include <crypto/sha256.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_execution_context.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

// Build a simple P2PKH spending transaction for testing
struct SchnorrTestTx {
    CMutableTransaction fundingTx;
    CMutableTransaction spendingTx;
    CKey key;
    CScript scriptPubKey;
    CAmount amount{1000000}; // 0.01 BCH2

    SchnorrTestTx() {
        key.MakeNewKey(true); // compressed
        scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

        // Create funding tx
        fundingTx.nVersion = 2;
        fundingTx.vin.resize(1);
        fundingTx.vin[0].prevout.hash.SetNull();
        fundingTx.vin[0].prevout.n = 0;
        fundingTx.vout.resize(1);
        fundingTx.vout[0].nValue = amount;
        fundingTx.vout[0].scriptPubKey = scriptPubKey;

        // Create spending tx
        spendingTx.nVersion = 2;
        spendingTx.vin.resize(1);
        spendingTx.vin[0].prevout.hash = fundingTx.GetHash();
        spendingTx.vin[0].prevout.n = 0;
        spendingTx.vout.resize(1);
        spendingTx.vout[0].nValue = amount - 1000;
        spendingTx.vout[0].scriptPubKey = scriptPubKey;
    }

    // Sign with Schnorr (64-byte sig, no hashtype byte in scriptSig)
    bool SignSchnorr() {
        uint256 sighash = SignatureHash(scriptPubKey, spendingTx, 0,
            SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);

        std::vector<unsigned char> sig(64);
        if (!key.SignSchnorr(sighash, sig, nullptr, uint256::ZERO)) return false;

        // BCH Schnorr: scriptSig = <64-byte-sig> <pubkey> (no hashtype byte)
        CScript scriptSig;
        scriptSig << sig << ToByteVector(key.GetPubKey());
        spendingTx.vin[0].scriptSig = scriptSig;
        return true;
    }

    // Sign with ECDSA (standard DER + hashtype byte)
    bool SignECDSA() {
        uint256 sighash = SignatureHash(scriptPubKey, spendingTx, 0,
            SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);

        std::vector<unsigned char> sig;
        if (!key.Sign(sighash, sig)) return false;
        sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

        CScript scriptSig;
        scriptSig << sig << ToByteVector(key.GetPubKey());
        spendingTx.vin[0].scriptSig = scriptSig;
        return true;
    }

    // Verify with given flags
    bool Verify(unsigned int flags) {
        ScriptError serror;
        MutableTransactionSignatureChecker checker(&spendingTx, 0, amount, MissingDataBehavior::FAIL);
        return VerifyScript(spendingTx.vin[0].scriptSig, scriptPubKey,
                            nullptr, flags, checker, &serror);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(bch2_schnorr_tests, BasicTestingSetup)

// ============================================================================
// Schnorr signature via OP_CHECKSIG (Graviton)
// ============================================================================

BOOST_AUTO_TEST_CASE(schnorr_valid_p2pkh)
{
    SchnorrTestTx t;
    BOOST_CHECK(t.SignSchnorr());
    BOOST_CHECK(t.Verify(BCH2_SCRIPT_VERIFY_FLAGS));
}

BOOST_AUTO_TEST_CASE(schnorr_requires_enable_flag)
{
    SchnorrTestTx t;
    BOOST_CHECK(t.SignSchnorr());
    // Without SCRIPT_ENABLE_SCHNORR, 64-byte sig treated as bad ECDSA
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_ENABLE_SCHNORR;
    BOOST_CHECK(!t.Verify(flags));
}

BOOST_AUTO_TEST_CASE(schnorr_invalid_signature_fails)
{
    SchnorrTestTx t;
    BOOST_CHECK(t.SignSchnorr());
    // Corrupt the signature (flip a byte)
    auto& scriptSig = t.spendingTx.vin[0].scriptSig;
    std::vector<unsigned char> raw(scriptSig.begin(), scriptSig.end());
    raw[2] ^= 0xff; // Flip byte inside the 64-byte sig
    t.spendingTx.vin[0].scriptSig = CScript(raw.begin(), raw.end());
    BOOST_CHECK(!t.Verify(BCH2_SCRIPT_VERIFY_FLAGS));
}

BOOST_AUTO_TEST_CASE(schnorr_wrong_pubkey_fails)
{
    SchnorrTestTx t;
    BOOST_CHECK(t.SignSchnorr());
    // Replace pubkey with a different key
    CKey wrongKey;
    wrongKey.MakeNewKey(true);
    // Rebuild scriptSig with wrong pubkey
    auto& scriptSig = t.spendingTx.vin[0].scriptSig;
    CScript::const_iterator it = scriptSig.begin();
    opcodetype opcode;
    std::vector<unsigned char> sig;
    scriptSig.GetOp(it, opcode, sig); // extract sig
    CScript newScriptSig;
    newScriptSig << sig << ToByteVector(wrongKey.GetPubKey());
    t.spendingTx.vin[0].scriptSig = newScriptSig;
    // Fails because pubkey doesn't match scriptPubKey's hash
    BOOST_CHECK(!t.Verify(BCH2_SCRIPT_VERIFY_FLAGS));
}

BOOST_AUTO_TEST_CASE(schnorr_uncompressed_pubkey_rejected)
{
    // BCH Schnorr requires compressed pubkey
    CKey key;
    key.MakeNewKey(false); // uncompressed
    CScript scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

    CMutableTransaction fundingTx;
    fundingTx.nVersion = 2;
    fundingTx.vin.resize(1);
    fundingTx.vout.resize(1);
    fundingTx.vout[0].nValue = 1000000;
    fundingTx.vout[0].scriptPubKey = scriptPubKey;

    CMutableTransaction spendingTx;
    spendingTx.nVersion = 2;
    spendingTx.vin.resize(1);
    spendingTx.vin[0].prevout.hash = fundingTx.GetHash();
    spendingTx.vin[0].prevout.n = 0;
    spendingTx.vout.resize(1);
    spendingTx.vout[0].nValue = 999000;
    spendingTx.vout[0].scriptPubKey = scriptPubKey;

    // Can't do Schnorr with uncompressed key (SignSchnorr needs compressed)
    // But we can test that even if we forge a 64-byte sig with uncompressed pubkey, it fails
    // Create a dummy 64-byte sig
    std::vector<unsigned char> fakeSig(64, 0x42);
    CScript scriptSig;
    scriptSig << fakeSig << ToByteVector(key.GetPubKey());
    spendingTx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&spendingTx, 0, 1000000, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(spendingTx.vin[0].scriptSig, scriptPubKey,
                              nullptr, BCH2_SCRIPT_VERIFY_FLAGS, checker, &serror));
}

BOOST_AUTO_TEST_CASE(ecdsa_still_works_with_schnorr_enabled)
{
    // ECDSA signatures (DER-encoded, with hashtype byte) should still work
    SchnorrTestTx t;
    BOOST_CHECK(t.SignECDSA());
    BOOST_CHECK(t.Verify(BCH2_SCRIPT_VERIFY_FLAGS));
}

// ============================================================================
// Schnorr via OP_CHECKDATASIG
// ============================================================================

BOOST_AUTO_TEST_CASE(schnorr_checkdatasig)
{
    // OP_CHECKDATASIG: <sig> <msg> <pubkey> OP_CHECKDATASIG
    // Schnorr path: 64-byte sig, SHA256(msg) used as digest
    CKey key;
    key.MakeNewKey(true);

    std::vector<unsigned char> msg = {0x01, 0x02, 0x03, 0x04};

    // Compute SHA256(msg) for the Schnorr digest
    uint256 digest;
    CSHA256().Write(msg.data(), msg.size()).Finalize(digest.begin());

    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(digest, sig, nullptr, uint256::ZERO));

    // Build script: <sig> <msg> <pubkey> OP_CHECKDATASIG
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKDATASIG;

    CScript scriptSig;
    scriptSig << sig << msg;

    // Need a transaction context for VerifyScript
    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);
    dummyTx.vout[0].nValue = 0;

    ScriptError serror;
    // Use flags that enable Schnorr + BCH2 opcodes but remove CLEANSTACK
    // since we're testing raw script, not P2PKH
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "Schnorr OP_CHECKDATASIG failed: " + ScriptErrorString(serror));
}

BOOST_AUTO_TEST_CASE(schnorr_checkdatasig_invalid_sig)
{
    CKey key;
    key.MakeNewKey(true);

    std::vector<unsigned char> msg = {0x01, 0x02, 0x03, 0x04};

    // Bad 64-byte sig
    std::vector<unsigned char> badSig(64, 0x00);

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKDATASIGVERIFY << OP_TRUE;

    CScript scriptSig;
    scriptSig << badSig << msg;

    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror));
}

// ============================================================================
// ECDSA via OP_CHECKDATASIG (raw DER, no hashtype byte)
// ============================================================================

BOOST_AUTO_TEST_CASE(ecdsa_checkdatasig)
{
    CKey key;
    key.MakeNewKey(true);

    std::vector<unsigned char> msg = {0xAA, 0xBB, 0xCC, 0xDD};

    // Compute SHA256(msg) — OP_CHECKDATASIG verifies sig over SHA256(message)
    uint256 digest;
    CSHA256().Write(msg.data(), msg.size()).Finalize(digest.begin());

    // ECDSA sign the digest (raw DER, no hashtype byte)
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(digest, sig));

    // Build script: <sig> <msg> <pubkey> OP_CHECKDATASIG
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKDATASIG;

    CScript scriptSig;
    scriptSig << sig << msg;

    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);
    dummyTx.vout[0].nValue = 0;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "ECDSA OP_CHECKDATASIG failed: " + ScriptErrorString(serror));
}

BOOST_AUTO_TEST_CASE(ecdsa_checkdatasigverify)
{
    CKey key;
    key.MakeNewKey(true);

    std::vector<unsigned char> msg = {0xAA, 0xBB};

    uint256 digest;
    CSHA256().Write(msg.data(), msg.size()).Finalize(digest.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(digest, sig));

    // OP_CHECKDATASIGVERIFY should consume the bool and continue
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKDATASIGVERIFY << OP_TRUE;

    CScript scriptSig;
    scriptSig << sig << msg;

    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);
    dummyTx.vout[0].nValue = 0;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "ECDSA OP_CHECKDATASIGVERIFY failed: " + ScriptErrorString(serror));
}

BOOST_AUTO_TEST_CASE(checkdatasig_empty_sig_returns_false)
{
    CKey key;
    key.MakeNewKey(true);

    std::vector<unsigned char> msg = {0x42};
    std::vector<unsigned char> emptySig; // Empty signature → returns false (not error)

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKDATASIG << OP_NOT; // NOT(false) = true

    CScript scriptSig;
    scriptSig << emptySig << msg;

    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);
    dummyTx.vout[0].nValue = 0;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "Empty sig OP_CHECKDATASIG should return false (NOT → true): " + ScriptErrorString(serror));
}

// ============================================================================
// OP_ACTIVEBYTECODE: returns currently executing script
// ============================================================================

BOOST_AUTO_TEST_CASE(op_activebytecode)
{
    // scriptPubKey: OP_ACTIVEBYTECODE <expected_script> OP_EQUAL
    // The script should return its own bytecode on the stack.
    // The expected_script includes the OP_ACTIVEBYTECODE, the push, and OP_EQUAL itself.
    // This is circular, so use a simpler test: just verify SIZE of returned bytecode.

    // Alternative approach: OP_ACTIVEBYTECODE OP_SIZE <expected_size> OP_EQUALVERIFY OP_DROP
    // scriptPubKey = OP_ACTIVEBYTECODE OP_SIZE <N> OP_EQUALVERIFY OP_DROP
    // where N is the size of the scriptPubKey itself.

    // Build it manually: OP_ACTIVEBYTECODE(0xc1) OP_SIZE(0x82) OP_5(0x55) OP_EQUALVERIFY(0x88) OP_DROP(0x75)
    // That's 5 bytes. So N=5. Must use OP_5 (not CScriptNum(5)) to keep script at 5 bytes.
    CScript scriptPubKey;
    scriptPubKey << OP_ACTIVEBYTECODE << OP_SIZE << OP_5 << OP_EQUALVERIFY << OP_DROP;

    // Verify scriptPubKey is 5 bytes
    BOOST_CHECK_EQUAL(scriptPubKey.size(), 5u);

    // Set up transaction with introspection context
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = scriptPubKey;

    CScript scriptSig;
    scriptSig << OP_TRUE;
    tx.vin[0].scriptSig = scriptSig;

    CTransaction txConst(tx);
    ScriptExecutionContext context(0, txConst, spentOutputs);

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA;
    ScriptError serror;
    PrecomputedTransactionData txdata;
    txdata.Init(txConst, std::vector<CTxOut>(spentOutputs));
    TransactionSignatureChecker checker(&txConst, 0, 2000, txdata, MissingDataBehavior::FAIL, &context);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "OP_ACTIVEBYTECODE size check failed: " + ScriptErrorString(serror));
}

// ============================================================================
// OP_CHECKDATASIG error paths
// ============================================================================

BOOST_AUTO_TEST_CASE(checkdatasig_bad_der_encoding)
{
    // Non-empty sig that's not valid DER → SCRIPT_ERR_SIG_DER (STRICTENC)
    CKey key;
    key.MakeNewKey(true);

    std::vector<unsigned char> msg = {0x42};
    // Garbage 10-byte "signature" that isn't 64 bytes (not Schnorr) and not valid DER
    std::vector<unsigned char> badDerSig = {0x30, 0x06, 0x02, 0x01, 0xFF, 0x02, 0x01, 0xFF, 0xAA, 0xBB};

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKDATASIG;

    CScript scriptSig;
    scriptSig << badDerSig << msg;

    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror));
}

BOOST_AUTO_TEST_CASE(checkdatasig_wrong_message_nullfail)
{
    // Valid DER signature over wrong message + NULLFAIL → error
    CKey key;
    key.MakeNewKey(true);

    std::vector<unsigned char> msg = {0xAA};
    uint256 digest;
    CSHA256().Write(msg.data(), msg.size()).Finalize(digest.begin());

    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(digest, sig));

    // Pass a different message — sig was over {0xAA} but we verify against {0xBB}
    std::vector<unsigned char> wrongMsg = {0xBB};
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKDATASIG;

    CScript scriptSig;
    scriptSig << sig << wrongMsg;

    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    // Should fail due to NULLFAIL (valid DER sig that doesn't verify)
    BOOST_CHECK(!VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror));
}

BOOST_AUTO_TEST_CASE(checkdatasig_invalid_pubkey_nullfail)
{
    // Invalid pubkey (wrong prefix) + non-empty sig → SCRIPT_ERR_SIG_NULLFAIL
    std::vector<unsigned char> msg = {0x42};
    // A valid-looking DER sig (valid format)
    CKey tempKey;
    tempKey.MakeNewKey(true);
    uint256 digest;
    CSHA256().Write(msg.data(), msg.size()).Finalize(digest.begin());
    std::vector<unsigned char> sig;
    BOOST_CHECK(tempKey.Sign(digest, sig));

    // Invalid pubkey: wrong prefix byte
    std::vector<unsigned char> badPubkey(33, 0x05); // 0x05 is not a valid prefix

    CScript scriptPubKey;
    scriptPubKey << badPubkey << OP_CHECKDATASIG;

    CScript scriptSig;
    scriptSig << sig << msg;

    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror));
}

BOOST_AUTO_TEST_CASE(checkdatasig_short_ecdsa_sig_nullfail)
{
    // ECDSA sig with <8 bytes (too short for DER) + NULLFAIL → error
    CKey key;
    key.MakeNewKey(true);

    std::vector<unsigned char> msg = {0x42};
    // 7-byte "sig" — too short for valid DER but not empty (triggers NULLFAIL path)
    std::vector<unsigned char> shortSig = {0x30, 0x05, 0x02, 0x01, 0x01, 0x02, 0x00};

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKDATASIG;

    CScript scriptSig;
    scriptSig << shortSig << msg;

    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror));
}

BOOST_AUTO_TEST_CASE(checkdatasig_verify_failed_nullfail)
{
    // Valid DER sig over wrong message + NULLFAIL → SCRIPT_ERR_SIG_NULLFAIL
    CKey key;
    key.MakeNewKey(true);

    std::vector<unsigned char> msg1 = {0xAA};
    std::vector<unsigned char> msg2 = {0xBB};

    uint256 digest;
    CSHA256().Write(msg1.data(), msg1.size()).Finalize(digest.begin());
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(digest, sig));

    // scriptSig pushes sig (over msg1) and msg2 — verification will fail
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKDATASIG;

    CScript scriptSig;
    scriptSig << sig << msg2;

    CMutableTransaction dummyTx;
    dummyTx.nVersion = 2;
    dummyTx.vin.resize(1);
    dummyTx.vin[0].scriptSig = scriptSig;
    dummyTx.vout.resize(1);

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&dummyTx, 0, 0, MissingDataBehavior::FAIL);
    BOOST_CHECK(!VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror));
}

// ============================================================================
// Mixed Schnorr + ECDSA in the same script (both sig types in one execution)
// ============================================================================

BOOST_AUTO_TEST_CASE(mixed_schnorr_ecdsa_same_script)
{
    // scriptPubKey: <pubkey1> OP_CHECKSIGVERIFY <pubkey2> OP_CHECKSIG
    // scriptSig: <schnorr_sig2> <ecdsa_sig1>
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);

    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key1.GetPubKey()) << OP_CHECKSIGVERIFY
                 << ToByteVector(key2.GetPubKey()) << OP_CHECKSIG;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 60000;

    // Sign with key1 (ECDSA — DER + hashtype byte)
    uint256 hash1 = SignatureHash(scriptPubKey, tx, 0,
        SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> ecdsaSig;
    BOOST_CHECK(key1.Sign(hash1, ecdsaSig));
    ecdsaSig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    // Sign with key2 (Schnorr — 64 bytes, no hashtype byte)
    uint256 hash2 = SignatureHash(scriptPubKey, tx, 0,
        SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key2.SignSchnorr(hash2, schnorrSig, nullptr, uint256::ZERO));

    // scriptSig: <schnorr_sig2> <ecdsa_sig1> (stack order: ecdsa popped first)
    CScript scriptSig;
    scriptSig << schnorrSig << ecdsaSig;
    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, amount, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "Mixed Schnorr+ECDSA script failed: " + ScriptErrorString(serror));
}

// ============================================================================
// Schnorr with SIGHASH_NONE (no-outputs commit)
// ============================================================================

BOOST_AUTO_TEST_CASE(schnorr_sighash_none)
{
    // Schnorr sig with SIGHASH_NONE|FORKID should work (implicit hashtype byte not in sig)
    CKey key;
    key.MakeNewKey(true);
    CScript scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 60000;

    // BCH Schnorr always uses SIGHASH_ALL|FORKID implicitly (no hashtype byte)
    // The 64-byte sig path forces SIGHASH_ALL|FORKID in the checker
    uint256 hash = SignatureHash(scriptPubKey, tx, 0,
        SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(hash, sig, nullptr, uint256::ZERO));

    CScript scriptSig;
    scriptSig << sig << ToByteVector(key.GetPubKey());
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, amount, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr,
                               BCH2_SCRIPT_VERIFY_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "Schnorr implicit ALL|FORKID failed: " + ScriptErrorString(serror));
}

// ============================================================================
// 65-byte sig NOT treated as Schnorr (length discrimination)
// ============================================================================

BOOST_AUTO_TEST_CASE(sig_65_bytes_not_schnorr)
{
    // A 65-byte signature is NOT 64 bytes, so it goes through ECDSA path
    // Since 65 bytes isn't valid DER either, it should fail
    CKey key;
    key.MakeNewKey(true);
    CScript scriptPubKey;
    scriptPubKey << ToByteVector(key.GetPubKey()) << OP_CHECKSIG;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // 65-byte garbage — not valid DER, not 64-byte Schnorr
    std::vector<unsigned char> badSig(65, 0x42);
    badSig.back() = SIGHASH_ALL | SIGHASH_FORKID;

    CScript scriptSig;
    scriptSig << badSig;
    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_SIGHASH_FORKID | SCRIPT_ENABLE_SCHNORR;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 60000, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    // Should fail as invalid DER (goes through ECDSA path since size != 64)
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_DER);
}

// ============================================================================
// OP_UTXOBYTECODE: returns UTXO's scriptPubKey
// ============================================================================

BOOST_AUTO_TEST_CASE(op_utxobytecode)
{
    // Create a UTXO with a known scriptPubKey, then verify OP_UTXOBYTECODE returns it
    CScript utxoScript;
    utxoScript << OP_DUP << OP_DROP << OP_TRUE;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    std::vector<CTxOut> spentOutputs(1);
    spentOutputs[0].nValue = 2000;
    spentOutputs[0].scriptPubKey = utxoScript; // This is what we expect OP_UTXOBYTECODE to return

    // scriptPubKey that checks: <0> OP_UTXOBYTECODE == <utxoScript bytes>
    std::vector<unsigned char> expectedBytes(utxoScript.begin(), utxoScript.end());
    CScript testScript;
    testScript << CScriptNum(0) << OP_UTXOBYTECODE << expectedBytes << OP_EQUALVERIFY;

    // But we need to set the actual scriptPubKey to testScript for evaluation.
    // However, OP_UTXOBYTECODE returns the scriptPubKey of the UTXO being spent,
    // which is spentOutputs[0].scriptPubKey. We set that to utxoScript above,
    // but then we override it in Eval. So use a 2-input setup.

    // Simpler: use input 0's UTXO as the test script, and have it introspect itself via index 0.
    // Wait — OP_UTXOBYTECODE(0) returns spentOutputs[0].scriptPubKey, which IS the script
    // being executed. So this becomes self-referential.
    // Use a 2-input transaction: input 0 executes the test, input 0 introspects input 1's UTXO.

    tx.vin.resize(2);
    tx.vin[1].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 1);
    tx.vin[1].nSequence = CTxIn::SEQUENCE_FINAL;

    spentOutputs.resize(2);
    spentOutputs[1].nValue = 3000;
    spentOutputs[1].scriptPubKey = utxoScript; // This is what we'll introspect

    // testScript checks: <1> OP_UTXOBYTECODE == <utxoScript bytes>
    CScript testScript2;
    testScript2 << CScriptNum(1) << OP_UTXOBYTECODE << expectedBytes << OP_EQUALVERIFY;

    spentOutputs[0].scriptPubKey = testScript2;

    CScript scriptSig;
    scriptSig << OP_TRUE;
    tx.vin[0].scriptSig = scriptSig;

    CTransaction txConst(tx);
    ScriptExecutionContext context(0, txConst, spentOutputs);

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                         & ~SCRIPT_VERIFY_SIGPUSHONLY & ~SCRIPT_VERIFY_MINIMALDATA;
    ScriptError serror;
    PrecomputedTransactionData txdata;
    txdata.Init(txConst, std::vector<CTxOut>(spentOutputs));
    TransactionSignatureChecker checker(&txConst, 0, 2000, txdata, MissingDataBehavior::FAIL, &context);
    bool result = VerifyScript(scriptSig, testScript2, nullptr, flags, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "OP_UTXOBYTECODE failed: " + ScriptErrorString(serror));
}

// ============================================================================
// XOnlyPubKey class tests
// ============================================================================

BOOST_AUTO_TEST_CASE(xonly_pubkey_from_cpubkey)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    XOnlyPubKey xonly(pubkey);
    BOOST_CHECK(xonly.IsFullyValid());
    BOOST_CHECK(!xonly.IsNull());
}

BOOST_AUTO_TEST_CASE(xonly_pubkey_from_bytes)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Extract x-coordinate (bytes 1-32 of compressed pubkey)
    std::vector<unsigned char> xbytes(pubkey.begin() + 1, pubkey.begin() + 33);
    XOnlyPubKey xonly(xbytes);
    BOOST_CHECK(xonly.IsFullyValid());
}

BOOST_AUTO_TEST_CASE(xonly_pubkey_null_default)
{
    XOnlyPubKey xonly;
    BOOST_CHECK(xonly.IsNull());
    // A null key is not fully valid
    BOOST_CHECK(!xonly.IsFullyValid());
}

BOOST_AUTO_TEST_CASE(xonly_pubkey_invalid_bytes)
{
    // All-zero x-coordinate is not a valid point
    std::vector<unsigned char> zeros(32, 0x00);
    XOnlyPubKey xonly(zeros);
    BOOST_CHECK(!xonly.IsFullyValid());
}

BOOST_AUTO_TEST_CASE(xonly_pubkey_verify_schnorr)
{
    CKey key;
    key.MakeNewKey(true);

    uint256 msg;
    msg.SetHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    // Sign with CKey::SignSchnorr
    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(msg, sig, nullptr, uint256::ZERO));

    // Verify using XOnlyPubKey
    XOnlyPubKey xonly(key.GetPubKey());
    BOOST_CHECK(xonly.VerifySchnorr(msg, sig));

    // Corrupt the signature
    sig[0] ^= 0xFF;
    BOOST_CHECK(!xonly.VerifySchnorr(msg, sig));
}

BOOST_AUTO_TEST_CASE(xonly_pubkey_get_key_ids)
{
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey xonly(key.GetPubKey());

    std::vector<CKeyID> ids = xonly.GetKeyIDs();
    // Should return exactly 2 key IDs (for 0x02 and 0x03 prefix variants)
    BOOST_CHECK_EQUAL(ids.size(), 2u);

    // The two IDs should be different (different prefix bytes → different Hash160)
    BOOST_CHECK(ids[0] != ids[1]);

    // One of them should match the original CPubKey's key ID
    CKeyID originalId = key.GetPubKey().GetID();
    BOOST_CHECK(ids[0] == originalId || ids[1] == originalId);
}

BOOST_AUTO_TEST_CASE(xonly_pubkey_get_even_cpubkey)
{
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey xonly(key.GetPubKey());

    CPubKey evenKey = xonly.GetEvenCorrespondingCPubKey();
    BOOST_CHECK(evenKey.IsFullyValid());
    BOOST_CHECK(evenKey.IsCompressed());
    // Even key has 0x02 prefix
    BOOST_CHECK_EQUAL(evenKey[0], 0x02);

    // The x-coordinate should match the original
    XOnlyPubKey roundtrip(evenKey);
    BOOST_CHECK(roundtrip == xonly);
}

BOOST_AUTO_TEST_CASE(xonly_compute_tap_tweak_hash)
{
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey xonly(key.GetPubKey());

    // With nullptr merkle_root: hash = H_TapTweak(pubkey)
    uint256 hash1 = xonly.ComputeTapTweakHash(nullptr);
    BOOST_CHECK(!hash1.IsNull());

    // With non-null merkle_root: hash = H_TapTweak(pubkey || merkle_root)
    uint256 merkleRoot;
    merkleRoot.SetHex("0102030405060708091011121314151617181920212223242526272829303132");
    uint256 hash2 = xonly.ComputeTapTweakHash(&merkleRoot);
    BOOST_CHECK(!hash2.IsNull());

    // Different merkle roots should produce different hashes
    BOOST_CHECK(hash1 != hash2);

    // Same inputs should produce same output (deterministic)
    uint256 hash3 = xonly.ComputeTapTweakHash(nullptr);
    BOOST_CHECK(hash1 == hash3);
}

BOOST_AUTO_TEST_CASE(xonly_create_tap_tweak)
{
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey xonly(key.GetPubKey());

    // Create a tweak with no merkle root
    auto result = xonly.CreateTapTweak(nullptr);
    BOOST_CHECK(result.has_value());

    auto [tweakedKey, parity] = *result;
    BOOST_CHECK(tweakedKey.IsFullyValid());
    // Tweaked key should differ from original
    BOOST_CHECK(!(tweakedKey == xonly));
}

BOOST_AUTO_TEST_CASE(xonly_check_tap_tweak)
{
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey internal(key.GetPubKey());

    // CheckTapTweak takes merkle_root by reference (always non-null pointer),
    // so use a real merkle root for consistency
    uint256 merkleRoot;
    merkleRoot.SetHex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

    auto result = internal.CreateTapTweak(&merkleRoot);
    BOOST_CHECK(result.has_value());

    auto [tweakedKey, parity] = *result;

    // CheckTapTweak should validate the relationship
    BOOST_CHECK(tweakedKey.CheckTapTweak(internal, merkleRoot, parity));

    // Wrong parity should fail
    BOOST_CHECK(!tweakedKey.CheckTapTweak(internal, merkleRoot, !parity));
}

BOOST_AUTO_TEST_CASE(xonly_create_tap_tweak_with_merkle_root)
{
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey internal(key.GetPubKey());

    uint256 merkleRoot;
    merkleRoot.SetHex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");

    auto result = internal.CreateTapTweak(&merkleRoot);
    BOOST_CHECK(result.has_value());

    auto [tweakedKey, parity] = *result;
    BOOST_CHECK(tweakedKey.IsFullyValid());

    // Verify the tweak
    BOOST_CHECK(tweakedKey.CheckTapTweak(internal, merkleRoot, parity));

    // Different merkle root should fail
    uint256 wrongRoot = uint256::ONE;
    BOOST_CHECK(!tweakedKey.CheckTapTweak(internal, wrongRoot, parity));
}

// ============================================================================
// CKey::SignSchnorr with merkle_root parameter
// ============================================================================

BOOST_AUTO_TEST_CASE(sign_schnorr_with_merkle_root)
{
    CKey key;
    key.MakeNewKey(true);

    uint256 msg;
    msg.SetHex("1111111111111111111111111111111111111111111111111111111111111111");

    uint256 merkleRoot;
    merkleRoot.SetHex("2222222222222222222222222222222222222222222222222222222222222222");

    // Sign with merkle_root tweak
    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(msg, sig, &merkleRoot, uint256::ZERO));

    // The signature should verify against the tweaked pubkey, not the original
    XOnlyPubKey internal(key.GetPubKey());
    auto tweakResult = internal.CreateTapTweak(&merkleRoot);
    BOOST_CHECK(tweakResult.has_value());

    auto [tweakedKey, parity] = *tweakResult;
    BOOST_CHECK(tweakedKey.VerifySchnorr(msg, sig));

    // Should NOT verify against the untweaked key
    BOOST_CHECK(!internal.VerifySchnorr(msg, sig));
}

BOOST_AUTO_TEST_CASE(sign_schnorr_with_null_merkle_root)
{
    // merkle_root->IsNull() case: SignSchnorr internally uses
    // ComputeTapTweakHash(nullptr) → H(pubkey), so verify with
    // CreateTapTweak(nullptr) to match
    CKey key;
    key.MakeNewKey(true);

    uint256 msg;
    msg.SetHex("3333333333333333333333333333333333333333333333333333333333333333");

    uint256 nullMerkle; // zero-initialized, IsNull() returns true

    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(msg, sig, &nullMerkle, uint256::ZERO));

    // SignSchnorr with null merkle_root uses ComputeTapTweakHash(nullptr),
    // so CreateTapTweak(nullptr) produces the matching tweaked key
    XOnlyPubKey internal(key.GetPubKey());
    auto tweakResult = internal.CreateTapTweak(nullptr);
    BOOST_CHECK(tweakResult.has_value());

    auto [tweakedKey, parity] = *tweakResult;
    BOOST_CHECK(tweakedKey.VerifySchnorr(msg, sig));
}

BOOST_AUTO_TEST_CASE(sign_schnorr_no_tweak)
{
    // nullptr merkle_root: sign with raw key (no tweaking)
    CKey key;
    key.MakeNewKey(true);

    uint256 msg;
    msg.SetHex("4444444444444444444444444444444444444444444444444444444444444444");

    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(msg, sig, nullptr, uint256::ZERO));

    // Verify against the untweaked XOnlyPubKey
    XOnlyPubKey xonly(key.GetPubKey());
    BOOST_CHECK(xonly.VerifySchnorr(msg, sig));
}

BOOST_AUTO_TEST_CASE(sign_schnorr_different_aux_entropy)
{
    // Different aux entropy should produce different signatures
    CKey key;
    key.MakeNewKey(true);

    uint256 msg;
    msg.SetHex("5555555555555555555555555555555555555555555555555555555555555555");

    std::vector<unsigned char> sig1(64);
    std::vector<unsigned char> sig2(64);

    BOOST_CHECK(key.SignSchnorr(msg, sig1, nullptr, uint256::ZERO));
    BOOST_CHECK(key.SignSchnorr(msg, sig2, nullptr, uint256::ONE));

    // Both should be valid
    XOnlyPubKey xonly(key.GetPubKey());
    BOOST_CHECK(xonly.VerifySchnorr(msg, sig1));
    BOOST_CHECK(xonly.VerifySchnorr(msg, sig2));

    // Signatures should differ (different aux entropy)
    BOOST_CHECK(sig1 != sig2);
}

// ============================================================================
// OP_CHECKSIGVERIFY with Schnorr and ECDSA
// ============================================================================

BOOST_AUTO_TEST_CASE(schnorr_checksigverify_valid)
{
    // OP_CHECKSIGVERIFY should succeed with valid Schnorr sig and leave stack clean
    SchnorrTestTx t;
    BOOST_REQUIRE(t.SignSchnorr());

    // Build custom scriptPubKey: <pubkey> OP_CHECKSIGVERIFY OP_TRUE
    CScript customPubKey;
    customPubKey << ToByteVector(t.key.GetPubKey()) << OP_CHECKSIGVERIFY << OP_TRUE;
    t.scriptPubKey = customPubKey;

    // Rebuild spending tx scriptPubKey reference
    t.fundingTx.vout[0].scriptPubKey = customPubKey;
    t.spendingTx.vin[0].prevout.hash = t.fundingTx.GetHash();

    // Re-sign for the new scriptPubKey
    uint256 sighash = SignatureHash(customPubKey, t.spendingTx, 0,
        SIGHASH_ALL | SIGHASH_FORKID, t.amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig(64);
    BOOST_REQUIRE(t.key.SignSchnorr(sighash, sig, nullptr, uint256::ZERO));

    CScript scriptSig;
    scriptSig << sig;
    t.spendingTx.vin[0].scriptSig = scriptSig;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                        & ~SCRIPT_VERIFY_SIGPUSHONLY;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&t.spendingTx, 0, t.amount, MissingDataBehavior::FAIL);
    BOOST_CHECK(VerifyScript(scriptSig, customPubKey, nullptr, flags, checker, &serror));
}

BOOST_AUTO_TEST_CASE(ecdsa_checksigverify_valid)
{
    // OP_CHECKSIGVERIFY should succeed with valid ECDSA sig
    SchnorrTestTx t;

    CScript customPubKey;
    customPubKey << ToByteVector(t.key.GetPubKey()) << OP_CHECKSIGVERIFY << OP_TRUE;
    t.fundingTx.vout[0].scriptPubKey = customPubKey;
    t.spendingTx.vin[0].prevout.hash = t.fundingTx.GetHash();

    uint256 sighash = SignatureHash(customPubKey, t.spendingTx, 0,
        SIGHASH_ALL | SIGHASH_FORKID, t.amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(t.key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    CScript scriptSig;
    scriptSig << sig;
    t.spendingTx.vin[0].scriptSig = scriptSig;

    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                        & ~SCRIPT_VERIFY_SIGPUSHONLY;
    ScriptError serror;
    MutableTransactionSignatureChecker checker(&t.spendingTx, 0, t.amount, MissingDataBehavior::FAIL);
    BOOST_CHECK(VerifyScript(scriptSig, customPubKey, nullptr, flags, checker, &serror));
}

BOOST_AUTO_TEST_CASE(checksig_empty_sig_returns_false)
{
    // Empty signature → CHECKSIG returns FALSE (not an error)
    // With NULLFAIL, non-empty sig that fails → error, but empty sig → FALSE is OK
    SchnorrTestTx t;
    BOOST_REQUIRE(t.SignSchnorr());

    // Replace sig with empty
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>{} << ToByteVector(t.key.GetPubKey());
    t.spendingTx.vin[0].scriptSig = scriptSig;

    // CHECKSIG returns FALSE (0), which means the script result is FALSE
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS & ~SCRIPT_VERIFY_CLEANSTACK
                        & ~SCRIPT_VERIFY_SIGPUSHONLY;
    BOOST_CHECK(!t.Verify(flags));
}

BOOST_AUTO_TEST_SUITE_END()
