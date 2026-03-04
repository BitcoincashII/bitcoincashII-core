// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for BCH2-specific P2SH behavior.
// Covers P2SH spending, P2SH + Schnorr, P2SH + multisig,
// P2SH witness rejection, and P2SH CashAddr format.

#include <addresstype.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

namespace {

static const unsigned int P2SH_FLAGS = BCH2_SCRIPT_VERIFY_FLAGS;

// Helper: verify a P2SH spend
bool VerifyP2SH(const CScript& scriptSig, const CScript& redeemScript,
                CMutableTransaction& tx, CAmount amount, unsigned int flags = P2SH_FLAGS)
{
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, amount, MissingDataBehavior::FAIL);
    return VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(bch2_p2sh_tests, BasicTestingSetup)

// ============================================================================
// P2SH: simple OP_TRUE redeemScript
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_simple_true)
{
    // redeemScript = OP_TRUE
    CScript redeemScript;
    redeemScript << OP_TRUE;

    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    // scriptSig: <serialized redeemScript>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 2000, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "Simple P2SH(OP_TRUE) should succeed: " + ScriptErrorString(serror));
}

// ============================================================================
// P2SH: ECDSA P2PKH inside P2SH
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_ecdsa_p2pkh)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // redeemScript = standard P2PKH script
    CScript redeemScript = GetScriptForDestination(PKHash(pubkey));
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 2000;

    // Sign with ECDSA + SIGHASH_FORKID
    uint256 sighash = SignatureHash(redeemScript, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    // scriptSig: <sig> <pubkey> <serialized redeemScript>
    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey)
              << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    BOOST_CHECK(VerifyP2SH(scriptSig, redeemScript, tx, amount));
}

// ============================================================================
// P2SH: Schnorr P2PKH inside P2SH
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_schnorr_p2pkh)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript redeemScript = GetScriptForDestination(PKHash(pubkey));
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 2000;

    // Sign with Schnorr (64 bytes, no hashtype)
    uint256 sighash = SignatureHash(redeemScript, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key.SignSchnorr(sighash, schnorrSig, nullptr, uint256::ZERO));

    // scriptSig: <schnorr_sig> <pubkey> <serialized redeemScript>
    CScript scriptSig;
    scriptSig << schnorrSig << ToByteVector(pubkey)
              << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    BOOST_CHECK_MESSAGE(VerifyP2SH(scriptSig, redeemScript, tx, amount),
                        "P2SH with Schnorr signature should succeed");
}

// ============================================================================
// P2SH: 2-of-2 multisig
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_multisig_2of2)
{
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);

    // redeemScript: 2 <pubkey1> <pubkey2> 2 OP_CHECKMULTISIG
    CScript redeemScript;
    redeemScript << OP_2
                 << ToByteVector(key1.GetPubKey())
                 << ToByteVector(key2.GetPubKey())
                 << OP_2 << OP_CHECKMULTISIG;

    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 2000;

    uint256 sighash = SignatureHash(redeemScript, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);

    std::vector<unsigned char> sig1, sig2;
    BOOST_CHECK(key1.Sign(sighash, sig1));
    sig1.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));
    BOOST_CHECK(key2.Sign(sighash, sig2));
    sig2.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    // scriptSig: OP_0 <sig1> <sig2> <serialized redeemScript>
    // (OP_0 is the dummy element for CHECKMULTISIG bug)
    CScript scriptSig;
    scriptSig << OP_0 << sig1 << sig2
              << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    BOOST_CHECK_MESSAGE(VerifyP2SH(scriptSig, redeemScript, tx, amount),
                        "P2SH 2-of-2 multisig should succeed");
}

// ============================================================================
// P2SH: non-push-only scriptSig fails
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_non_pushonly_fails)
{
    CScript redeemScript;
    redeemScript << OP_TRUE;
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    // scriptSig with a non-push opcode (OP_NOP)
    CScript scriptSig;
    scriptSig << OP_NOP
              << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 2000, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(!result, "P2SH with non-pushonly scriptSig should fail");
}

// ============================================================================
// P2SH: wrong redeemScript fails
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_wrong_redeemscript_fails)
{
    CScript realRedeem;
    realRedeem << OP_TRUE;
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(realRedeem));

    // Provide a different redeemScript
    CScript wrongRedeem;
    wrongRedeem << OP_2DROP << OP_TRUE;

    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(wrongRedeem.begin(), wrongRedeem.end());

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 2000, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(!result, "P2SH with wrong redeemScript should fail (hash mismatch)");
}

// ============================================================================
// P2SH: CashAddr prefix is "bitcoincashii:p"
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_cashaddr_prefix)
{
    CScript redeemScript;
    redeemScript << OP_TRUE;
    std::string addr = EncodeDestination(ScriptHash(redeemScript));
    BOOST_CHECK_MESSAGE(addr.substr(0, 14) == "bitcoincashii:",
                        "P2SH CashAddr should start with 'bitcoincashii:' but got: " + addr);
    BOOST_CHECK_EQUAL(addr[14], 'p');
}

// ============================================================================
// P2SH: 1-of-2 multisig with ECDSA (key2)
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_multisig_1of2_key2)
{
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);

    // 1-of-2 multisig redeemScript
    CScript redeemScript;
    redeemScript << OP_1
                 << ToByteVector(key1.GetPubKey())
                 << ToByteVector(key2.GetPubKey())
                 << OP_2 << OP_CHECKMULTISIG;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 2000;
    uint256 sighash = SignatureHash(redeemScript, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);

    // Sign with ECDSA using key2
    std::vector<unsigned char> sig2;
    BOOST_CHECK(key2.Sign(sighash, sig2));
    sig2.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    // scriptSig: OP_0 (dummy) <sig2> <serialized redeemScript>
    CScript scriptSig;
    scriptSig << OP_0 << sig2
              << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    BOOST_CHECK_MESSAGE(VerifyP2SH(scriptSig, redeemScript, tx, amount),
                        "P2SH 1-of-2 multisig with key2 should succeed");
}

// ============================================================================
// P2SH32: 32-byte hash P2SH using OP_HASH256
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh32_simple_true)
{
    // redeemScript = OP_TRUE
    CScript redeemScript;
    redeemScript << OP_TRUE;

    // P2SH32 scriptPubKey: OP_HASH256 <32-byte-hash> OP_EQUAL
    // Compute HASH256(redeemScript) = SHA256(SHA256(redeemScript))
    uint256 hash;
    CHash256().Write(redeemScript).Finalize(hash);

    CScript scriptPubKey;
    scriptPubKey << OP_HASH256;
    scriptPubKey << ToByteVector(hash);
    scriptPubKey << OP_EQUAL;

    // Verify it's detected as P2SH32
    BOOST_CHECK(scriptPubKey.IsPayToScriptHash32());
    BOOST_CHECK_EQUAL(scriptPubKey.size(), 35u);

    // scriptSig: <serialized redeemScript>
    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 2000, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "P2SH32(OP_TRUE) should succeed: " + ScriptErrorString(serror));
}

BOOST_AUTO_TEST_CASE(p2sh32_wrong_hash_fails)
{
    CScript redeemScript;
    redeemScript << OP_TRUE;

    // Use wrong hash
    uint256 wrongHash = uint256::ONE;
    CScript scriptPubKey;
    scriptPubKey << OP_HASH256;
    scriptPubKey << ToByteVector(wrongHash);
    scriptPubKey << OP_EQUAL;

    BOOST_CHECK(scriptPubKey.IsPayToScriptHash32());

    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 2000, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(!result, "P2SH32 with wrong hash should fail");
}

BOOST_AUTO_TEST_CASE(p2sh32_ecdsa_p2pkh)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // redeemScript = P2PKH
    CScript redeemScript = GetScriptForDestination(PKHash(pubkey));

    // P2SH32 scriptPubKey
    uint256 hash;
    CHash256().Write(redeemScript).Finalize(hash);
    CScript scriptPubKey;
    scriptPubKey << OP_HASH256 << ToByteVector(hash) << OP_EQUAL;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 2000;

    // Sign with ECDSA
    uint256 sighash = SignatureHash(redeemScript, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey)
              << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, amount, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "P2SH32 ECDSA P2PKH should succeed: " + ScriptErrorString(serror));
}

// ============================================================================
// CLEANSTACK enforcement
// ============================================================================

BOOST_AUTO_TEST_CASE(cleanstack_extra_item_on_stack_fails)
{
    // Push extra items: scriptSig pushes 2 items, scriptPubKey is just OP_TRUE
    // Final stack has 3 items (2 from scriptSig + 1 from OP_TRUE) → CLEANSTACK fails
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    CScript scriptSig;
    scriptSig << CScriptNum(42) << CScriptNum(99);
    CScript scriptPubKey;
    scriptPubKey << OP_TRUE;

    tx.vin[0].scriptSig = scriptSig;

    // With CLEANSTACK (and P2SH required for cleanstack, plus NO_SEGWIT to skip witness assert)
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_NO_SEGWIT;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CLEANSTACK);
}

BOOST_AUTO_TEST_CASE(cleanstack_single_true_passes)
{
    // scriptSig is empty, scriptPubKey pushes exactly one TRUE
    // Final stack has 1 item → CLEANSTACK passes
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_TRUE;

    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CLEANSTACK | SCRIPT_VERIFY_NO_SEGWIT;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(result);
}

// ============================================================================
// SIGPUSHONLY enforcement
// ============================================================================

BOOST_AUTO_TEST_CASE(sigpushonly_opcode_in_scriptsig_fails)
{
    // scriptSig contains OP_NOP (not a push) → SIGPUSHONLY fails
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    CScript scriptSig;
    scriptSig << OP_NOP << OP_TRUE;
    CScript scriptPubKey;
    scriptPubKey << OP_TRUE;

    tx.vin[0].scriptSig = scriptSig;

    // Include SIGPUSHONLY
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_NO_SEGWIT;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SIG_PUSHONLY);
}

BOOST_AUTO_TEST_CASE(sigpushonly_pure_push_scriptsig_passes)
{
    // scriptSig is only push data → SIGPUSHONLY passes
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    CScript scriptSig;
    scriptSig << CScriptNum(1); // push-only
    CScript scriptPubKey;
    scriptPubKey << OP_DROP << OP_TRUE; // consume the pushed value

    tx.vin[0].scriptSig = scriptSig;

    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_NO_SEGWIT;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(result);
}

// ============================================================================
// P2SH edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_non_push_scriptsig_fails)
{
    // P2SH requires scriptSig to be push-only (VerifyScript line 3055)
    CScript redeemScript;
    redeemScript << OP_TRUE;
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    // scriptSig has OP_NOP (non-push) before the redeemScript push
    CScript scriptSig;
    scriptSig << OP_NOP << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    // Note: Using just P2SH flag (without SIGPUSHONLY which checks earlier)
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_NO_SEGWIT;
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
}

BOOST_AUTO_TEST_CASE(p2sh_redeemscript_false_result_fails)
{
    // redeemScript evaluates to FALSE → P2SH fails
    CScript redeemScript;
    redeemScript << OP_FALSE;
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_NO_SEGWIT;
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_EVAL_FALSE);
}

BOOST_AUTO_TEST_CASE(p2sh_empty_redeemscript_fails)
{
    // Empty redeemScript → stack empty after eval → EVAL_FALSE
    CScript redeemScript;
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 0;

    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 0, MissingDataBehavior::FAIL);
    unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_NO_SEGWIT;
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, flags, checker, &serror);
    BOOST_CHECK(!result);
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_EVAL_FALSE);
}

// ============================================================================
// P2SH32: Schnorr P2PKH inside P2SH32
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh32_schnorr_p2pkh)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript redeemScript = GetScriptForDestination(PKHash(pubkey));

    // P2SH32 scriptPubKey
    uint256 hash;
    CHash256().Write(redeemScript).Finalize(hash);
    CScript scriptPubKey;
    scriptPubKey << OP_HASH256 << ToByteVector(hash) << OP_EQUAL;

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 2000;

    // Sign with Schnorr (64-byte, implicit hashtype)
    uint256 sighash = SignatureHash(redeemScript, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> schnorrSig(64);
    BOOST_CHECK(key.SignSchnorr(sighash, schnorrSig, nullptr, uint256::ZERO));

    CScript scriptSig;
    scriptSig << schnorrSig << ToByteVector(pubkey)
              << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, amount, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "P2SH32 Schnorr P2PKH should succeed: " + ScriptErrorString(serror));
}

// ============================================================================
// P2SH with OP_CHECKDATASIG in redeemScript
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_checkdatasig_in_redeem)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // redeemScript: <pubkey> OP_CHECKDATASIG
    CScript redeemScript;
    redeemScript << ToByteVector(pubkey) << OP_CHECKDATASIG;

    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 2000;

    // Sign the message "hello" with Schnorr for CHECKDATASIG
    std::vector<unsigned char> message = {'h', 'e', 'l', 'l', 'o'};
    uint256 msgHash;
    CSHA256().Write(message.data(), message.size()).Finalize(msgHash.data());

    std::vector<unsigned char> dataSig(64);
    BOOST_CHECK(key.SignSchnorr(msgHash, dataSig, nullptr, uint256::ZERO));

    // scriptSig: <sig> <message> <serialized redeemScript>
    CScript scriptSig;
    scriptSig << dataSig << message
              << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, amount, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "P2SH with OP_CHECKDATASIG should succeed: " + ScriptErrorString(serror));
}

// ============================================================================
// P2SH: redeemScript at max push size (520 bytes)
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_large_redeemscript_520)
{
    // Build a 520-byte redeemScript using data pushes (no opcodes that cost VM budget)
    // OP_TRUE (1 byte) + push of 517 bytes (1 opcode + 2 len bytes + 517 data = 520)
    // Then OP_DROP to consume the push, but that's 521 total.
    // Simpler: use push-only script that evaluates to true
    // 515-byte data push: OP_PUSHDATA2 <2 len bytes> <515 bytes data> = 518 bytes
    // Then OP_DROP (1 byte) + OP_TRUE (1 byte) = 520 total
    CScript redeemScript;
    std::vector<uint8_t> data(515, 0x42);
    redeemScript << data << OP_DROP << OP_TRUE;
    BOOST_CHECK_EQUAL(redeemScript.size(), 520u);

    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 2000, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(result, "P2SH with 520-byte redeemScript should succeed: " + ScriptErrorString(serror));
}

BOOST_AUTO_TEST_CASE(p2sh_redeemscript_over_520_fails)
{
    // RedeemScript at 521 bytes — exceeds MAX_SCRIPT_ELEMENT_SIZE push limit
    // 516-byte data push: OP_PUSHDATA2 <2 len bytes> <516 bytes> = 519 bytes
    // + OP_DROP (1) + OP_TRUE (1) = 521 total
    CScript redeemScript;
    std::vector<uint8_t> data(516, 0x42);
    redeemScript << data << OP_DROP << OP_TRUE;
    BOOST_CHECK_EQUAL(redeemScript.size(), 521u);

    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CScript scriptSig;
    scriptSig << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vin[0].scriptSig = scriptSig;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    ScriptError serror;
    MutableTransactionSignatureChecker checker(&tx, 0, 2000, MissingDataBehavior::FAIL);
    bool result = VerifyScript(scriptSig, scriptPubKey, nullptr, P2SH_FLAGS, checker, &serror);
    BOOST_CHECK_MESSAGE(!result, "P2SH with 521-byte redeemScript should fail (push size exceeded)");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_PUSH_SIZE);
}

// ============================================================================
// P2SH: SIGHASH_NONE|FORKID spend
// ============================================================================

BOOST_AUTO_TEST_CASE(p2sh_sighash_none_forkid)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript redeemScript = GetScriptForDestination(PKHash(pubkey));
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(redeemScript));

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    CAmount amount = 2000;

    // Sign with SIGHASH_NONE|FORKID
    uint256 sighash = SignatureHash(redeemScript, tx, 0, SIGHASH_NONE | SIGHASH_FORKID, amount, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_NONE | SIGHASH_FORKID));

    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey)
              << std::vector<unsigned char>(redeemScript.begin(), redeemScript.end());

    BOOST_CHECK_MESSAGE(VerifyP2SH(scriptSig, redeemScript, tx, amount),
                        "P2SH with SIGHASH_NONE|FORKID should succeed");
}

BOOST_AUTO_TEST_SUITE_END()
