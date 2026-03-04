// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// After BCH2 fork, SegWit UTXOs can be spent by placing witness data in scriptSig
// instead of the witness field. This file tests that migration path.

#include <coins.h>
#include <key.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/translation.h>
#include <util/transaction_identifier.h>

#include <boost/test/unit_test.hpp>

#include <vector>

BOOST_FIXTURE_TEST_SUITE(bch2_segwit_migration_tests, BasicTestingSetup)

// Helper to create a simple transaction for testing
static CMutableTransaction CreateSpendingTx(const CScript& scriptSig, const CScriptWitness& witness = CScriptWitness())
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;
    tx.vin.resize(1);
    tx.vin[0].prevout.hash = Txid::FromUint256(uint256::ONE);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].scriptSig = scriptSig;
    tx.vin[0].scriptWitness = witness;
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    tx.vout.resize(1);
    tx.vout[0].nValue = 1000;
    tx.vout[0].scriptPubKey = CScript() << OP_TRUE;
    return tx;
}

// Test: P2WPKH can be spent via scriptSig after BCH2 fork
BOOST_AUTO_TEST_CASE(p2wpkh_via_scriptsig)
{
    // Generate a key pair
    CKey key;
    key.MakeNewKey(true); // compressed
    CPubKey pubkey = key.GetPubKey();

    // Create P2WPKH scriptPubKey (witness v0 keyhash)
    CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));
    BOOST_CHECK(scriptPubKey.IsPayToWitnessScriptHash() == false);
    BOOST_CHECK(scriptPubKey.size() == 22); // 0x00 0x14 <20-byte-hash>

    // Create the spending transaction
    CMutableTransaction tx = CreateSpendingTx(CScript());

    // For P2WPKH, we need to sign using the implicit P2PKH script
    CScript implicitP2PKH;
    implicitP2PKH << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;

    // Create signature with SIGHASH_ALL | SIGHASH_FORKID
    uint256 sighash = SignatureHash(implicitP2PKH, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    // BCH2 post-fork: Put signature and pubkey in scriptSig (not witness)
    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    // Verify with BCH2 post-fork flags (NO_SEGWIT + SIGHASH_FORKID required)
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig,
        scriptPubKey,
        nullptr, // no witness
        flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "P2WPKH via scriptSig should succeed: " + ScriptErrorString(serror));
}

// Test: P2WPKH fails with witness data after BCH2 fork (SCRIPT_VERIFY_NO_SEGWIT)
BOOST_AUTO_TEST_CASE(p2wpkh_with_witness_fails_after_fork)
{
    // Generate a key pair
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Create P2WPKH scriptPubKey
    CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));

    // Create spending transaction with witness data
    CMutableTransaction tx = CreateSpendingTx(CScript());

    // Create signature
    CScript implicitP2PKH;
    implicitP2PKH << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    uint256 sighash = SignatureHash(implicitP2PKH, tx, 0, SIGHASH_ALL, 1000, SigVersion::WITNESS_V0);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL));

    // Put signature in witness (pre-fork style)
    CScriptWitness witness;
    witness.stack.push_back(sig);
    witness.stack.push_back(ToByteVector(pubkey));
    tx.vin[0].scriptWitness = witness;

    // Verify with BCH2 post-fork flags - should FAIL due to witness data
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig,
        scriptPubKey,
        &witness,
        flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2WPKH with witness should fail after fork");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SEGWIT_NOT_ALLOWED);
}

// Test: P2WSH can be spent via scriptSig after BCH2 fork
BOOST_AUTO_TEST_CASE(p2wsh_via_scriptsig)
{
    // Generate key pairs for 2-of-2 multisig
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    CPubKey pubkey1 = key1.GetPubKey();
    CPubKey pubkey2 = key2.GetPubKey();

    // Create 2-of-2 multisig witness script
    CScript witnessScript;
    witnessScript << OP_2 << ToByteVector(pubkey1) << ToByteVector(pubkey2) << OP_2 << OP_CHECKMULTISIG;

    // Create P2WSH scriptPubKey (witness v0 scripthash - SHA256)
    uint256 witnessHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(witnessHash.begin());
    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(witnessHash);
    BOOST_CHECK(scriptPubKey.size() == 34); // 0x00 0x20 <32-byte-hash>

    // Create spending transaction
    CMutableTransaction tx = CreateSpendingTx(CScript());

    // Create signatures with SIGHASH_ALL | SIGHASH_FORKID
    uint256 sighash = SignatureHash(witnessScript, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, 1000, SigVersion::BCH_FORKID);

    std::vector<unsigned char> sig1, sig2;
    BOOST_CHECK(key1.Sign(sighash, sig1));
    sig1.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));
    BOOST_CHECK(key2.Sign(sighash, sig2));
    sig2.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    // BCH2 post-fork: Put everything in scriptSig
    // Stack order: OP_0 (CHECKMULTISIG bug), sig1, sig2, witnessScript
    CScript scriptSig;
    scriptSig << OP_0 << sig1 << sig2 << ToByteVector(witnessScript);
    tx.vin[0].scriptSig = scriptSig;

    // Verify with BCH2 post-fork flags
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig,
        scriptPubKey,
        nullptr,
        flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "P2WSH via scriptSig should succeed: " + ScriptErrorString(serror));
}

// Test: P2SH-P2WPKH can be spent via scriptSig after BCH2 fork
BOOST_AUTO_TEST_CASE(p2sh_p2wpkh_via_scriptsig)
{
    // Generate a key pair
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Create P2WPKH witness program (this becomes the redeemScript)
    CScript witnessProgram = GetScriptForDestination(WitnessV0KeyHash(pubkey));

    // Create P2SH scriptPubKey wrapping the witness program
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(witnessProgram));
    BOOST_CHECK(scriptPubKey.IsPayToScriptHash());

    // Create spending transaction
    CMutableTransaction tx = CreateSpendingTx(CScript());

    // For P2SH-P2WPKH, implicit script is P2PKH
    CScript implicitP2PKH;
    implicitP2PKH << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;

    // Create signature with SIGHASH_ALL | SIGHASH_FORKID
    uint256 sighash = SignatureHash(implicitP2PKH, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    // BCH2 post-fork: scriptSig = <sig> <pubkey> <redeemScript>
    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey) << ToByteVector(witnessProgram);
    tx.vin[0].scriptSig = scriptSig;

    // Verify with BCH2 post-fork flags
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig,
        scriptPubKey,
        nullptr,
        flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "P2SH-P2WPKH via scriptSig should succeed: " + ScriptErrorString(serror));
}

// Test: Signature without SIGHASH_FORKID fails after BCH2 fork
BOOST_AUTO_TEST_CASE(missing_forkid_fails)
{
    // Generate a key pair
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Create P2WPKH scriptPubKey
    CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));

    // Create spending transaction
    CMutableTransaction tx = CreateSpendingTx(CScript());

    // Create signature WITHOUT SIGHASH_FORKID (should fail)
    CScript implicitP2PKH;
    implicitP2PKH << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;
    uint256 sighash = SignatureHash(implicitP2PKH, tx, 0, SIGHASH_ALL, 1000, SigVersion::BASE);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL)); // No FORKID!

    // Put in scriptSig
    CScript scriptSig;
    scriptSig << sig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    // Verify with BCH2 post-fork flags - should FAIL
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig,
        scriptPubKey,
        nullptr,
        flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Signature without FORKID should fail after fork");
    // Should fail signature verification (wrong sighash)
    BOOST_CHECK(serror == SCRIPT_ERR_SIG_HASHTYPE || serror == SCRIPT_ERR_EVAL_FALSE);
}

// Test: P2TR key-path can be spent via scriptSig after BCH2 fork
BOOST_AUTO_TEST_CASE(p2tr_keypath_via_scriptsig)
{
    // Generate a key pair for Taproot
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey xpubkey{key.GetPubKey()};

    // Create P2TR scriptPubKey (witness v1)
    CScript scriptPubKey;
    scriptPubKey << OP_1 << ToByteVector(xpubkey);
    BOOST_CHECK(scriptPubKey.size() == 34); // 0x51 0x20 <32-byte-xonly-pubkey>

    // Create spending transaction
    CMutableTransaction tx = CreateSpendingTx(CScript());

    // For P2TR key-path, we need a Schnorr signature
    // Create the sighash for Taproot key spend
    PrecomputedTransactionData txdata;
    txdata.Init(tx, {CTxOut(1000, scriptPubKey)}, true);

    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;

    uint256 sighash;
    // Use SIGHASH_DEFAULT for Taproot (implicitly ALL)
    BOOST_CHECK(SignatureHashSchnorr(sighash, execdata, tx, 0, SIGHASH_DEFAULT, SigVersion::TAPROOT, txdata, MissingDataBehavior::FAIL));

    // Create Schnorr signature
    std::vector<unsigned char> sig(64);
    BOOST_CHECK(key.SignSchnorr(sighash, sig, nullptr, {}));

    // BCH2 post-fork: Put Schnorr signature in scriptSig
    CScript scriptSig;
    scriptSig << sig;
    tx.vin[0].scriptSig = scriptSig;

    // Verify with BCH2 post-fork flags
    unsigned int flags = BCH2_SCRIPT_VERIFY_FLAGS;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig,
        scriptPubKey,
        nullptr,
        flags,
        MutableTransactionSignatureChecker(&tx, 0, 1000, txdata, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(result, "P2TR key-path via scriptSig should succeed: " + ScriptErrorString(serror));
}

// ============================================================================
// VerifyWitnessProgramViaScriptSig — error paths
// ============================================================================

// Test: P2WPKH with wrong stack size (3 items instead of 2)
BOOST_AUTO_TEST_CASE(p2wpkh_wrong_stack_size)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));
    CMutableTransaction tx = CreateSpendingTx(CScript());

    CScript implicitP2PKH;
    implicitP2PKH << OP_DUP << OP_HASH160 << ToByteVector(pubkey.GetID()) << OP_EQUALVERIFY << OP_CHECKSIG;

    uint256 sighash = SignatureHash(implicitP2PKH, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    // Push 3 items instead of 2 — extra dummy item
    CScript scriptSig;
    std::vector<unsigned char> dummy{0x42};
    scriptSig << dummy << sig << ToByteVector(pubkey);
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2WPKH with 3 stack items should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

// Test: P2WSH with empty stack (no items in scriptSig)
BOOST_AUTO_TEST_CASE(p2wsh_empty_stack)
{
    // Create a simple witnessScript
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    CScript witnessScript;
    witnessScript << ToByteVector(pubkey) << OP_CHECKSIG;

    // Create P2WSH scriptPubKey
    uint256 witnessHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(witnessHash.begin());
    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(witnessHash);

    // Empty scriptSig — no items on stack
    CMutableTransaction tx = CreateSpendingTx(CScript());

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2WSH with empty stack should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
}

// Test: P2WSH with wrong script hash
BOOST_AUTO_TEST_CASE(p2wsh_wrong_script_hash)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    CScript witnessScript;
    witnessScript << ToByteVector(pubkey) << OP_CHECKSIG;

    // Create P2WSH scriptPubKey with a DIFFERENT hash (wrong hash)
    uint256 wrongHash = uint256::ONE;
    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(wrongHash);

    CMutableTransaction tx = CreateSpendingTx(CScript());

    // Sign properly but with wrong hash in scriptPubKey
    uint256 sighash = SignatureHash(witnessScript, tx, 0, SIGHASH_ALL | SIGHASH_FORKID, 1000, SigVersion::BCH_FORKID);
    std::vector<unsigned char> sig;
    BOOST_CHECK(key.Sign(sighash, sig));
    sig.push_back(static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_FORKID));

    CScript scriptSig;
    scriptSig << sig << ToByteVector(witnessScript);
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2WSH with wrong script hash should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

// Test: P2TR with empty stack (no signature)
BOOST_AUTO_TEST_CASE(p2tr_empty_stack)
{
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey xpubkey{key.GetPubKey()};

    CScript scriptPubKey;
    scriptPubKey << OP_1 << ToByteVector(xpubkey);

    // Empty scriptSig
    CMutableTransaction tx = CreateSpendingTx(CScript());

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2TR with empty stack should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY);
}

// Test: P2TR script-path spending rejected (2 items on stack)
BOOST_AUTO_TEST_CASE(p2tr_script_path_rejected)
{
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey xpubkey{key.GetPubKey()};

    CScript scriptPubKey;
    scriptPubKey << OP_1 << ToByteVector(xpubkey);

    CMutableTransaction tx = CreateSpendingTx(CScript());

    // Push 2 items (simulating script-path: script + control block)
    std::vector<unsigned char> dummySig(64, 0x42);
    std::vector<unsigned char> dummyControlBlock(33, 0x01);
    CScript scriptSig;
    scriptSig << dummySig << dummyControlBlock;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2TR script-path should be rejected");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
}

// Test: Unknown witness version (v2+) rejected
BOOST_AUTO_TEST_CASE(unknown_witness_version_rejected)
{
    // Create witness v16 program (OP_16 + 32-byte push)
    std::vector<unsigned char> program(32, 0xab);
    CScript scriptPubKey;
    scriptPubKey << OP_16 << program;

    CMutableTransaction tx = CreateSpendingTx(CScript());

    // Push some dummy data in scriptSig
    std::vector<unsigned char> dummySig(64, 0x42);
    CScript scriptSig;
    scriptSig << dummySig;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Unknown witness version should be rejected");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
}

// Test: Witness v0 wrong program length (not 20 or 32 bytes)
BOOST_AUTO_TEST_CASE(witness_v0_wrong_program_length)
{
    // Create witness v0 with 25-byte program (invalid length)
    std::vector<unsigned char> program(25, 0xcd);
    CScript scriptPubKey;
    scriptPubKey << OP_0 << program;

    CMutableTransaction tx = CreateSpendingTx(CScript());

    // Push some data (use a value > 16 to avoid MINIMALDATA violation with OP_n)
    std::vector<unsigned char> dummy{0x42, 0x43};
    CScript scriptSig;
    scriptSig << dummy;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Witness v0 with wrong program length should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH);
}

// Test: P2TR with invalid Schnorr signature
BOOST_AUTO_TEST_CASE(p2tr_invalid_schnorr_sig)
{
    CKey key;
    key.MakeNewKey(true);
    XOnlyPubKey xpubkey{key.GetPubKey()};

    CScript scriptPubKey;
    scriptPubKey << OP_1 << ToByteVector(xpubkey);

    CMutableTransaction tx = CreateSpendingTx(CScript());

    // Push a valid-length but wrong Schnorr signature
    std::vector<unsigned char> badSig(64, 0x00);
    CScript scriptSig;
    scriptSig << badSig;
    tx.vin[0].scriptSig = scriptSig;

    PrecomputedTransactionData txdata;
    txdata.Init(tx, {CTxOut(1000, scriptPubKey)}, true);

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, txdata, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2TR with invalid Schnorr signature should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_SCHNORR_SIG);
}

// Test: P2WSH cleanstack violation (extra items after script execution)
BOOST_AUTO_TEST_CASE(p2wsh_cleanstack_violation)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Witness script that leaves 2 items on stack: OP_TRUE OP_TRUE
    CScript witnessScript;
    witnessScript << OP_TRUE << OP_TRUE;

    uint256 witnessHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(witnessHash.begin());
    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(witnessHash);

    CMutableTransaction tx = CreateSpendingTx(CScript());

    // scriptSig pushes only the witnessScript
    CScript scriptSig;
    scriptSig << ToByteVector(witnessScript);
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "P2WSH with unclean stack should fail");
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_CLEANSTACK);
}

// Test: Witness v1 wrong program length (not 32 bytes) falls through to unknown
BOOST_AUTO_TEST_CASE(witness_v1_wrong_program_length)
{
    // Create witness v1 with 20-byte program (invalid for Taproot)
    std::vector<unsigned char> program(20, 0xef);
    CScript scriptPubKey;
    scriptPubKey << OP_1 << program;

    CMutableTransaction tx = CreateSpendingTx(CScript());

    std::vector<unsigned char> dummySig(64, 0x42);
    CScript scriptSig;
    scriptSig << dummySig;
    tx.vin[0].scriptSig = scriptSig;

    ScriptError serror;
    bool result = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );

    BOOST_CHECK_MESSAGE(!result, "Witness v1 with wrong program length should fail");
    // Falls through to "unknown witness version" path
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM);
}

// ============================================================================
// ProduceSignature with bch2_witness_via_scriptsig
// ============================================================================

// Test: ProduceSignature for P2WPKH with bch2_witness_via_scriptsig=true
BOOST_AUTO_TEST_CASE(produce_signature_p2wpkh_via_scriptsig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Set up signing provider
    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));

    CMutableTransaction tx = CreateSpendingTx(CScript());

    // Create signature creator
    MutableTransactionSignatureCreator creator(tx, 0, 1000, SIGHASH_ALL | SIGHASH_FORKID);

    SignatureData sigdata;
    bool result = ProduceSignature(keystore, creator, scriptPubKey, sigdata, true);
    BOOST_CHECK_MESSAGE(result, "ProduceSignature P2WPKH via scriptSig should succeed");

    // Verify signature went to scriptSig, NOT witness
    BOOST_CHECK(!sigdata.scriptSig.empty());
    BOOST_CHECK(sigdata.scriptWitness.IsNull());

    // Apply and verify
    tx.vin[0].scriptSig = sigdata.scriptSig;

    ScriptError serror;
    bool verified = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );
    BOOST_CHECK_MESSAGE(verified, "ProduceSignature P2WPKH verify failed: " + ScriptErrorString(serror));
}

// Test: ProduceSignature for P2WSH with bch2_witness_via_scriptsig=true
BOOST_AUTO_TEST_CASE(produce_signature_p2wsh_via_scriptsig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    // Create simple checksig witness script
    CScript witnessScript;
    witnessScript << ToByteVector(pubkey) << OP_CHECKSIG;

    // Add the witness script to the keystore
    BOOST_CHECK(keystore.AddCScript(witnessScript));

    // Create P2WSH scriptPubKey
    uint256 witnessHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(witnessHash.begin());
    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(witnessHash);

    CMutableTransaction tx = CreateSpendingTx(CScript());

    MutableTransactionSignatureCreator creator(tx, 0, 1000, SIGHASH_ALL | SIGHASH_FORKID);

    SignatureData sigdata;
    bool result = ProduceSignature(keystore, creator, scriptPubKey, sigdata, true);
    BOOST_CHECK_MESSAGE(result, "ProduceSignature P2WSH via scriptSig should succeed");

    // Verify signature went to scriptSig, NOT witness
    BOOST_CHECK(!sigdata.scriptSig.empty());
    BOOST_CHECK(sigdata.scriptWitness.IsNull());

    // Apply and verify
    tx.vin[0].scriptSig = sigdata.scriptSig;

    ScriptError serror;
    bool verified = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );
    BOOST_CHECK_MESSAGE(verified, "ProduceSignature P2WSH verify failed: " + ScriptErrorString(serror));
}

// Test: ProduceSignature for P2TR with bch2_witness_via_scriptsig=true
BOOST_AUTO_TEST_CASE(produce_signature_p2tr_via_scriptsig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    XOnlyPubKey xpubkey{pubkey};

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    // Create P2TR scriptPubKey
    CScript scriptPubKey;
    scriptPubKey << OP_1 << ToByteVector(xpubkey);

    CMutableTransaction tx = CreateSpendingTx(CScript());

    // For Taproot, we need PrecomputedTransactionData
    PrecomputedTransactionData txdata;
    txdata.Init(tx, {CTxOut(1000, scriptPubKey)}, true);

    MutableTransactionSignatureCreator creator(tx, 0, 1000, &txdata, SIGHASH_DEFAULT);

    SignatureData sigdata;
    bool result = ProduceSignature(keystore, creator, scriptPubKey, sigdata, true);
    BOOST_CHECK_MESSAGE(result, "ProduceSignature P2TR via scriptSig should succeed");

    // Verify signature went to scriptSig, NOT witness
    BOOST_CHECK(!sigdata.scriptSig.empty());
    BOOST_CHECK(sigdata.scriptWitness.IsNull());

    // Apply and verify
    tx.vin[0].scriptSig = sigdata.scriptSig;

    ScriptError serror;
    bool verified = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, txdata, MissingDataBehavior::FAIL),
        &serror
    );
    BOOST_CHECK_MESSAGE(verified, "ProduceSignature P2TR verify failed: " + ScriptErrorString(serror));
}

// Test: ProduceSignature for P2WPKH without bch2 flag puts data in witness
BOOST_AUTO_TEST_CASE(produce_signature_p2wpkh_witness_prefork)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));

    CMutableTransaction tx = CreateSpendingTx(CScript());

    MutableTransactionSignatureCreator creator(tx, 0, 1000, SIGHASH_ALL);

    SignatureData sigdata;
    // bch2_witness_via_scriptsig=false (default, pre-fork behavior)
    bool result = ProduceSignature(keystore, creator, scriptPubKey, sigdata, false);
    BOOST_CHECK_MESSAGE(result, "ProduceSignature P2WPKH pre-fork should succeed");

    // Pre-fork: data goes to witness, NOT scriptSig
    BOOST_CHECK(sigdata.scriptSig.empty());
    BOOST_CHECK(!sigdata.scriptWitness.IsNull());
    BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack.size(), 2u); // sig + pubkey
}

// Test: ProduceSignature for P2SH-P2WPKH with bch2_witness_via_scriptsig=true
BOOST_AUTO_TEST_CASE(produce_signature_p2sh_p2wpkh_via_scriptsig)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    // Create P2WPKH witness program (redeemScript)
    CScript witnessProgram = GetScriptForDestination(WitnessV0KeyHash(pubkey));
    BOOST_CHECK(keystore.AddCScript(witnessProgram));

    // P2SH wrapping
    CScript scriptPubKey = GetScriptForDestination(ScriptHash(witnessProgram));

    CMutableTransaction tx = CreateSpendingTx(CScript());

    MutableTransactionSignatureCreator creator(tx, 0, 1000, SIGHASH_ALL | SIGHASH_FORKID);

    SignatureData sigdata;
    bool result = ProduceSignature(keystore, creator, scriptPubKey, sigdata, true);
    BOOST_CHECK_MESSAGE(result, "ProduceSignature P2SH-P2WPKH via scriptSig should succeed");

    // Verify: data in scriptSig, not witness
    BOOST_CHECK(!sigdata.scriptSig.empty());
    BOOST_CHECK(sigdata.scriptWitness.IsNull());

    // Apply and verify
    tx.vin[0].scriptSig = sigdata.scriptSig;

    ScriptError serror;
    bool verified = VerifyScript(
        tx.vin[0].scriptSig, scriptPubKey, nullptr,
        BCH2_SCRIPT_VERIFY_FLAGS,
        MutableTransactionSignatureChecker(&tx, 0, 1000, MissingDataBehavior::FAIL),
        &serror
    );
    BOOST_CHECK_MESSAGE(verified, "ProduceSignature P2SH-P2WPKH verify failed: " + ScriptErrorString(serror));
}

// ============================================================================
// SignTransaction() with bch2_witness_via_scriptsig (integrated path)
// ============================================================================

BOOST_AUTO_TEST_CASE(sign_transaction_p2wpkh_via_scriptsig)
{
    // SignTransaction() automatically sets bch2_witness_via_scriptsig
    // when SIGHASH_FORKID is set, routing witness data to scriptSig
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    // Create P2WPKH output
    CScript scriptPubKey = GetScriptForDestination(WitnessV0KeyHash(pubkey));

    // Funding outpoint
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    // Create spending tx
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = prevout;
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 900;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    // Set up coins map
    std::map<COutPoint, Coin> coins;
    coins[prevout] = Coin(CTxOut(1000, scriptPubKey), 1, false);

    std::map<int, bilingual_str> input_errors;
    bool result = SignTransaction(mtx, &keystore, coins, SIGHASH_ALL | SIGHASH_FORKID, input_errors);
    BOOST_CHECK_MESSAGE(result, "SignTransaction P2WPKH via scriptSig should succeed");
    BOOST_CHECK(input_errors.empty());

    // Verify: data in scriptSig, NOT witness
    BOOST_CHECK(!mtx.vin[0].scriptSig.empty());
    BOOST_CHECK(mtx.vin[0].scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(sign_transaction_p2wsh_via_scriptsig)
{
    // P2WSH spending via SignTransaction with SIGHASH_FORKID
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key1));
    BOOST_CHECK(keystore.AddKey(key2));

    // Create 2-of-2 multisig witness script
    CScript witnessScript;
    witnessScript << OP_2 << ToByteVector(key1.GetPubKey()) << ToByteVector(key2.GetPubKey()) << OP_2 << OP_CHECKMULTISIG;

    // Register the redeem script
    BOOST_CHECK(keystore.AddCScript(witnessScript));

    // P2WSH: OP_0 <32-byte-script-hash>
    CScript scriptPubKey = GetScriptForDestination(WitnessV0ScriptHash(witnessScript));

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = prevout;
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 900;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    std::map<COutPoint, Coin> coins;
    coins[prevout] = Coin(CTxOut(1000, scriptPubKey), 1, false);

    std::map<int, bilingual_str> input_errors;
    bool result = SignTransaction(mtx, &keystore, coins, SIGHASH_ALL | SIGHASH_FORKID, input_errors);
    BOOST_CHECK_MESSAGE(result, "SignTransaction P2WSH via scriptSig should succeed");
    BOOST_CHECK(input_errors.empty());

    // Data in scriptSig, not witness
    BOOST_CHECK(!mtx.vin[0].scriptSig.empty());
    BOOST_CHECK(mtx.vin[0].scriptWitness.IsNull());
}

BOOST_AUTO_TEST_CASE(sign_transaction_p2pkh_with_forkid)
{
    // Standard P2PKH spending via SignTransaction
    CKey key;
    key.MakeNewKey(true);

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    CScript scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = prevout;
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 900;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    std::map<COutPoint, Coin> coins;
    coins[prevout] = Coin(CTxOut(1000, scriptPubKey), 1, false);

    std::map<int, bilingual_str> input_errors;
    bool result = SignTransaction(mtx, &keystore, coins, SIGHASH_ALL | SIGHASH_FORKID, input_errors);
    BOOST_CHECK_MESSAGE(result, "SignTransaction P2PKH should succeed");
    BOOST_CHECK(input_errors.empty());
    BOOST_CHECK(!mtx.vin[0].scriptSig.empty());

    // Verify the last byte of the DER signature is SIGHASH_ALL|FORKID = 0x41
    std::vector<unsigned char> raw(mtx.vin[0].scriptSig.begin(), mtx.vin[0].scriptSig.end());
    // scriptSig: <sig> <pubkey>
    // First byte is the push opcode for the sig length
    BOOST_CHECK(raw.size() > 2);
    uint8_t sigLen = raw[0]; // push length
    BOOST_CHECK(sigLen > 0 && sigLen < raw.size());
    // Last byte of the signature should be 0x41 (SIGHASH_ALL|FORKID)
    BOOST_CHECK_EQUAL(raw[sigLen], 0x41);
}

BOOST_AUTO_TEST_CASE(sign_transaction_missing_key_fails)
{
    // SignTransaction without the right key should fail
    CKey key;
    key.MakeNewKey(true);

    FillableSigningProvider keystore; // Empty — no key added

    CScript scriptPubKey = GetScriptForDestination(PKHash(key.GetPubKey()));
    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = prevout;
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 900;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    std::map<COutPoint, Coin> coins;
    coins[prevout] = Coin(CTxOut(1000, scriptPubKey), 1, false);

    std::map<int, bilingual_str> input_errors;
    bool result = SignTransaction(mtx, &keystore, coins, SIGHASH_ALL | SIGHASH_FORKID, input_errors);
    BOOST_CHECK(!result);
    BOOST_CHECK(!input_errors.empty());
}

BOOST_AUTO_TEST_CASE(sign_transaction_missing_coin_fails)
{
    // SignTransaction with missing UTXO should fail
    CKey key;
    key.MakeNewKey(true);

    FillableSigningProvider keystore;
    BOOST_CHECK(keystore.AddKey(key));

    COutPoint prevout(Txid::FromUint256(uint256::ONE), 0);

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vin[0].prevout = prevout;
    mtx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 900;
    mtx.vout[0].scriptPubKey = CScript() << OP_TRUE;

    std::map<COutPoint, Coin> coins; // Empty — no coins

    std::map<int, bilingual_str> input_errors;
    bool result = SignTransaction(mtx, &keystore, coins, SIGHASH_ALL | SIGHASH_FORKID, input_errors);
    BOOST_CHECK(!result);
    BOOST_CHECK(!input_errors.empty());
}

BOOST_AUTO_TEST_SUITE_END()
