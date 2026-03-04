// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Copyright (C) 2020 Calin Culianu <calin.culianu@gmail.com>
// Copyright (C) 2021 Fernando Pelliccioni <fpelliccioni@gmail.com>
// Copyright (C) 2022 The Bitcoin developers
// Copyright (c) 2021-2024 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bch2_fork.h>
#include <chainparams.h>
#include <coins.h>
#include <dsp/dsproof.h>
#include <hash.h>
#include <logging.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <streams.h>
#include <txmempool.h>
#include <validation.h>

#include <stdexcept>
#include <vector>

namespace {

/**
 *
 * This checker recomputes the sighash using the precomputed hashes from the
 * Spender struct and verifies the signature against it.
 */
class DSPSignatureChecker : public BaseSignatureChecker {
public:
    DSPSignatureChecker(const DoubleSpendProof* proof, const DoubleSpendProof::Spender& spender, const CTxOut& txOut)
        : m_proof(proof)
        , m_spender(spender)
        , m_txout(txOut)
    {
    }

    bool CheckECDSASignature(const std::vector<unsigned char>& vchSigIn,
                             const std::vector<unsigned char>& vchPubKey,
                             const CScript& scriptCode,
                             SigVersion sigversion) const override
    {
        CPubKey pubkey(vchPubKey);
        if (!pubkey.IsValid())
            return false;

        if (vchSigIn.empty())
            return false;

        // Remove the hashtype byte from the end of the signature
        std::vector<unsigned char> vchSig(vchSigIn.begin(), vchSigIn.end() - 1);

        // Compute the sighash using the Spender's precomputed hashes
        // This follows the BIP143/BCH FORKID sighash algorithm
        HashWriter ss{};
        ss << m_spender.txVersion;
        ss << m_spender.hashPrevOutputs;
        ss << m_spender.hashSequence;
        ss << m_proof->outPoint();
        // Note: ss << scriptCode already writes CompactSize + data (CScript serialization).
        // Do NOT add a second WriteCompactSize here — that would produce a double-length
        // prefix and a different sighash than SignatureHash() computes.
        ss << scriptCode;
        ss << m_txout.nValue;
        ss << m_spender.outSequence;
        ss << m_spender.hashOutputs;
        ss << m_spender.lockTime;
        // Hash type from the signature (includes FORKID flag)
        ss << static_cast<int32_t>(m_spender.pushData.front().back());

        const uint256 sighash = ss.GetHash();

        // Verify the ECDSA signature
        return pubkey.Verify(sighash, vchSig);
    }

    bool CheckLockTime(const CScriptNum&) const override {
        return true;
    }

    bool CheckSequence(const CScriptNum&) const override {
        return true;
    }

private:
    const DoubleSpendProof* m_proof;
    const DoubleSpendProof::Spender& m_spender;
    const CTxOut& m_txout;
};

} // namespace

auto DoubleSpendProof::validate(const CTxMemPool &mempool, const CCoinsView* coinsView,
                                 CTransactionRef spendingTx) const -> Validity
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    // DSProof is only for FORKID transactions (post-fork), use BCH2 flags
    const uint32_t scriptFlags = BCH2_SCRIPT_VERIFY_FLAGS;

    try {
        // This ensures not empty and that all pushData vectors have exactly 1 item, among other things.
        checkSanityOrThrow(scriptFlags);
    } catch (const std::runtime_error &e) {
        LogPrint(BCLog::MEMPOOL, "DoubleSpendProof::%s: %s\n", __func__, e.what());
        return Invalid;
    }

    // Check if ordering is proper (canonical ordering)
    int32_t diff = m_spender1.hashOutputs.Compare(m_spender2.hashOutputs);
    if (diff == 0)
        diff = m_spender1.hashPrevOutputs.Compare(m_spender2.hashPrevOutputs);
    if (diff > 0)
        return Invalid; // non-canonical order

    // Get the previous output we are spending
    Coin coin;
    if (coinsView) {
        // Use the provided coins view (includes both mempool and confirmed coins)
        CCoinsViewMemPool viewMemPool(const_cast<CCoinsView*>(coinsView), mempool);
        if (!viewMemPool.GetCoin(outPoint(), coin)) {
            // If the output we spend is missing, either the tx just got mined
            // or, more likely, our mempool just doesn't have it.
            return MissingUTXO;
        }
    } else {
        // Fallback: check mempool only (no confirmed coins)
        // This is less accurate but allows validation without full coins view
        return MissingUTXO;
    }

    const CTxOut& txOut = coin.out;
    const CScript& prevOutScript = coin.out.scriptPubKey;

    // Find the matching transaction spending this
    if (!spendingTx) {
        auto it = mempool.mapNextTx.find(m_outPoint);
        if (it == mempool.mapNextTx.end())
            return MissingTransaction;
        spendingTx = mempool.get(it->second->GetHash());
    }

    if (!spendingTx)
        return MissingTransaction;

    // For now we only support P2PKH payments
    // Check that the output is P2PKH
    TxoutType outType;
    std::vector<std::vector<unsigned char>> solutions;
    outType = Solver(prevOutScript, solutions);
    if (outType != TxoutType::PUBKEYHASH) {
        LogPrint(BCLog::MEMPOOL, "DoubleSpendProof: output is not P2PKH\n");
        return Invalid;
    }

    // Extract the public key from the spending transaction
    std::vector<uint8_t> pubkey;
    for (const auto& vin : spendingTx->vin) {
        if (vin.prevout == m_outPoint) {
            // Found the input script we need
            const CScript& inScript = vin.scriptSig;
            auto scriptIter = inScript.begin();
            opcodetype type;
            inScript.GetOp(scriptIter, type); // P2PKH: first signature
            inScript.GetOp(scriptIter, type, pubkey); // then pubkey
            break;
        }
    }

    if (pubkey.empty()) {
        LogPrint(BCLog::MEMPOOL, "DoubleSpendProof: could not extract pubkey\n");
        return Invalid;
    }

    // Verify signature for spender 1
    CScript inScript1;
    inScript1 << m_spender1.pushData.front();
    inScript1 << pubkey;

    DSPSignatureChecker checker1(this, m_spender1, txOut);
    ScriptError error1;
    if (!VerifyScript(inScript1, prevOutScript, nullptr, scriptFlags, checker1, &error1)) {
        LogPrint(BCLog::MEMPOOL, "DoubleSpendProof: failed validating first tx due to %s\n", ScriptErrorString(error1));
        return Invalid;
    }

    // Verify signature for spender 2
    CScript inScript2;
    inScript2 << m_spender2.pushData.front();
    inScript2 << pubkey;

    DSPSignatureChecker checker2(this, m_spender2, txOut);
    ScriptError error2;
    if (!VerifyScript(inScript2, prevOutScript, nullptr, scriptFlags, checker2, &error2)) {
        LogPrint(BCLog::MEMPOOL, "DoubleSpendProof: failed validating second tx due to %s\n", ScriptErrorString(error2));
        return Invalid;
    }

    return Valid;
}

/* static */
bool DoubleSpendProof::checkIsProofPossibleForAllInputsOfTx(const CTxMemPool &mempool, const CCoinsView* coinsView,
                                                            const CTransaction &tx, bool *pProtected)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    if (pProtected) *pProtected = false;
    if (tx.vin.empty() || tx.IsCoinBase()) {
        return false;
    }

    if (!coinsView) {
        return false;
    }

    // Create a view that includes both mempool and confirmed coins
    CCoinsViewMemPool view(const_cast<CCoinsView*>(coinsView), mempool);

    // Check all inputs
    bool foundUnprotected = false;
    for (size_t nIn = 0; nIn < tx.vin.size(); ++nIn) {
        const auto& txin = tx.vin[nIn];

        // Check if the coin exists
        Coin coin;
        if (!view.GetCoin(txin.prevout, coin)) {
            // If the Coin this tx spends is missing, then either this tx just got mined
            // or our mempool + blockchain view just doesn't have the coin.
            return false;
        }

        const CTxOut& txOut = coin.out;

        // For now, dsproof only supports P2PKH
        TxoutType outType;
        std::vector<std::vector<unsigned char>> solutions;
        outType = Solver(txOut.scriptPubKey, solutions);
        if (outType != TxoutType::PUBKEYHASH) {
            return false;
        }

        // Check if the input's scriptSig has a signature with FORKID
        const CScript& scriptSig = txin.scriptSig;
        if (scriptSig.empty()) {
            return false; // No scriptSig means can't verify
        }

        // Try to extract signature and check for FORKID
        std::vector<uint8_t> sig;
        auto scriptIter = scriptSig.begin();
        opcodetype type;
        if (!scriptSig.GetOp(scriptIter, type, sig) || sig.empty()) {
            return false;
        }

        const uint8_t hashType = sig.back();
        if (!(hashType & SIGHASH_FORKID)) {
            // Must have SIGHASH_FORKID for BCH-style transactions
            return false;
        }
        const uint8_t baseType = hashType & 0x1f;
        foundUnprotected = foundUnprotected || (hashType & SIGHASH_ANYONECANPAY) || baseType != SIGHASH_ALL;
    }

    if (pProtected) *pProtected = !foundUnprotected;
    return true;
}
