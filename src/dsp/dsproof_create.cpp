// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Copyright (C) 2020 Calin Culianu <calin.culianu@gmail.com>
// Copyright (c) 2021-2024 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dsp/dsproof.h>
#include <hash.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <tinyformat.h>

#include <stdexcept>

namespace {
// Non-verifying signature getter. Used for tests.
std::vector<uint8_t> getP2PKHSignature(const CScript &script)
{
    std::vector<uint8_t> vchRet;
    auto scriptIter = script.begin();
    opcodetype type;
    script.GetOp(scriptIter, type, vchRet);

    if (vchRet.empty())
        throw std::runtime_error("scriptSig has no signature");

    // Check the sighash type
    const uint8_t hashType = vchRet.back();
    if (!(hashType & SIGHASH_FORKID))
        throw std::runtime_error("Tx is not a Bitcoin Cash P2PKH transaction (missing SIGHASH_FORKID)");
    return vchRet;
}

void hashTx(DoubleSpendProof::Spender &spender, const CTransaction &tx, size_t inputIndex)
{
    assert(!spender.pushData.empty());
    assert(!spender.pushData.front().empty());

    const uint8_t hashType = spender.pushData.front().back();
    const uint8_t baseType = hashType & 0x1f;

    if (!(hashType & SIGHASH_ANYONECANPAY)) {
        HashWriter ss{};
        for (size_t n = 0; n < tx.vin.size(); ++n) {
            ss << tx.vin[n].prevout;
        }
        spender.hashPrevOutputs = ss.GetHash();
    }
    if (!(hashType & SIGHASH_ANYONECANPAY) &&
        baseType != SIGHASH_SINGLE &&
        baseType != SIGHASH_NONE) {
        HashWriter ss{};
        for (size_t n = 0; n < tx.vin.size(); ++n) {
            ss << tx.vin[n].nSequence;
        }
        spender.hashSequence = ss.GetHash();
    }
    if (baseType != SIGHASH_SINGLE && baseType != SIGHASH_NONE) {
        HashWriter ss{};
        for (size_t n = 0; n < tx.vout.size(); ++n) {
            ss << tx.vout[n];
        }
        spender.hashOutputs = ss.GetHash();
    } else if (baseType == SIGHASH_SINGLE && inputIndex < tx.vout.size()) {
        HashWriter ss{};
        ss << tx.vout[inputIndex];
        spender.hashOutputs = ss.GetHash();
    }
}
} // namespace

// static
std::vector<uint8_t> DoubleSpendProof::getP2PKHSignature(const CTransaction &tx, unsigned int inputIndex,
                                                         const CTxOut &txOut)
{
    std::vector<uint8_t> vchRet;

    // Check if output is P2PKH
    TxoutType outtype;
    std::vector<std::vector<unsigned char>> solutions;
    outtype = Solver(txOut.scriptPubKey, solutions);
    if (outtype != TxoutType::PUBKEYHASH)
        throw std::runtime_error("TxOut destination is not P2PKH");

    // Extract signature from the input's scriptSig
    const CScript &scriptSig = tx.vin[inputIndex].scriptSig;
    auto scriptIter = scriptSig.begin();
    opcodetype type;
    scriptSig.GetOp(scriptIter, type, vchRet);

    if (vchRet.empty())
        throw std::runtime_error("scriptSig has no signature");

    // Check the sighash type
    const uint8_t hashType = vchRet.back();
    if (!(hashType & SIGHASH_FORKID))
        throw std::runtime_error("Tx is not a Bitcoin Cash P2PKH transaction (missing SIGHASH_FORKID)");

    return vchRet;
}

// static
DoubleSpendProof DoubleSpendProof::create(const uint32_t scriptFlags, const CTransaction &tx1, const CTransaction &tx2,
                                          const COutPoint &prevout, const CTxOut *txOut)
{
    DoubleSpendProof answer;
    if (tx1.GetHash() == tx2.GetHash())
        throw std::invalid_argument(tfm::format("DSProof %s: CTransaction arguments must point to different transactions", __func__));
    Spender &s1 = answer.m_spender1;
    Spender &s2 = answer.m_spender2;

    size_t inputIndex1 = 0;
    size_t inputIndex2 = 0;
    int foundCt = 0;

    for (; foundCt == 0 && inputIndex1 < tx1.vin.size(); ++inputIndex1) {
        if (tx1.vin[inputIndex1].prevout == prevout) {
            ++foundCt;
            break;
        }
    }
    for (; foundCt == 1 && inputIndex2 < tx2.vin.size(); ++inputIndex2) {
        if (tx2.vin[inputIndex2].prevout == prevout) {
            ++foundCt;
            break;
        }
    }
    if (foundCt != 2)
        throw std::runtime_error("Transactions do not double spend each other with the specified COutPoint");
    const CTxIn &in1 = tx1.vin[inputIndex1];
    const CTxIn &in2 = tx2.vin[inputIndex2];
    assert(in1.prevout == in2.prevout && in1.prevout == prevout);

    answer.m_outPoint = in1.prevout;

    s1.outSequence = in1.nSequence;
    s2.outSequence = in2.nSequence;

    // Allow only p2pkh for now.  Below calls to getP2PKHSignature may throw
    s1.pushData.clear();
    // may throw
    s1.pushData.emplace_back( txOut
                              ? getP2PKHSignature(tx1, inputIndex1, *txOut) // verify sig
                              : ::getP2PKHSignature(in1.scriptSig) );       // non-verifying (for test code)
    s2.pushData.clear();
    // may throw
    s2.pushData.emplace_back( txOut
                              ? getP2PKHSignature(tx2, inputIndex2, *txOut) // verify sig
                              : ::getP2PKHSignature(in2.scriptSig) );       // non-verifying (for test code)

    assert(!s1.pushData.front().empty() && !s2.pushData.front().empty());

    s1.txVersion = tx1.nVersion;
    s2.txVersion = tx2.nVersion;
    s1.lockTime = tx1.nLockTime;
    s2.lockTime = tx2.nLockTime;

    hashTx(s1, tx1, inputIndex1);
    hashTx(s2, tx2, inputIndex2);

    // Sort the spenders so the proof stays the same, independent of the order of tx seen first
    int32_t diff = s1.hashOutputs.Compare(s2.hashOutputs);
    if (diff == 0)
        diff = s1.hashPrevOutputs.Compare(s2.hashPrevOutputs);
    if (diff > 0)
        std::swap(s1, s2);

    answer.setHash(); // finally, set the hash

    // Finally, ensure that we can eat our own dog food -- this should always succeed,
    // it is a programming error if it does not.
    answer.checkSanityOrThrow(scriptFlags);

    return answer;
}
