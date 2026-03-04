// Copyright (c) 2021-2022 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_SCRIPT_SCRIPT_EXECUTION_CONTEXT_H
#define BITCOINII_SCRIPT_SCRIPT_EXECUTION_CONTEXT_H

#include <coins.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <memory>
#include <optional>
#include <vector>

/**
 *
 * This class provides access to transaction data during script evaluation,
 * enabling opcodes like OP_INPUTINDEX, OP_TXVERSION, OP_UTXOVALUE, etc.
 */
class ScriptExecutionContext {
public:
    /**
     * Construct a context for a specific input.
     *
     * @param inputIndex The index of the input being validated
     * @param tx The transaction being validated
     * @param coins The coins being spent by all inputs
     */
    ScriptExecutionContext(unsigned int inputIndex,
                           const CTransaction& tx,
                           const std::vector<CTxOut>& spentOutputs)
        : m_inputIndex(inputIndex)
        , m_tx(tx)
        , m_spentOutputs(spentOutputs)
    {}

    /**
     * Construct a limited context with only the current input's spent output.
     * Used when full UTXO data is not available.
     */
    ScriptExecutionContext(unsigned int inputIndex,
                           const CTransaction& tx,
                           const CTxOut& spentOutput)
        : m_inputIndex(inputIndex)
        , m_tx(tx)
        , m_limited(true)
    {
        m_spentOutputs.resize(tx.vin.size());
        if (inputIndex < m_spentOutputs.size()) {
            m_spentOutputs[inputIndex] = spentOutput;
        }
    }

    // Accessors

    /** Get the index of the input being evaluated */
    unsigned int inputIndex() const { return m_inputIndex; }

    /** Get the transaction being evaluated */
    const CTransaction& tx() const { return m_tx; }

    /** Check if this is a limited context (only has data for current input) */
    bool isLimited() const { return m_limited; }

    /** Get the number of inputs */
    size_t inputCount() const { return m_tx.vin.size(); }

    /** Get the number of outputs */
    size_t outputCount() const { return m_tx.vout.size(); }

    /** Get the transaction version */
    int32_t txVersion() const { return m_tx.nVersion; }

    /** Get the transaction locktime */
    uint32_t txLockTime() const { return m_tx.nLockTime; }

    /** Get the spent output (UTXO) for an input */
    const CTxOut& spentOutput(unsigned int inputIdx) const {
        return m_spentOutputs.at(inputIdx);
    }

    /** Get the spent output for the current input */
    const CTxOut& spentOutput() const {
        return spentOutput(m_inputIndex);
    }

    /** Get the scriptPubKey of the spent output for an input */
    const CScript& utxoBytecode(unsigned int inputIdx) const {
        return spentOutput(inputIdx).scriptPubKey;
    }

    /** Get the value of the spent output for an input */
    CAmount utxoValue(unsigned int inputIdx) const {
        return spentOutput(inputIdx).nValue;
    }

    /** Get the outpoint txid for an input */
    const uint256& outpointTxHash(unsigned int inputIdx) const {
        return m_tx.vin.at(inputIdx).prevout.hash;
    }

    /** Get the outpoint index for an input */
    uint32_t outpointIndex(unsigned int inputIdx) const {
        return m_tx.vin.at(inputIdx).prevout.n;
    }

    /** Get the scriptSig for an input */
    const CScript& inputBytecode(unsigned int inputIdx) const {
        return m_tx.vin.at(inputIdx).scriptSig;
    }

    /** Get the sequence number for an input */
    uint32_t inputSequenceNumber(unsigned int inputIdx) const {
        return m_tx.vin.at(inputIdx).nSequence;
    }

    /** Get the value of an output */
    CAmount outputValue(unsigned int outputIdx) const {
        return m_tx.vout.at(outputIdx).nValue;
    }

    /** Get the scriptPubKey of an output */
    const CScript& outputBytecode(unsigned int outputIdx) const {
        return m_tx.vout.at(outputIdx).scriptPubKey;
    }


    /** Check if a UTXO has token data */
    bool utxoHasToken(unsigned int inputIdx) const {
        return spentOutput(inputIdx).HasTokenData();
    }

    /** Get token data from a UTXO (may return nullptr) */
    const OutputToken* utxoToken(unsigned int inputIdx) const {
        return spentOutput(inputIdx).GetTokenData();
    }

    /** Check if an output has token data */
    bool outputHasToken(unsigned int outputIdx) const {
        return m_tx.vout.at(outputIdx).HasTokenData();
    }

    /** Get token data from an output (may return nullptr) */
    const OutputToken* outputToken(unsigned int outputIdx) const {
        return m_tx.vout.at(outputIdx).GetTokenData();
    }

private:
    unsigned int m_inputIndex;
    const CTransaction& m_tx;
    std::vector<CTxOut> m_spentOutputs;
    bool m_limited{false};
};

using ScriptExecutionContextOpt = std::optional<ScriptExecutionContext>;

#endif // BITCOINII_SCRIPT_SCRIPT_EXECUTION_CONTEXT_H
