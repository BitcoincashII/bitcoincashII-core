// Copyright (c) 2022-2024 The Bitcoin Cash Node developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_CONSENSUS_TOKENS_H
#define BITCOINII_CONSENSUS_TOKENS_H

#include <primitives/token.h>
#include <primitives/transaction.h>

#include <map>
#include <string>

class CCoinsViewCache;

/**
 * CashTokens (CHIP-2022-02) consensus validation for BCH2.
 *
 * Token Genesis Rules:
 * - A token category is created when a transaction input has index 0 and
 *   outputs include tokens with a category ID matching that input's outpoint txid.
 * - The genesis output can create any combination of fungible tokens (with amount)
 *   and NFTs (with any capability level).
 *
 * Token Transfer Rules:
 * - Fungible tokens: sum of outputs <= sum of inputs for each category
 * - Immutable NFTs: must exist in inputs to appear in outputs
 * - Mutable NFTs: can modify commitment if mutable/minting capability input exists
 * - Minting NFTs: can create new NFTs of the same category
 *
 * Token Burning:
 * - Tokens can be burned by simply not including them in outputs
 * - Minting capability can be downgraded (minting -> mutable -> immutable)
 */

/** Token validation result */
struct TokenValidationResult {
    bool valid{true};
    std::string error;

    TokenValidationResult() = default;
    explicit TokenValidationResult(const std::string& err) : valid(false), error(err) {}

    static TokenValidationResult Ok() { return TokenValidationResult(); }
    static TokenValidationResult Error(const std::string& msg) { return TokenValidationResult(msg); }

    operator bool() const { return valid; }
};

/**
 * Check if a transaction's token operations are valid.
 *
 * @param tx The transaction to validate
 * @param spentOutputs The outputs being spent by this transaction's inputs
 * @param requireTokens If true, require tokens to be enabled (for post-activation validation)
 * @return TokenValidationResult with valid=true or error message
 */
TokenValidationResult CheckTokens(const CTransaction& tx,
                                  const std::vector<CTxOut>& spentOutputs,
                                  bool requireTokens = true);

/**
 * Check if this transaction creates a new token category (genesis transaction).
 *
 * @param tx The transaction to check
 * @return true if input 0's outpoint txid matches any output token category
 */
bool IsTokenGenesis(const CTransaction& tx);

/**
 * Get the genesis category ID for a transaction (input 0's outpoint txid).
 *
 * @param tx The transaction
 * @return The potential genesis category ID (may not actually be used)
 */
uint256 GetGenesisCategoryId(const CTransaction& tx);

/**
 * Check if any output in the transaction has token data.
 *
 * @param tx The transaction to check
 * @return true if any output has token data
 */
bool HasTokenOutputs(const CTransaction& tx);

/**
 * Check if any input being spent has token data.
 *
 * @param spentOutputs The outputs being spent
 * @return true if any spent output has token data
 */
bool HasTokenInputs(const std::vector<CTxOut>& spentOutputs);

#endif // BITCOINII_CONSENSUS_TOKENS_H
