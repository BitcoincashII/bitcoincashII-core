// Copyright (c) 2022-2024 The Bitcoin Cash Node developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tokens.h>

#include <tinyformat.h>

#include <map>
#include <set>

namespace {

/** Helper structure to track token category state during validation */
struct CategoryState {
    int64_t fungibleInput{0};
    int64_t fungibleOutput{0};
    bool hasMintingInput{false};
    bool hasMutableInput{false};
    int immutableNftsInput{0};
    int immutableNftsOutput{0};
    int mutableNftsOutput{0};
    int mintingNftsOutput{0};
    // Track unique commitment hashes for immutable NFTs
    std::multiset<std::vector<uint8_t>> immutableCommitmentsInput;
    std::multiset<std::vector<uint8_t>> immutableCommitmentsOutput;
};

} // namespace

bool IsTokenGenesis(const CTransaction& tx) {
    if (tx.vin.empty()) return false;

    // Get the potential genesis category ID (input 0's outpoint txid)
    const uint256& genesisCat = tx.vin[0].prevout.hash;

    // Check if any output uses this as its category ID
    for (const auto& out : tx.vout) {
        if (out.HasTokenData() && out.GetTokenData()->categoryId == genesisCat) {
            return true;
        }
    }
    return false;
}

uint256 GetGenesisCategoryId(const CTransaction& tx) {
    if (tx.vin.empty()) return uint256();
    return tx.vin[0].prevout.hash;
}

bool HasTokenOutputs(const CTransaction& tx) {
    for (const auto& out : tx.vout) {
        if (out.HasTokenData()) return true;
    }
    return false;
}

bool HasTokenInputs(const std::vector<CTxOut>& spentOutputs) {
    for (const auto& out : spentOutputs) {
        if (out.HasTokenData()) return true;
    }
    return false;
}

TokenValidationResult CheckTokens(const CTransaction& tx,
                                  const std::vector<CTxOut>& spentOutputs,
                                  bool requireTokens) {
    // Quick check: if no tokens involved, nothing to validate
    if (!HasTokenOutputs(tx) && !HasTokenInputs(spentOutputs)) {
        return TokenValidationResult::Ok();
    }

    // Coinbase transactions cannot have token outputs
    if (tx.IsCoinBase()) {
        if (HasTokenOutputs(tx)) {
            return TokenValidationResult::Error("coinbase-has-tokens");
        }
        return TokenValidationResult::Ok();
    }

    // Size check
    if (spentOutputs.size() != tx.vin.size()) {
        return TokenValidationResult::Error("token-inputs-mismatch");
    }

    // Get the genesis category ID (input 0's outpoint txid)
    const uint256 genesisCategoryId = GetGenesisCategoryId(tx);
    const bool isGenesis = IsTokenGenesis(tx);

    // Build category state from inputs
    std::map<uint256, CategoryState> categories;

    for (size_t i = 0; i < spentOutputs.size(); ++i) {
        const CTxOut& spent = spentOutputs[i];
        if (!spent.HasTokenData()) continue;

        const OutputToken* token = spent.GetTokenData();
        if (!token->IsValid()) {
            return TokenValidationResult::Error("invalid-token-input");
        }

        auto& state = categories[token->categoryId];

        // Track fungible tokens
        if (token->HasAmount()) {
            if (token->amount > token::MAX_AMOUNT - state.fungibleInput) {
                return TokenValidationResult::Error("token-amount-overflow-input");
            }
            state.fungibleInput += token->amount;
        }

        // Track NFT capabilities
        if (token->HasNFT()) {
            switch (token->GetCapability()) {
                case token::Minting:
                    state.hasMintingInput = true;
                    break;
                case token::Mutable:
                    state.hasMutableInput = true;
                    break;
                case token::None:
                    state.immutableNftsInput++;
                    state.immutableCommitmentsInput.insert(token->commitment);
                    break;
            }
        }
    }

    // Process outputs
    for (const auto& out : tx.vout) {
        if (!out.HasTokenData()) continue;

        const OutputToken* token = out.GetTokenData();
        if (!token->IsValid()) {
            return TokenValidationResult::Error("invalid-token-output");
        }

        const uint256& catId = token->categoryId;

        // Check if this is a genesis output
        bool isGenesisOutput = isGenesis && (catId == genesisCategoryId);

        // If not genesis and category doesn't exist in inputs, error
        if (!isGenesisOutput && categories.find(catId) == categories.end()) {
            return TokenValidationResult::Error(
                strprintf("token-category-not-in-inputs: %s", catId.GetHex()));
        }

        auto& state = categories[catId];

        // Track fungible tokens
        if (token->HasAmount()) {
            if (token->amount > token::MAX_AMOUNT - state.fungibleOutput) {
                return TokenValidationResult::Error("token-amount-overflow-output");
            }
            state.fungibleOutput += token->amount;
        }

        // Track NFT capabilities in outputs
        if (token->HasNFT()) {
            switch (token->GetCapability()) {
                case token::Minting:
                    state.mintingNftsOutput++;
                    break;
                case token::Mutable:
                    state.mutableNftsOutput++;
                    break;
                case token::None:
                    state.immutableNftsOutput++;
                    state.immutableCommitmentsOutput.insert(token->commitment);
                    break;
            }
        }
    }

    // Validate each category
    for (const auto& [catId, state] : categories) {
        bool isGenesisCategory = isGenesis && (catId == genesisCategoryId);

        // Rule: Fungible output amount cannot exceed input amount (unless genesis)
        if (!isGenesisCategory && state.fungibleOutput > state.fungibleInput) {
            return TokenValidationResult::Error(
                strprintf("token-amount-exceeds-input: category %s, in=%d, out=%d",
                          catId.GetHex(), state.fungibleInput, state.fungibleOutput));
        }

        // Rule: Minting NFTs in output require minting capability in input (or genesis)
        if (state.mintingNftsOutput > 0 && !state.hasMintingInput && !isGenesisCategory) {
            return TokenValidationResult::Error(
                strprintf("token-minting-without-capability: %s", catId.GetHex()));
        }

        // Rule: Mutable NFTs in output require minting or mutable capability in input (or genesis)
        if (state.mutableNftsOutput > 0 &&
            !state.hasMintingInput && !state.hasMutableInput && !isGenesisCategory) {
            return TokenValidationResult::Error(
                strprintf("token-mutable-without-capability: %s", catId.GetHex()));
        }

        // Rule: Immutable NFTs must match between input and output
        // (with minting capability, new immutable NFTs can be created)
        if (!isGenesisCategory && !state.hasMintingInput) {
            // Without minting capability, immutable NFT count and commitments must match
            // (unless mutable capability allows modification)
            if (!state.hasMutableInput) {
                // Strict matching: each immutable NFT output must have matching input
                if (state.immutableCommitmentsOutput != state.immutableCommitmentsInput) {
                    return TokenValidationResult::Error(
                        strprintf("token-immutable-nft-mismatch: %s", catId.GetHex()));
                }
            } else {
                // With mutable capability: count must not exceed input
                if (state.immutableNftsOutput > state.immutableNftsInput + 1) {
                    // Mutable can convert to at most one immutable
                    return TokenValidationResult::Error(
                        strprintf("token-immutable-nft-count-exceeded: %s", catId.GetHex()));
                }
            }
        }
    }

    return TokenValidationResult::Ok();
}
