// Copyright (c) 2009-2025 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2025 The BitcoinII developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Forked from Bitcoin Core version 0.27.0
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <outputtype.h>

#include <pubkey.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <util/vector.h>

#include <assert.h>
#include <optional>
#include <string>

static const std::string OUTPUT_TYPE_STRING_LEGACY = "legacy";
static const std::string OUTPUT_TYPE_STRING_P2SH_SEGWIT = "p2sh-segwit";
static const std::string OUTPUT_TYPE_STRING_BECH32 = "bech32";
static const std::string OUTPUT_TYPE_STRING_BECH32M = "bech32m";
static const std::string OUTPUT_TYPE_STRING_UNKNOWN = "unknown";

std::optional<OutputType> ParseOutputType(const std::string& type)
{
    if (type == OUTPUT_TYPE_STRING_LEGACY) {
        return OutputType::LEGACY;
    } else if (type == OUTPUT_TYPE_STRING_P2SH_SEGWIT) {
        return OutputType::LEGACY;
    } else if (type == OUTPUT_TYPE_STRING_BECH32) {
        return OutputType::LEGACY;
    } else if (type == OUTPUT_TYPE_STRING_BECH32M) {
        return OutputType::LEGACY;
    }
    return std::nullopt;
}

const std::string& FormatOutputType(OutputType type)
{
    switch (type) {
    case OutputType::LEGACY: return OUTPUT_TYPE_STRING_LEGACY;
    case OutputType::P2SH_SEGWIT: return OUTPUT_TYPE_STRING_P2SH_SEGWIT;
    case OutputType::BECH32: return OUTPUT_TYPE_STRING_BECH32;
    case OutputType::BECH32M: return OUTPUT_TYPE_STRING_BECH32M;
    case OutputType::UNKNOWN: return OUTPUT_TYPE_STRING_UNKNOWN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

CTxDestination GetDestinationForKey(const CPubKey& key, OutputType type)
{
    switch (type) {
    case OutputType::LEGACY:
    case OutputType::P2SH_SEGWIT:
    case OutputType::BECH32:
    case OutputType::BECH32M:
        return PKHash(key);
    case OutputType::UNKNOWN: {} // This function should never be used with UNKNOWN, so let it assert
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::vector<CTxDestination> GetAllDestinationsForKey(const CPubKey& key)
{
    // This allows wallet recovery to find pre-fork witness UTXOs that can still be spent
    // Post-fork, new addresses will only be P2PKH (enforced in GetDestinationForKey)
    PKHash keyid(key);
    std::vector<CTxDestination> result;
    result.push_back(PKHash{key});
    if (key.IsCompressed()) {
        // Include witness addresses for pre-fork UTXO recovery
        result.push_back(WitnessV0KeyHash{key});
        result.push_back(ScriptHash{GetScriptForDestination(WitnessV0KeyHash{key})});
    }
    return result;
}

CTxDestination AddAndGetDestinationForScript(FillableSigningProvider& keystore, const CScript& script, OutputType type)
{
    // Add script to keystore
    keystore.AddCScript(script);
    switch (type) {
    case OutputType::LEGACY:
    case OutputType::P2SH_SEGWIT:
    case OutputType::BECH32:
    case OutputType::BECH32M:
        return ScriptHash(script);
    case OutputType::UNKNOWN: {} // This function should not be used for UNKNOWN, so let it assert
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

std::optional<OutputType> OutputTypeFromDestination(const CTxDestination& dest) {
    if (std::holds_alternative<PKHash>(dest) ||
        std::holds_alternative<ScriptHash>(dest)) {
        return OutputType::LEGACY;
    }
    if (std::holds_alternative<WitnessV0KeyHash>(dest) ||
        std::holds_alternative<WitnessV0ScriptHash>(dest)) {
        return OutputType::BECH32;
    }
    if (std::holds_alternative<WitnessV1Taproot>(dest) ||
        std::holds_alternative<WitnessUnknown>(dest)) {
        return OutputType::BECH32M;
    }
    return std::nullopt;
}
