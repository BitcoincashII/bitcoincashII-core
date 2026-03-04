// Copyright (c) 2022-2024 The Bitcoin Cash Node developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/token.h>

#include <tinyformat.h>
#include <util/strencodings.h>

std::string OutputToken::ToString() const {
    std::string result = strprintf("OutputToken(category=%s", categoryId.GetHex());

    if (HasNFT()) {
        const char* capStr = "none";
        switch (GetCapability()) {
            case token::Mutable: capStr = "mutable"; break;
            case token::Minting: capStr = "minting"; break;
            default: break;
        }
        result += strprintf(", nft=%s", capStr);
        if (HasCommitment()) {
            result += strprintf(", commitment=%s", HexStr(commitment));
        }
    }

    if (HasAmount()) {
        result += strprintf(", amount=%d", amount);
    }

    result += ")";
    return result;
}
