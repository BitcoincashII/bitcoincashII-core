// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// This file provides the G_TRANSLATION_FUN symbol needed by libbitcoinII_util.a
// It's kept separate to ensure correct link ordering.

#include <functional>
#include <string>

// extern is needed to give the const variable external linkage
extern const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;
