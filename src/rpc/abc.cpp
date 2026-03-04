// Copyright (c) 2017-2023 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/consensus.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <validation.h>

#include <univalue.h>

static RPCHelpMan getexcessiveblock()
{
    return RPCHelpMan{"getexcessiveblock",
        "\nReturn the excessive block size.\n"
        "\nThis is the maximum block size that BCH2 will accept.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::NUM, "excessiveBlockSize", "Block size limit in bytes"},
            }
        },
        RPCExamples{
            HelpExampleCli("getexcessiveblock", "") +
            HelpExampleRpc("getexcessiveblock", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            UniValue ret(UniValue::VOBJ);
            ret.pushKV("excessiveBlockSize", (int64_t)MAX_BLOCK_SERIALIZED_SIZE);
            return ret;
        },
    };
}

void RegisterABCRPCCommands(CRPCTable &t)
{
    static const CRPCCommand commands[]{
        {"network", &getexcessiveblock},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
