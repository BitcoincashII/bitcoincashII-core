// Copyright (c) 2021-2022 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <core_io.h>
#include <dsp/dsproof.h>
#include <dsp/storage.h>
#include <node/context.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <streams.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>

using node::NodeContext;

namespace {

inline constexpr int verbosityMax = 3; ///< Max verbosity for ToObject() below

void ThrowIfDisabled() {
    if (!DoubleSpendProof::IsEnabled())
        throw JSONRPCError(RPC_MISC_ERROR,
                           "Double-spend proofs subsystem is disabled. Restart with -doublespendproof=1 to enable.");
}

UniValue SpenderToJson(const DoubleSpendProof::Spender &spender) {
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("txversion", (int)spender.txVersion);
    ret.pushKV("sequence", (int64_t)spender.outSequence);
    ret.pushKV("locktime", (int64_t)spender.lockTime);
    ret.pushKV("hashprevoutputs", spender.hashPrevOutputs.ToString());
    ret.pushKV("hashsequence", spender.hashSequence.ToString());
    ret.pushKV("hashoutputs", spender.hashOutputs.ToString());

    UniValue pushData(UniValue::VOBJ);
    CScript script;
    for (const auto &data : spender.pushData)
        script << data;
    pushData.pushKV("asm", ScriptToAsmStr(script, true));
    pushData.pushKV("hex", HexStr(script));
    ret.pushKV("pushdata", pushData);
    return ret;
}

UniValue DSProofToJson(int verbosity, const DoubleSpendProof &dsproof, bool isOrphan = false) {
    UniValue ret(UniValue::VOBJ);

    if (verbosity <= 0 || verbosity > verbosityMax)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Bad verbosity");

    // verbosity = 1, dump an object with keys: "hex", "dspid", "orphan"
    if (verbosity >= 1) {
        // add "hex" data blob
        DataStream ss{};
        ss << dsproof;
        ret.pushKV("hex", HexStr(ss));
        ret.pushKV("dspid", dsproof.GetId().ToString());
        ret.pushKV("orphan", isOrphan);
    }
    // verbosity = 2 or above, add "outpoint"
    if (verbosity >= 2) {
        UniValue outpoint(UniValue::VOBJ);
        outpoint.pushKV("txid", dsproof.prevTxId().ToString());
        outpoint.pushKV("vout", (int)dsproof.prevOutIndex());
        ret.pushKV("outpoint", outpoint);
    }
    // verbosity = 3 or above, add the "spenders" array
    if (verbosity >= 3) {
        UniValue spenders(UniValue::VARR);
        spenders.push_back(SpenderToJson(dsproof.spender1()));
        spenders.push_back(SpenderToJson(dsproof.spender2()));
        ret.pushKV("spenders", spenders);
    }
    return ret;
}

} // namespace

// Note: BCH2 DSProof RPC commands are simplified compared to BCHN.
// Full mempool integration would require additional work.

static RPCHelpMan getdsproof()
{
    return RPCHelpMan{"getdsproof",
        "\nGet information for a double-spend proof by its ID.\n",
        {
            {"dspid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The double-spend proof ID (hash) to look up."},
            {"verbosity", RPCArg::Type::NUM, RPCArg::Default{2},
             "Values 1-3 return progressively more information."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hex", "The raw serialized double-spend proof data"},
                {RPCResult::Type::STR_HEX, "dspid", "Double-spend proof ID"},
                {RPCResult::Type::BOOL, "orphan", "Whether this is an orphan proof"},
                {RPCResult::Type::OBJ, "outpoint", "The outpoint being double-spent (verbosity >= 2)",
                    {
                        {RPCResult::Type::STR_HEX, "txid", "The previous output txid"},
                        {RPCResult::Type::NUM, "vout", "The previous output index"},
                    }
                },
                {RPCResult::Type::ARR, "spenders", "The conflicting spenders (verbosity >= 3)",
                    {
                        {RPCResult::Type::OBJ, "", "",
                            {
                                {RPCResult::Type::NUM, "txversion", "Transaction version"},
                                {RPCResult::Type::NUM, "sequence", "Sequence number"},
                                {RPCResult::Type::NUM, "locktime", "Lock time"},
                                {RPCResult::Type::STR_HEX, "hashprevoutputs", "Hash of previous outputs"},
                                {RPCResult::Type::STR_HEX, "hashsequence", "Hash of sequences"},
                                {RPCResult::Type::STR_HEX, "hashoutputs", "Hash of outputs"},
                            }
                        }
                    }
                },
            }
        },
        RPCExamples{
            HelpExampleCli("getdsproof", "\"dspid_hex\"") +
            HelpExampleRpc("getdsproof", "\"dspid_hex\", 2")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            ThrowIfDisabled();

            const NodeContext& node = EnsureAnyNodeContext(request.context);
            const CTxMemPool& mempool = EnsureMemPool(node);

            DspId hash = ParseHashV(request.params[0], "dspid");
            int verbosity = 2;
            if (!request.params[1].isNull()) {
                verbosity = request.params[1].getInt<int>();
                if (verbosity < 1 || verbosity > verbosityMax)
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "verbosity must be 1-3");
            }

            // Look up the proof in the mempool's DSProof storage
            DoubleSpendProof proof = mempool.doubleSpendProofStorage().lookup(hash);
            if (proof.isEmpty()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Double-spend proof not found");
            }

            // Check if it's an orphan by looking at all proofs
            bool isOrphan = false;
            auto allProofs = mempool.doubleSpendProofStorage().getAll(true);
            for (const auto& [p, orphan] : allProofs) {
                if (p.GetId() == hash) {
                    isOrphan = orphan;
                    break;
                }
            }

            return DSProofToJson(verbosity, proof, isOrphan);
        },
    };
}

static RPCHelpMan getdsprooflist()
{
    return RPCHelpMan{"getdsprooflist",
        "\nList all double-spend proofs currently known.\n"
        "\nNote: BCH2 DSProof support is currently limited.\n",
        {
            {"verbosity", RPCArg::Type::NUM, RPCArg::Default{0},
             "Values 0-3 return progressively more information."},
            {"include_orphans", RPCArg::Type::BOOL, RPCArg::Default{false},
             "If true, include orphan proofs."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "",
            {
                {RPCResult::Type::STR_HEX, "", "Double-spend proof ID (verbosity=0)"},
            }
        },
        RPCExamples{
            HelpExampleCli("getdsprooflist", "") +
            HelpExampleCli("getdsprooflist", "2 true") +
            HelpExampleRpc("getdsprooflist", "1, false")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            ThrowIfDisabled();

            const NodeContext& node = EnsureAnyNodeContext(request.context);
            const CTxMemPool& mempool = EnsureMemPool(node);

            int verbosity = 0;
            if (!request.params[0].isNull()) {
                verbosity = request.params[0].getInt<int>();
                if (verbosity < 0 || verbosity > verbosityMax)
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "verbosity must be 0-3");
            }

            bool includeOrphans = false;
            if (!request.params[1].isNull()) {
                includeOrphans = request.params[1].get_bool();
            }

            // Get all proofs from storage
            auto allProofs = mempool.doubleSpendProofStorage().getAll(includeOrphans);

            UniValue ret(UniValue::VARR);
            for (const auto& [proof, isOrphan] : allProofs) {
                if (verbosity == 0) {
                    // Just return the dspid
                    ret.push_back(proof.GetId().ToString());
                } else {
                    // Return full object based on verbosity
                    ret.push_back(DSProofToJson(verbosity, proof, isOrphan));
                }
            }
            return ret;
        },
    };
}

static RPCHelpMan getdsproofscore()
{
    return RPCHelpMan{"getdsproofscore",
        "\nReturn a double-spend confidence score for a mempool transaction.\n"
        "\nNote: BCH2 DSProof support is currently limited.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The mempool txid to query."},
        },
        RPCResult{
            RPCResult::Type::NUM, "", "A value from 0.0 to 1.0 indicating double-spend confidence"
        },
        RPCExamples{
            HelpExampleCli("getdsproofscore", "\"txid_hex\"") +
            HelpExampleRpc("getdsproofscore", "\"txid_hex\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            ThrowIfDisabled();

            const NodeContext& node = EnsureAnyNodeContext(request.context);
            const CTxMemPool& mempool = EnsureMemPool(node);

            uint256 txid = ParseHashV(request.params[0], "txid");

            // Check if transaction exists in mempool
            CTransactionRef tx;
            {
                LOCK(mempool.cs);
                tx = mempool.get(txid);
            }
            if (!tx) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Transaction not in mempool");
            }

            // Check if any DSProof exists for any of the transaction's inputs
            // If a proof exists, return 0.0 (double-spend detected)
            // If no proof exists, return 1.0 (transaction appears safe)
            auto allProofs = mempool.doubleSpendProofStorage().getAll(false);
            for (const auto& [proof, isOrphan] : allProofs) {
                const COutPoint& proofOutpoint = proof.outPoint();
                for (const auto& txin : tx->vin) {
                    if (txin.prevout == proofOutpoint) {
                        // Found a DSProof for one of this transaction's inputs
                        return 0.0;
                    }
                }
            }

            // No DSProof found - transaction appears safe
            return 1.0;
        },
    };
}

void RegisterDSProofRPCCommands(CRPCTable &t)
{
    static const CRPCCommand commands[]{
        {"blockchain", &getdsproof},
        {"blockchain", &getdsprooflist},
        {"blockchain", &getdsproofscore},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
