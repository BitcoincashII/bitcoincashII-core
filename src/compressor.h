// Copyright (c) 2009-2025 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2025 The BitcoinII developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Forked from Bitcoin Core version 0.27.0
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_COMPRESSOR_H
#define BITCOINII_COMPRESSOR_H

#include <prevector.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>

/**
 * This saves us from making many heap allocations when serializing
 * and deserializing compressed scripts.
 *
 * This prevector size is determined by the largest .resize() in the
 * CompressScript function. The largest compressed script format is a
 * compressed public key, which is 33 bytes.
 */
using CompressedScript = prevector<33, unsigned char>;

bool CompressScript(const CScript& script, CompressedScript& out);
unsigned int GetSpecialScriptSize(unsigned int nSize);
bool DecompressScript(CScript& script, unsigned int nSize, const CompressedScript& in);

/**
 * Compress amount.
 *
 * nAmount is of type uint64_t and thus cannot be negative. If you're passing in
 * a CAmount (int64_t), make sure to properly handle the case where the amount
 * is negative before calling CompressAmount(...).
 *
 * @pre Function defined only for 0 <= nAmount <= MAX_MONEY.
 */
uint64_t CompressAmount(uint64_t nAmount);

uint64_t DecompressAmount(uint64_t nAmount);

/** Compact serializer for scripts.
 *
 *  It detects common cases and encodes them much more efficiently.
 *  3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 *  Other scripts up to 121 bytes require 1 byte + script length. Above
 *  that, scripts up to 16505 bytes require 2 bytes + script length.
 */
struct ScriptCompression
{
    /**
     * make this static for now (there are only 6 special scripts defined)
     * this can potentially be extended together with a new nVersion for
     * transactions, in which case this value becomes dependent on nVersion
     * and nHeight of the enclosing transaction.
     */
    static const unsigned int nSpecialScripts = 6;

    template<typename Stream>
    void Ser(Stream &s, const CScript& script) {
        CompressedScript compr;
        if (CompressScript(script, compr)) {
            s << Span{compr};
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << Span{script};
    }

    template<typename Stream>
    void Unser(Stream &s, CScript& script) {
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            CompressedScript vch(GetSpecialScriptSize(nSize), 0x00);
            s >> Span{vch};
            DecompressScript(script, nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            // Overly long script, replace with a short invalid one
            script << OP_RETURN;
            s.ignore(nSize);
        } else {
            script.resize(nSize);
            s >> Span{script};
        }
    }
};

struct AmountCompression
{
    template<typename Stream, typename I> void Ser(Stream& s, I val)
    {
        s << VARINT(CompressAmount(val));
    }
    template<typename Stream, typename I> void Unser(Stream& s, I& val)
    {
        uint64_t v;
        s >> VARINT(v);
        val = DecompressAmount(v);
    }
};

/** wrapper for CTxOut that provides a more compact serialization.
 *  Preserves CashToken data (if any) by encoding it into the script stream
 *  using the same 0xEF prefix convention as CTxOut's native serialization.
 *  Token-bearing outputs bypass ScriptCompression's special cases (stored
 *  uncompressed) since 0xEF never matches P2PKH/P2SH/P2PK patterns.
 *  Backward compatible: pre-token UTXOs have no 0xEF prefix.
 */
struct TxOutCompression
{
    template<typename Stream>
    void Ser(Stream& s, const CTxOut& obj) {
        ::Serialize(s, Using<AmountCompression>(obj.nValue));
        if (obj.HasTokenData()) {
            // Build combined: 0xEF prefix + serialized token data + scriptPubKey
            std::vector<unsigned char> tokenBytes;
            VectorWriter tw(tokenBytes, 0);
            obj.tokenData->Serialize(tw);

            CScript combined;
            combined.reserve(1 + tokenBytes.size() + obj.scriptPubKey.size());
            combined.push_back(SPECIAL_TOKEN_PREFIX); // 0xEF
            combined.insert(combined.end(), tokenBytes.begin(), tokenBytes.end());
            combined.insert(combined.end(), obj.scriptPubKey.begin(), obj.scriptPubKey.end());
            ::Serialize(s, Using<ScriptCompression>(combined));
        } else {
            ::Serialize(s, Using<ScriptCompression>(obj.scriptPubKey));
        }
    }

    template<typename Stream>
    void Unser(Stream& s, CTxOut& obj) {
        ::Unserialize(s, Using<AmountCompression>(obj.nValue));
        CScript script;
        ::Unserialize(s, Using<ScriptCompression>(script));
        if (!script.empty() && script[0] == SPECIAL_TOKEN_PREFIX) {
            // Token-bearing output: parse token data, remainder is scriptPubKey
            SpanReader reader({script.data() + 1, script.size() - 1});
            OutputToken token;
            token.Unserialize(reader);
            obj.tokenData.emplace(std::move(token));
            size_t remaining = reader.size();
            obj.scriptPubKey.assign(script.end() - remaining, script.end());
        } else {
            obj.scriptPubKey = std::move(script);
            obj.tokenData.reset();
        }
    }
};

#endif // BITCOINII_COMPRESSOR_H
