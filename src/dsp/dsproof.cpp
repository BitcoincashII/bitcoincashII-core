// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Copyright (C) 2020 Calin Culianu <calin.culianu@gmail.com>
// Copyright (c) 2021-2024 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dsp/dsproof.h>
#include <hash.h>
#include <streams.h>

#include <limits>
#include <stdexcept>

/* static */
bool DoubleSpendProof::s_enabled = true;

bool DoubleSpendProof::isEmpty() const
{
    // NB: default constructed COutPoint has n == 0xffffffff, hash.IsNull().
    return prevOutIndex() > static_cast<uint32_t>(std::numeric_limits<int32_t>::max())
            || prevTxId().IsNull() || GetId().IsNull();
}

void DoubleSpendProof::setHash()
{
    DataStream ss{};
    ss << *this;
    m_hash = Hash(ss);
}

void DoubleSpendProof::checkSanityOrThrow(uint32_t scriptFlags) const
{
    if (isEmpty())
        throw std::runtime_error("DSProof is empty");

    // Check limits for both pushData vectors above
    for (auto *pushData : {&m_spender1.pushData, &m_spender2.pushData}) {
        // Message must contain exactly 1 pushData
        if (pushData->size() != 1)
            throw std::runtime_error("DSProof must contain exactly 1 pushData");
        // Script data must be within size limits (520 bytes or larger depending on scriptFlags)
        if (!pushData->empty() && pushData->front().size() > DetermineMaxPushDataSize(scriptFlags))
            throw std::runtime_error("DSProof script size limit exceeded");
    }
    if (m_spender1 == m_spender2)
        throw std::runtime_error("DSProof both spenders are the same");
}
