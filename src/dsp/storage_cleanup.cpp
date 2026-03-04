// Copyright (C) 2019-2020 Tom Zander <tomz@freedommail.ch>
// Copyright (C) 2020 Calin Culianu <calin.culianu@gmail.com>
// Copyright (c) 2021 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dsp/storage.h>
#include <logging.h>
#include <net_processing.h>
#include <util/time.h>

bool DoubleSpendProofStorage::periodicCleanup()
{
    std::vector<NodeId> punishPeers;
    {
        LOCK(m_lock);
        const auto expire = GetTime() - m_secondsToKeepOrphans;
        auto &index = m_proofs.get<tag_TimeStamp>();
        const auto end = index.upper_bound(expire);
        size_t erased = 0;
        for (auto it = index.begin(); it != end; ) {
            if (it->orphan) {
                if (it->nodeId > -1)
                    punishPeers.push_back(it->nodeId);
                it = index.erase(it);
                decrementOrphans(1);
                ++erased;
            } else
                ++it;
        }
        if (erased)
            LogPrint(BCLog::MEMPOOL, "DSP orphans erased: %d, DSProof count: %d\n", erased, m_proofs.size());
    }
    // For now, we just log and skip the peer punishment as it requires access to
    // the PeerManager which isn't easily available from here.
    if (!punishPeers.empty()) {
        LogPrint(BCLog::MEMPOOL, "DSProof: %d peers would be punished for expired orphans\n", punishPeers.size());
    }

    return true; // repeat
}
