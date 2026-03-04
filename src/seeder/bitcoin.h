// Copyright (c) 2017-2022 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_SEEDER_BITCOIN_H
#define BITCOINII_SEEDER_BITCOIN_H

#include <chainparams.h>
#include <compat/compat.h>
#include <protocol.h>
#include <streams.h>
#include <util/sock.h>

#include <memory>
#include <string>
#include <vector>

static inline unsigned short GetDefaultPort() {
    return Params().GetDefaultPort();
}

// Returns a pointer to the latest checkpoint, or nullptr if the selected network lacks checkpoints
static inline const std::pair<const int, uint256> *GetCheckpoint() {
    const auto &mapCheckpoints = Params().Checkpoints().mapCheckpoints;
    if (!mapCheckpoints.empty()) {
        return &*mapCheckpoints.rbegin();
    }
    return nullptr;
}

// If we have a checkpoint, returns its height, otherwise returns 0.
static inline int GetRequireHeight() {
    if (auto *pair = GetCheckpoint()) {
        return pair->first;
    }
    return 0;
}

// After the 1000th addr, the seeder will only add one more address per addr
// message.
static const unsigned int ADDR_SOFT_CAP = 1000;

enum class PeerMessagingState {
    AwaitingMessages,
    Finished,
};

class CSeederNode {
protected:
    std::unique_ptr<Sock> sock;
    DataStream vSend;
    DataStream vRecv;
    uint32_t nHeaderStart;
    uint32_t nMessageStart;
    int nVersion;
    std::string strSubVer;
    int nStartingHeight;
    std::vector<CAddress> *vAddr;
    int ban;
    int64_t doneAfter;
    CAddress you;
    bool checkpointVerified;
    bool needAddrReply = false;

    int GetTimeout() const { return you.IsI2P() ? 120 : 30; }

    void BeginMessage(const char *pszCommand);

    void AbortMessage();

    void EndMessage();

    void Send();

    void PushVersion();

    bool ProcessMessages();

    PeerMessagingState ProcessMessage(const std::string &msg_type,
                                      DataStream &recv);

public:
    CSeederNode(const CService &ip, std::vector<CAddress> *vAddrIn);
    ~CSeederNode();

    bool Run();

    int GetBan() const { return ban; }

    int GetClientVersion() const { return nVersion; }

    const std::string & GetClientSubVersion() const { return strSubVer; }

    int GetStartingHeight() const { return nStartingHeight; }

    ServiceFlags GetServices() const { return you.nServices; }

    bool IsCheckpointVerified() const { return checkpointVerified; }
};

bool TestNode(const CService &cip, int &ban, int &client, std::string &clientSV,
              int &blocks, std::vector<CAddress> *vAddr, ServiceFlags &services, bool &checkpointVerified);

#endif // BITCOINII_SEEDER_BITCOIN_H
