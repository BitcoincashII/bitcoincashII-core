// Copyright (c) 2017-2024 The Bitcoin developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifdef HAVE_CONFIG_H
#include <config/bitcoinII-config.h>
#endif

#include <seeder/bitcoin.h>

#include <chainparams.h>
#include <clientversion.h>
#include <compat/compat.h>
#include <hash.h>
#include <netbase.h>
#include <primitives/block.h>
#include <seeder/db.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>
#include <node/protocol_version.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <ctime>

#define BITCOIN_SEED_NONCE 0x0539a019ca550825ULL

// Maximum headers we expect in a response (same as in net_processing.cpp)
static const unsigned int MAX_HEADERS_RESULTS = 2000;

static const uint32_t allones(-1);

void CSeederNode::BeginMessage(const char *pszCommand) {
    if (nHeaderStart != allones) {
        AbortMessage();
    }
    nHeaderStart = vSend.size();
    CMessageHeader hdr(Params().MessageStart(), pszCommand, 0);
    vSend << hdr;
    nMessageStart = vSend.size();
    // std::fprintf(stdout, "%s: SEND %s\n", ToString(you).c_str(), pszCommand);
}

void CSeederNode::AbortMessage() {
    if (nHeaderStart == allones) {
        return;
    }
    vSend.resize(nHeaderStart);
    nHeaderStart = allones;
    nMessageStart = allones;
}

void CSeederNode::EndMessage() {
    if (nHeaderStart == allones) {
        return;
    }
    uint32_t nSize = vSend.size() - nMessageStart;
    std::memcpy((char *)&vSend[nHeaderStart] +
                    offsetof(CMessageHeader, nMessageSize),
                &nSize, sizeof(nSize));
    // Compute and set checksum
    uint256 hash = Hash(Span{vSend}.subspan(nMessageStart));
    unsigned int nChecksum = 0;
    std::memcpy(&nChecksum, &hash, sizeof(nChecksum));
    assert(nMessageStart - nHeaderStart >=
           offsetof(CMessageHeader, pchChecksum) + sizeof(nChecksum));
    std::memcpy((char *)&vSend[nHeaderStart] +
                    offsetof(CMessageHeader, pchChecksum),
                &nChecksum, sizeof(nChecksum));
    nHeaderStart = allones;
    nMessageStart = allones;
}

void CSeederNode::Send() {
    if (!sock) {
        return;
    }
    if (vSend.empty()) {
        return;
    }
    ssize_t nBytes = sock->Send(vSend.data(), vSend.size(), 0);
    if (nBytes > 0) {
        vSend.ignore(nBytes);
    } else {
        sock.reset();
    }
}

void CSeederNode::PushVersion() {
    const int64_t nTime = static_cast<int64_t>(std::time(nullptr)); // nTime sent as int64_t always
    const uint64_t nLocalNonce = BITCOIN_SEED_NONCE;
    const uint64_t nLocalServices = 0;
    BeginMessage(NetMsgType::VERSION);
    const int nBestHeight = GetRequireHeight();
    const std::string ver = strprintf("/bch2-seeder:%i.%i.%i/",
                                      CLIENT_VERSION_MAJOR, CLIENT_VERSION_MINOR, CLIENT_VERSION_BUILD);
    const uint8_t fRelayTxs = 0;
    // VERSION message uses pre-31402 format: services + CNetAddr (no time)
    // addrYou = your_services + CNetAddr::V1(addr_you)
    // addrMe = my_services + CNetAddr::V1(CService{})
    uint64_t yourServices = static_cast<uint64_t>(you.nServices);
    // Cast to CService to serialize just the address part (CNetAddr + port)
    const CService& youService = you;
    vSend << PROTOCOL_VERSION << nLocalServices << nTime
          << yourServices << CNetAddr::V1(youService)       // addrYou (pre-31402 format)
          << nLocalServices << CNetAddr::V1(CService{}) // addrMe (pre-31402 format)
          << nLocalNonce << ver << nBestHeight << fRelayTxs;
    EndMessage();
}

PeerMessagingState CSeederNode::ProcessMessage(const std::string &msg_type,
                                               DataStream &recv) {
    if (msg_type == NetMsgType::VERSION) {
        int64_t nTime;
        uint64_t nNonce = 1;
        uint64_t nServiceInt;
        // VERSION uses pre-31402 format: services + CNetAddr (no time)
        uint64_t addrMeServices, addrFromServices;
        CService addrMe, addrFrom;
        recv >> nVersion >> nServiceInt >> nTime;
        recv >> addrMeServices >> CNetAddr::V1(addrMe);  // addrMe (pre-31402 format)
        you.nServices = ServiceFlags(nServiceInt);
        recv >> addrFromServices >> CNetAddr::V1(addrFrom); // addrFrom (pre-31402 format)
        recv >> nNonce;
        recv >> strSubVer;
        recv >> nStartingHeight;

        // Send BIP155 "sendaddrv2" message *before* verack
        BeginMessage(NetMsgType::SENDADDRV2);
        EndMessage();

        BeginMessage(NetMsgType::VERACK);
        EndMessage();
        return PeerMessagingState::AwaitingMessages;
    }

    const int64_t now = std::time(nullptr);

    if (msg_type == NetMsgType::VERACK) {
        // std::fprintf(stdout, "\n%s: version %i\n", ToString(you).c_str(),
        //              nVersion);
        int64_t doneAfterDelta = 1;
        if (vAddr) { // Note in the current codebase: vAddr is non-nullptr only once per day for each node we check
            BeginMessage(NetMsgType::GETADDR);
            EndMessage();
            doneAfterDelta = GetTimeout();
            needAddrReply = true;
        }
        // request headers starting after last checkpoint (only if we have checkpoints for this network)
        if (auto *pair = GetCheckpoint()) {
            checkpointVerified = false;
            std::vector<uint256> locatorHash(1, pair->second);
            BeginMessage(NetMsgType::GETHEADERS);
            vSend << CBlockLocator(std::move(locatorHash)) << uint256();
            EndMessage();
            doneAfterDelta = std::max<int64_t>(GetTimeout(), doneAfterDelta);
        } else {
            // There are no checkpoints that need to be reached on this network, so
            // consider the verification passed
            checkpointVerified = true;
        }
        doneAfter = now + doneAfterDelta;
        return PeerMessagingState::AwaitingMessages;
    }

    if (vAddr && (msg_type == NetMsgType::ADDR || msg_type == NetMsgType::ADDRV2)) {
        needAddrReply = false;
        std::vector<CAddress> vAddrNew;
        // Use ParamsStream with appropriate format for address deserialization
        if (msg_type == NetMsgType::ADDRV2) {
            ParamsStream s{CAddress::V2_NETWORK, recv};
            s >> vAddrNew;
        } else {
            ParamsStream s{CAddress::V1_NETWORK, recv};
            s >> vAddrNew;
        }
        // std::fprintf(stdout, "%s: got %i addresses\n", ToString(you).c_str(),
        //              (int)vAddrNew.size());
        std::vector<CAddress>::iterator it = vAddrNew.begin();
        if (vAddrNew.size() > 1) {
            if (checkpointVerified && (doneAfter == 0 || doneAfter > now + 1)) {
                doneAfter = now + 1;
            }
        }
        while (it != vAddrNew.end()) {
            CAddress &addr = *it;
            // std::fprintf(stdout, "%s: got address %s\n", ToString(you).c_str(), addr.ToStringAddrPort().c_str());
            it++;
            auto addrTime = (addr.nTime == NodeSeconds{}) ? NodeSeconds{} : addr.nTime;
            auto addrTimeSec = std::chrono::duration_cast<std::chrono::seconds>(addrTime.time_since_epoch()).count();
            if (addrTimeSec <= 100000000 || addrTimeSec > now + 600) {
                addr.nTime = NodeSeconds{std::chrono::seconds{now - 5 * 86400}};
            }
            if (addrTimeSec > now - 604800) {
                vAddr->push_back(addr);
            }
            // std::fprintf(stdout, "%s: added address %s (#%i)\n",
            //              ToString(you).c_str(),
            //              addr.ToStringAddrPort().c_str(), (int)(vAddr->size()));
            if (vAddr->size() > ADDR_SOFT_CAP) {
                if (checkpointVerified) {
                    // stop processing addresses and since we aren't waiting for headers, stop processing immediately
                    doneAfter = now;
                    return PeerMessagingState::Finished;
                } else {
                    // stop processing addresses now since we hit the soft cap, but we will continue to await headers
                    break;
                }
            }
        }
        return PeerMessagingState::AwaitingMessages;
    }

    if (msg_type == NetMsgType::HEADERS) {
        unsigned int nCount = ReadCompactSize(recv);
        if (nCount > MAX_HEADERS_RESULTS) {
            ban = 100000;
            return PeerMessagingState::Finished;
        }

        if (nCount == 0) {
            return PeerMessagingState::AwaitingMessages;
        }

        CBlockHeader header;
        recv >> header;

        if (auto *pair = GetCheckpoint(); pair && nStartingHeight > pair->first && header.hashPrevBlock != pair->second) {
            ban = 100000;
            return PeerMessagingState::Finished;
        }
        checkpointVerified = true;
        if (!needAddrReply) {
            doneAfter = now;
        }
        return PeerMessagingState::AwaitingMessages;
    }

    return PeerMessagingState::AwaitingMessages;
}

bool CSeederNode::ProcessMessages() {
    if (vRecv.empty()) {
        return false;
    }

    const MessageStartChars &netMagic = Params().MessageStart();
    const size_t nHeaderSize = CMessageHeader::HEADER_SIZE;

    // Convert netMagic to std::byte for comparison with vRecv
    std::array<std::byte, 4> netMagicBytes;
    for (size_t i = 0; i < 4; ++i) {
        netMagicBytes[i] = static_cast<std::byte>(netMagic[i]);
    }

    do {
        // Search for the magic bytes
        auto pstart = std::search(
            vRecv.begin(), vRecv.end(),
            netMagicBytes.begin(), netMagicBytes.end());
        if (std::size_t(vRecv.end() - pstart) < nHeaderSize) {
            if (vRecv.size() > nHeaderSize) {
                // Erase data before the incomplete header
                vRecv.ignore(vRecv.size() - nHeaderSize);
            }
            break;
        }
        // Erase data before the magic
        if (pstart != vRecv.begin()) {
            vRecv.ignore(pstart - vRecv.begin());
        }

        // Read header
        std::vector<std::byte> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
        CMessageHeader hdr;
        vRecv >> hdr;

        // Validate magic
        if (hdr.pchMessageStart != netMagic) {
            // std::fprintf(stdout, "%s: BAD (invalid header)\n", ToString(you).c_str());
            ban = 100000;
            return true;
        }
        std::string msg_type = hdr.GetCommand();
        unsigned int nMessageSize = hdr.nMessageSize;
        if (nMessageSize > MAX_SIZE) {
            // std::fprintf(stdout, "%s: BAD (message too large)\n", ToString(you).c_str());
            ban = 100000;
            return true;
        }
        if (nMessageSize > vRecv.size()) {
            // Put the header back, preserving any partial payload already received
            std::vector<std::byte> saved(vHeaderSave);
            if (vRecv.size() > 0) {
                saved.insert(saved.end(), vRecv.data(), vRecv.data() + vRecv.size());
            }
            vRecv = DataStream(Span<const std::byte>{saved});
            break;
        }
        // Verify checksum
        uint256 hash = Hash(Span{vRecv}.first(nMessageSize));
        if (std::memcmp(hash.begin(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) != 0) {
            continue;
        }
        // Extract message
        DataStream vMsg(Span{vRecv}.first(nMessageSize));
        vRecv.ignore(nMessageSize);
        if (ProcessMessage(msg_type, vMsg) == PeerMessagingState::Finished) {
            return true;
        }
        // std::fprintf(stdout, "%s: done processing %s\n",
        //              ToString(you).c_str(),
        //              msg_type.c_str());
    } while (1);
    return false;
}

CSeederNode::CSeederNode(const CService &ip, std::vector<CAddress> *vAddrIn)
    : sock{}, vSend{}, vRecv{},
      nHeaderStart(-1), nMessageStart(-1), nVersion(0), nStartingHeight(0),
      vAddr(vAddrIn), ban(0), doneAfter(0),
      you(ip, ServiceFlags(NODE_NETWORK)), checkpointVerified(false) {
}

CSeederNode::~CSeederNode() {
    // The unique_ptr will automatically close the socket via Sock destructor
}

/// Polls the socket at 2 Hz for data, keeping sure to check the ShutdownRequested() flag as it loops.
/// @return true if data is available, or false otherwise on timeout, or if ShutdownRequested().
static bool waitSocket(const Sock& sock, const int timeout_secs) {
    constexpr int poll_hz = 2;
    constexpr auto tick_msec = std::chrono::milliseconds(1000 / poll_hz);
    int timeout_ticks = timeout_secs * poll_hz;
    while (!seeder::ShutdownRequested() && timeout_ticks > 0) {
        Sock::Event occurred = 0;
        if (!sock.Wait(tick_msec, Sock::RECV, &occurred)) {
            // Error occurred
            return false;
        }
        if (occurred & Sock::RECV) {
            // data is available
            return true;
        }
        // otherwise, keep polling until timeout_secs expires
        --timeout_ticks;
    }
    return false; // timeout or shutdown requested
}

bool CSeederNode::Run() {
    // FIXME: This logic is duplicated with CConnman::ConnectNode for no
    // good reason.
    bool connected = false;
    Proxy proxy;

    if (you.IsValid()) {
        bool proxyConnectionFailed = false;

        if (GetProxy(you.GetNetwork(), proxy)) {
            sock = CreateSock(proxy.proxy);
            if (!sock) {
                return false;
            }
            connected = ConnectThroughProxy(proxy, you.ToStringAddr(), you.GetPort(), *sock, nConnectTimeout,
                                            proxyConnectionFailed);
        } else {
            // no proxy needed (none set for target network)
            sock = CreateSock(you);
            if (!sock) {
                return false;
            }
            // no proxy needed (none set for target network)
            connected =
                ConnectSocketDirectly(you, *sock, nConnectTimeout, false);
        }
    }

    if (!connected) {
        std::fprintf(stdout, "Cannot connect to %s\n", you.ToStringAddrPort().c_str());
        sock.reset();
        return false;
    }

    PushVersion();
    Send();

    bool res = true;
    int64_t now;
    auto Predicate = [&now, this] {
        now = std::time(nullptr);
        return !seeder::ShutdownRequested() && ban == 0 && (doneAfter == 0 || doneAfter > now) && sock;
    };
    while (Predicate()) {
        char pchBuf[0x10000];
        const bool waitRes = waitSocket(*sock, (doneAfter ? static_cast<int>(doneAfter - now) : GetTimeout()));
        if (!waitRes) {
            if (!doneAfter) {
                res = false;
            }
            break;
        }
        const ssize_t nBytes = sock->Recv(pchBuf, sizeof(pchBuf), 0);
        if (nBytes > 0) {
            vRecv.write(MakeByteSpan(Span<char>(pchBuf, nBytes)));
        } else {
            res = false;
            break;
        }
        ProcessMessages();
        Send();
    }
    if (!sock) {
        res = false;
    } else {
        sock.reset();
    }
    return (ban == 0) && res;
}

bool TestNode(const CService &cip, int &ban, int &clientV,
              std::string &clientSV, int &blocks,
              std::vector<CAddress> *vAddr, ServiceFlags &services, bool &checkpointVerified) {
    try {
        CSeederNode node(cip, vAddr);
        bool ret = node.Run();
        if (!ret) {
            ban = node.GetBan();
        } else {
            ban = 0;
        }
        clientV = node.GetClientVersion();
        clientSV = node.GetClientSubVersion();
        blocks = node.GetStartingHeight();
        services = node.GetServices();
        checkpointVerified = node.IsCheckpointVerified();
        std::fprintf(stdout, "%s: %s (ver=%d, blocks=%d, svcs=0x%x, chkpt=%s, ban=%d)\n",
                     cip.ToStringAddrPort().c_str(), ret ? "GOOD" : "BAD",
                     clientV, blocks, (unsigned)services,
                     checkpointVerified ? "yes" : "no", ban);
        return ret;
    } catch (std::ios_base::failure &e) {
        std::fprintf(stdout, "%s: EXCEPTION %s\n", cip.ToStringAddrPort().c_str(), e.what());
        ban = 0;
        return false;
    }
}
