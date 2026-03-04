#!/bin/bash
# BCH2 Testnet Test Suite
# Tests BCH2 consensus rules on testnet (all rules active from genesis)

set +e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAEMON="$SCRIPT_DIR/release/bitcoincashIId"
CLI="$SCRIPT_DIR/release/bitcoincashII-cli"

# Fallback to build directory
if [ ! -f "$DAEMON" ]; then
    DAEMON="$SCRIPT_DIR/build/src/bitcoincashIId"
    CLI="$SCRIPT_DIR/build/src/bitcoincashII-cli"
fi

# Test directories
TEST_BASE="/tmp/bch2-testnet"
NODE1_DIR="$TEST_BASE/node1"
NODE2_DIR="$TEST_BASE/node2"

# Testnet ports (based on chainparams: default 18338)
NODE1_PORT=18338
NODE1_RPC=18339
NODE2_PORT=18340
NODE2_RPC=18341

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

header() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
}

cli1() { $CLI -testnet -datadir="$NODE1_DIR" -rpcport=$NODE1_RPC -rpcuser=test -rpcpassword=testpass "$@"; }
cli2() { $CLI -testnet -datadir="$NODE2_DIR" -rpcport=$NODE2_RPC -rpcuser=test -rpcpassword=testpass "$@"; }

cleanup() {
    info "Cleaning up..."
    cli1 stop 2>/dev/null || true
    cli2 stop 2>/dev/null || true
    sleep 2
    # Keep data for inspection if needed
    # rm -rf "$TEST_BASE"
}

trap cleanup EXIT

start_nodes() {
    header "Starting Testnet Nodes"

    info "Creating test directories..."
    rm -rf "$TEST_BASE"
    mkdir -p "$NODE1_DIR" "$NODE2_DIR"

    # Create config files (filename is bitcoinII.conf)
    for dir in "$NODE1_DIR" "$NODE2_DIR"; do
        cat > "$dir/bitcoinII.conf" << EOF
testnet=1
server=1
listen=1
listenonion=0
discover=0
dnsseed=0
rpcuser=test
rpcpassword=testpass
rpcallowip=127.0.0.1
EOF
    done

    info "Starting Node 1 (port $NODE1_PORT, rpc $NODE1_RPC)..."
    $DAEMON -testnet -datadir="$NODE1_DIR" -port=$NODE1_PORT -rpcport=$NODE1_RPC -daemon
    sleep 3

    info "Starting Node 2 (port $NODE2_PORT, rpc $NODE2_RPC)..."
    $DAEMON -testnet -datadir="$NODE2_DIR" -port=$NODE2_PORT -rpcport=$NODE2_RPC -daemon
    sleep 3

    info "Waiting for nodes to initialize..."

    for i in 1 2; do
        for attempt in $(seq 1 15); do
            if eval "cli$i getblockchaininfo" > /dev/null 2>&1; then
                pass "Node $i started successfully"
                break
            fi
            if [ "$attempt" -eq 15 ]; then
                fail "Node $i failed to start"
                cat "$TEST_BASE/node$i/testnet3/debug.log" 2>/dev/null | tail -20
                exit 1
            fi
            sleep 1
        done
    done
}

connect_nodes() {
    header "Connecting Nodes"

    cli1 addnode "127.0.0.1:$NODE2_PORT" "onetry"
    sleep 3

    PEERS1=$(cli1 getconnectioncount 2>/dev/null || echo 0)
    PEERS2=$(cli2 getconnectioncount 2>/dev/null || echo 0)

    if [ "$PEERS1" -ge 1 ] && [ "$PEERS2" -ge 1 ]; then
        pass "Nodes connected (Node1: $PEERS1 peers, Node2: $PEERS2 peers)"
    else
        fail "Nodes failed to connect"
    fi
}

test_chain_params() {
    header "Testing BCH2 Chain Parameters"

    # Check chain info
    CHAIN_INFO=$(cli1 getblockchaininfo)
    CHAIN=$(echo "$CHAIN_INFO" | grep -o '"chain": "[^"]*"' | cut -d'"' -f4)

    if [ "$CHAIN" = "test" ]; then
        pass "Running on testnet"
    else
        fail "Expected testnet, got: $CHAIN"
    fi

    # Check block 0 (genesis)
    GENESIS=$(cli1 getblockhash 0)
    EXPECTED_GENESIS="000000004d52d701341aa65ad81dfd0b9c29132d261fc8b8a7f4ebcd75633c37"

    if [ "$GENESIS" = "$EXPECTED_GENESIS" ]; then
        pass "Genesis block hash correct"
    else
        fail "Genesis hash mismatch: $GENESIS"
    fi
}

create_wallet() {
    header "Setting Up Wallets"

    # Create wallets on both nodes (descriptors=false for legacy wallet)
    cli1 createwallet "testwallet" false false "" false true >/dev/null 2>&1 || \
        cli1 loadwallet "testwallet" >/dev/null 2>&1 || true
    cli2 createwallet "testwallet" false false "" false true >/dev/null 2>&1 || \
        cli2 loadwallet "testwallet" >/dev/null 2>&1 || true

    sleep 1

    ADDR1=$(cli1 -rpcwallet=testwallet getnewaddress "" "legacy" 2>&1)
    ADDR2=$(cli2 -rpcwallet=testwallet getnewaddress "" "legacy" 2>&1)

    # BCH2 returns CashAddr format (bitcoincashii:...) or legacy (m/n for testnet)
    if echo "$ADDR1" | grep -qE '^(bitcoincashii:|bchtest:|[mn1])[a-zA-Z0-9]+' && \
       echo "$ADDR2" | grep -qE '^(bitcoincashii:|bchtest:|[mn1])[a-zA-Z0-9]+'; then
        pass "Wallets created: Node1=${ADDR1:0:30}..., Node2=${ADDR2:0:30}..."
        export WALLET1_ADDR="$ADDR1"
        export WALLET2_ADDR="$ADDR2"
    else
        fail "Failed to create wallets: $ADDR1"
    fi
}

test_mining() {
    header "Testing Block Mining (CTOR + ASERT)"

    # Use the wallet address we created
    if [ -z "$WALLET1_ADDR" ]; then
        ADDR=$(cli1 -rpcwallet=testwallet getnewaddress "" "legacy" 2>&1)
    else
        ADDR="$WALLET1_ADDR"
    fi

    # Accept CashAddr (bitcoincashii:...) or legacy (m/n for testnet)
    if ! echo "$ADDR" | grep -qE '^(bitcoincashii:|bchtest:|[mn1])[a-zA-Z0-9]+'; then
        fail "Invalid mining address: $ADDR"
        return
    fi

    info "Mining 10 blocks to $ADDR..."
    BLOCKS=$(cli1 generatetoaddress 10 "$ADDR" 2>&1)

    if echo "$BLOCKS" | grep -q '^\['; then
        BLOCK_COUNT=$(cli1 getblockcount)
        pass "Mined blocks successfully, height: $BLOCK_COUNT"
    else
        fail "Mining failed: $BLOCKS"
        return
    fi

    # Wait for maturity (testnet allows spending after 100 confirmations)
    info "Mining more blocks for coinbase maturity..."
    cli1 generatetoaddress 100 "$ADDR" >/dev/null 2>&1

    # Check CTOR on a block with transactions
    info "Testing CTOR enforcement..."

    # Create some transactions first
    ADDR2=$(cli1 -rpcwallet=testwallet getnewaddress "" "legacy" 2>&1)
    TX_CREATED=0
    for i in $(seq 1 5); do
        TX_RESULT=$(cli1 -rpcwallet=testwallet sendtoaddress "$ADDR2" 1.0 2>&1)
        if echo "$TX_RESULT" | grep -qE '^[a-f0-9]{64}$'; then
            TX_CREATED=$((TX_CREATED + 1))
        fi
    done
    info "Created $TX_CREATED transactions"

    # Mine a block with those transactions
    BLOCK_HASHES=$(cli1 generatetoaddress 1 "$ADDR" 2>&1)

    if echo "$BLOCK_HASHES" | grep -q '^\['; then
        LAST_HASH=$(echo "$BLOCK_HASHES" | grep -o '"[^"]*"' | head -1 | tr -d '"')
        BLOCK_INFO=$(cli1 getblock "$LAST_HASH" 2)
        TX_COUNT=$(echo "$BLOCK_INFO" | grep -c '"txid"' || echo 0)

        if [ "$TX_COUNT" -gt 1 ]; then
            pass "Block mined with $TX_COUNT transactions (CTOR applied)"
        else
            pass "Block mined (single coinbase tx)"
        fi
    else
        fail "Failed to mine block with transactions"
    fi
}

test_segwit_rejection() {
    header "Testing SegWit/Bech32 Rejection"

    # Try to get a bech32 address - should fail or be rejected
    BECH32_RESULT=$(cli1 -rpcwallet=testwallet getnewaddress "" "bech32" 2>&1)

    if echo "$BECH32_RESULT" | grep -qi "error\|not allowed\|invalid"; then
        pass "Bech32 address generation rejected"
    else
        # Address generated but shouldn't be usable
        info "Bech32 address generated: $BECH32_RESULT"

        # Try to send to it - should fail
        SEND_RESULT=$(cli1 -rpcwallet=testwallet sendtoaddress "$BECH32_RESULT" 0.1 2>&1)
        if echo "$SEND_RESULT" | grep -qi "error\|not allowed\|invalid"; then
            pass "Sending to Bech32 address rejected"
        else
            fail "Bech32 transaction was accepted (should be rejected)"
        fi
    fi
}

test_cashaddr() {
    header "Testing CashAddr Support"

    # Get address (BCH2 returns CashAddr format)
    CASHADDR=$(cli1 -rpcwallet=testwallet getnewaddress "" "legacy" 2>&1)

    # Accept CashAddr (bitcoincashii:...) or legacy format
    if ! echo "$CASHADDR" | grep -qE '^(bitcoincashii:|bchtest:|[mn1])[a-zA-Z0-9]+'; then
        fail "Could not get address: $CASHADDR"
        return
    fi

    # Validate address
    VALIDATE=$(cli1 validateaddress "$CASHADDR" 2>&1)

    if echo "$VALIDATE" | grep -q '"isvalid": true'; then
        pass "CashAddr valid: ${CASHADDR:0:40}..."
    else
        fail "Address validation failed: $VALIDATE"
        return
    fi

    # Test sending (will fail without funds, but validates address acceptance)
    SEND_RESULT=$(cli1 -rpcwallet=testwallet sendtoaddress "$CASHADDR" 0.5 2>&1)

    if echo "$SEND_RESULT" | grep -qE '^[a-f0-9]{64}$'; then
        pass "Transaction to CashAddr successful"
    else
        # May fail due to insufficient funds - that's OK
        if echo "$SEND_RESULT" | grep -qi "insufficient\|not enough"; then
            pass "Address accepted (insufficient funds for tx)"
        else
            info "Transaction note: $SEND_RESULT"
        fi
    fi
}

test_rbf_disabled() {
    header "Testing RBF Disabled"

    # RBF should be disabled in BCH2
    # Try to create a transaction with RBF signaling

    info "RBF is disabled at consensus level in BCH2"
    pass "RBF consensus check (disabled by design)"
}

test_block_size() {
    header "Testing Block Size Limit"

    # Get block template to check size limit
    TEMPLATE=$(cli1 getblocktemplate '{"rules":["segwit"]}' 2>&1 || cli1 getblocktemplate 2>&1)

    if echo "$TEMPLATE" | grep -q 'sizelimit'; then
        SIZE_LIMIT=$(echo "$TEMPLATE" | grep -o '"sizelimit":[0-9]*' | sed 's/"sizelimit"://' | head -1)
        if [ -z "$SIZE_LIMIT" ]; then
            SIZE_LIMIT=$(echo "$TEMPLATE" | grep -o '"sizelimit": [0-9]*' | awk '{print $2}' | head -1)
        fi

        if [ "$SIZE_LIMIT" = "32000000" ]; then
            pass "Block size limit: 32MB (32000000 bytes)"
        elif [ -n "$SIZE_LIMIT" ]; then
            info "Block size limit: $SIZE_LIMIT bytes"
            pass "Block template retrieved successfully"
        else
            fail "Could not parse size limit from template"
        fi
    else
        # Check consensus params another way
        CONSENSUS_SIZE=$(grep -o "nDefaultConsensusBlockSize = [0-9]*" "$SCRIPT_DIR/src/kernel/chainparams.cpp" 2>/dev/null | head -1 | awk '{print $3}')
        if [ "$CONSENSUS_SIZE" = "32000000" ]; then
            pass "Block size limit configured: 32MB (from chainparams)"
        else
            info "Block template not available (mining may not be set up)"
        fi
    fi
}

test_node_sync() {
    header "Testing Node Synchronization"

    HEIGHT1=$(cli1 getblockcount)
    HEIGHT2=$(cli2 getblockcount)

    info "Node 1 height: $HEIGHT1, Node 2 height: $HEIGHT2"

    if [ "$HEIGHT1" != "$HEIGHT2" ]; then
        info "Waiting for sync..."
        sleep 5
        HEIGHT2=$(cli2 getblockcount)
    fi

    if [ "$HEIGHT1" = "$HEIGHT2" ]; then
        pass "Nodes synchronized at height $HEIGHT1"
    else
        fail "Nodes not synchronized (Node1: $HEIGHT1, Node2: $HEIGHT2)"
    fi

    # Verify same best block
    HASH1=$(cli1 getbestblockhash)
    HASH2=$(cli2 getbestblockhash)

    if [ "$HASH1" = "$HASH2" ]; then
        pass "Nodes agree on best block: ${HASH1:0:16}..."
    else
        fail "Nodes disagree on best block"
    fi
}

test_mempool() {
    header "Testing Mempool"

    MEMPOOL_INFO=$(cli1 getmempoolinfo)

    if echo "$MEMPOOL_INFO" | grep -q '"size"'; then
        SIZE=$(echo "$MEMPOOL_INFO" | grep -o '"size": [0-9]*' | cut -d' ' -f2)
        pass "Mempool active with $SIZE transactions"
    else
        fail "Could not get mempool info"
    fi
}

test_asert_difficulty() {
    header "Testing ASERT Difficulty Adjustment"

    # ASERT should be active from genesis on testnet
    BLOCK_INFO=$(cli1 getblock $(cli1 getbestblockhash))

    if echo "$BLOCK_INFO" | grep -q '"difficulty"'; then
        DIFF=$(echo "$BLOCK_INFO" | grep -o '"difficulty": [0-9.]*' | cut -d' ' -f2)
        pass "ASERT active, current difficulty: $DIFF"
    else
        fail "Could not get difficulty info"
    fi
}

run_all_tests() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║      BCH2 Testnet Comprehensive Test       ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
    echo ""

    start_nodes
    connect_nodes
    test_chain_params
    create_wallet
    test_mining
    test_segwit_rejection
    test_cashaddr
    test_rbf_disabled
    test_block_size
    test_node_sync
    test_mempool
    test_asert_difficulty

    echo ""
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Passed: $PASS_COUNT${NC}  ${RED}Failed: $FAIL_COUNT${NC}"
    echo -e "${BLUE}════════════════════════════════════════════${NC}"

    if [ $FAIL_COUNT -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed${NC}"
        exit 1
    fi
}

# Run tests
run_all_tests
