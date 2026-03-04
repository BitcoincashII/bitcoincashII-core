#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BCH2 P2P adversarial block rejection rules.

Verifies the node correctly rejects:
1. Block with witness transaction data (unexpected-witness)
2. Non-CTOR ordered block (tx-ordering)
3. Block with duplicate transactions (tx-duplicate)
4. Witness commitment in coinbase (unexpected-witness-commitment)
5. Block with wrong difficulty bits (bad-diffbits)
6. Valid block accepted (sanity check)
"""
from test_framework.blocktools import (
    create_block,
    create_coinbase,
    create_tx_with_script,
)
from test_framework.messages import (
    COIN,
    CTxInWitness,
    CTxOut,
    CTxWitness,
    ser_uint256,
)
from test_framework.p2p import P2PDataStore
from test_framework.script import CScript, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


def ctor_sort_key(tx):
    """Sort key matching the node's CTOR ordering (memcmp on raw txid bytes)."""
    tx.calc_sha256()
    return ser_uint256(tx.sha256)


class BCH2AdversarialTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=noban@127.0.0.1"]]

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PDataStore())

        self.log.info("Mining to fork height (200) + maturity (100)...")
        self.generatetoaddress(node, 300, node.get_deterministic_priv_key().address)
        assert_equal(node.getblockcount(), 300)

        # Create a block with multiple spendable outputs for later tests
        self.log.info("Creating spendable coinbase with multiple outputs...")
        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1

        # Coinbase with 3 anyone-can-spend outputs (6 BCH2 each)
        coinbase = create_coinbase(height)
        coinbase.vout[0].nValue = 4 * COIN
        coinbase.vout.append(CTxOut(4 * COIN, CScript([OP_TRUE])))
        coinbase.vout.append(CTxOut(4 * COIN, CScript([OP_TRUE])))
        coinbase.rehash()

        setup_block = create_block(tip, coinbase, block_time)
        setup_block.solve()
        peer.send_blocks_and_test([setup_block], node, success=True)

        # Mature the coinbase
        self.generatetoaddress(node, 100, node.get_deterministic_priv_key().address)

        def get_tip_info():
            bb = node.getblock(node.getbestblockhash())
            return int(node.getbestblockhash(), 16), bb["height"] + 1, bb["time"] + 1

        # ====================================================================
        # Test 1: Block with witness tx → rejected (unexpected-witness)
        # ====================================================================
        self.log.info("Test 1: Block with witness tx rejected (unexpected-witness)")
        tip, height, block_time = get_tip_info()

        tx_wit = create_tx_with_script(setup_block.vtx[0], 0, script_sig=b'', amount=3 * COIN)
        tx_wit.wit = CTxWitness()
        tx_wit.wit.vtxinwit = [CTxInWitness()]
        tx_wit.wit.vtxinwit[0].scriptWitness.stack = [b'\x01']
        tx_wit.rehash()

        block_wit = create_block(tip, create_coinbase(height), block_time, txlist=[tx_wit])
        block_wit.solve()
        peer.send_blocks_and_test([block_wit], node, success=False,
                                  reject_reason='unexpected-witness')
        self.log.info("Block with witness data correctly rejected")

        # ====================================================================
        # Test 2: Non-CTOR ordered block → rejected (tx-ordering)
        # ====================================================================
        self.log.info("Test 2: Non-CTOR ordered block rejected (tx-ordering)")
        tip, height, block_time = get_tip_info()

        # Create two independent transactions spending different outputs
        tx_a = create_tx_with_script(setup_block.vtx[0], 0, script_sig=b'', amount=3 * COIN)
        tx_b = create_tx_with_script(setup_block.vtx[0], 1, script_sig=b'', amount=3 * COIN)
        tx_a.calc_sha256()
        tx_b.calc_sha256()

        # Sort correctly then reverse
        txs_sorted = sorted([tx_a, tx_b], key=ctor_sort_key)
        txs_reversed = list(reversed(txs_sorted))

        if txs_reversed[0].sha256 != txs_sorted[0].sha256:
            block_bad_order = create_block(tip, create_coinbase(height), block_time, txlist=txs_reversed)
            block_bad_order.solve()
            peer.send_blocks_and_test([block_bad_order], node, success=False,
                                      reject_reason='tx-ordering')
            self.log.info("Out-of-order block correctly rejected")
        else:
            self.log.info("Skipping reverse-order test (txs have same hash)")

        # ====================================================================
        # Test 3: Block with duplicate transactions → rejected (tx-duplicate)
        # ====================================================================
        self.log.info("Test 3: Block with duplicate transactions rejected (tx-duplicate)")
        tip, height, block_time = get_tip_info()

        tx_dup = create_tx_with_script(setup_block.vtx[0], 0, script_sig=b'', amount=3 * COIN)
        tx_dup.calc_sha256()

        block_dup = create_block(tip, create_coinbase(height), block_time, txlist=[tx_dup, tx_dup])
        block_dup.solve()
        peer.send_blocks_and_test([block_dup], node, success=False,
                                  reject_reason='tx-duplicate')
        self.log.info("Block with duplicate transactions correctly rejected")

        # ====================================================================
        # Test 4: Witness commitment in coinbase → rejected (unexpected-witness-commitment)
        # ====================================================================
        self.log.info("Test 4: Witness commitment in coinbase rejected")
        tip, height, block_time = get_tip_info()

        cb_commit = create_coinbase(height)
        # Add witness commitment output: OP_RETURN + 0x24 + aa21a9ed + 32 zero bytes
        witness_commitment = bytes([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]) + b'\x00' * 32
        cb_commit.vout.append(CTxOut(0, CScript(witness_commitment)))
        cb_commit.rehash()

        block_commit = create_block(tip, cb_commit, block_time)
        block_commit.solve()
        peer.send_blocks_and_test([block_commit], node, success=False,
                                  reject_reason='unexpected-witness-commitment')
        self.log.info("Block with witness commitment correctly rejected")

        # ====================================================================
        # Test 5: Block with wrong difficulty bits → rejected (bad-diffbits)
        # ====================================================================
        self.log.info("Test 5: Block with wrong difficulty bits rejected (bad-diffbits)")
        tip, height, block_time = get_tip_info()

        block_bad_bits = create_block(tip, create_coinbase(height), block_time)
        # Set nBits to slightly different from regtest (0x207fffff → 0x207ffffe)
        # Still trivially easy to solve, but wrong for regtest consensus
        block_bad_bits.nBits = 0x207ffffe
        block_bad_bits.solve()

        # Use force_send=True because the header-level rejection means the node
        # will never send getdata (the normal flow waits for getdata and times out).
        # Use a fresh peer to avoid accumulated misbehavior from earlier tests.
        peer2 = node.add_p2p_connection(P2PDataStore())
        peer2.send_blocks_and_test([block_bad_bits], node, success=False,
                                   force_send=True, reject_reason='bad-diffbits')
        self.log.info("Block with wrong difficulty bits correctly rejected")

        # ====================================================================
        # Test 6: Valid block accepted (sanity check)
        # ====================================================================
        self.log.info("Test 6: Valid block accepted (sanity check)")
        tip, height, block_time = get_tip_info()

        block_valid = create_block(tip, create_coinbase(height), block_time)
        block_valid.solve()
        peer.send_blocks_and_test([block_valid], node, success=True)
        self.log.info("Valid block accepted")

        self.log.info("All BCH2 adversarial tests passed!")


if __name__ == '__main__':
    BCH2AdversarialTest().main()
