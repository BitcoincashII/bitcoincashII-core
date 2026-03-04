#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BCH2 block consensus rules via P2P block submission.

Verifies:
1. CTOR (Canonical Transaction Ordering) — CTOR-ordered block accepted post-fork
2. Out-of-order transactions rejected (CTOR enforcement)
3. Normal post-fork block acceptance
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


class BCH2ConsensusTest(BitcoinTestFramework):
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

        self.log.info("Creating spendable coinbase with multiple outputs...")
        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1

        # Create block with coinbase that has TWO anyone-can-spend outputs
        # This allows creating two INDEPENDENT transactions later
        # At height 301 (regtest halving=150), subsidy is 12.5 BCH2
        coinbase = create_coinbase(height)
        coinbase.vout[0].nValue = 6 * COIN
        coinbase.vout.append(CTxOut(6 * COIN, CScript([OP_TRUE])))
        coinbase.rehash()

        block1 = create_block(tip, coinbase, block_time)
        block1.solve()
        peer.send_blocks_and_test([block1], node, success=True)

        # Mature the coinbase
        self.generatetoaddress(node, 100, node.get_deterministic_priv_key().address)

        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1

        self.log.info("Test 1: Block with CTOR-ordered transactions accepted")
        # Create two INDEPENDENT transactions spending different coinbase outputs
        tx_a = create_tx_with_script(block1.vtx[0], 0, script_sig=b'', amount=5 * COIN)
        tx_b = create_tx_with_script(block1.vtx[0], 1, script_sig=b'', amount=5 * COIN)
        tx_a.calc_sha256()
        tx_b.calc_sha256()

        # Sort in CTOR order (by txid)
        txs_sorted = sorted([tx_a, tx_b], key=ctor_sort_key)
        self.log.info(f"tx_a hash: {tx_a.hash}, tx_b hash: {tx_b.hash}")

        block_ctor = create_block(tip, create_coinbase(height), block_time, txlist=txs_sorted)
        block_ctor.solve()
        peer.send_blocks_and_test([block_ctor], node, success=True)
        self.log.info("CTOR-ordered block accepted")

        height += 1
        tip = int(block_ctor.hash, 16)
        block_time += 1

        self.log.info("Test 2: Block with out-of-order transactions rejected (CTOR enforcement)")
        # Create a new spendable coinbase with two outputs
        # Subsidy at this height (~402) is still 12.5 BCH2
        coinbase2 = create_coinbase(height)
        coinbase2.vout[0].nValue = 6 * COIN
        coinbase2.vout.append(CTxOut(6 * COIN, CScript([OP_TRUE])))
        coinbase2.rehash()

        block2 = create_block(tip, coinbase2, block_time)
        block2.solve()
        peer.send_blocks_and_test([block2], node, success=True)

        # Mature it
        self.generatetoaddress(node, 100, node.get_deterministic_priv_key().address)

        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1

        # Create two independent transactions
        tx_c = create_tx_with_script(block2.vtx[0], 0, script_sig=b'', amount=5 * COIN)
        tx_d = create_tx_with_script(block2.vtx[0], 1, script_sig=b'', amount=5 * COIN)
        tx_c.calc_sha256()
        tx_d.calc_sha256()

        # Sort correctly first, then reverse
        txs_sorted2 = sorted([tx_c, tx_d], key=ctor_sort_key)
        txs_reversed = list(reversed(txs_sorted2))

        # Only test if the reversed order is actually different from sorted
        if txs_reversed[0].sha256 != txs_sorted2[0].sha256:
            block_bad_order = create_block(tip, create_coinbase(height), block_time, txlist=txs_reversed)
            block_bad_order.solve()
            peer.send_blocks_and_test([block_bad_order], node, success=False,
                                      reject_reason='tx-ordering')
            self.log.info("Out-of-order block correctly rejected")
        else:
            self.log.info("Skipping reverse-order test (txs happen to have same hash)")

        # Now send the correctly ordered version
        block_good_order = create_block(tip, create_coinbase(height), block_time, txlist=txs_sorted2)
        block_good_order.solve()
        peer.send_blocks_and_test([block_good_order], node, success=True)
        self.log.info("Correctly-ordered block accepted")

        self.log.info("Test 3: Normal post-fork block acceptance")
        height += 1
        tip = int(block_good_order.hash, 16)
        block_time += 1

        block_normal = create_block(tip, create_coinbase(height), block_time)
        block_normal.solve()
        peer.send_blocks_and_test([block_normal], node, success=True)
        self.log.info("Normal post-fork block accepted")

        # ====================================================================
        # Test 4: Block with duplicate transactions → "tx-duplicate"
        # ====================================================================
        self.log.info("Test 4: Block with duplicate transactions rejected")
        height += 1
        tip = int(block_normal.hash, 16)
        block_time += 1

        # Create a single transaction from block_normal's coinbase
        # block_normal's coinbase is an anyone-can-spend with default output
        tx_dup = create_tx_with_script(block_normal.vtx[0], 0, script_sig=b'', amount=49 * COIN // 4)
        tx_dup.calc_sha256()

        # Create block with the same tx added twice
        block_dup = create_block(tip, create_coinbase(height), block_time, txlist=[tx_dup, tx_dup])
        block_dup.solve()
        peer.send_blocks_and_test([block_dup], node, success=False,
                                  reject_reason='tx-duplicate')
        self.log.info("Block with duplicate transactions correctly rejected")

        # ====================================================================
        # Test 5: Block with witness data → "unexpected-witness"
        # ====================================================================
        self.log.info("Test 5: Block with witness data rejected post-fork")

        # Create a transaction and attach witness data
        tx_wit = create_tx_with_script(block_normal.vtx[0], 0, script_sig=b'', amount=49 * COIN // 4)
        tx_wit.wit = CTxWitness()
        tx_wit.wit.vtxinwit = [CTxInWitness()]
        tx_wit.wit.vtxinwit[0].scriptWitness.stack = [b'\x01']
        tx_wit.rehash()

        block_wit = create_block(tip, create_coinbase(height), block_time + 1, txlist=[tx_wit])
        block_wit.solve()
        peer.send_blocks_and_test([block_wit], node, success=False,
                                  reject_reason='unexpected-witness')
        self.log.info("Block with witness data correctly rejected")

        # ====================================================================
        # Test 6: Block with witness commitment in coinbase → "unexpected-witness-commitment"
        # ====================================================================
        self.log.info("Test 6: Block with witness commitment in coinbase rejected")

        # Create a coinbase that has a witness commitment output
        # Witness commitment: OP_RETURN 0x24 0xaa 0x21 0xa9 0xed + 32 bytes
        cb_commit = create_coinbase(height)
        # Add witness commitment output to coinbase
        witness_commitment = bytes([0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]) + b'\x00' * 32
        cb_commit.vout.append(CTxOut(0, CScript(witness_commitment)))
        cb_commit.rehash()

        block_commit = create_block(tip, cb_commit, block_time + 2)
        block_commit.solve()
        peer.send_blocks_and_test([block_commit], node, success=False,
                                  reject_reason='unexpected-witness-commitment')
        self.log.info("Block with witness commitment correctly rejected")

        self.log.info("All BCH2 consensus tests passed!")


if __name__ == '__main__':
    BCH2ConsensusTest().main()
