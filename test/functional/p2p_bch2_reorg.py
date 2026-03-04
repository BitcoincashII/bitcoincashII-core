#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BCH2 multi-node reorganization and finalization behavior.

Verifies:
1. Competing chains — longer chain wins (no finalization)
2. Reorg above finalization point succeeds
3. Reorg crossing finalization boundary is rejected
4. parkblock / unparkblock with competing chains
"""
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BCH2ReorgTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all()

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        addr0 = node0.get_deterministic_priv_key().address
        addr1 = node1.get_deterministic_priv_key().address

        self.log.info("Mining past fork height (200) + maturity (100) on both nodes...")
        self.generatetoaddress(node0, 300, addr0)
        self.sync_all()
        assert_equal(node0.getblockcount(), 300)
        assert_equal(node1.getblockcount(), 300)

        # ====================================================================
        # Test 1: Competing chains — longer chain wins (no finalization)
        # ====================================================================
        self.log.info("Test 1: Competing chains — longer chain wins")
        common_height = node0.getblockcount()

        # Disconnect nodes
        self.disconnect_nodes(0, 1)

        # Node0 mines 3 blocks, node1 mines 5 blocks (no sync while disconnected)
        self.generatetoaddress(node0, 3, addr0, sync_fun=self.no_op)
        self.generatetoaddress(node1, 5, addr1, sync_fun=self.no_op)

        assert_equal(node0.getblockcount(), common_height + 3)
        assert_equal(node1.getblockcount(), common_height + 5)

        # Reconnect — both should converge on node1's chain (more work)
        self.connect_nodes(0, 1)
        self.sync_all()

        assert_equal(node0.getblockcount(), common_height + 5)
        assert_equal(node1.getblockcount(), common_height + 5)
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        self.log.info("Both nodes converged on longer chain")

        # ====================================================================
        # Test 2: Reorg above finalization point succeeds
        # ====================================================================
        self.log.info("Test 2: Reorg above finalization point succeeds")

        # Finalize a block well below current tip
        fin_height = node0.getblockcount() - 5
        fin_hash = node0.getblockhash(fin_height)
        node0.finalizeblock(fin_hash)
        node1.finalizeblock(fin_hash)

        common_height2 = node0.getblockcount()

        # Disconnect nodes
        self.disconnect_nodes(0, 1)

        # Node0 mines 3, node1 mines 8 — fork point is ABOVE finalization
        self.generatetoaddress(node0, 3, addr0, sync_fun=self.no_op)
        self.generatetoaddress(node1, 8, addr1, sync_fun=self.no_op)

        assert_equal(node0.getblockcount(), common_height2 + 3)
        assert_equal(node1.getblockcount(), common_height2 + 8)

        # Reconnect — node0 should switch to node1's longer chain
        # (fork point is above finalization, so reorg is allowed)
        self.connect_nodes(0, 1)
        self.sync_all()

        assert_equal(node0.getblockcount(), common_height2 + 8)
        assert_equal(node0.getbestblockhash(), node1.getbestblockhash())
        self.log.info("Reorg above finalization succeeded")

        # ====================================================================
        # Test 3: Reorg crossing finalization boundary is rejected
        # ====================================================================
        self.log.info("Test 3: Reorg crossing finalization boundary is rejected")

        # Sync and get common state
        self.sync_all()
        common_height3 = node0.getblockcount()

        # Disconnect nodes
        self.disconnect_nodes(0, 1)

        # Node0 mines 5 blocks, then finalizes at tip-2
        self.generatetoaddress(node0, 5, addr0, sync_fun=self.no_op)
        fin_target = node0.getblockhash(node0.getblockcount() - 2)
        node0.finalizeblock(fin_target)
        node0_tip = node0.getbestblockhash()
        node0_height = node0.getblockcount()

        self.log.info(f"Node0 at height {node0_height}, finalized at {node0.getfinalizedblockhash()[:16]}...")

        # Node1 mines 20 blocks from the same common height
        # Fork point is at common_height3 which is BELOW node0's finalization
        self.generatetoaddress(node1, 20, addr1, sync_fun=self.no_op)
        node1_tip = node1.getbestblockhash()
        node1_height = node1.getblockcount()

        self.log.info(f"Node1 at height {node1_height} (longer chain)")

        # Reconnect — node0 should NOT reorg to node1's chain
        # because it would cross the finalization boundary
        self.connect_nodes(0, 1)

        # Give nodes time to exchange blocks
        time.sleep(2)

        # Node0 should stay on its own chain (finalization prevents deep reorg)
        assert_equal(node0.getbestblockhash(), node0_tip)
        assert_equal(node0.getblockcount(), node0_height)
        self.log.info("Node0 correctly rejected reorg crossing finalization boundary")

        # Node1 has more work and no finalization conflict — it may or may not reorg
        # The key assertion is that node0 didn't reorg
        assert node0.getbestblockhash() != node1.getbestblockhash(), \
            "Nodes should be on different chains (finalization prevented convergence)"
        self.log.info("Nodes remain on different chains as expected")

        # ====================================================================
        # Test 4: parkblock / unparkblock with competing chains
        # ====================================================================
        self.log.info("Test 4: parkblock / unparkblock")

        # Work with node1 in isolation
        self.disconnect_nodes(0, 1)

        # Mine 1 block on node1
        self.generatetoaddress(node1, 1, addr1, sync_fun=self.no_op)
        tip_hash = node1.getbestblockhash()
        tip_height = node1.getblockcount()

        # Park the tip
        node1.parkblock(tip_hash)

        # After parking, chain should roll back
        assert node1.getbestblockhash() != tip_hash, "Tip should change after parking"
        assert_equal(node1.getblockcount(), tip_height - 1)
        self.log.info("Parked tip, chain rolled back")

        # Unpark it
        node1.unparkblock(tip_hash)

        # Chain should restore
        assert_equal(node1.getbestblockhash(), tip_hash)
        assert_equal(node1.getblockcount(), tip_height)
        self.log.info("Unparked tip, chain restored")

        self.log.info("All BCH2 reorg tests passed!")


if __name__ == '__main__':
    BCH2ReorgTest().main()
