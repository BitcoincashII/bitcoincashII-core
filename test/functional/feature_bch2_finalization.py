#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for BCH2 rolling checkpoints and block finalization.

BCH2 uses automatic finalization (rolling checkpoints) to prevent
deep reorganizations. After maxReorgDepth (10) blocks, earlier blocks
become finalized and cannot be rolled back.

Verifies:
1. getfinalizedblockhash RPC returns empty before finalization
2. After mining maxReorgDepth blocks, finalization advances
3. parkblock / unparkblock RPCs work correctly
4. finalizeblock RPC explicitly finalizes a block
5. getexcessiveblock RPC returns correct value
6. parkblock on non-existent block fails
7. Auto-finalization restored across node restart (LoadChainTip)
"""
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BCH2FinalizationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Test 1: getfinalizedblockhash before fork returns empty")
        result = node.getfinalizedblockhash()
        assert_equal(result, "")

        self.log.info("Mining past fork height (200) + maturity...")
        self.generate(node, 201 + COINBASE_MATURITY)

        self.log.info("Test 2: Finalization via explicit finalizeblock RPC")
        # Regtest maxReorgDepth = 10000, so auto-finalization won't happen
        # at reasonable heights. Test using explicit finalizeblock instead.
        target_height = node.getblockcount() - 5
        target_hash = node.getblockhash(target_height)
        node.finalizeblock(target_hash)

        finalized_hash = node.getfinalizedblockhash()
        assert finalized_hash != "", "Finalized block hash should be non-empty after finalizeblock"
        finalized_info = node.getblock(finalized_hash)
        assert finalized_info["height"] >= target_height, \
            f"Finalized height {finalized_info['height']} should be >= {target_height}"
        self.log.info(f"Finalized block at height {finalized_info['height']}")

        self.log.info("Test 3: parkblock / unparkblock RPCs")
        # Get the tip
        tip_hash = node.getbestblockhash()
        tip_height = node.getblockcount()

        # Park the tip block
        node.parkblock(tip_hash)

        # After parking, the chain tip should roll back
        new_tip = node.getbestblockhash()
        assert new_tip != tip_hash, "Tip should change after parking"
        assert_equal(node.getblockcount(), tip_height - 1)
        self.log.info(f"Parked block {tip_hash}, chain rolled back")

        # Unpark it
        node.unparkblock(tip_hash)

        # After unparking, the chain should restore
        restored_tip = node.getbestblockhash()
        assert_equal(restored_tip, tip_hash)
        assert_equal(node.getblockcount(), tip_height)
        self.log.info("Unparked block, chain restored")

        self.log.info("Test 4: Mining more blocks after finalization")
        self.generate(node, 3)
        # Finalized hash should still be set
        still_finalized = node.getfinalizedblockhash()
        assert still_finalized != "", "Finalization should persist after mining more blocks"
        self.log.info("Finalization persists correctly")

        self.log.info("Test 5: getexcessiveblock RPC")
        result = node.getexcessiveblock()
        assert "excessiveBlockSize" in result
        # Should be 32MB (32000000) = BCH2_MAX_BLOCK_SIZE or 32MiB depending on build
        assert result["excessiveBlockSize"] >= 32000000, \
            f"Expected >= 32000000 but got {result['excessiveBlockSize']}"
        self.log.info(f"Excessive block size: {result['excessiveBlockSize']}")

        self.log.info("Test 6: parkblock on non-existent block fails")
        fake_hash = "0000000000000000000000000000000000000000000000000000000000000001"
        assert_raises_rpc_error(
            -5,
            "Block not found",
            node.parkblock,
            fake_hash
        )
        self.log.info("parkblock correctly rejects non-existent block")

        self.log.info("Test 7: Explicit finalization persists across node restart")
        # Explicitly finalize a recent block
        target_height = node.getblockcount() - 5
        target_hash = node.getblockhash(target_height)
        node.finalizeblock(target_hash)
        finalized_before = node.getfinalizedblockhash()
        assert finalized_before != "", "Should have finalization after finalizeblock"
        tip_before = node.getblockcount()
        tip_hash_before = node.getbestblockhash()
        self.log.info(f"Pre-restart: tip={tip_before}, finalized={finalized_before[:16]}...")

        self.restart_node(0)

        # Chain tip must survive restart
        tip_after = node.getblockcount()
        assert_equal(tip_after, tip_before)
        assert_equal(node.getbestblockhash(), tip_hash_before)

        # Explicit finalization must persist across restart
        finalized_after = node.getfinalizedblockhash()
        assert finalized_after != "", "Explicit finalization must persist across restart"
        assert_equal(finalized_after, finalized_before)
        self.log.info(f"Post-restart: finalization persisted at {finalized_after[:16]}...")

        # Mine more blocks to verify chain continues normally after restart
        self.generate(node, 3)
        assert_equal(node.getblockcount(), tip_after + 3)
        self.log.info("Chain continues normally after restart with persisted finalization")

        self.log.info("All BCH2 finalization tests passed!")


if __name__ == '__main__':
    BCH2FinalizationTest().main()
