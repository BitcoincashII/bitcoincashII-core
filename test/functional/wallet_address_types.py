#!/usr/bin/env python3
# Copyright (c) 2017-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that the wallet can send and receive using all combinations of address types.

BCH2 note: This test is simplified because BCH2 has no SegWit. All address
types collapse to P2PKH (legacy). The original test tested legacy, p2sh-segwit,
and bech32 across 5 nodes, but since BCH2 only supports legacy addresses,
we use 2 nodes-under-test (both legacy) plus a mining node.

There are 3 nodes:
    - node0 uses legacy addresses
    - node1 uses legacy addresses (configured as p2sh-segwit, but BCH2 falls back to legacy)
    - node2 exists to generate new blocks.

## Multisig address test

Test that adding a multisig address with:
    - an uncompressed pubkey always gives a legacy address
    - only compressed pubkeys gives a legacy address (BCH2: always legacy)

## Sending to address types test

A series of tests, iterating over node0-node1. In each iteration of the test, one node sends:
    - to itself and to the other node
    - verifies balances update correctly

As every node sends coins after receiving, this also
verifies that spending coins sent to all these address types works.
"""

from decimal import Decimal
import itertools

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.descriptors import (
    descsum_create,
    descsum_check,
)
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

class AddressTypeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        # BCH2: Only legacy addresses exist. We keep 2 test nodes + 1 mining node.
        self.num_nodes = 3
        self.extra_args = [
            ["-addresstype=legacy"],
            ["-addresstype=legacy"],
            [],
        ]
        # whitelist all peers to speed up tx relay / mempool sync
        for args in self.extra_args:
            args.append("-whitelist=noban@127.0.0.1")
        self.supports_cli = False

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()

        # Fully mesh-connect nodes for faster mempool sync
        for i, j in itertools.product(range(self.num_nodes), repeat=2):
            if i > j:
                self.connect_nodes(i, j)
        self.sync_all()

    def get_balances(self, key='trusted'):
        """Return a list of balances."""
        return [self.nodes[i].getbalances()['mine'][key] for i in range(2)]

    def test_address(self, node, address, multisig, typ):
        """Run sanity checks on an address."""
        info = self.nodes[node].getaddressinfo(address)
        assert self.nodes[node].validateaddress(address)['isvalid']
        assert_equal(info.get('solvable'), True)

        # BCH2: All addresses are legacy (P2PKH or P2SH-multisig)
        if not multisig and typ == 'legacy':
            # P2PKH
            assert not info['isscript']
            assert not info['iswitness']
            assert 'pubkey' in info
        elif typ == 'legacy':
            # P2SH-multisig
            assert info['isscript']
            assert_equal(info['script'], 'multisig')
            assert not info['iswitness']
            assert 'pubkeys' in info
        else:
            # Unknown type - should not happen in BCH2
            assert False, "BCH2 only supports legacy addresses, got typ={}".format(typ)

    def test_desc(self, node, address, multisig, typ, utxo):
        """Run sanity checks on a descriptor reported by getaddressinfo."""
        info = self.nodes[node].getaddressinfo(address)
        assert 'desc' in info
        assert_equal(info['desc'], utxo['desc'])
        assert self.nodes[node].validateaddress(address)['isvalid']

        # Use a ridiculously roundabout way to find the key origin info through
        # the PSBT logic. However, this does test consistency between the PSBT reported
        # fingerprints/paths and the descriptor logic.
        psbt = self.nodes[node].createpsbt([{'txid':utxo['txid'], 'vout':utxo['vout']}],[{address:0.00010000}])
        psbt = self.nodes[node].walletprocesspsbt(psbt, False, "ALL", True)
        decode = self.nodes[node].decodepsbt(psbt['psbt'])
        key_descs = {}
        for deriv in decode['inputs'][0]['bip32_derivs']:
            assert_equal(len(deriv['master_fingerprint']), 8)
            assert_equal(deriv['path'][0], 'm')
            key_descs[deriv['pubkey']] = '[' + deriv['master_fingerprint'] + deriv['path'][1:].replace("'","h") + ']' + deriv['pubkey']

        # Verify the descriptor checksum against the Python implementation
        assert descsum_check(info['desc'])
        # Verify that stripping the checksum and recreating it using Python roundtrips
        assert info['desc'] == descsum_create(info['desc'][:-9])
        # Verify that stripping the checksum and feeding it to getdescriptorinfo roundtrips
        assert info['desc'] == self.nodes[0].getdescriptorinfo(info['desc'][:-9])['descriptor']
        assert_equal(info['desc'][-8:], self.nodes[0].getdescriptorinfo(info['desc'][:-9])['checksum'])
        # Verify that keeping the checksum and feeding it to getdescriptorinfo roundtrips
        assert info['desc'] == self.nodes[0].getdescriptorinfo(info['desc'])['descriptor']
        assert_equal(info['desc'][-8:], self.nodes[0].getdescriptorinfo(info['desc'])['checksum'])

        # BCH2: Only legacy descriptors
        if not multisig and typ == 'legacy':
            # P2PKH
            assert_equal(info['desc'], descsum_create("pkh(%s)" % key_descs[info['pubkey']]))
        elif typ == 'legacy':
            # P2SH-multisig
            assert_equal(info['desc'], descsum_create("sh(multi(2,%s,%s))" % (key_descs[info['pubkeys'][0]], key_descs[info['pubkeys'][1]])))
        else:
            # Unknown type
            assert False, "BCH2 only supports legacy descriptors"

    def test_change_output_type(self, node_sender, destinations, expected_type):
        txid = self.nodes[node_sender].sendmany(dummy="", amounts=dict.fromkeys(destinations, 0.001))
        tx = self.nodes[node_sender].gettransaction(txid=txid, verbose=True)['decoded']

        # Make sure the transaction has change:
        assert_equal(len(tx["vout"]), len(destinations) + 1)

        # Make sure the destinations are included, and remove them:
        output_addresses = [vout['scriptPubKey']['address'] for vout in tx["vout"]]
        change_addresses = [d for d in output_addresses if d not in destinations]
        assert_equal(len(change_addresses), 1)

        self.log.debug("Check if change address " + change_addresses[0] + " is " + expected_type)
        self.test_address(node_sender, change_addresses[0], multisig=False, typ=expected_type)

    def run_test(self):
        # Mine 101 blocks on the mining node to bring nodes out of IBD and make sure that
        # no coinbases are maturing for the nodes-under-test during the test
        self.generate(self.nodes[2], COINBASE_MATURITY + 1)

        uncompressed_1 = "0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858ee"
        uncompressed_2 = "047211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073dee6c89064984f03385237d92167c13e236446b417ab79a0fcae412ae3316b77"
        compressed_1 = "0296b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52"
        compressed_2 = "037211a824f55b505228e4c3d5194c1fcfaa15a456abdf37f9b9d97a4040afc073"

        if not self.options.descriptors:
            # Tests for addmultisigaddress's address type behavior is only for legacy wallets.
            # Descriptor wallets do not have addmultsigaddress so these tests are not needed for those.
            # addmultisigaddress with at least 1 uncompressed key should return a legacy address.
            for node in range(2):
                self.test_address(node, self.nodes[node].addmultisigaddress(2, [uncompressed_1, uncompressed_2])['address'], True, 'legacy')
                self.test_address(node, self.nodes[node].addmultisigaddress(2, [compressed_1, uncompressed_2])['address'], True, 'legacy')
                self.test_address(node, self.nodes[node].addmultisigaddress(2, [uncompressed_1, compressed_2])['address'], True, 'legacy')
            # BCH2: addmultisigaddress with all compressed keys always returns legacy
            self.test_address(0, self.nodes[0].addmultisigaddress(2, [compressed_1, compressed_2])['address'], True, 'legacy')
            self.test_address(1, self.nodes[1].addmultisigaddress(2, [compressed_1, compressed_2])['address'], True, 'legacy')

        do_multisigs = [False]
        if not self.options.descriptors:
            do_multisigs.append(True)

        for explicit_type, multisig, from_node in itertools.product([False, True], do_multisigs, range(2)):
            address_type = None
            if explicit_type and not multisig:
                # BCH2: Explicit type is always legacy
                address_type = 'legacy'
            self.log.info("Sending from node {} ({}) with{} multisig using {}".format(from_node, self.extra_args[from_node], "" if multisig else "out", "default" if address_type is None else address_type))
            old_balances = self.get_balances()
            self.log.debug("Old balances are {}".format(old_balances))
            to_send = (old_balances[from_node] / (COINBASE_MATURITY + 1)).quantize(Decimal("0.00000001"))
            sends = {}
            addresses = {}

            self.log.debug("Prepare sends")
            for n, to_node in enumerate(range(from_node, from_node + 2)):
                to_node %= 2
                change = False
                if not multisig:
                    if from_node == to_node:
                        # When sending non-multisig to self, use getrawchangeaddress
                        address = self.nodes[to_node].getrawchangeaddress(address_type=address_type)
                        change = True
                    else:
                        address = self.nodes[to_node].getnewaddress(address_type=address_type)
                else:
                    addr1 = self.nodes[to_node].getnewaddress()
                    addr2 = self.nodes[to_node].getnewaddress()
                    address = self.nodes[to_node].addmultisigaddress(2, [addr1, addr2])['address']

                # BCH2: All addresses are legacy
                typ = 'legacy'
                self.test_address(to_node, address, multisig, typ)

                # Output entry
                sends[address] = to_send * 10 * (1 + n)
                addresses[to_node] = (address, typ)

            self.log.debug("Sending: {}".format(sends))
            self.nodes[from_node].sendmany("", sends)
            self.sync_mempools()

            unconf_balances = self.get_balances('untrusted_pending')
            self.log.debug("Check unconfirmed balances: {}".format(unconf_balances))
            assert_equal(unconf_balances[from_node], 0)
            for n, to_node in enumerate(range(from_node + 1, from_node + 2)):
                to_node %= 2
                assert_equal(unconf_balances[to_node], to_send * 10 * (2 + n))

            # mining node collects fee and block subsidy to keep accounting simple
            self.generate(self.nodes[2], 1)

            # Verify that the receiving wallet contains a UTXO with the expected address, and expected descriptor
            for n, to_node in enumerate(range(from_node, from_node + 2)):
                to_node %= 2
                found = False
                for utxo in self.nodes[to_node].listunspent():
                    if utxo['address'] == addresses[to_node][0]:
                        found = True
                        self.test_desc(to_node, addresses[to_node][0], multisig, addresses[to_node][1], utxo)
                        break
                assert found

            new_balances = self.get_balances()
            self.log.debug("Check new balances: {}".format(new_balances))
            # We don't know what fee was set, so we can only check bounds on the balance of the sending node.
            # BCH2: With 2 nodes, from_node sends 10*to_send to self + 20*to_send to other.
            # Balance should be approximately old_balance - 20*to_send - fee.
            total_sent_to_others = to_send * 20
            assert_greater_than(new_balances[from_node], old_balances[from_node] - total_sent_to_others - to_send)
            assert_greater_than(old_balances[from_node] - total_sent_to_others + to_send, new_balances[from_node])
            for n, to_node in enumerate(range(from_node + 1, from_node + 2)):
                to_node %= 2
                assert_equal(new_balances[to_node], old_balances[to_node] + to_send * 10 * (2 + n))

        # BCH2: All addresses are legacy, test change output type
        to_address_legacy_1 = self.nodes[0].getnewaddress()
        to_address_legacy_2 = self.nodes[1].getnewaddress()

        # Fund node 0 a bit more if needed for change test
        self.log.info("Nodes with addresstype=legacy always use a legacy change output:")
        self.test_change_output_type(0, [to_address_legacy_2], 'legacy')

        self.log.info("Both nodes use legacy change (BCH2: no SegWit)")
        self.test_change_output_type(1, [to_address_legacy_1], 'legacy')

        self.log.info('getrawchangeaddress defaults to legacy in BCH2')
        self.test_address(0, self.nodes[0].getrawchangeaddress(), multisig=False, typ='legacy')
        self.test_address(1, self.nodes[1].getrawchangeaddress(), multisig=False, typ='legacy')

        self.log.info('test invalid address type arguments')
        assert_raises_rpc_error(-5, "Unknown address type ''", self.nodes[0].addmultisigaddress, 2, [compressed_1, compressed_2], None, '')
        assert_raises_rpc_error(-5, "Unknown address type ''", self.nodes[0].getnewaddress, None, '')
        assert_raises_rpc_error(-5, "Unknown address type ''", self.nodes[0].getrawchangeaddress, '')
        assert_raises_rpc_error(-5, "Unknown address type 'bech23'", self.nodes[0].getrawchangeaddress, 'bech23')

        # BCH2: bech32m tests skipped - BCH2 has no SegWit/Taproot support
        self.log.info("BCH2: Skipping bech32m tests (no SegWit/Taproot)")

if __name__ == '__main__':
    AddressTypeTest().main()
