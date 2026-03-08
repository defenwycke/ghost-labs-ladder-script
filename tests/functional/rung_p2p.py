#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""P2P relay test for v3 RUNG_TX transactions.

Tests that v3 transactions are properly relayed between two connected nodes
and that both nodes confirm the transaction after mining.
"""

from decimal import Decimal

from test_framework.key import ECKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


def make_keypair():
    """Generate an ECKey and return (wif, pubkey_hex)."""
    eckey = ECKey()
    eckey.generate(compressed=True)
    wif = bytes_to_wif(eckey.get_bytes(), compressed=True)
    pubkey_hex = eckey.get_pubkey().get_bytes().hex()
    return wif, pubkey_hex


class LadderScriptP2PTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [["-txindex"], ["-txindex"]]

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]
        wallet = MiniWallet(node0)

        self.log.info("Mining maturity blocks on node0...")
        self.generate(node0, 101)
        self.generatetoaddress(node0, 101, wallet.get_address())
        wallet.rescan_utxos()
        self.sync_blocks()

        self.log.info("Creating v3 RUNG_TX on node0...")
        privkey_wif, pubkey_hex = make_keypair()

        utxo = wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        txout_info = node0.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        output_amount = Decimal(input_amount) - Decimal("0.001")

        # Create v3 tx
        result = node0.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG",
                "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]
            }]}]}]
        )

        # Sign (bootstrap spend)
        sign_result = node0.signrungtx(
            result["hex"],
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_result["complete"]

        # Broadcast on node0
        txid = node0.sendrawtransaction(sign_result["hex"])
        self.log.info(f"  Broadcast v3 tx on node0: {txid}")

        # Verify relay to node1's mempool
        self.log.info("Syncing mempools...")
        self.sync_mempools()
        mempool1 = node1.getrawmempool()
        assert txid in mempool1, f"v3 tx {txid} not relayed to node1 mempool"
        self.log.info("  v3 tx found in node1's mempool — relay confirmed!")

        # Mine on node0, sync blocks
        self.generate(node0, 1)
        self.sync_blocks()

        # Verify confirmed on both nodes
        tx_info0 = node0.getrawtransaction(txid, True)
        tx_info1 = node1.getrawtransaction(txid, True)
        assert tx_info0["confirmations"] >= 1, "tx not confirmed on node0"
        assert tx_info1["confirmations"] >= 1, "tx not confirmed on node1"
        assert_equal(tx_info0["txid"], tx_info1["txid"])
        self.log.info("  v3 tx confirmed on both nodes!")

        # Verify it's a v3 transaction on both nodes
        assert_equal(tx_info0["version"], 3)
        assert_equal(tx_info1["version"], 3)
        self.log.info("  P2P relay test PASSED!")


if __name__ == '__main__':
    LadderScriptP2PTest(__file__).main()
