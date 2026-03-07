#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""PQ stress test: 10 FALCON512-signed transactions in a single block.

Each transaction creates a FALCON512-locked output, then all 10 are
spent in a second wave and mined in one block.
"""

from decimal import Decimal

from test_framework.key import ECKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


def make_keypair():
    eckey = ECKey()
    eckey.generate(compressed=True)
    wif = bytes_to_wif(eckey.get_bytes(), compressed=True)
    pubkey_hex = eckey.get_pubkey().get_bytes().hex()
    return wif, pubkey_hex


NUM_TXS = 10


class PQBlockTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-txindex"]]

    def skip_test_if_missing_module(self):
        pass

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info("Mining initial blocks for maturity...")
        self.generate(node, 110)
        self.generatetoaddress(node, 110, wallet.get_address())
        wallet.rescan_utxos()

        # Check PQ support
        try:
            node.generatepqkeypair("FALCON512")
        except Exception as e:
            if "liboqs" in str(e).lower():
                self.log.info("SKIP: liboqs not available")
                return
            raise

        self.log.info(f"=== Creating {NUM_TXS} FALCON512-locked outputs ===")

        # Step 1: Create NUM_TXS outputs locked with FALCON512
        pq_keys = []
        locked_utxos = []  # (txid, vout, amount, spk)

        for i in range(NUM_TXS):
            keypair = node.generatepqkeypair("FALCON512")
            pq_keys.append(keypair)

            utxo = wallet.get_utxo()
            input_amount = Decimal(utxo["value"])
            txout_info = node.gettxout(utxo["txid"], utxo["vout"])
            spent_spk = txout_info["scriptPubKey"]["hex"]

            output_amount = input_amount - Decimal("0.001")

            conditions = [{"blocks": [{"type": "SIG", "fields": [
                {"type": "SCHEME", "hex": "10"},  # FALCON512 = 0x10
                {"type": "PUBKEY", "hex": keypair["pubkey"]},
            ]}]}]

            result = node.createrungtx(
                [{"txid": utxo["txid"], "vout": utxo["vout"]}],
                [{"amount": output_amount, "conditions": conditions}]
            )

            # Sign with bootstrap key (MiniWallet UTXO is Schnorr)
            boot_wif, boot_pk = make_keypair()
            sign_result = node.signrungtx(
                result["hex"],
                [{"privkey": boot_wif, "input": 0}],
                [{"amount": input_amount, "scriptPubKey": spent_spk}]
            )
            assert_equal(sign_result["complete"], True)

            txid = node.sendrawtransaction(sign_result["hex"])
            self.log.info(f"  TX {i+1}/{NUM_TXS}: {txid[:16]}... locked with FALCON512 ({output_amount} BTC)")

            locked_utxos.append((txid, 0, output_amount, None))

        # Mine the creation transactions
        self.log.info("Mining creation block...")
        self.generate(node, 1)

        # Fetch scriptPubKeys from confirmed outputs
        for i in range(NUM_TXS):
            txid, vout, amount, _ = locked_utxos[i]
            tx_info = node.getrawtransaction(txid, True)
            assert tx_info["confirmations"] >= 1
            spk = tx_info["vout"][vout]["scriptPubKey"]["hex"]
            locked_utxos[i] = (txid, vout, amount, spk)

        self.log.info(f"=== Spending {NUM_TXS} FALCON512 outputs in one block ===")

        # Step 2: Spend all FALCON512 outputs — each with a PQ signature
        spend_txids = []
        for i in range(NUM_TXS):
            txid, vout, amount, spk = locked_utxos[i]
            keypair = pq_keys[i]

            spend_amount = amount - Decimal("0.001")

            # Destination: simple Schnorr-locked output
            dest_wif, dest_pk = make_keypair()
            dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": dest_pk}
            ]}]}]

            spend = node.createrungtx(
                [{"txid": txid, "vout": vout}],
                [{"amount": spend_amount, "conditions": dest_conditions}]
            )

            sign_result = node.signrungtx(
                spend["hex"],
                [{"input": 0, "blocks": [
                    {"type": "SIG", "scheme": "FALCON512", "pq_privkey": keypair["privkey"]}
                ]}],
                [{"amount": amount, "scriptPubKey": spk}]
            )
            assert_equal(sign_result["complete"], True)

            spend_txid = node.sendrawtransaction(sign_result["hex"])
            spend_txids.append(spend_txid)

            # Decode to show sig size
            decoded = node.decoderawtransaction(sign_result["hex"])
            witness_hex = decoded["vin"][0]["txinwitness"][0] if decoded["vin"][0].get("txinwitness") else "?"
            wit_bytes = len(witness_hex) // 2 if witness_hex != "?" else 0
            self.log.info(f"  TX {i+1}/{NUM_TXS}: {spend_txid[:16]}... FALCON512 sig, witness={wit_bytes}B")

        # Verify all 10 are in mempool
        mempool = node.getrawmempool()
        for stxid in spend_txids:
            assert stxid in mempool, f"TX {stxid} not in mempool"
        self.log.info(f"  All {NUM_TXS} PQ-signed transactions in mempool!")

        # Mine them all in one block
        self.log.info("Mining the FALCON512 block...")
        block_hashes = self.generate(node, 1)
        block = node.getblock(block_hashes[0], 2)

        pq_tx_count = 0
        total_witness_bytes = 0
        for tx in block["tx"]:
            for vin in tx.get("vin", []):
                if vin.get("txinwitness"):
                    wit_hex = vin["txinwitness"][0]
                    total_witness_bytes += len(wit_hex) // 2
            if tx["txid"] in spend_txids:
                pq_tx_count += 1

        self.log.info("")
        self.log.info("=" * 60)
        self.log.info(f"  BLOCK {block_hashes[0][:16]}...")
        self.log.info(f"  Height:              {block['height']}")
        self.log.info(f"  Total transactions:  {len(block['tx'])} ({pq_tx_count} FALCON512)")
        self.log.info(f"  Block size:          {block['size']} bytes")
        self.log.info(f"  Block weight:        {block['weight']} WU")
        self.log.info(f"  Total witness data:  {total_witness_bytes} bytes")
        self.log.info(f"  Avg witness/tx:      {total_witness_bytes // max(pq_tx_count, 1)} bytes")
        self.log.info("=" * 60)
        self.log.info("")

        # Confirm all spent
        for stxid in spend_txids:
            tx_info = node.getrawtransaction(stxid, True)
            assert tx_info["confirmations"] >= 1

        self.log.info(f"All {NUM_TXS} FALCON512 transactions confirmed in one block!")


if __name__ == '__main__':
    PQBlockTest(__file__).main()
