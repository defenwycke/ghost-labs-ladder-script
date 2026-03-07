#!/usr/bin/env python3
"""Ladder Script signet test suite.

Runs all rung_basic.py tests against a live signet node via JSON-RPC.
Usage: python3 test/functional/rung_signet.py [--rpcport=38332] [--rpcuser=ghost] [--rpcpassword=ghostrpc]
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import traceback
import urllib.request
from decimal import Decimal

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from test_framework.key import ECKey
from test_framework.script import hash160


# ── Configuration ──────────────────────────────────────────────────────────

RPCPORT = 38332
RPCUSER = "ghost"
RPCPASSWORD = "ghostrpc"
WALLET = "signet-miner"
MINER_CLI = os.path.expanduser("~/.ghost-signet/ghost-cli.sh")
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.path.join(os.getcwd(), "test", "functional")
GRIND_CMD = os.path.join(_SCRIPT_DIR, "..", "..", "build", "bin", "ghost-util grind")
MINER_ADDRESS = "tb1qpykdzr40fhvsucjevspenspx6lakklzrw7q2hz"
MINER_SCRIPT = os.path.join(_SCRIPT_DIR, "..", "..", "contrib", "signet", "miner")

# Parse args
for arg in sys.argv[1:]:
    if arg.startswith("--rpcport="):
        RPCPORT = int(arg.split("=")[1])
    elif arg.startswith("--rpcuser="):
        RPCUSER = arg.split("=")[1]
    elif arg.startswith("--rpcpassword="):
        RPCPASSWORD = arg.split("=")[1]


# ── RPC Client ─────────────────────────────────────────────────────────────

AUTH = "Basic " + base64.b64encode(f"{RPCUSER}:{RPCPASSWORD}".encode()).decode()

def rpc(method, params=[], wallet=None):
    url = f"http://127.0.0.1:{RPCPORT}/"
    if wallet:
        url += f"wallet/{wallet}"
    data = json.dumps({"jsonrpc": "1.0", "id": "signet-test", "method": method, "params": params}).encode()
    req = urllib.request.Request(url, data=data,
        headers={"Content-Type": "application/json", "Authorization": AUTH})
    try:
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        if result.get("error"):
            raise RPCError(result["error"]["code"], result["error"]["message"])
        return result["result"]
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        raise RPCError(body["error"]["code"], body["error"]["message"])


class RPCError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"RPC error {code}: {message}")


def assert_raises_rpc_error(code, msg_part, fn, *args):
    try:
        fn(*args)
        raise AssertionError(f"Expected RPC error {code} but call succeeded")
    except RPCError as e:
        if code is not None and e.code != code:
            raise AssertionError(f"Expected error code {code}, got {e.code}: {e.message}")
        if msg_part and msg_part not in e.message:
            raise AssertionError(f"Expected '{msg_part}' in error, got: {e.message}")


# ── Helpers ────────────────────────────────────────────────────────────────

def numeric_hex(val):
    return val.to_bytes(4, "little").hex()

def locktime_hex(val):
    return val.to_bytes(4, "little").hex()

def make_keypair():
    eckey = ECKey()
    eckey.generate(compressed=True)
    privkey_bytes = eckey.get_bytes()
    pubkey_hex = eckey.get_pubkey().get_bytes().hex()
    wif = _to_wif(privkey_bytes)
    return wif, pubkey_hex

def _to_wif(privkey_bytes):
    raw = bytes.fromhex("ef") + privkey_bytes + b"\x01"
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    payload = raw + checksum
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(payload, "big")
    result = ""
    while n > 0:
        n, r = divmod(n, 58)
        result = alphabet[r] + result
    for byte in payload:
        if byte == 0:
            result = "1" + result
        else:
            break
    return result


# ── Node wrapper ───────────────────────────────────────────────────────────

class Node:
    """Wraps RPC calls to look like the test framework's node object."""

    def createrung(self, rungs):
        return rpc("createrung", [rungs])

    def decoderung(self, hex_str):
        return rpc("decoderung", [hex_str])

    def validateladder(self, hex_str):
        return rpc("validateladder", [hex_str])

    def createrungtx(self, inputs, outputs, locktime=None):
        params = [inputs, outputs]
        if locktime is not None:
            params.append(locktime)
        return rpc("createrungtx", params)

    def signrungtx(self, hex_str, signers, spent_outputs):
        return rpc("signrungtx", [hex_str, signers, spent_outputs])

    def sendrawtransaction(self, hex_str):
        return rpc("sendrawtransaction", [hex_str])

    def getrawtransaction(self, txid, verbose=False):
        return rpc("getrawtransaction", [txid, verbose])

    def gettxout(self, txid, vout):
        return rpc("gettxout", [txid, vout])

    def getblockcount(self):
        return rpc("getblockcount")

    def getbestblockhash(self):
        return rpc("getbestblockhash")

    def getblock(self, blockhash, verbosity=1):
        return rpc("getblock", [blockhash, verbosity])

    def getblockchaininfo(self):
        return rpc("getblockchaininfo")

    def listunspent(self, minconf=1, maxconf=9999):
        return rpc("listunspent", [minconf, maxconf], wallet=WALLET)

    def generatepqkeypair(self, scheme):
        return rpc("generatepqkeypair", [scheme])

    def pqpubkeycommit(self, pubkey_hex):
        return rpc("pqpubkeycommit", [pubkey_hex])

    def computectvhash(self, hex_str, input_index):
        return rpc("computectvhash", [hex_str, input_index])

    def extractadaptorsecret(self, pre_sig, adapted_sig):
        return rpc("extractadaptorsecret", [pre_sig, adapted_sig])


node = Node()


# ── Mining ─────────────────────────────────────────────────────────────────

def mine_blocks(n=1):
    """Mine n blocks on the custom signet using set-block-time for instant mining."""
    for i in range(n):
        # Get current tip time
        bh = rpc("getbestblockhash")
        tip = rpc("getblock", [bh])
        block_time = tip["time"] + 10  # 10 seconds after tip
        subprocess.run([
            sys.executable, MINER_SCRIPT,
            "--cli", MINER_CLI,
            "generate",
            "--address", MINER_ADDRESS,
            "--grind-cmd", GRIND_CMD,
            "--min-nbits",
            "--set-block-time", str(block_time),
        ], capture_output=True, timeout=30)


def get_utxo():
    """Get a spendable UTXO from the wallet."""
    utxos = node.listunspent()
    good = [u for u in utxos if float(u["amount"]) >= 49]
    if not good:
        good = [u for u in utxos if float(u["amount"]) >= 1]
    if not good:
        raise RuntimeError("No spendable UTXOs available")
    return good[0]


def bootstrap_v4_output(conditions, output_amount=None):
    """Create a confirmed v4 rung output. Returns (txid, vout, amount, spk)."""
    utxo = get_utxo()
    input_amount = float(utxo["amount"])
    txid = utxo["txid"]
    vout_n = utxo["vout"]
    spk = utxo["scriptPubKey"]

    if output_amount is None:
        output_amount = round(input_amount - 0.001, 8)

    boot_wif, boot_pub = make_keypair()
    outputs = [{"amount": output_amount, "conditions": conditions}]

    change = round(input_amount - output_amount - 0.001, 8)
    if change > 0.01:
        change_wif, change_pub = make_keypair()
        change_conds = [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": change_pub}]}]}]
        outputs.append({"amount": change, "conditions": change_conds})

    result = node.createrungtx([{"txid": txid, "vout": vout_n}], outputs)
    sign_result = node.signrungtx(
        result["hex"],
        [{"privkey": boot_wif, "input": 0}],
        [{"amount": input_amount, "scriptPubKey": spk}]
    )
    assert sign_result["complete"], "Bootstrap signing failed"

    sent_txid = node.sendrawtransaction(sign_result["hex"])
    mine_blocks(1)

    tx_info = node.getrawtransaction(sent_txid, True)
    assert tx_info["confirmations"] >= 1, f"Bootstrap tx not confirmed: {sent_txid}"
    out_spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
    return sent_txid, 0, output_amount, out_spk


# ── Test runner ────────────────────────────────────────────────────────────

PASSED = []
FAILED = []
SKIPPED = []
ladder_hex = None  # shared state for createrung/decoderung


def run_test(name, fn):
    global ladder_hex
    try:
        fn()
        PASSED.append(name)
        print(f"  \033[32mPASS\033[0m  {name}")
    except Exception as e:
        err = str(e)
        if err.startswith("SKIP:"):
            SKIPPED.append(name)
            print(f"  \033[33mSKIP\033[0m  {name}: {err}")
        else:
            FAILED.append((name, err))
            print(f"  \033[31mFAIL\033[0m  {name}: {err}")
            traceback.print_exc()


# ── Tests ──────────────────────────────────────────────────────────────────

def test_createrung():
    global ladder_hex
    pubkey_hex = "02" + "aa" * 32
    sig_hex = "bb" * 64
    result = node.createrung([{"blocks": [{"type": "SIG", "fields": [
        {"type": "PUBKEY", "hex": pubkey_hex},
        {"type": "SIGNATURE", "hex": sig_hex},
    ]}]}])
    assert "hex" in result
    assert result["size"] > 0
    ladder_hex = result["hex"]

def test_decoderung():
    result = node.decoderung(ladder_hex)
    assert result["num_rungs"] == 1
    assert len(result["rungs"]) == 1
    block = result["rungs"][0]["blocks"][0]
    assert block["type"] == "SIG"
    assert block["fields"][0]["type"] == "PUBKEY"
    assert block["fields"][1]["type"] == "SIGNATURE"
    coil = result["coil"]
    assert coil["type"] == "UNLOCK"
    assert coil["attestation"] == "INLINE"
    assert coil["scheme"] == "SCHNORR"

def test_validateladder():
    raw_tx = ("01000000" "01" + "00"*32 + "00000000" "00" "ffffffff"
              "01" "0000000000000000" "016a" "00000000")
    result = node.validateladder(raw_tx)
    assert result["valid"] == False
    assert "Not a v4" in result["error"]

def test_decoderung_malformed():
    assert_raises_rpc_error(-22, "Failed to decode", node.decoderung, "00")
    assert_raises_rpc_error(-22, "unknown block type", node.decoderung, "0101ff000000010101" + "0000")

def test_createrungtx_signrungtx_spend():
    wif, pub = make_keypair()
    txid1, vout1, amount1, spk1 = bootstrap_v4_output(
        [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]}]}]
    )
    # Rung-to-rung spend
    wif2, pub2 = make_keypair()
    amount2 = round(amount1 - 0.001, 8)
    result2 = node.createrungtx(
        [{"txid": txid1, "vout": 0}],
        [{"amount": amount2, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub2}]}]}]}]
    )
    sign2 = node.signrungtx(result2["hex"], [{"privkey": wif, "input": 0}], [{"amount": amount1, "scriptPubKey": spk1}])
    assert sign2["complete"]
    txid2 = node.sendrawtransaction(sign2["hex"])
    mine_blocks(1)
    tx2 = node.getrawtransaction(txid2, True)
    assert tx2["confirmations"] >= 1

def test_hash_preimage_spend():
    preimage = os.urandom(32)
    hash_digest = hashlib.sha256(preimage).digest()
    conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [{"type": "HASH256", "hex": hash_digest.hex()}]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    dest_conds = [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}], [{"amount": out_amount, "conditions": dest_conds}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": preimage.hex()}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_hash160_preimage_spend():
    preimage = os.urandom(20)
    h = hash160(preimage)
    conditions = [{"blocks": [{"type": "HASH160_PREIMAGE", "fields": [{"type": "HASH160", "hex": h.hex()}]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "HASH160_PREIMAGE", "preimage": preimage.hex()}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_csv_spend():
    wif, pub = make_keypair()
    conditions = [{"blocks": [
        {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(10)}]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]}
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    mine_blocks(10)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0, "sequence": 10}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "CSV"}, {"type": "SIG", "privkey": wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_cltv_spend():
    wif, pub = make_keypair()
    height = node.getblockcount()
    target = height + 5
    conditions = [{"blocks": [
        {"type": "CLTV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(target)}]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]}
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    mine_blocks(5)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}],
        target)
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "CLTV"}, {"type": "SIG", "privkey": wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_multisig_spend():
    wif1, pub1 = make_keypair()
    wif2, pub2 = make_keypair()
    conditions = [{"blocks": [{"type": "MULTISIG", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(2)},
        {"type": "PUBKEY", "hex": pub1},
        {"type": "PUBKEY", "hex": pub2},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "MULTISIG", "privkeys": [wif1, wif2]}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_sig_plus_csv():
    wif, pub = make_keypair()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
        {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(5)}]},
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    mine_blocks(5)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0, "sequence": 5}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "SIG", "privkey": wif}, {"type": "CSV"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_or_logic():
    wif1, pub1 = make_keypair()
    wif2, pub2 = make_keypair()
    preimage = os.urandom(16)
    hash_val = hashlib.sha256(preimage).digest()
    conditions = [
        {"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub1}]}]},
        {"blocks": [{"type": "HASH_PREIMAGE", "fields": [{"type": "HASH256", "hex": hash_val.hex()}]}]},
    ]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    # Spend via rung 1 (hash preimage)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "rung": 1, "blocks": [{"type": "HASH_PREIMAGE", "preimage": preimage.hex()}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_negative_wrong_sig():
    wif, pub = make_keypair()
    wrong_wif, wrong_pub = make_keypair()
    conditions = [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"privkey": wrong_wif, "input": 0}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign["hex"])

def test_negative_wrong_preimage():
    preimage = os.urandom(16)
    hash_val = hashlib.sha256(preimage).digest()
    conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [{"type": "HASH256", "hex": hash_val.hex()}]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    wrong_preimage = os.urandom(16)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": wrong_preimage.hex()}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign["hex"])

def test_tagged_hash():
    preimage = os.urandom(32)
    tag = b"GhostTaggedHash"
    tag_hash = hashlib.sha256(tag).digest()
    expected = hashlib.sha256(tag_hash + tag_hash + preimage).digest()
    conditions = [{"blocks": [{"type": "TAGGED_HASH", "fields": [
        {"type": "HASH256", "hex": tag_hash.hex()},
        {"type": "HASH256", "hex": expected.hex()},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "TAGGED_HASH", "preimage": preimage.hex()}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_amount_lock():
    # Use a small output amount that fits within the lock range
    min_sats = 10000       # 0.0001 BTC
    max_sats = 200000000   # 2.0 BTC
    conditions = [{"blocks": [{"type": "AMOUNT_LOCK", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(min_sats)},
        {"type": "NUMERIC", "hex": numeric_hex(max_sats)},
    ]}]}]
    # Bootstrap with a small output (1 BTC) that fits within the amount lock range
    txid, vout, amount, spk = bootstrap_v4_output(conditions, output_amount=1.0)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "AMOUNT_LOCK"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_anchor_output():
    conditions = [{"blocks": [{"type": "ANCHOR", "fields": [
        {"type": "HASH256", "hex": os.urandom(32).hex()},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "ANCHOR"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_compare_block():
    conditions = [{"blocks": [{"type": "COMPARE", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(5)},  # GTE (0x05)
        {"type": "NUMERIC", "hex": numeric_hex(1000)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions, output_amount=1.0)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "COMPARE"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_adaptor_sig():
    wif, pub = make_keypair()
    adaptor_wif, adaptor_pub = make_keypair()
    # Adaptor point must be 32-byte x-only (strip 02/03 prefix)
    adaptor_xonly = adaptor_pub[2:]  # remove compressed prefix byte
    conditions = [{"blocks": [{"type": "ADAPTOR_SIG", "fields": [
        {"type": "PUBKEY", "hex": pub},
        {"type": "PUBKEY", "hex": adaptor_xonly},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "ADAPTOR_SIG", "privkey": wif, "adaptor_secret": os.urandom(32).hex()}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_recurse_same():
    wif, pub = make_keypair()
    conditions = [{"blocks": [
        {"type": "RECURSE_SAME", "fields": [{"type": "NUMERIC", "hex": numeric_hex(10)}]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    # Spend: re-encumber with same conditions
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": conditions}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "RECURSE_SAME"}, {"type": "SIG", "privkey": wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_vault_lock():
    recovery_wif, recovery_pub = make_keypair()
    hot_wif, hot_pub = make_keypair()
    conditions = [{"blocks": [{"type": "VAULT_LOCK", "fields": [
        {"type": "PUBKEY", "hex": recovery_pub},   # recovery_key (PUBKEY[0])
        {"type": "PUBKEY", "hex": hot_pub},         # hot_key (PUBKEY[1])
        {"type": "NUMERIC", "hex": numeric_hex(10)},  # hot_delay
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    # Sign with recovery key — instant cold sweep (no CSV delay needed)
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "VAULT_LOCK", "privkey": recovery_wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_hysteresis_value():
    # Field order: numerics[0]=high_sats, numerics[1]=low_sats. Must have high >= low.
    conditions = [{"blocks": [{"type": "HYSTERESIS_VALUE", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(200000000)},  # high: 2 BTC
        {"type": "NUMERIC", "hex": numeric_hex(50000000)},   # low: 0.5 BTC
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions, output_amount=1.0)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "HYSTERESIS_VALUE"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_hysteresis_fee():
    # Field order: numerics[0]=high_sat_vb, numerics[1]=low_sat_vb. Must have high >= low.
    conditions = [{"blocks": [{"type": "HYSTERESIS_FEE", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(500)},  # high_sat_vb
        {"type": "NUMERIC", "hex": numeric_hex(1)},    # low_sat_vb
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions, output_amount=1.0)
    dest_wif, dest_pub = make_keypair()
    # Fee = amount - out_amount (in sats). Target ~10-100 sat/vB for a ~150 vB tx.
    out_amount = round(amount - 0.0001, 8)  # ~10000 sats fee / ~150 vB ≈ 66 sat/vB
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "HYSTERESIS_FEE"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_rate_limit():
    # max_per_block (sats), accumulation_cap, refill_blocks
    conditions = [{"blocks": [{"type": "RATE_LIMIT", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(500000000)},   # max_per_block: 5 BTC
        {"type": "NUMERIC", "hex": numeric_hex(1000000000)},  # accumulation_cap: 10 BTC
        {"type": "NUMERIC", "hex": numeric_hex(144)},         # refill_blocks
    ]}]}]
    # Use 1 BTC output so output_amount < max_per_block (5 BTC)
    txid, vout, amount, spk = bootstrap_v4_output(conditions, output_amount=1.0)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "RATE_LIMIT"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_sequencer():
    conditions = [{"blocks": [{"type": "SEQUENCER", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(0)},
        {"type": "NUMERIC", "hex": numeric_hex(5)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "SEQUENCER"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_timer_continuous():
    _wif, pub = make_keypair()
    conditions = [{"blocks": [{"type": "TIMER_CONTINUOUS", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(100)},
        {"type": "NUMERIC", "hex": numeric_hex(10)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "TIMER_CONTINUOUS"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_timer_off_delay():
    _wif, pub = make_keypair()
    conditions = [{"blocks": [{"type": "TIMER_OFF_DELAY", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(5)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "TIMER_OFF_DELAY"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_latch_set():
    _wif, pub = make_keypair()
    conditions = [{"blocks": [{"type": "LATCH_SET", "fields": [
        {"type": "PUBKEY", "hex": pub},
        {"type": "NUMERIC", "hex": numeric_hex(0)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "LATCH_SET"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_latch_reset():
    _wif, pub = make_keypair()
    conditions = [{"blocks": [{"type": "LATCH_RESET", "fields": [
        {"type": "PUBKEY", "hex": pub},
        {"type": "NUMERIC", "hex": numeric_hex(1)},
        {"type": "NUMERIC", "hex": numeric_hex(0)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "LATCH_RESET"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_counter_down():
    _wif, pub = make_keypair()
    conditions = [{"blocks": [{"type": "COUNTER_DOWN", "fields": [
        {"type": "PUBKEY", "hex": pub},
        {"type": "NUMERIC", "hex": numeric_hex(10)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "COUNTER_DOWN"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_counter_preset():
    conditions = [{"blocks": [{"type": "COUNTER_PRESET", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(5)},
        {"type": "NUMERIC", "hex": numeric_hex(100)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "COUNTER_PRESET"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_counter_up():
    _wif, pub = make_keypair()
    conditions = [{"blocks": [{"type": "COUNTER_UP", "fields": [
        {"type": "PUBKEY", "hex": pub},
        {"type": "NUMERIC", "hex": numeric_hex(0)},
        {"type": "NUMERIC", "hex": numeric_hex(10)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "COUNTER_UP"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_one_shot():
    conditions = [{"blocks": [{"type": "ONE_SHOT", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(0)},
        {"type": "HASH256", "hex": os.urandom(32).hex()},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "ONE_SHOT"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_recurse_decay():
    wif, pub = make_keypair()
    # RECURSE_DECAY legacy format: 4 NUMERICs = max_depth, block_idx, param_idx, delta
    # Decay negates delta: output = input - delta.
    # Targets block_idx=1 (COUNTER_DOWN), param_idx=1 (count NUMERIC — idx 0 is PUBKEY), delta=1
    conditions = [{"blocks": [
        {"type": "RECURSE_DECAY", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # max_depth
            {"type": "NUMERIC", "hex": numeric_hex(1)},   # block_idx (COUNTER_DOWN)
            {"type": "NUMERIC", "hex": numeric_hex(1)},   # param_idx (NUMERIC is idx 1; PUBKEY is idx 0)
            {"type": "NUMERIC", "hex": numeric_hex(1)},   # delta (decay by 1 each spend)
        ]},
        {"type": "COUNTER_DOWN", "fields": [
            {"type": "PUBKEY", "hex": pub},
            {"type": "NUMERIC", "hex": numeric_hex(100)},  # starting count
        ]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    out_amount = round(amount - 0.001, 8)
    # Decay output: count decremented from 100 to 99 (output = input - delta)
    decay_conds = [{"blocks": [
        {"type": "RECURSE_DECAY", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},
            {"type": "NUMERIC", "hex": numeric_hex(1)},
            {"type": "NUMERIC", "hex": numeric_hex(1)},
            {"type": "NUMERIC", "hex": numeric_hex(1)},
        ]},
        {"type": "COUNTER_DOWN", "fields": [
            {"type": "PUBKEY", "hex": pub},
            {"type": "NUMERIC", "hex": numeric_hex(99)},  # count decremented
        ]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": decay_conds}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "RECURSE_DECAY"}, {"type": "COUNTER_DOWN"}, {"type": "SIG", "privkey": wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_anchor_channel():
    _, pub1 = make_keypair()
    _, pub2 = make_keypair()
    conditions = [{"blocks": [{"type": "ANCHOR_CHANNEL", "fields": [
        {"type": "PUBKEY", "hex": pub1},       # local_key
        {"type": "PUBKEY", "hex": pub2},       # remote_key
        {"type": "NUMERIC", "hex": numeric_hex(2)},  # commitment_number
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "ANCHOR_CHANNEL"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_anchor_pool():
    conditions = [{"blocks": [{"type": "ANCHOR_POOL", "fields": [
        {"type": "HASH256", "hex": os.urandom(32).hex()},
        {"type": "NUMERIC", "hex": numeric_hex(5)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "ANCHOR_POOL"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_anchor_reserve():
    conditions = [{"blocks": [{"type": "ANCHOR_RESERVE", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(2)},         # threshold_n
        {"type": "NUMERIC", "hex": numeric_hex(3)},         # threshold_m
        {"type": "HASH256", "hex": os.urandom(32).hex()},   # guardian set hash
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "ANCHOR_RESERVE"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_anchor_seal():
    conditions = [{"blocks": [{"type": "ANCHOR_SEAL", "fields": [
        {"type": "HASH256", "hex": os.urandom(32).hex()},  # asset_id
        {"type": "HASH256", "hex": os.urandom(32).hex()},  # state_transition
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "ANCHOR_SEAL"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_anchor_oracle():
    _, oracle_pub = make_keypair()
    conditions = [{"blocks": [{"type": "ANCHOR_ORACLE", "fields": [
        {"type": "PUBKEY", "hex": oracle_pub},             # oracle_key
        {"type": "NUMERIC", "hex": numeric_hex(3)},        # outcome_count
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "ANCHOR_ORACLE"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_recurse_split():
    wif, pub = make_keypair()
    conditions = [{"blocks": [
        {"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(2)},       # max_splits
            {"type": "NUMERIC", "hex": numeric_hex(10000)},   # min_split_sats
        ]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions, output_amount=1.0)
    split_amount = round(amount / 2 - 0.001, 8)
    # Output conditions must have max_splits decremented to 1
    split_conds = [{"blocks": [
        {"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(1)},       # max_splits - 1
            {"type": "NUMERIC", "hex": numeric_hex(10000)},   # min_split_sats (unchanged)
        ]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": split_amount, "conditions": split_conds},
         {"amount": split_amount, "conditions": split_conds}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "RECURSE_SPLIT"}, {"type": "SIG", "privkey": wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_recurse_count():
    wif, pub = make_keypair()
    conditions = [{"blocks": [
        {"type": "RECURSE_COUNT", "fields": [{"type": "NUMERIC", "hex": numeric_hex(3)}]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    out_amount = round(amount - 0.001, 8)
    # Spend with count-1
    next_conds = [{"blocks": [
        {"type": "RECURSE_COUNT", "fields": [{"type": "NUMERIC", "hex": numeric_hex(2)}]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": next_conds}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "RECURSE_COUNT"}, {"type": "SIG", "privkey": wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_recurse_modified():
    wif, pub = make_keypair()
    # RECURSE_MODIFIED legacy format: 4 NUMERICs = max_depth, block_idx, param_idx, delta
    # Targets block_idx=1 (SEQUENCER), param_idx=0 (current_step), delta=+1
    conditions = [{"blocks": [
        {"type": "RECURSE_MODIFIED", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # max_depth
            {"type": "NUMERIC", "hex": numeric_hex(1)},   # block_idx (SEQUENCER is block 1)
            {"type": "NUMERIC", "hex": numeric_hex(0)},   # param_idx (current_step)
            {"type": "NUMERIC", "hex": numeric_hex(1)},   # delta (+1)
        ]},
        {"type": "SEQUENCER", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # current_step
            {"type": "NUMERIC", "hex": numeric_hex(5)},  # total_steps
        ]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    out_amount = round(amount - 0.001, 8)
    # Next state: step 0->1 (RECURSE_MODIFIED verifies current_step incremented by delta)
    next_conds = [{"blocks": [
        {"type": "RECURSE_MODIFIED", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},
            {"type": "NUMERIC", "hex": numeric_hex(1)},
            {"type": "NUMERIC", "hex": numeric_hex(0)},
            {"type": "NUMERIC", "hex": numeric_hex(1)},
        ]},
        {"type": "SEQUENCER", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(1)},  # incremented
            {"type": "NUMERIC", "hex": numeric_hex(5)},
        ]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": next_conds}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "RECURSE_MODIFIED"}, {"type": "SEQUENCER"}, {"type": "SIG", "privkey": wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_extractadaptorsecret_rpc():
    pre_sig = "aa" * 64
    adapted_sig = "bb" * 64
    result = node.extractadaptorsecret(pre_sig, adapted_sig)
    assert "secret" in result
    assert len(result["secret"]) == 64

def test_inverted_csv():
    """Inverted CSV: spendable BEFORE the timelock, blocked AFTER."""
    wif, pub = make_keypair()
    conditions = [{"blocks": [
        {"type": "CSV", "inverted": True, "fields": [{"type": "NUMERIC", "hex": numeric_hex(1000)}]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0, "sequence": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "CSV"}, {"type": "SIG", "privkey": wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_inverted_hash_preimage():
    """Inverted HASH_PREIMAGE: spend when hash does NOT match."""
    wrong_hash = os.urandom(32)
    conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "inverted": True, "fields": [
        {"type": "HASH256", "hex": wrong_hash.hex()}
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    # Provide a preimage whose hash does NOT match wrong_hash
    any_preimage = os.urandom(32)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": any_preimage.hex()}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_recurse_until():
    wif, pub = make_keypair()
    height = node.getblockcount()
    target = height + 20
    conditions = [{"blocks": [
        {"type": "RECURSE_UNTIL", "fields": [{"type": "NUMERIC", "hex": numeric_hex(target)}]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]},
    ]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    out_amount = round(amount - 0.001, 8)
    # Re-encumber (before target)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": conditions}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "RECURSE_UNTIL"}, {"type": "SIG", "privkey": wif}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1


# ── Missing block types: CSV_TIME, CLTV_TIME, CTV, COSIGN ─────────────────

def test_csv_time_spend():
    """CSV_TIME: relative time-based sequence lock."""
    # Time-based CSV: bit 22 (0x00400000) set, value = units of 512 seconds
    csv_time_units = 1  # 512 seconds
    csv_sequence = 0x00400000 | csv_time_units
    conditions = [{"blocks": [{"type": "CSV_TIME", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(csv_sequence)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    # Mine 60 blocks (10s apart each = 600s elapsed > 512s needed for 1 CSV_TIME unit)
    mine_blocks(60)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0, "sequence": csv_sequence}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "CSV_TIME"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_cltv_time_spend():
    """CLTV_TIME: absolute time-based locktime spend."""
    # Use current block time minus 1 second (already in the past)
    tip = rpc("getblock", [rpc("getbestblockhash")])
    target_time = tip["mediantime"] - 1  # already passed
    conditions = [{"blocks": [{"type": "CLTV_TIME", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(target_time)},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}],
        target_time)
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "CLTV_TIME"}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_ctv_template():
    """CTV: CheckTemplateVerify — lock and spend with template hash."""
    wif, pub = make_keypair()
    dest_wif, dest_pub = make_keypair()
    # Step 1: Create a SIG-locked output we control
    sig_conds = [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pub}]}]}]
    sig_txid, sig_vout, sig_amount, sig_spk = bootstrap_v4_output(sig_conds, output_amount=1.0)
    # Step 2: Pre-compute the CTV template hash
    spend_amount = round(sig_amount - 0.002, 8)
    dest_conds = [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]
    template_tx = node.createrungtx(
        [{"txid": sig_txid, "vout": 0}],
        [{"amount": spend_amount, "conditions": dest_conds}])
    ctv_hash = node.computectvhash(template_tx["hex"], 0)["hash"]
    # Step 3: Create CTV-locked output
    ctv_conds = [{"blocks": [{"type": "CTV", "fields": [
        {"type": "HASH256", "hex": ctv_hash},
    ]}]}]
    ctv_amount = round(sig_amount - 0.001, 8)
    ctv_tx = node.createrungtx(
        [{"txid": sig_txid, "vout": 0}],
        [{"amount": ctv_amount, "conditions": ctv_conds}])
    ctv_sign = node.signrungtx(ctv_tx["hex"],
        [{"privkey": wif, "input": 0}],
        [{"amount": sig_amount, "scriptPubKey": sig_spk}])
    assert ctv_sign["complete"]
    ctv_txid = node.sendrawtransaction(ctv_sign["hex"])
    mine_blocks(1)
    ctv_info = node.getrawtransaction(ctv_txid, True)
    assert ctv_info["confirmations"] >= 1
    ctv_spk = ctv_info["vout"][0]["scriptPubKey"]["hex"]
    # Step 4: Spend the CTV output — tx must match the template
    spend_ctv = node.createrungtx(
        [{"txid": ctv_txid, "vout": 0}],
        [{"amount": spend_amount, "conditions": dest_conds}])
    sign_ctv = node.signrungtx(spend_ctv["hex"],
        [{"input": 0, "blocks": [{"type": "CTV"}]}],
        [{"amount": ctv_amount, "scriptPubKey": ctv_spk}])
    assert sign_ctv["complete"]
    final_txid = node.sendrawtransaction(sign_ctv["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(final_txid, True)["confirmations"] >= 1

def test_cosign_spend():
    """COSIGN: two UTXOs co-spent — child requires anchor's scriptPubKey hash."""
    anchor_wif, anchor_pub = make_keypair()
    anchor_conds = [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": anchor_pub}]}]}]
    anchor_txid, anchor_vout, anchor_amount, anchor_spk = bootstrap_v4_output(anchor_conds, output_amount=0.5)
    # COSIGN hash = SHA256 of anchor's scriptPubKey
    cosign_hash = hashlib.sha256(bytes.fromhex(anchor_spk)).hexdigest()
    child_wif, child_pub = make_keypair()
    child_conds = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": child_pub}]},
        {"type": "COSIGN", "fields": [{"type": "HASH256", "hex": cosign_hash}]},
    ]}]
    child_txid, child_vout, child_amount, child_spk = bootstrap_v4_output(child_conds)
    # Spend both in same tx
    dest_wif, dest_pub = make_keypair()
    dest_conds = [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]
    spend = node.createrungtx(
        [{"txid": anchor_txid, "vout": 0}, {"txid": child_txid, "vout": 0}],
        [{"amount": round(anchor_amount - 0.0005, 8), "conditions": dest_conds},
         {"amount": round(child_amount - 0.0005, 8), "conditions": dest_conds}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "SIG", "privkey": anchor_wif}]},
         {"input": 1, "blocks": [{"type": "SIG", "privkey": child_wif}, {"type": "COSIGN"}]}],
        [{"amount": anchor_amount, "scriptPubKey": anchor_spk},
         {"amount": child_amount, "scriptPubKey": child_spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1


# ── Post-Quantum Signature Tests ──────────────────────────────────────────

_PQ_AVAILABLE = None

def _has_pq():
    global _PQ_AVAILABLE
    if _PQ_AVAILABLE is None:
        try:
            node.generatepqkeypair("FALCON512")
            _PQ_AVAILABLE = True
        except RPCError as e:
            if "liboqs" in e.message.lower() or "not compiled" in e.message.lower():
                _PQ_AVAILABLE = False
            else:
                raise
    return _PQ_AVAILABLE

def test_pq_keygen_all_schemes():
    """PQ keygen: generate keypairs for all 4 schemes."""
    if not _has_pq():
        raise Exception("SKIP: liboqs not available")
    for scheme in ["FALCON512", "FALCON1024", "DILITHIUM3"]:
        result = node.generatepqkeypair(scheme)
        assert result["scheme"] == scheme
        assert len(result["pubkey"]) > 0
        assert len(result["privkey"]) > 0
        bytes.fromhex(result["pubkey"])
        bytes.fromhex(result["privkey"])

def test_pq_falcon512_sig():
    """PQ SIG: FALCON512 end-to-end sign and spend on signet."""
    if not _has_pq():
        raise Exception("SKIP: liboqs not available")
    keypair = node.generatepqkeypair("FALCON512")
    pq_pubkey = keypair["pubkey"]
    pq_privkey = keypair["privkey"]
    # SCHEME=0x10 (FALCON512) + full PQ pubkey in conditions
    conditions = [{"blocks": [{"type": "SIG", "fields": [
        {"type": "SCHEME", "hex": "10"},
        {"type": "PUBKEY", "hex": pq_pubkey},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions, output_amount=1.0)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [{"type": "SIG", "scheme": "FALCON512", "pq_privkey": pq_privkey}]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_pq_falcon512_pubkey_commit():
    """PQ PUBKEY_COMMIT: 32-byte commitment in UTXO, full pubkey in witness."""
    if not _has_pq():
        raise Exception("SKIP: liboqs not available")
    keypair = node.generatepqkeypair("FALCON512")
    pq_pubkey = keypair["pubkey"]
    pq_privkey = keypair["privkey"]
    commit_hex = node.pqpubkeycommit(pq_pubkey)["commit"]
    # Verify commitment = SHA256(pubkey)
    expected = hashlib.sha256(bytes.fromhex(pq_pubkey)).hexdigest()
    assert commit_hex == expected
    # Conditions: SCHEME(FALCON512) + PUBKEY_COMMIT (34 bytes in UTXO!)
    conditions = [{"blocks": [{"type": "SIG", "fields": [
        {"type": "SCHEME", "hex": "10"},
        {"type": "PUBKEY_COMMIT", "hex": commit_hex},
    ]}]}]
    txid, vout, amount, spk = bootstrap_v4_output(conditions, output_amount=1.0)
    dest_wif, dest_pub = make_keypair()
    out_amount = round(amount - 0.001, 8)
    spend = node.createrungtx([{"txid": txid, "vout": 0}],
        [{"amount": out_amount, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [
            {"type": "SIG", "scheme": "FALCON512", "pq_privkey": pq_privkey, "pq_pubkey": pq_pubkey}
        ]}],
        [{"amount": amount, "scriptPubKey": spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    assert node.getrawtransaction(stxid, True)["confirmations"] >= 1

def test_pq_cosign_anchor():
    """PQ COSIGN: Quantum anchor protects Schnorr child via co-spending.
    1 PQ anchor (FALCON512 + PUBKEY_COMMIT + RECURSE_SAME) + 1 Schnorr child (SIG + COSIGN).
    """
    if not _has_pq():
        raise Exception("SKIP: liboqs not available")
    # Create PQ anchor
    keypair = node.generatepqkeypair("FALCON512")
    pq_pubkey = keypair["pubkey"]
    pq_privkey = keypair["privkey"]
    commit = node.pqpubkeycommit(pq_pubkey)["commit"]
    anchor_conds = [{"blocks": [
        {"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "10"},
            {"type": "PUBKEY_COMMIT", "hex": commit},
        ]},
        {"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(1000)},
        ]},
    ]}]
    anchor_txid, anchor_vout, anchor_amount, anchor_spk = bootstrap_v4_output(anchor_conds, output_amount=0.01)
    # COSIGN hash = SHA256(anchor scriptPubKey)
    cosign_hash = hashlib.sha256(bytes.fromhex(anchor_spk)).hexdigest()
    # Create child with SIG + COSIGN
    child_wif, child_pub = make_keypair()
    child_conds = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": child_pub}]},
        {"type": "COSIGN", "fields": [{"type": "HASH256", "hex": cosign_hash}]},
    ]}]
    child_txid, child_vout, child_amount, child_spk = bootstrap_v4_output(child_conds, output_amount=1.0)
    # Spend both: anchor re-encumbers, child freed
    dest_wif, dest_pub = make_keypair()
    spend = node.createrungtx(
        [{"txid": anchor_txid, "vout": 0}, {"txid": child_txid, "vout": 0}],
        [{"amount": round(anchor_amount - 0.0001, 8), "conditions": anchor_conds},
         {"amount": round(child_amount - 0.001, 8), "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]}])
    sign = node.signrungtx(spend["hex"],
        [{"input": 0, "blocks": [
            {"type": "SIG", "scheme": "FALCON512", "pq_privkey": pq_privkey, "pq_pubkey": pq_pubkey},
            {"type": "RECURSE_SAME"},
        ]},
         {"input": 1, "blocks": [
            {"type": "SIG", "privkey": child_wif},
            {"type": "COSIGN"},
        ]}],
        [{"amount": anchor_amount, "scriptPubKey": anchor_spk},
         {"amount": child_amount, "scriptPubKey": child_spk}])
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    tx_info = node.getrawtransaction(stxid, True)
    assert tx_info["confirmations"] >= 1
    # Verify anchor re-encumbered with same conditions
    assert tx_info["vout"][0]["scriptPubKey"]["hex"] == anchor_spk

def test_pq_cosign_10_children():
    """PQ COSIGN at scale: 1 FALCON512 anchor + 10 Schnorr children in one tx."""
    if not _has_pq():
        raise Exception("SKIP: liboqs not available")
    keypair = node.generatepqkeypair("FALCON512")
    pq_pubkey = keypair["pubkey"]
    pq_privkey = keypair["privkey"]
    commit = node.pqpubkeycommit(pq_pubkey)["commit"]
    anchor_conds = [{"blocks": [
        {"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "10"},
            {"type": "PUBKEY_COMMIT", "hex": commit},
        ]},
        {"type": "RECURSE_SAME", "fields": [{"type": "NUMERIC", "hex": numeric_hex(1000)}]},
    ]}]
    anchor_txid, anchor_vout, anchor_amount, anchor_spk = bootstrap_v4_output(anchor_conds, output_amount=0.01)
    cosign_hash = hashlib.sha256(bytes.fromhex(anchor_spk)).hexdigest()
    # Create 10 child UTXOs with SIG + COSIGN
    children = []
    for i in range(10):
        c_wif, c_pub = make_keypair()
        c_conds = [{"blocks": [
            {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": c_pub}]},
            {"type": "COSIGN", "fields": [{"type": "HASH256", "hex": cosign_hash}]},
        ]}]
        c_txid, c_vout, c_amount, c_spk = bootstrap_v4_output(c_conds, output_amount=0.1)
        children.append({"txid": c_txid, "vout": c_vout, "amount": c_amount, "spk": c_spk, "wif": c_wif})
    # Build 11-input transaction: anchor + 10 children
    dest_wif, dest_pub = make_keypair()
    dest_conds = [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pub}]}]}]
    inputs = [{"txid": anchor_txid, "vout": 0}]
    for c in children:
        inputs.append({"txid": c["txid"], "vout": c["vout"]})
    outputs = [{"amount": round(anchor_amount - 0.0001, 8), "conditions": anchor_conds}]
    for c in children:
        outputs.append({"amount": round(c["amount"] - 0.001, 8), "conditions": dest_conds})
    spend = node.createrungtx(inputs, outputs)
    signers = [{"input": 0, "blocks": [
        {"type": "SIG", "scheme": "FALCON512", "pq_privkey": pq_privkey, "pq_pubkey": pq_pubkey},
        {"type": "RECURSE_SAME"},
    ]}]
    for idx, c in enumerate(children, 1):
        signers.append({"input": idx, "blocks": [
            {"type": "SIG", "privkey": c["wif"]},
            {"type": "COSIGN"},
        ]})
    spent_outputs = [{"amount": anchor_amount, "scriptPubKey": anchor_spk}]
    for c in children:
        spent_outputs.append({"amount": c["amount"], "scriptPubKey": c["spk"]})
    sign = node.signrungtx(spend["hex"], signers, spent_outputs)
    assert sign["complete"]
    stxid = node.sendrawtransaction(sign["hex"])
    mine_blocks(1)
    tx_info = node.getrawtransaction(stxid, True)
    assert tx_info["confirmations"] >= 1
    assert tx_info["vout"][0]["scriptPubKey"]["hex"] == anchor_spk


# ── RPC hardening tests (no UTXOs needed) ─────────────────────────────────

def test_rpc_unknown_block_type():
    assert_raises_rpc_error(-8, None, node.createrung, [{"blocks": [{"type": "FOOBAR", "fields": []}]}])

def test_rpc_unknown_data_type():
    assert_raises_rpc_error(-8, None, node.createrung, [{"blocks": [{"type": "SIG", "fields": [{"type": "FOOBAR", "hex": "aa"}]}]}])

def test_rpc_empty_rungs():
    # Empty array is accepted (produces empty ladder); verify it returns valid hex
    result = node.createrung([])
    assert "hex" in result

def test_rpc_invalid_field_hex():
    assert_raises_rpc_error(-8, None, node.createrung, [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": "ZZZZ"}]}]}])

def test_rpc_createrungtx_negative_amount():
    assert_raises_rpc_error(None, None, node.createrungtx,
        [{"txid": "a"*64, "vout": 0}],
        [{"amount": -1, "conditions": [{"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": "02" + "aa"*32}]}]}]}])


# ── Main ───────────────────────────────────────────────────────────────────

ALL_TESTS = [
    # RPC basics
    ("test_createrung", test_createrung),
    ("test_decoderung", test_decoderung),
    ("test_validateladder", test_validateladder),
    ("test_decoderung_malformed", test_decoderung_malformed),

    # End-to-end spend
    ("test_createrungtx_signrungtx_spend", test_createrungtx_signrungtx_spend),

    # Block types
    ("test_hash_preimage_spend", test_hash_preimage_spend),
    ("test_hash160_preimage_spend", test_hash160_preimage_spend),
    ("test_csv_spend", test_csv_spend),
    ("test_cltv_spend", test_cltv_spend),
    ("test_multisig_spend", test_multisig_spend),
    ("test_sig_plus_csv", test_sig_plus_csv),
    ("test_or_logic", test_or_logic),
    ("test_tagged_hash", test_tagged_hash),
    ("test_amount_lock", test_amount_lock),
    ("test_anchor_output", test_anchor_output),
    ("test_compare_block", test_compare_block),
    ("test_adaptor_sig", test_adaptor_sig),
    ("test_vault_lock", test_vault_lock),

    # PLC blocks
    ("test_hysteresis_value", test_hysteresis_value),
    ("test_hysteresis_fee", test_hysteresis_fee),
    ("test_rate_limit", test_rate_limit),
    ("test_sequencer", test_sequencer),
    ("test_timer_continuous", test_timer_continuous),
    ("test_timer_off_delay", test_timer_off_delay),
    ("test_latch_set", test_latch_set),
    ("test_latch_reset", test_latch_reset),
    ("test_counter_down", test_counter_down),
    ("test_counter_preset", test_counter_preset),
    ("test_counter_up", test_counter_up),
    ("test_one_shot", test_one_shot),

    # Recursion
    ("test_recurse_same", test_recurse_same),
    ("test_recurse_count", test_recurse_count),
    ("test_recurse_modified", test_recurse_modified),
    ("test_recurse_split", test_recurse_split),
    ("test_recurse_decay", test_recurse_decay),
    ("test_recurse_until", test_recurse_until),

    # Anchor variants
    ("test_anchor_channel", test_anchor_channel),
    ("test_anchor_pool", test_anchor_pool),
    ("test_anchor_reserve", test_anchor_reserve),
    ("test_anchor_seal", test_anchor_seal),
    ("test_anchor_oracle", test_anchor_oracle),

    # Missing block types
    ("test_csv_time_spend", test_csv_time_spend),
    ("test_cltv_time_spend", test_cltv_time_spend),
    ("test_ctv_template", test_ctv_template),
    ("test_cosign_spend", test_cosign_spend),

    # Post-Quantum
    ("test_pq_keygen_all_schemes", test_pq_keygen_all_schemes),
    ("test_pq_falcon512_sig", test_pq_falcon512_sig),
    ("test_pq_falcon512_pubkey_commit", test_pq_falcon512_pubkey_commit),
    ("test_pq_cosign_anchor", test_pq_cosign_anchor),
    ("test_pq_cosign_10_children", test_pq_cosign_10_children),

    # Inversion
    ("test_inverted_csv", test_inverted_csv),
    ("test_inverted_hash_preimage", test_inverted_hash_preimage),

    # Negative tests
    ("test_negative_wrong_sig", test_negative_wrong_sig),
    ("test_negative_wrong_preimage", test_negative_wrong_preimage),

    # RPC hardening
    ("test_rpc_unknown_block_type", test_rpc_unknown_block_type),
    ("test_rpc_unknown_data_type", test_rpc_unknown_data_type),
    ("test_rpc_empty_rungs", test_rpc_empty_rungs),
    ("test_rpc_invalid_field_hex", test_rpc_invalid_field_hex),
    ("test_rpc_createrungtx_negative_amount", test_rpc_createrungtx_negative_amount),

    # Adaptor RPC
    ("test_extractadaptorsecret_rpc", test_extractadaptorsecret_rpc),
]


if __name__ == "__main__":
    print("=" * 60)
    print("LADDER SCRIPT — SIGNET TEST SUITE")
    print("=" * 60)

    # Check node connectivity
    try:
        info = node.getblockchaininfo()
        print(f"Chain:   {info['chain']}")
        print(f"Height:  {info['blocks']}")
        print(f"Tests:   {len(ALL_TESTS)}")
        print("=" * 60)
    except Exception as e:
        print(f"ERROR: Cannot connect to ghost node at 127.0.0.1:{RPCPORT}")
        print(f"       {e}")
        sys.exit(1)

    # Ensure we have enough UTXOs
    utxos = node.listunspent()
    available = len([u for u in utxos if float(u["amount"]) >= 1])
    needed = len([t for t in ALL_TESTS if "rpc_" not in t[0] and "negative" not in t[0] and "decoderung" not in t[0] and "validateladder" not in t[0] and "createrung" != t[0] and "extractadaptor" not in t[0]])
    print(f"UTXOs:   {available} available, ~{needed} needed")
    if available < needed:
        print(f"Mining {needed - available + 10} more blocks for funding...")
        mine_blocks(needed - available + 10)
    print("=" * 60)

    t0 = time.time()
    for name, fn in ALL_TESTS:
        run_test(name, fn)

    elapsed = time.time() - t0
    print("=" * 60)
    print(f"Results: {len(PASSED)} passed, {len(FAILED)} failed, {len(SKIPPED)} skipped")
    print(f"Time:    {elapsed:.1f}s")
    height = node.getblockcount()
    print(f"Height:  {height}")

    if FAILED:
        print("\nFailed tests:")
        for name, err in FAILED:
            print(f"  {name}: {err}")
        sys.exit(1)
    else:
        print("\nAll tests passed!")
        sys.exit(0)
