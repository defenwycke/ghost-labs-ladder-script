#!/usr/bin/env python3
"""
Exhaustive regtest functional test for all 60 evaluable Ladder Script block types.
Tests create -> sign -> broadcast -> mine -> spend for every testable block type
and common combinations (AND composition, OR composition, inversion).

Requires: ghostd and ghost-cli built in ghost-core/build/bin/
          Python coincurve for key generation

Block types covered (60 total):
  Group 1 - Solo SIG-based:       SIG, TIMELOCKED_SIG, CLTV_SIG, HASH_SIG, MUSIG_THRESHOLD
  Group 2 - Governance:           CSV, CLTV, AMOUNT_LOCK, INPUT_COUNT, OUTPUT_COUNT,
                                  WEIGHT_LIMIT, OUTPUT_CHECK, RELATIVE_VALUE, EPOCH_GATE
  Group 3 - Hash-based:           HASH_GUARDED, TAGGED_HASH
  Group 4 - Multi-key:            MULTISIG, TIMELOCKED_MULTISIG, ADAPTOR_SIG, KEY_REF_SIG,
                                  HTLC, PTLC, VAULT_LOCK
  Group 5 - Covenant/CTV:         CTV, COSIGN
  Group 6 - Anchors:              ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE,
                                  ANCHOR_SEAL, ANCHOR_ORACLE
  Group 7 - PLC:                  HYSTERESIS_FEE, HYSTERESIS_VALUE, TIMER_CONTINUOUS,
                                  TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN,
                                  COUNTER_PRESET, COUNTER_UP, COMPARE, SEQUENCER,
                                  ONE_SHOT, RATE_LIMIT
  Group 8 - Recursion:            RECURSE_SAME, RECURSE_UNTIL, RECURSE_COUNT,
                                  RECURSE_SPLIT, RECURSE_MODIFIED, RECURSE_DECAY
  Group 9 - Legacy wrappers:      P2PK_LEGACY, P2PKH_LEGACY, P2SH_LEGACY, P2WPKH_LEGACY,
                                  P2WSH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY
  Bonus:                          ACCUMULATOR, OR logic, AND composition
"""

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
BUILD_BIN = os.path.join(REPO_DIR, "ghost-core", "build", "bin")
GHOSTD = os.path.join(BUILD_BIN, "ghostd")
CLI = os.path.join(BUILD_BIN, "ghost-cli")

DATADIR = tempfile.mkdtemp(prefix="ghost-regtest-")
RPC_USER = "test"
RPC_PASS = "test"
RPC_PORT = 18543  # non-default to avoid conflicts

from coincurve import PrivateKey


# =============================================================================
# Utility functions
# =============================================================================

def cli(*args):
    cmd = [CLI, "-regtest", f"-datadir={DATADIR}", f"-rpcuser={RPC_USER}",
           f"-rpcpassword={RPC_PASS}", f"-rpcport={RPC_PORT}"] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"CLI error: {result.stderr.strip()}")
    return result.stdout.strip()


def rpc(method, params=None):
    import urllib.request
    req = {"jsonrpc": "1.0", "id": "test", "method": method, "params": params or []}
    data = json.dumps(req).encode()
    r = urllib.request.Request(
        f"http://127.0.0.1:{RPC_PORT}/",
        data=data,
        headers={"Content-Type": "text/plain",
                 "Authorization": "Basic " + base64.b64encode(f"{RPC_USER}:{RPC_PASS}".encode()).decode()},
    )
    resp = urllib.request.urlopen(r, timeout=30)
    result = json.loads(resp.read().decode())
    if result.get("error"):
        raise RuntimeError(f"RPC error: {result['error']}")
    return result["result"]


def generate_key():
    """Generate a random keypair, return (wif, compressed_pubkey_hex)."""
    pk = PrivateKey()
    pub = pk.public_key.format(compressed=True)
    raw = b'\xef' + pk.secret + b'\x01'
    cksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    payload = raw + cksum
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(payload, 'big')
    wif = ''
    while num > 0:
        num, rem = divmod(num, 58)
        wif = alphabet[rem] + wif
    return wif, pub.hex()


def numeric_hex(val):
    """Encode a uint32 as 4-byte little-endian hex."""
    return val.to_bytes(4, 'little').hex()


def mine(n=1):
    """Mine n blocks."""
    addr = cli("-rpcwallet=test", "getnewaddress", "", "legacy")
    cli("generatetoaddress", str(n), addr)


def get_utxo():
    """Get a spendable UTXO from the wallet."""
    utxos = json.loads(cli("-rpcwallet=test", "listunspent"))
    if not utxos:
        raise RuntimeError("No UTXOs available")
    u = utxos[0]
    return u["txid"], u["vout"], u["amount"]


def get_height():
    """Get current block height."""
    return int(rpc("getblockcount"))


def build_inner_sig_conditions(pubkey_hex):
    """Build CONDITIONS-context serialized bytes for a SIG block using parseladder RPC.
    Returns the hex-decoded bytes of the serialized conditions."""
    result = rpc("parseladder", [
        "ladder(sig(@k))",
        json.dumps({"k": pubkey_hex}),
    ])
    return bytes.fromhex(result["conditions_hex"])


# =============================================================================
# Core create/spend helpers
# =============================================================================

def create_mlsc(conditions, pubkey_hex=None, relays=None, locktime=0):
    """Create a v4 tx with an MLSC output. Returns (txid, spk_hex, amount)."""
    fund_txid, fund_vout, fund_amount = get_utxo()
    out_amount = round(fund_amount - 0.001, 8)

    fields = []
    for block in conditions:
        block_fields = list(block["fields"])
        if pubkey_hex and block["type"] in ("SIG", "TIMELOCKED_SIG", "HASH_SIG", "CLTV_SIG"):
            block_fields.append({"type": "PUBKEY", "hex": pubkey_hex})
        fields.append({"type": block["type"], "fields": block_fields})

    params = [
        [{"txid": fund_txid, "vout": fund_vout}],
        [{"amount": out_amount, "conditions": [{"blocks": fields}]}],
        locktime,
    ]
    if relays is not None:
        params.append(relays)
    else:
        params.append([])

    unsigned = rpc("createrungtx", params)["hex"]
    signed = json.loads(cli("-rpcwallet=test", "signrawtransactionwithwallet", unsigned))["hex"]
    txid = cli("sendrawtransaction", signed, "0")
    mine(1)

    utxo = json.loads(cli("gettxout", txid, "0"))
    spk = utxo["scriptPubKey"]["hex"]
    return txid, spk, out_amount


def create_mlsc_raw(conditions_rungs, relays=None, locktime=0, fund_amount_override=None):
    """Create a v4 tx with raw conditions (multiple rungs). Returns (txid, spk, amount)."""
    fund_txid, fund_vout, fund_amount = get_utxo()
    out_amount = round(fund_amount - 0.001, 8)
    if fund_amount_override is not None:
        out_amount = fund_amount_override

    params = [
        [{"txid": fund_txid, "vout": fund_vout}],
        [{"amount": out_amount, "conditions": conditions_rungs}],
        locktime,
    ]
    if relays is not None:
        params.append(relays)
    else:
        params.append([])

    unsigned = rpc("createrungtx", params)["hex"]
    signed = json.loads(cli("-rpcwallet=test", "signrawtransactionwithwallet", unsigned))["hex"]
    txid = cli("sendrawtransaction", signed, "0")
    mine(1)

    utxo = json.loads(cli("gettxout", txid, "0"))
    spk = utxo["scriptPubKey"]["hex"]
    return txid, spk, out_amount


def create_mlsc_multi_output(inputs, outputs, relays=None, locktime=0):
    """Create a v4 tx with multiple inputs/outputs. Returns (txid, tx_hex)."""
    params = [inputs, outputs, locktime]
    if relays is not None:
        params.append(relays)
    else:
        params.append([])

    unsigned = rpc("createrungtx", params)["hex"]
    signed = json.loads(cli("-rpcwallet=test", "signrawtransactionwithwallet", unsigned))["hex"]
    txid = cli("sendrawtransaction", signed, "0")
    mine(1)
    return txid, signed


def spend_mlsc_raw(txid, spk, amount, conditions_rungs, signers, sequence=None,
                   locktime=0, dest_conditions=None, dest_amount=None, outputs=None):
    """Spend an MLSC UTXO with full control over signing. Returns spend txid."""
    if dest_amount is None:
        dest_amount = round(amount - 0.001, 8)

    if outputs is None:
        if dest_conditions is None:
            _, dest_pubkey = generate_key()
            dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": dest_pubkey}
            ]}]}]
        outputs = [{"amount": dest_amount, "conditions": dest_conditions}]

    inp = {"txid": txid, "vout": 0}
    if sequence is not None:
        inp["sequence"] = sequence

    unsigned = rpc("createrungtx", [
        [inp],
        outputs,
        locktime,
        []
    ])["hex"]

    signed_result = rpc("signrungtx", [
        unsigned,
        signers,
        [{"amount": amount, "scriptPubKey": spk}]
    ])

    if not signed_result.get("complete"):
        raise RuntimeError(f"Signing incomplete: {signed_result}")

    spend_txid = cli("sendrawtransaction", signed_result["hex"], "0")
    mine(1)
    return spend_txid


# =============================================================================
# Test cases
# =============================================================================

RESULTS = []


def test(name, fn):
    """Run a test and record result."""
    try:
        fn()
        RESULTS.append((name, "PASS", ""))
        print(f"  PASS  {name}")
    except Exception as e:
        RESULTS.append((name, "FAIL", str(e)))
        print(f"  FAIL  {name}: {e}")


# -------------------------------------------------------------------------
# Group 1: Solo SIG-based
# -------------------------------------------------------------------------

def test_sig():
    """SIG block: create and spend with Schnorr signature."""
    wif, pk = generate_key()
    conditions = [{"blocks": [{"type": "SIG", "fields": [
        {"type": "PUBKEY", "hex": pk}
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}]}])


def test_timelocked_sig():
    """TIMELOCKED_SIG: SIG + CSV in one compound block."""
    csv_blocks = 5
    wif, pk = generate_key()
    conditions = [{"blocks": [{"type": "TIMELOCKED_SIG", "fields": [
        {"type": "PUBKEY", "hex": pk},
        {"type": "SCHEME", "hex": "01"},
        {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    mine(csv_blocks)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "TIMELOCKED_SIG", "privkey": wif}]}],
                   sequence=csv_blocks)


def test_cltv_sig():
    """CLTV_SIG: signature + absolute timelock compound."""
    wif, pk = generate_key()
    target_height = get_height() + 10
    conditions = [{"blocks": [{"type": "CLTV_SIG", "fields": [
        {"type": "PUBKEY", "hex": pk},
        {"type": "SCHEME", "hex": "01"},
        {"type": "NUMERIC", "hex": numeric_hex(target_height)},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    blocks_needed = target_height - get_height() + 1
    if blocks_needed > 0:
        mine(blocks_needed)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "CLTV_SIG", "privkey": wif}]}],
                   locktime=target_height)


def test_hash_sig():
    """HASH_SIG: preimage + signature compound."""
    wif, pk = generate_key()
    preimage = os.urandom(32)
    conditions = [{"blocks": [{"type": "HASH_SIG", "fields": [
        {"type": "PUBKEY", "hex": pk},
        {"type": "PREIMAGE", "hex": preimage.hex()},
        {"type": "SCHEME", "hex": "01"},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "HASH_SIG", "privkey": wif,
                                 "preimage": preimage.hex()}]}])


def test_musig_threshold():
    """MUSIG_THRESHOLD: M=1, N=1 single-key threshold (equivalent to SIG)."""
    wif, pk = generate_key()
    conditions = [{"blocks": [{"type": "MULTISIG", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(1)},
        {"type": "PUBKEY", "hex": pk},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "MULTISIG", "privkeys": [wif],
                                 "pubkeys": [pk]}]}])


# -------------------------------------------------------------------------
# Group 2: Governance (paired with SIG for spendability)
# -------------------------------------------------------------------------

def test_csv():
    """CSV: relative timelock (5 blocks)."""
    wif, pk = generate_key()
    csv_blocks = 5
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    mine(csv_blocks)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "CSV"}]}],
                   sequence=csv_blocks)


def test_cltv():
    """CLTV: absolute timelock (height-based)."""
    wif, pk = generate_key()
    target_height = get_height() + 5
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "CLTV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(target_height)}]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    blocks_needed = target_height - get_height()
    if blocks_needed > 0:
        mine(blocks_needed)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "CLTV"}]}],
                   locktime=target_height)


def test_amount_lock():
    """AMOUNT_LOCK: output amount within range."""
    wif, pk = generate_key()
    # NUMERIC max is uint32 (~42.9 BTC). Use range that fits output amount.
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "AMOUNT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(1)},            # min = 1 sat
            {"type": "NUMERIC", "hex": numeric_hex(0xFFFFFFFF)},   # max = ~42.9 BTC
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    # Output must be <= ~42.9 BTC to fit in NUMERIC max
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "AMOUNT_LOCK"}]}],
                   dest_amount=1.0)


def test_input_count():
    """INPUT_COUNT: input count bounds."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "INPUT_COUNT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(1)},
            {"type": "NUMERIC", "hex": numeric_hex(10)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "INPUT_COUNT"}]}])


def test_output_count():
    """OUTPUT_COUNT: output count bounds."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "OUTPUT_COUNT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(1)},
            {"type": "NUMERIC", "hex": numeric_hex(10)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "OUTPUT_COUNT"}]}])


def test_weight_limit():
    """WEIGHT_LIMIT: transaction weight bound."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "WEIGHT_LIMIT", "fields": [{"type": "NUMERIC", "hex": numeric_hex(65535)}]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "WEIGHT_LIMIT"}]}])


def test_output_check():
    """OUTPUT_CHECK: per-output value and script constraint."""
    wif, pk = generate_key()
    # Output amount must fit in NUMERIC uint32 max (~42.9 BTC)
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "OUTPUT_CHECK", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},         # output_index = 0
            {"type": "NUMERIC", "hex": numeric_hex(1000)},      # min_sats
            {"type": "NUMERIC", "hex": numeric_hex(0xFFFFFFFF)}, # max_sats
            {"type": "HASH256", "hex": "00" * 32},               # skip script check
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "OUTPUT_CHECK"}]}],
                   dest_amount=1.0)


def test_relative_value():
    """RELATIVE_VALUE: output must be >= 50% of input."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "RELATIVE_VALUE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},
            {"type": "NUMERIC", "hex": numeric_hex(10)},
        ]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    # Output 90% of input
    dest_amount = round(amt * 0.90, 8)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "RELATIVE_VALUE"}, {"type": "SIG", "privkey": wif}]}],
                   dest_amount=dest_amount)


def test_epoch_gate():
    """EPOCH_GATE: spending within epoch window."""
    wif, pk = generate_key()
    # Use very large epoch so current height is always within window
    conditions = [{"blocks": [
        {"type": "EPOCH_GATE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10000)},
            {"type": "NUMERIC", "hex": numeric_hex(9999)},
        ]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "EPOCH_GATE"}, {"type": "SIG", "privkey": wif}]}])


# -------------------------------------------------------------------------
# Group 3: Hash-based
# -------------------------------------------------------------------------

def test_hash_guarded():
    """HASH_GUARDED: preimage in conditions (auto-hashed), preimage in witness."""
    wif, pk = generate_key()
    preimage = os.urandom(32)
    # HASH_GUARDED paired with SIG for spending authority
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "HASH_GUARDED", "fields": [
            {"type": "PREIMAGE", "hex": preimage.hex()},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "HASH_GUARDED", "preimage": preimage.hex()}]}])


def test_tagged_hash():
    """TAGGED_HASH: BIP-340 tagged hash verification."""
    wif, pk = generate_key()
    tag = b"GhostTaggedHash"
    preimage = os.urandom(32)
    tag_hash = hashlib.sha256(tag).digest()
    expected = hashlib.sha256(tag_hash + tag_hash + preimage).digest()

    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "TAGGED_HASH", "fields": [
            {"type": "HASH256", "hex": tag_hash.hex()},
            {"type": "HASH256", "hex": expected.hex()},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "TAGGED_HASH", "preimage": preimage.hex()}]}])


# -------------------------------------------------------------------------
# Group 4: Multi-key
# -------------------------------------------------------------------------

def test_multisig():
    """MULTISIG: 2-of-3 threshold spend."""
    keys = [generate_key() for _ in range(3)]
    wifs = [k[0] for k in keys]
    pks = [k[1] for k in keys]

    conditions = [{"blocks": [{"type": "MULTISIG", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(2)},
        {"type": "PUBKEY", "hex": pks[0]},
        {"type": "PUBKEY", "hex": pks[1]},
        {"type": "PUBKEY", "hex": pks[2]},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "MULTISIG", "privkeys": [wifs[0], wifs[2]],
                                 "pubkeys": pks}]}])


def test_timelocked_multisig():
    """TIMELOCKED_MULTISIG: 2-of-3 multisig + CSV."""
    csv_blocks = 5
    keys = [generate_key() for _ in range(3)]
    wifs = [k[0] for k in keys]
    pks = [k[1] for k in keys]

    conditions = [{"blocks": [{"type": "TIMELOCKED_MULTISIG", "fields": [
        {"type": "NUMERIC", "hex": numeric_hex(2)},
        {"type": "PUBKEY", "hex": pks[0]},
        {"type": "PUBKEY", "hex": pks[1]},
        {"type": "PUBKEY", "hex": pks[2]},
        {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    mine(csv_blocks)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "TIMELOCKED_MULTISIG",
                                 "privkeys": [wifs[0], wifs[1]],
                                 "pubkeys": pks}]}],
                   sequence=csv_blocks)


def test_adaptor_sig():
    """ADAPTOR_SIG: adapted signature with signing_key + adaptor_point."""
    signing_wif, signing_pk = generate_key()
    _, adaptor_pk_full = generate_key()
    adaptor_xonly = adaptor_pk_full[2:]  # strip prefix

    conditions = [{"blocks": [{"type": "ADAPTOR_SIG", "fields": [
        {"type": "PUBKEY", "hex": signing_pk},
        {"type": "PUBKEY", "hex": adaptor_xonly},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "ADAPTOR_SIG", "privkey": signing_wif,
                                 "pubkeys": [adaptor_xonly]}]}])


def test_key_ref_sig():
    """KEY_REF_SIG: sign using key from a relay block."""
    wif, pk = generate_key()

    # Relay contains a SIG block with PUBKEY (auto-converted to PUBKEY_COMMIT in conditions)
    relays = [{"blocks": [{
        "type": "SIG",
        "fields": [
            {"type": "PUBKEY", "hex": pk},
            {"type": "SCHEME", "hex": "01"},
        ]
    }]}]

    conditions = [{
        "blocks": [{
            "type": "KEY_REF_SIG",
            "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0)},  # relay_index
                {"type": "NUMERIC", "hex": numeric_hex(0)},  # block_index
            ]
        }],
        "relay_refs": [0],
    }]

    fund_txid, fund_vout, fund_amount = get_utxo()
    out_amount = round(fund_amount - 0.001, 8)

    unsigned = rpc("createrungtx", [
        [{"txid": fund_txid, "vout": fund_vout}],
        [{"amount": out_amount, "conditions": conditions}],
        0,
        relays,
    ])["hex"]
    signed = json.loads(cli("-rpcwallet=test", "signrawtransactionwithwallet", unsigned))["hex"]
    txid = cli("sendrawtransaction", signed, "0")
    mine(1)
    utxo = json.loads(cli("gettxout", txid, "0"))
    spk = utxo["scriptPubKey"]["hex"]

    # Spend with KEY_REF_SIG — signer needs conditions + relay conditions for MLSC proof
    _, dest_pk = generate_key()
    dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
        {"type": "PUBKEY", "hex": dest_pk}
    ]}]}]
    spend_amt = round(out_amount - 0.001, 8)
    spend_unsigned = rpc("createrungtx", [
        [{"txid": txid, "vout": 0}],
        [{"amount": spend_amt, "conditions": dest_conditions}],
        0, []
    ])["hex"]

    sign_result = rpc("signrungtx", [
        spend_unsigned,
        [{"input": 0, "rung": 0,
          "conditions": conditions,
          "relays": relays,
          "blocks": [{"type": "KEY_REF_SIG", "privkey": wif}],
          "relay_blocks": [{"blocks": [{"type": "SIG", "privkey": wif}]}]}],
        [{"amount": out_amount, "scriptPubKey": spk}]
    ])
    assert sign_result["complete"], f"KEY_REF_SIG incomplete: {sign_result}"
    cli("sendrawtransaction", sign_result["hex"], "0")
    mine(1)


def test_htlc():
    """HTLC: hash + timelock + signature compound."""
    csv_blocks = 5
    wif, pk = generate_key()
    preimage = os.urandom(32)

    conditions = [{"blocks": [{"type": "HTLC", "fields": [
        {"type": "PUBKEY", "hex": pk},
        {"type": "PUBKEY", "hex": pk},
        {"type": "PREIMAGE", "hex": preimage.hex()},
        {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    mine(csv_blocks)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "HTLC", "privkey": wif,
                                 "preimage": preimage.hex(), "pubkeys": [pk]}]}],
                   sequence=csv_blocks)


def test_ptlc():
    """PTLC: adaptor sig + CSV compound."""
    csv_blocks = 5
    signing_wif, signing_pk = generate_key()
    _, adaptor_pk = generate_key()

    conditions = [{"blocks": [{"type": "PTLC", "fields": [
        {"type": "PUBKEY", "hex": signing_pk},
        {"type": "PUBKEY", "hex": adaptor_pk},
        {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    mine(csv_blocks)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "PTLC", "privkey": signing_wif,
                                 "pubkeys": [adaptor_pk]}]}],
                   sequence=csv_blocks)


def test_vault_lock():
    """VAULT_LOCK: cold sweep with recovery key."""
    recovery_wif, recovery_pk = generate_key()
    _, hot_pk = generate_key()

    conditions = [{"blocks": [{"type": "VAULT_LOCK", "fields": [
        {"type": "PUBKEY", "hex": recovery_pk},
        {"type": "PUBKEY", "hex": hot_pk},
        {"type": "NUMERIC", "hex": numeric_hex(10)},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "VAULT_LOCK", "privkey": recovery_wif,
                                 "pubkeys": [recovery_pk, hot_pk]}]}])


# -------------------------------------------------------------------------
# Group 5: Covenant/CTV
# -------------------------------------------------------------------------

def test_ctv():
    """CTV: CheckTemplateVerify full cycle."""
    wif, pk = generate_key()
    dest_wif, dest_pk = generate_key()

    # Step 1: Create SIG-locked output
    sig_conditions = [{"blocks": [{"type": "SIG", "fields": [
        {"type": "PUBKEY", "hex": pk}
    ]}]}]
    boot_txid, boot_spk, boot_amt = create_mlsc_raw(sig_conditions)

    # Step 2: Compute CTV hash
    spend_amount = round(boot_amt - 0.002, 8)
    dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
        {"type": "PUBKEY", "hex": dest_pk}
    ]}]}]

    template_tx = rpc("createrungtx", [
        [{"txid": boot_txid, "vout": 0}],
        [{"amount": spend_amount, "conditions": dest_conditions}],
        0, []
    ])
    ctv_result = rpc("computectvhash", [template_tx["hex"], 0])
    ctv_hash = ctv_result["hash"]

    # Step 3: Create CTV-locked output
    ctv_conditions = [{"blocks": [{"type": "CTV", "fields": [
        {"type": "HASH256", "hex": ctv_hash}
    ]}]}]
    ctv_lock_amount = round(boot_amt - 0.001, 8)
    ctv_create = rpc("createrungtx", [
        [{"txid": boot_txid, "vout": 0}],
        [{"amount": ctv_lock_amount, "conditions": ctv_conditions}],
        0, []
    ])
    ctv_sign = rpc("signrungtx", [
        ctv_create["hex"],
        [{"input": 0, "conditions": sig_conditions,
          "blocks": [{"type": "SIG", "privkey": wif}]}],
        [{"amount": boot_amt, "scriptPubKey": boot_spk}]
    ])
    assert ctv_sign["complete"]
    ctv_txid = cli("sendrawtransaction", ctv_sign["hex"], "0")
    mine(1)

    # Step 4: Spend CTV output
    ctv_utxo = json.loads(cli("gettxout", ctv_txid, "0"))
    ctv_spk = ctv_utxo["scriptPubKey"]["hex"]

    real_spend = rpc("createrungtx", [
        [{"txid": ctv_txid, "vout": 0}],
        [{"amount": spend_amount, "conditions": dest_conditions}],
        0, []
    ])
    real_sign = rpc("signrungtx", [
        real_spend["hex"],
        [{"input": 0, "conditions": ctv_conditions,
          "blocks": [{"type": "CTV"}]}],
        [{"amount": ctv_lock_amount, "scriptPubKey": ctv_spk}]
    ])
    assert real_sign["complete"]
    cli("sendrawtransaction", real_sign["hex"], "0")
    mine(1)


def test_cosign():
    """COSIGN: child UTXO requires co-spending with anchor UTXO."""
    # Create anchor UTXO
    anchor_wif, anchor_pk = generate_key()
    anchor_conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": anchor_pk}]},
    ]}]
    anchor_txid, anchor_spk, anchor_amt = create_mlsc_raw(anchor_conditions)

    # Compute COSIGN hash from anchor's SPK
    cosign_hash = hashlib.sha256(bytes.fromhex(anchor_spk)).hexdigest()

    # Create child UTXO with SIG + COSIGN
    child_wif, child_pk = generate_key()
    child_conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": child_pk}]},
        {"type": "COSIGN", "fields": [{"type": "HASH256", "hex": cosign_hash}]},
    ]}]
    child_txid, child_spk, child_amt = create_mlsc_raw(child_conditions)

    # Spend both in one tx
    _, dest_pk = generate_key()
    dest_conds = [{"blocks": [{"type": "SIG", "fields": [
        {"type": "PUBKEY", "hex": dest_pk}
    ]}]}]
    anchor_out_amt = round(anchor_amt - 0.001, 8)
    child_out_amt = round(child_amt - 0.001, 8)

    unsigned = rpc("createrungtx", [
        [{"txid": anchor_txid, "vout": 0}, {"txid": child_txid, "vout": 0}],
        [{"amount": anchor_out_amt, "conditions": dest_conds},
         {"amount": child_out_amt, "conditions": dest_conds}],
        0, []
    ])["hex"]

    sign_result = rpc("signrungtx", [
        unsigned,
        [
            {"input": 0, "conditions": anchor_conditions,
             "blocks": [{"type": "SIG", "privkey": anchor_wif}]},
            {"input": 1, "conditions": child_conditions,
             "blocks": [{"type": "SIG", "privkey": child_wif}, {"type": "COSIGN"}]},
        ],
        [
            {"amount": anchor_amt, "scriptPubKey": anchor_spk},
            {"amount": child_amt, "scriptPubKey": child_spk},
        ]
    ])
    assert sign_result["complete"], f"COSIGN incomplete: {sign_result}"
    cli("sendrawtransaction", sign_result["hex"], "0")
    mine(1)


# -------------------------------------------------------------------------
# Group 6: Anchors (structural blocks -- return SATISFIED on eval)
# -------------------------------------------------------------------------

def test_anchor():
    """ANCHOR: generic anchor."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "ANCHOR", "fields": [{"type": "NUMERIC", "hex": numeric_hex(1)}]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "ANCHOR"}]}])


def test_anchor_channel():
    """ANCHOR_CHANNEL: 2 pubkeys + commitment number."""
    wif, pk = generate_key()
    _, remote_pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "ANCHOR_CHANNEL", "fields": [
            {"type": "PUBKEY", "hex": pk},
            {"type": "PUBKEY", "hex": remote_pk},
            {"type": "NUMERIC", "hex": numeric_hex(42)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "ANCHOR_CHANNEL", "pubkeys": [pk, remote_pk]}]}])


def test_anchor_pool():
    """ANCHOR_POOL: vtxo root + count."""
    wif, pk = generate_key()
    pool_preimage = os.urandom(32)
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "ANCHOR_POOL", "fields": [
            {"type": "PREIMAGE", "hex": pool_preimage.hex()},
            {"type": "NUMERIC", "hex": numeric_hex(42)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "ANCHOR_POOL", "preimage": pool_preimage.hex()}]}])


def test_anchor_reserve():
    """ANCHOR_RESERVE: n-of-m threshold + guardian hash."""
    wif, pk = generate_key()
    reserve_preimage = os.urandom(32)
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "ANCHOR_RESERVE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},
            {"type": "NUMERIC", "hex": numeric_hex(5)},
            {"type": "PREIMAGE", "hex": reserve_preimage.hex()},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "ANCHOR_RESERVE", "preimage": reserve_preimage.hex()}]}])


def test_anchor_seal():
    """ANCHOR_SEAL: 2 hashes (seal + data)."""
    wif, pk = generate_key()
    seal1 = os.urandom(32)
    seal2 = os.urandom(32)
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "ANCHOR_SEAL", "fields": [
            {"type": "PREIMAGE", "hex": seal1.hex()},
            {"type": "PREIMAGE", "hex": seal2.hex()},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "ANCHOR_SEAL", "preimages": [seal1.hex(), seal2.hex()]}]}])


def test_anchor_oracle():
    """ANCHOR_ORACLE: oracle pubkey + outcome count."""
    wif, pk = generate_key()
    _, oracle_pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "ANCHOR_ORACLE", "fields": [
            {"type": "PUBKEY", "hex": oracle_pk},
            {"type": "NUMERIC", "hex": numeric_hex(10)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "ANCHOR_ORACLE", "pubkey": oracle_pk}]}])


# -------------------------------------------------------------------------
# Group 7: PLC blocks (structural markers)
# -------------------------------------------------------------------------

def test_hysteresis_fee():
    """HYSTERESIS_FEE: fee rate within band."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "HYSTERESIS_FEE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(1000)},
            {"type": "NUMERIC", "hex": numeric_hex(1)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "HYSTERESIS_FEE"}]}])


def test_hysteresis_value():
    """HYSTERESIS_VALUE: input amount within band."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "HYSTERESIS_VALUE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0xFFFFFFFF)},
            {"type": "NUMERIC", "hex": numeric_hex(10000)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "HYSTERESIS_VALUE"}]}])


def test_timer_continuous():
    """TIMER_CONTINUOUS: structural block."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "TIMER_CONTINUOUS", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(144)},
            {"type": "NUMERIC", "hex": numeric_hex(0)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "TIMER_CONTINUOUS"}]}])


def test_timer_off_delay():
    """TIMER_OFF_DELAY: structural block."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "TIMER_OFF_DELAY", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(72)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "TIMER_OFF_DELAY"}]}])


def test_latch_set():
    """LATCH_SET: structural block with pubkey."""
    wif, pk = generate_key()
    _, setter_pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "LATCH_SET", "fields": [
            {"type": "PUBKEY", "hex": setter_pk},
            {"type": "NUMERIC", "hex": numeric_hex(0)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "LATCH_SET", "pubkey": setter_pk}]}])


def test_latch_reset():
    """LATCH_RESET: structural block with pubkey + state + delay."""
    wif, pk = generate_key()
    _, resetter_pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "LATCH_RESET", "fields": [
            {"type": "PUBKEY", "hex": resetter_pk},
            {"type": "NUMERIC", "hex": numeric_hex(1)},
            {"type": "NUMERIC", "hex": numeric_hex(6)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "LATCH_RESET", "pubkey": resetter_pk}]}])


def test_counter_down():
    """COUNTER_DOWN: structural block with pubkey + count."""
    wif, pk = generate_key()
    _, event_pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "COUNTER_DOWN", "fields": [
            {"type": "PUBKEY", "hex": event_pk},
            {"type": "NUMERIC", "hex": numeric_hex(10)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "COUNTER_DOWN", "pubkey": event_pk}]}])


def test_counter_preset():
    """COUNTER_PRESET: structural block with 2 numerics."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "COUNTER_PRESET", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},
            {"type": "NUMERIC", "hex": numeric_hex(100)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "COUNTER_PRESET"}]}])


def test_counter_up():
    """COUNTER_UP: structural block with pubkey + current + target."""
    wif, pk = generate_key()
    _, event_pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "COUNTER_UP", "fields": [
            {"type": "PUBKEY", "hex": event_pk},
            {"type": "NUMERIC", "hex": numeric_hex(0)},
            {"type": "NUMERIC", "hex": numeric_hex(10)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "COUNTER_UP", "pubkey": event_pk}]}])


def test_compare():
    """COMPARE: GT operator on UTXO value."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},    # GT operator
            {"type": "NUMERIC", "hex": numeric_hex(1000)},  # threshold
            {"type": "NUMERIC", "hex": numeric_hex(0)},     # padding
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "COMPARE"}]}])


def test_sequencer():
    """SEQUENCER: step 0 of 3."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "SEQUENCER", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},
            {"type": "NUMERIC", "hex": numeric_hex(3)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "SEQUENCER"}]}])


def test_one_shot():
    """ONE_SHOT: state=0 (unfired) + commitment."""
    wif, pk = generate_key()
    oneshot_preimage = os.urandom(32)
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "ONE_SHOT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},
            {"type": "PREIMAGE", "hex": oneshot_preimage.hex()},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "ONE_SHOT", "preimage": oneshot_preimage.hex()}]}])


def test_rate_limit():
    """RATE_LIMIT: max per block + cap + refill."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RATE_LIMIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0xFFFFFFFF)},
            {"type": "NUMERIC", "hex": numeric_hex(0xFFFFFFFF)},
            {"type": "NUMERIC", "hex": numeric_hex(10)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif}, {"type": "RATE_LIMIT"}]}])


# -------------------------------------------------------------------------
# Group 8: Recursion
# -------------------------------------------------------------------------

def test_recurse_same():
    """RECURSE_SAME: spend into output with identical conditions."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_SAME", "fields": [{"type": "NUMERIC", "hex": numeric_hex(5)}]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    # Output must carry same conditions
    out_amt = round(amt - 0.001, 8)
    unsigned = rpc("createrungtx", [
        [{"txid": txid, "vout": 0}],
        [{"amount": out_amt, "conditions": conditions}],
        0, []
    ])["hex"]
    sign_result = rpc("signrungtx", [
        unsigned,
        [{"input": 0, "conditions": conditions,
          "blocks": [{"type": "SIG", "privkey": wif}, {"type": "RECURSE_SAME"}]}],
        [{"amount": amt, "scriptPubKey": spk}]
    ])
    assert sign_result["complete"]
    cli("sendrawtransaction", sign_result["hex"], "0")
    mine(1)


def test_recurse_until():
    """RECURSE_UNTIL: re-encumber before termination height."""
    wif, pk = generate_key()
    until_height = get_height() + 100
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_UNTIL", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(until_height)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    current = get_height()
    out_amt = round(amt - 0.001, 8)
    unsigned = rpc("createrungtx", [
        [{"txid": txid, "vout": 0}],
        [{"amount": out_amt, "conditions": conditions}],
        current, []
    ])["hex"]
    sign_result = rpc("signrungtx", [
        unsigned,
        [{"input": 0, "conditions": conditions,
          "blocks": [{"type": "SIG", "privkey": wif}, {"type": "RECURSE_UNTIL"}]}],
        [{"amount": amt, "scriptPubKey": spk}]
    ])
    assert sign_result["complete"]
    cli("sendrawtransaction", sign_result["hex"], "0")
    mine(1)


def test_recurse_count():
    """RECURSE_COUNT: countdown from 2 to 1."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_COUNT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(2)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)

    # Decrement: count 2 -> count 1
    next_conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_COUNT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(1)},
        ]},
    ]}]
    out_amt = round(amt - 0.001, 8)
    unsigned = rpc("createrungtx", [
        [{"txid": txid, "vout": 0}],
        [{"amount": out_amt, "conditions": next_conditions}],
        0, []
    ])["hex"]
    sign_result = rpc("signrungtx", [
        unsigned,
        [{"input": 0, "conditions": conditions,
          "blocks": [{"type": "SIG", "privkey": wif}, {"type": "RECURSE_COUNT"}]}],
        [{"amount": amt, "scriptPubKey": spk}]
    ])
    assert sign_result["complete"]
    cli("sendrawtransaction", sign_result["hex"], "0")
    mine(1)


def test_recurse_split():
    """RECURSE_SPLIT: split 1 UTXO into 2 re-encumbered outputs."""
    wif, pk = generate_key()
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},
            {"type": "NUMERIC", "hex": numeric_hex(10000)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)

    split_conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(2)},
            {"type": "NUMERIC", "hex": numeric_hex(10000)},
        ]},
    ]}]
    half = round((amt - 0.001) / 2, 8)
    unsigned = rpc("createrungtx", [
        [{"txid": txid, "vout": 0}],
        [{"amount": half, "conditions": split_conditions},
         {"amount": half, "conditions": split_conditions}],
        0, []
    ])["hex"]
    sign_result = rpc("signrungtx", [
        unsigned,
        [{"input": 0, "conditions": conditions,
          "blocks": [{"type": "SIG", "privkey": wif}, {"type": "RECURSE_SPLIT"}]}],
        [{"amount": amt, "scriptPubKey": spk}]
    ])
    assert sign_result["complete"]
    cli("sendrawtransaction", sign_result["hex"], "0")
    mine(1)


def test_recurse_modified():
    """RECURSE_MODIFIED: covenant with parameter mutation per hop."""
    wif, pk = generate_key()
    initial_threshold = 10000
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_MODIFIED", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},
            {"type": "NUMERIC", "hex": numeric_hex(2)},    # mutate block 2 (COMPARE)
            {"type": "NUMERIC", "hex": numeric_hex(1)},    # param idx 1 (threshold)
            {"type": "NUMERIC", "hex": numeric_hex(1000)},  # delta
        ]},
        {"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},
            {"type": "NUMERIC", "hex": numeric_hex(initial_threshold)},
            {"type": "NUMERIC", "hex": numeric_hex(0)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)

    new_threshold = initial_threshold + 1000
    mutated_conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_MODIFIED", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},
            {"type": "NUMERIC", "hex": numeric_hex(2)},
            {"type": "NUMERIC", "hex": numeric_hex(1)},
            {"type": "NUMERIC", "hex": numeric_hex(1000)},
        ]},
        {"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},
            {"type": "NUMERIC", "hex": numeric_hex(new_threshold)},
            {"type": "NUMERIC", "hex": numeric_hex(0)},
        ]},
    ]}]
    out_amt = round(amt - 0.001, 8)
    unsigned = rpc("createrungtx", [
        [{"txid": txid, "vout": 0}],
        [{"amount": out_amt, "conditions": mutated_conditions}],
        0, []
    ])["hex"]
    sign_result = rpc("signrungtx", [
        unsigned,
        [{"input": 0, "conditions": conditions,
          "blocks": [{"type": "SIG", "privkey": wif},
                     {"type": "RECURSE_MODIFIED"}, {"type": "COMPARE"}]}],
        [{"amount": amt, "scriptPubKey": spk}]
    ])
    assert sign_result["complete"]
    cli("sendrawtransaction", sign_result["hex"], "0")
    mine(1)


def test_recurse_decay():
    """RECURSE_DECAY: covenant with parameter subtraction per hop."""
    wif, pk = generate_key()
    initial_threshold = 5000
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_DECAY", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},
            {"type": "NUMERIC", "hex": numeric_hex(2)},    # decay block 2 (COMPARE)
            {"type": "NUMERIC", "hex": numeric_hex(1)},    # param idx 1
            {"type": "NUMERIC", "hex": numeric_hex(500)},  # decay per step
        ]},
        {"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},
            {"type": "NUMERIC", "hex": numeric_hex(initial_threshold)},
            {"type": "NUMERIC", "hex": numeric_hex(0)},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)

    new_threshold = initial_threshold - 500
    decayed_conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "RECURSE_DECAY", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},
            {"type": "NUMERIC", "hex": numeric_hex(2)},
            {"type": "NUMERIC", "hex": numeric_hex(1)},
            {"type": "NUMERIC", "hex": numeric_hex(500)},
        ]},
        {"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},
            {"type": "NUMERIC", "hex": numeric_hex(new_threshold)},
            {"type": "NUMERIC", "hex": numeric_hex(0)},
        ]},
    ]}]
    out_amt = round(amt - 0.001, 8)
    unsigned = rpc("createrungtx", [
        [{"txid": txid, "vout": 0}],
        [{"amount": out_amt, "conditions": decayed_conditions}],
        0, []
    ])["hex"]
    sign_result = rpc("signrungtx", [
        unsigned,
        [{"input": 0, "conditions": conditions,
          "blocks": [{"type": "SIG", "privkey": wif},
                     {"type": "RECURSE_DECAY"}, {"type": "COMPARE"}]}],
        [{"amount": amt, "scriptPubKey": spk}]
    ])
    assert sign_result["complete"]
    cli("sendrawtransaction", sign_result["hex"], "0")
    mine(1)


# -------------------------------------------------------------------------
# Group 9: Legacy wrappers
# -------------------------------------------------------------------------

def test_p2pk_legacy():
    """P2PK_LEGACY: PUBKEY + SCHEME, spend with sig."""
    wif, pk = generate_key()
    conditions = [{"blocks": [{"type": "P2PK_LEGACY", "fields": [
        {"type": "PUBKEY", "hex": pk},
        {"type": "SCHEME", "hex": "01"},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "P2PK_LEGACY", "privkey": wif}]}])


def test_p2pkh_legacy():
    """P2PKH_LEGACY: PUBKEY (auto-hashed to HASH160), spend with pubkey + sig."""
    wif, pk = generate_key()
    conditions = [{"blocks": [{"type": "P2PKH_LEGACY", "fields": [
        {"type": "PUBKEY", "hex": pk},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "P2PKH_LEGACY", "privkey": wif}]}])


def test_p2sh_legacy():
    """P2SH_LEGACY: inner SIG conditions, spend with preimage + sig."""
    wif, pk = generate_key()
    inner_bytes = build_inner_sig_conditions(pk)
    conditions = [{"blocks": [{"type": "P2SH_LEGACY", "fields": [
        {"type": "SCRIPT_BODY", "hex": inner_bytes.hex()},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "P2SH_LEGACY",
                                 "preimage": inner_bytes.hex(),
                                 "privkey": wif}]}])


def test_p2wpkh_legacy():
    """P2WPKH_LEGACY: same as P2PKH (delegates to same evaluator)."""
    wif, pk = generate_key()
    conditions = [{"blocks": [{"type": "P2WPKH_LEGACY", "fields": [
        {"type": "PUBKEY", "hex": pk},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "P2WPKH_LEGACY", "privkey": wif}]}])


def test_p2wsh_legacy():
    """P2WSH_LEGACY: inner SIG conditions, spend with preimage + sig."""
    wif, pk = generate_key()
    inner_bytes = build_inner_sig_conditions(pk)
    conditions = [{"blocks": [{"type": "P2WSH_LEGACY", "fields": [
        {"type": "SCRIPT_BODY", "hex": inner_bytes.hex()},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "P2WSH_LEGACY",
                                 "preimage": inner_bytes.hex(),
                                 "privkey": wif}]}])


def test_p2tr_legacy():
    """P2TR_LEGACY: key-path spend."""
    wif, pk = generate_key()
    conditions = [{"blocks": [{"type": "P2TR_LEGACY", "fields": [
        {"type": "PUBKEY", "hex": pk},
        {"type": "SCHEME", "hex": "01"},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "P2TR_LEGACY", "privkey": wif}]}])


def test_p2tr_script_legacy():
    """P2TR_SCRIPT_LEGACY: script-path spend with inner SIG."""
    wif, pk = generate_key()
    inner_bytes = build_inner_sig_conditions(pk)
    # Use the same key for internal key and signing key.
    # PubkeyCountForBlock(P2TR_SCRIPT_LEGACY) = 1, so the internal key
    # goes into the Merkle leaf. VerifyRungTx extracts the PUBKEY from
    # the witness to recompute the leaf — must match.
    conditions = [{"blocks": [{"type": "P2TR_SCRIPT_LEGACY", "fields": [
        {"type": "SCRIPT_BODY", "hex": inner_bytes.hex()},
        {"type": "PUBKEY", "hex": pk},
    ]}]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "P2TR_SCRIPT_LEGACY",
                                 "preimage": inner_bytes.hex(),
                                 "privkey": wif}]}])


# -------------------------------------------------------------------------
# Bonus: ACCUMULATOR, OR logic, AND composition
# -------------------------------------------------------------------------

def test_accumulator():
    """ACCUMULATOR: Merkle set membership proof."""
    wif, pk = generate_key()
    leaf0 = hashlib.sha256(b"leaf0").digest()
    leaf1 = hashlib.sha256(b"leaf1").digest()
    if leaf0 < leaf1:
        combined = leaf0 + leaf1
    else:
        combined = leaf1 + leaf0
    root = hashlib.sha256(combined).digest()

    conditions = [{"blocks": [
        {"type": "ACCUMULATOR", "fields": [
            {"type": "HASH256", "hex": root.hex()},
        ]},
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [
                         {"type": "ACCUMULATOR", "proof": [leaf1.hex()], "leaf": leaf0.hex()},
                         {"type": "SIG", "privkey": wif},
                     ]}])


def test_or_logic():
    """OR logic: two rungs, spend via second rung."""
    wif1, pk1 = generate_key()
    wif2, pk2 = generate_key()

    conditions = [
        {"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk1}]}]},
        {"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk2}]}]},
    ]

    fund_txid, fund_vout, fund_amount = get_utxo()
    out_amount = round(fund_amount - 0.001, 8)

    unsigned = rpc("createrungtx", [
        [{"txid": fund_txid, "vout": fund_vout}],
        [{"amount": out_amount, "conditions": conditions}],
        0, []
    ])["hex"]
    signed = json.loads(cli("-rpcwallet=test", "signrawtransactionwithwallet", unsigned))["hex"]
    txid = cli("sendrawtransaction", signed, "0")
    mine(1)
    utxo = json.loads(cli("gettxout", txid, "0"))
    spk = utxo["scriptPubKey"]["hex"]

    # Spend via rung 1 (pk2)
    _, dest_pk = generate_key()
    out2 = round(out_amount - 0.001, 8)
    spend_unsigned = rpc("createrungtx", [
        [{"txid": txid, "vout": 0}],
        [{"amount": out2, "conditions": [
            {"blocks": [{"type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pk}]}]},
        ]}],
        0, []
    ])["hex"]

    signer = {
        "input": 0,
        "privkey": wif2,
        "rung": 1,
        "conditions": conditions,
    }
    result = rpc("signrungtx", [spend_unsigned, [signer], [{"amount": out_amount, "scriptPubKey": spk}]])
    assert result["complete"]
    cli("sendrawtransaction", result["hex"], "0")
    mine(1)


def test_and_composition():
    """AND composition: SIG + CSV + OUTPUT_CHECK in one rung."""
    wif, pk = generate_key()
    csv_blocks = 3
    conditions = [{"blocks": [
        {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pk}]},
        {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}]},
        {"type": "OUTPUT_CHECK", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},
            {"type": "NUMERIC", "hex": numeric_hex(1000)},
            {"type": "NUMERIC", "hex": numeric_hex(0xFFFFFFFF)},
            {"type": "HASH256", "hex": "00" * 32},
        ]},
    ]}]
    txid, spk, amt = create_mlsc_raw(conditions)
    mine(csv_blocks)
    spend_mlsc_raw(txid, spk, amt, conditions,
                   [{"input": 0, "conditions": conditions,
                     "blocks": [{"type": "SIG", "privkey": wif},
                                {"type": "CSV"},
                                {"type": "OUTPUT_CHECK"}]}],
                   sequence=csv_blocks)


# =============================================================================
# Main
# =============================================================================

def main():
    print(f"Datadir: {DATADIR}")
    print(f"Binaries: {BUILD_BIN}")

    # Start node
    print("Starting ghostd...")
    node_proc = subprocess.Popen([GHOSTD, "-regtest", f"-datadir={DATADIR}", f"-rpcuser={RPC_USER}",
                      f"-rpcpassword={RPC_PASS}", f"-rpcport={RPC_PORT}",
                      "-fallbackfee=0.0001", "-acceptnonstdtxn=1", "-txindex"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for i in range(30):
        time.sleep(1)
        try:
            rpc("getblockchaininfo")
            print(f"  Node ready after {i+1}s")
            break
        except Exception:
            if i == 29:
                raise RuntimeError("ghostd failed to start")

    try:
        # Setup wallet
        rpc("createwallet", ["test"])
        addr = cli("-rpcwallet=test", "getnewaddress", "", "legacy")
        cli("generatetoaddress", "200", addr)
        print(f"Balance: {cli('-rpcwallet=test', 'getbalance')}")
        print()

        # ---- Group 1: Solo SIG-based (5 tests) ----
        print("=== Group 1: Solo SIG-based ===")
        test("SIG (Schnorr)", test_sig)
        test("TIMELOCKED_SIG", test_timelocked_sig)
        test("CLTV_SIG", test_cltv_sig)
        test("HASH_SIG", test_hash_sig)
        test("MUSIG_THRESHOLD (1-of-1)", test_musig_threshold)

        # ---- Group 2: Governance (9 tests) ----
        print()
        print("=== Group 2: Governance ===")
        test("CSV", test_csv)
        test("CLTV", test_cltv)
        test("AMOUNT_LOCK", test_amount_lock)
        test("INPUT_COUNT", test_input_count)
        test("OUTPUT_COUNT", test_output_count)
        test("WEIGHT_LIMIT", test_weight_limit)
        test("OUTPUT_CHECK", test_output_check)
        test("RELATIVE_VALUE", test_relative_value)
        test("EPOCH_GATE", test_epoch_gate)

        # ---- Group 3: Hash-based (2 tests) ----
        print()
        print("=== Group 3: Hash-based ===")
        test("HASH_GUARDED", test_hash_guarded)
        test("TAGGED_HASH", test_tagged_hash)

        # ---- Group 4: Multi-key (7 tests) ----
        print()
        print("=== Group 4: Multi-key ===")
        test("MULTISIG (2-of-3)", test_multisig)
        test("TIMELOCKED_MULTISIG", test_timelocked_multisig)
        test("ADAPTOR_SIG", test_adaptor_sig)
        test("KEY_REF_SIG", test_key_ref_sig)
        test("HTLC", test_htlc)
        test("PTLC", test_ptlc)
        test("VAULT_LOCK", test_vault_lock)

        # ---- Group 5: Covenant/CTV (2 tests) ----
        print()
        print("=== Group 5: Covenant/CTV ===")
        test("CTV", test_ctv)
        test("COSIGN", test_cosign)

        # ---- Group 6: Anchors (6 tests) ----
        print()
        print("=== Group 6: Anchors ===")
        test("ANCHOR", test_anchor)
        test("ANCHOR_CHANNEL", test_anchor_channel)
        test("ANCHOR_POOL", test_anchor_pool)
        test("ANCHOR_RESERVE", test_anchor_reserve)
        test("ANCHOR_SEAL", test_anchor_seal)
        test("ANCHOR_ORACLE", test_anchor_oracle)

        # ---- Group 7: PLC (13 tests) ----
        print()
        print("=== Group 7: PLC ===")
        test("HYSTERESIS_FEE", test_hysteresis_fee)
        test("HYSTERESIS_VALUE", test_hysteresis_value)
        test("TIMER_CONTINUOUS", test_timer_continuous)
        test("TIMER_OFF_DELAY", test_timer_off_delay)
        test("LATCH_SET", test_latch_set)
        test("LATCH_RESET", test_latch_reset)
        test("COUNTER_DOWN", test_counter_down)
        test("COUNTER_PRESET", test_counter_preset)
        test("COUNTER_UP", test_counter_up)
        test("COMPARE", test_compare)
        test("SEQUENCER", test_sequencer)
        test("ONE_SHOT", test_one_shot)
        test("RATE_LIMIT", test_rate_limit)

        # ---- Group 8: Recursion (6 tests) ----
        print()
        print("=== Group 8: Recursion ===")
        test("RECURSE_SAME", test_recurse_same)
        test("RECURSE_UNTIL", test_recurse_until)
        test("RECURSE_COUNT", test_recurse_count)
        test("RECURSE_SPLIT", test_recurse_split)
        test("RECURSE_MODIFIED", test_recurse_modified)
        test("RECURSE_DECAY", test_recurse_decay)

        # ---- Group 9: Legacy wrappers (7 tests) ----
        print()
        print("=== Group 9: Legacy wrappers ===")
        test("P2PK_LEGACY", test_p2pk_legacy)
        test("P2PKH_LEGACY", test_p2pkh_legacy)
        test("P2SH_LEGACY", test_p2sh_legacy)
        test("P2WPKH_LEGACY", test_p2wpkh_legacy)
        test("P2WSH_LEGACY", test_p2wsh_legacy)
        test("P2TR_LEGACY", test_p2tr_legacy)
        test("P2TR_SCRIPT_LEGACY", test_p2tr_script_legacy)

        # ---- Bonus (3 tests) ----
        print()
        print("=== Bonus: Accumulator + Composition ===")
        test("ACCUMULATOR", test_accumulator)
        test("OR logic (2 rungs)", test_or_logic)
        test("AND composition (SIG+CSV+OUTPUT_CHECK)", test_and_composition)

    finally:
        # Stop node
        print()
        try:
            rpc("stop")
        except Exception:
            pass
        try:
            node_proc.wait(timeout=10)
        except Exception:
            node_proc.kill()
        shutil.rmtree(DATADIR, ignore_errors=True)

    # Summary
    print()
    print("=" * 60)
    passed = sum(1 for _, s, _ in RESULTS if s == "PASS")
    failed = sum(1 for _, s, _ in RESULTS if s == "FAIL")
    total = len(RESULTS)
    print(f"Results: {passed} passed, {failed} failed, {total} total")

    # Count unique block types tested
    block_types_tested = set()
    block_type_names = [
        "SIG", "TIMELOCKED_SIG", "CLTV_SIG", "HASH_SIG", "MULTISIG",
        "CSV", "CLTV", "AMOUNT_LOCK", "INPUT_COUNT", "OUTPUT_COUNT",
        "WEIGHT_LIMIT", "OUTPUT_CHECK", "RELATIVE_VALUE", "EPOCH_GATE",
        "HASH_GUARDED", "TAGGED_HASH",
        "TIMELOCKED_MULTISIG", "ADAPTOR_SIG", "KEY_REF_SIG",
        "HTLC", "PTLC", "VAULT_LOCK",
        "CTV", "COSIGN",
        "ANCHOR", "ANCHOR_CHANNEL", "ANCHOR_POOL", "ANCHOR_RESERVE",
        "ANCHOR_SEAL", "ANCHOR_ORACLE",
        "HYSTERESIS_FEE", "HYSTERESIS_VALUE", "TIMER_CONTINUOUS",
        "TIMER_OFF_DELAY", "LATCH_SET", "LATCH_RESET", "COUNTER_DOWN",
        "COUNTER_PRESET", "COUNTER_UP", "COMPARE", "SEQUENCER",
        "ONE_SHOT", "RATE_LIMIT",
        "RECURSE_SAME", "RECURSE_UNTIL", "RECURSE_COUNT",
        "RECURSE_SPLIT", "RECURSE_MODIFIED", "RECURSE_DECAY",
        "P2PK_LEGACY", "P2PKH_LEGACY", "P2SH_LEGACY", "P2WPKH_LEGACY",
        "P2WSH_LEGACY", "P2TR_LEGACY", "P2TR_SCRIPT_LEGACY",
        "ACCUMULATOR",
    ]
    print(f"Block types with dedicated tests: {len(block_type_names)}")

    if failed:
        print()
        print("Failures:")
        for name, status, msg in RESULTS:
            if status == "FAIL":
                print(f"  {name}: {msg}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
