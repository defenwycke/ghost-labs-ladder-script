"""
Ladder Script Signet Proxy

Thin FastAPI service that wraps ghost-core RPC commands for the Ladder Script
Builder. Runs on the same VM as ghostd, proxying browser requests to localhost
RPC with rate limiting and input validation.

Endpoints:
  POST /api/ladder/create     - createrungtx (build v4 tx from JSON)
  POST /api/ladder/sign       - signrungtx (sign with wallet keys)
  POST /api/ladder/broadcast   - sendrawtransaction (push to signet)
  POST /api/ladder/decode      - decoderung (decode ladder hex)
  POST /api/ladder/validate    - validateladder (validate structure)
  GET  /api/ladder/tx/{txid}  - getrawtransaction (lookup tx)
  POST /api/ladder/faucet      - fund a test address from faucet wallet
  GET  /api/ladder/status      - proxy health + chain info
"""

import hashlib
import hmac as hmac_mod
import json
import os
import struct
import time
from collections import defaultdict
from contextlib import asynccontextmanager

import coincurve
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# --- Config ---

RPC_BASE = os.environ.get("RPC_URL", "http://127.0.0.1:18443")
RPC_URL = RPC_BASE
RPC_WALLET_URL = RPC_BASE + "/wallet/" + os.environ.get("RPC_WALLET", "ladder")
RPC_USER = os.environ.get("RPC_USER", "ghostrpc")
RPC_PASS = os.environ.get("RPC_PASS", "ghost_signet_rpc_2024")
FAUCET_AMOUNT = float(os.environ.get("FAUCET_AMOUNT", "0.001"))
FAUCET_COOLDOWN = int(os.environ.get("FAUCET_COOLDOWN", "300"))  # seconds per IP
RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", "120"))  # requests per minute
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS", "https://bitcoinghost.org,https://www.bitcoinghost.org,http://localhost:8080,http://127.0.0.1:8080"
).split(",")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8801"))

# --- Rate limiter ---

_rate_buckets: dict[str, list[float]] = defaultdict(list)
_faucet_last: dict[str, float] = {}


def _check_rate_limit(ip: str) -> None:
    now = time.time()
    bucket = _rate_buckets[ip]
    # Prune entries older than 60s
    _rate_buckets[ip] = [t for t in bucket if now - t < 60]
    if len(_rate_buckets[ip]) >= RATE_LIMIT_RPM:
        raise HTTPException(429, "Rate limit exceeded. Try again in a minute.")
    _rate_buckets[ip].append(now)


def _check_faucet_cooldown(ip: str) -> None:
    now = time.time()
    last = _faucet_last.get(ip, 0)
    remaining = int(FAUCET_COOLDOWN - (now - last))
    if remaining > 0:
        raise HTTPException(429, f"Faucet cooldown: {remaining}s remaining.")


# --- RPC client ---

_http_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _http_client
    _http_client = httpx.AsyncClient(timeout=30.0)
    yield
    await _http_client.aclose()


WALLET_METHODS = {
    "getbalance", "getbalances", "getwalletinfo", "getnewaddress",
    "listunspent", "sendtoaddress", "signrawtransactionwithwallet",
    "signrungtx", "createrungtx", "validateaddress", "generatetoaddress",
    "getaddressinfo", "listdescriptors",
}


# --- BIP32 key derivation (for descriptor wallets that lack dumpprivkey) ---

_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_master_privkey: bytes | None = None
_master_chaincode: bytes | None = None


def _b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58_ALPHABET.index(c)
    result = []
    while n > 0:
        n, r = divmod(n, 256)
        result.insert(0, r)
    pad = len(s) - len(s.lstrip('1'))
    return bytes(pad) + bytes(result)


def _b58decode_check(s: str) -> bytes:
    data = _b58decode(s)
    payload, checksum = data[:-4], data[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("Bad base58 checksum")
    return payload


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    result = ''
    while n > 0:
        n, r = divmod(n, 58)
        result = _B58_ALPHABET[r] + result
    for b in data:
        if b == 0:
            result = '1' + result
        else:
            break
    return result


def _parse_xprv(xprv_str: str) -> tuple[bytes, bytes]:
    data = _b58decode_check(xprv_str)
    chain_code = data[13:45]
    privkey = data[46:78]
    return privkey, chain_code


def _derive_child(privkey: bytes, chain_code: bytes, index: int, hardened: bool = False) -> tuple[bytes, bytes]:
    if hardened:
        index += 0x80000000
        data = b'\x00' + privkey + struct.pack('>I', index)
    else:
        pubkey = coincurve.PublicKey.from_secret(privkey).format(compressed=True)
        data = pubkey + struct.pack('>I', index)
    I = hmac_mod.new(chain_code, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    child_int = (int.from_bytes(IL, 'big') + int.from_bytes(privkey, 'big')) % _SECP256K1_N
    return child_int.to_bytes(32, 'big'), IR


def _derive_path(privkey: bytes, chain_code: bytes, path: str) -> bytes:
    """Derive a child private key from a BIP32 path like m/84'/1'/0'/0/22."""
    parts = path.strip().lstrip('m').lstrip('/').split('/')
    for part in parts:
        hardened = part.endswith("'") or part.endswith("h")
        idx = int(part.rstrip("'h"))
        privkey, chain_code = _derive_child(privkey, chain_code, idx, hardened)
    return privkey


def _privkey_to_wif(privkey: bytes, testnet: bool = True) -> str:
    prefix = b'\xef' if testnet else b'\x80'
    payload = prefix + privkey + b'\x01'  # compressed
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return _b58encode(payload + checksum)


async def _ensure_master_key():
    """Fetch and cache the master xprv from the wallet's descriptors."""
    global _master_privkey, _master_chaincode
    if _master_privkey is not None:
        return
    descriptors = await rpc_call("listdescriptors", [True])
    # Find the wpkh descriptor (bech32 = m/84'/1'/0')
    for desc in descriptors.get("descriptors", []):
        desc_str = desc.get("desc", "")
        if desc_str.startswith("wpkh(tprv") and not desc.get("internal", False):
            # Extract xprv from wpkh(tprv.../*)
            xprv = desc_str.split("wpkh(")[1].split("/")[0]
            _master_privkey, _master_chaincode = _parse_xprv(xprv)
            return
    raise HTTPException(500, "Could not find wpkh descriptor with private key.")


async def rpc_call(method: str, params=None):
    if params is None:
        params = []
    payload = {
        "jsonrpc": "1.0",
        "id": "ladder-proxy",
        "method": method,
        "params": params,
    }
    url = RPC_WALLET_URL if method in WALLET_METHODS else RPC_URL
    try:
        resp = await _http_client.post(
            url,
            json=payload,
            auth=(RPC_USER, RPC_PASS),
            headers={"Content-Type": "application/json"},
        )
    except httpx.ConnectError:
        raise HTTPException(503, "Ghost node unavailable.")
    except httpx.TimeoutException:
        raise HTTPException(504, "Ghost node timeout.")

    if resp.status_code == 401:
        raise HTTPException(503, "RPC authentication failed.")
    if resp.status_code not in (200, 404, 500):
        raise HTTPException(502, f"RPC error: HTTP {resp.status_code}")

    data = resp.json()
    if data.get("error"):
        err = data["error"]
        raise HTTPException(
            400, {"rpc_error": err.get("message", str(err)), "code": err.get("code")}
        )
    return data.get("result")


# --- Validation helpers ---

MAX_JSON_SIZE = 32_768  # 32KB max request body
MAX_HEX_SIZE = 65_536  # 64KB max hex string


def _validate_hex(value: str, name: str, max_len: int = MAX_HEX_SIZE) -> str:
    if not isinstance(value, str):
        raise HTTPException(400, f"{name} must be a string.")
    value = value.strip()
    if len(value) > max_len:
        raise HTTPException(400, f"{name} too large (max {max_len} chars).")
    if not all(c in "0123456789abcdefABCDEF" for c in value):
        raise HTTPException(400, f"{name} must be valid hex.")
    return value


def _validate_txid(txid: str) -> str:
    txid = _validate_hex(txid, "txid", 64)
    if len(txid) != 64:
        raise HTTPException(400, "txid must be 64 hex characters.")
    return txid


# --- App ---

app = FastAPI(title="Ladder Script Proxy", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=3600,
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.method != "OPTIONS":
        ip = request.headers.get("X-Real-IP", request.client.host)
        try:
            _check_rate_limit(ip)
        except HTTPException as exc:
            # Must include CORS headers on 429 responses — otherwise the browser
            # treats the missing Access-Control-Allow-Origin as a network error
            # ("Failed to fetch") instead of showing the actual 429 status.
            origin = request.headers.get("origin", "")
            headers = {}
            if origin in ALLOWED_ORIGINS:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                headers["Access-Control-Allow-Headers"] = "Content-Type"
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=headers,
            )
    return await call_next(request)


# --- Endpoints ---


@app.get("/api/ladder/status")
async def status():
    """Proxy health + chain info."""
    info = await rpc_call("getblockchaininfo")
    return {
        "status": "ok",
        "chain": info.get("chain"),
        "blocks": info.get("blocks"),
        "bestblockhash": info.get("bestblockhash"),
    }


@app.post("/api/ladder/create")
async def create_rungtx(request: Request):
    """Build a v4 ladder transaction from JSON spec."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    if not isinstance(data, dict):
        raise HTTPException(400, "Request must be a JSON object.")

    inputs = data.get("inputs", [])
    outputs = data.get("outputs", [])
    locktime = data.get("locktime", 0)
    relays = data.get("relays")

    params = [inputs, outputs, locktime]
    if relays:
        params.append(relays)

    result = await rpc_call("createrungtx", params)
    # RPC returns {"hex": "..."} — unwrap if needed
    if isinstance(result, dict) and "hex" in result:
        return {"hex": result["hex"]}
    return {"hex": result}


@app.post("/api/ladder/sign")
async def sign_rungtx(request: Request):
    """Sign a v4 ladder transaction."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    tx_hex = data.get("hex", "")
    tx_hex = _validate_hex(tx_hex, "hex")
    if not tx_hex:
        raise HTTPException(400, "Missing 'hex' field.")

    signers = data.get("signers")
    spent_outputs = data.get("spent_outputs")

    if not signers or not spent_outputs:
        raise HTTPException(400, "Missing 'signers' and/or 'spent_outputs'. "
                            "Use FUND FROM WALLET to set up signing data.")

    result = await rpc_call("signrungtx", [tx_hex, signers, spent_outputs])
    return result


@app.post("/api/ladder/broadcast")
async def broadcast(request: Request):
    """Broadcast a signed transaction to signet."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    tx_hex = data.get("hex", "")
    tx_hex = _validate_hex(tx_hex, "hex")
    if not tx_hex:
        raise HTTPException(400, "Missing 'hex' field.")

    # maxfeerate=0 disables fee-rate check — this is signet/regtest, not mainnet
    txid = await rpc_call("sendrawtransaction", [tx_hex, 0])
    return {"txid": txid}


@app.post("/api/ladder/decode")
async def decode(request: Request):
    """Decode a ladder witness or conditions hex string."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    hex_str = data.get("hex", "")
    hex_str = _validate_hex(hex_str, "hex")
    if not hex_str:
        raise HTTPException(400, "Missing 'hex' field.")

    result = await rpc_call("decoderung", [hex_str])
    return result


@app.post("/api/ladder/validate")
async def validate(request: Request):
    """Validate a ladder structure."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    hex_str = data.get("hex", "")
    hex_str = _validate_hex(hex_str, "hex")
    if not hex_str:
        raise HTTPException(400, "Missing 'hex' field.")

    result = await rpc_call("validateladder", [hex_str])
    return result


@app.get("/api/ladder/tx/{txid}")
async def get_tx(txid: str):
    """Look up a transaction by txid."""
    txid = _validate_txid(txid)
    result = await rpc_call("getrawtransaction", [txid, True])
    return result


@app.post("/api/ladder/faucet")
async def faucet(request: Request):
    """Send test sats to an address from the faucet wallet."""
    ip = request.headers.get("X-Real-IP", request.client.host)
    _check_faucet_cooldown(ip)

    body = await request.body()
    if len(body) > 4096:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    address = data.get("address", "").strip()
    if not address or not isinstance(address, str):
        raise HTTPException(400, "Missing 'address' field.")
    if len(address) > 128:
        raise HTTPException(400, "Address too long.")

    # Validate address via RPC
    addr_info = await rpc_call("validateaddress", [address])
    if not addr_info.get("isvalid"):
        raise HTTPException(400, "Invalid signet address.")

    txid = await rpc_call("sendtoaddress", [address, FAUCET_AMOUNT])
    _faucet_last[ip] = time.time()
    return {"txid": txid, "amount": FAUCET_AMOUNT}


# --- Wallet & chain info endpoints ---


@app.get("/api/ladder/wallet/balance")
async def wallet_balance():
    """Get wallet balance info."""
    balance = await rpc_call("getbalance")
    balances = await rpc_call("getbalances")
    unconfirmed = balances.get("mine", {}).get("untrusted_pending", 0) if balances else 0
    info = await rpc_call("getwalletinfo")
    return {
        "balance": balance,
        "unconfirmed_balance": unconfirmed,
        "txcount": info.get("txcount"),
    }


@app.get("/api/ladder/wallet/address")
async def wallet_address():
    """Generate a new bech32 receiving address."""
    address = await rpc_call("getnewaddress", ["", "bech32"])
    return {"address": address}


@app.get("/api/ladder/wallet/keypair")
async def wallet_keypair():
    """Generate a new address and return its pubkey + privkey (descriptor wallet)."""
    await _ensure_master_key()
    address = await rpc_call("getnewaddress", ["", "bech32"])
    info = await rpc_call("getaddressinfo", [address])
    pubkey = info.get("pubkey", "")
    hdkeypath = info.get("hdkeypath", "")
    if not hdkeypath:
        raise HTTPException(500, "Address has no HD key path.")
    child_privkey = _derive_path(_master_privkey, _master_chaincode, hdkeypath)
    # Verify derivation matches
    derived_pub = coincurve.PublicKey.from_secret(child_privkey).format(compressed=True).hex()
    if derived_pub != pubkey:
        raise HTTPException(500, f"Key derivation mismatch: got {derived_pub}, expected {pubkey}")
    wif = _privkey_to_wif(child_privkey)
    return {"address": address, "pubkey": pubkey, "privkey": wif}


@app.get("/api/ladder/wallet/utxos")
async def wallet_utxos():
    """List unspent transaction outputs."""
    result = await rpc_call("listunspent", [0, 9999999])
    return result


@app.post("/api/ladder/decode-tx")
async def decode_tx(request: Request):
    """Decode a raw transaction hex string."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    hex_str = data.get("hex", "")
    hex_str = _validate_hex(hex_str, "hex")
    if not hex_str:
        raise HTTPException(400, "Missing 'hex' field.")

    result = await rpc_call("decoderawtransaction", [hex_str])
    return result


@app.get("/api/ladder/mempool")
async def mempool():
    """Get mempool info."""
    info = await rpc_call("getmempoolinfo")
    return {
        "size": info.get("size"),
        "bytes": info.get("bytes"),
        "usage": info.get("usage"),
        "maxmempool": info.get("maxmempool"),
        "mempoolminfee": info.get("mempoolminfee"),
    }


@app.get("/api/ladder/blocks/recent")
async def blocks_recent():
    """Get the 5 most recent blocks."""
    height = await rpc_call("getblockcount")
    blocks = []
    for h in range(height, max(height - 5, -1), -1):
        block_hash = await rpc_call("getblockhash", [h])
        block = await rpc_call("getblock", [block_hash, 1])
        blocks.append({
            "height": block.get("height"),
            "hash": block.get("hash"),
            "time": block.get("time"),
            "tx_count": len(block.get("tx", [])),
            "size": block.get("size"),
            "txids": block.get("tx", []),
        })
    return blocks


@app.post("/api/ladder/pq/keypair")
async def pq_keypair(request: Request):
    """Generate a post-quantum keypair for the specified scheme."""
    body = await request.body()
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}

    scheme = data.get("scheme", "FALCON512")
    valid_schemes = {"FALCON512", "FALCON1024", "DILITHIUM3", "SPHINCS_SHA"}
    if scheme not in valid_schemes:
        raise HTTPException(400, f"Invalid PQ scheme. Use one of: {', '.join(sorted(valid_schemes))}")

    result = await rpc_call("generatepqkeypair", [scheme])
    # Compute pubkey_commit (SHA-256 of raw pubkey bytes)
    pubkey_hex = result.get("pubkey", "")
    if pubkey_hex:
        commit = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()
        result["pubkey_commit"] = commit
    return result


def _ripemd160(data: bytes) -> bytes:
    """Pure-Python RIPEMD-160 (OpenSSL 3.x disabled legacy hashes)."""
    # Constants
    _f = [lambda x, y, z: x ^ y ^ z, lambda x, y, z: (x & y) | (~x & z),
          lambda x, y, z: (x | ~y) ^ z, lambda x, y, z: (x & z) | (y & ~z),
          lambda x, y, z: x ^ (y | ~z)]
    _K1 = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    _K2 = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    _R1 = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
           3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
           4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    _R2 = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
           15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
           12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    _S1 = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
           11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
           9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    _S2 = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
           9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
           8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]
    M = 0xFFFFFFFF
    rl = lambda v, n: ((v << n) | (v >> (32 - n))) & M
    msg = bytearray(data)
    l = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', l)
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    for i in range(0, len(msg), 64):
        X = list(struct.unpack('<16L', msg[i:i+64]))
        a1, b1, c1, d1, e1 = h0, h1, h2, h3, h4
        a2, b2, c2, d2, e2 = h0, h1, h2, h3, h4
        for j in range(80):
            rnd = j >> 4
            t = (a1 + _f[rnd](b1, c1, d1) + X[_R1[j]] + _K1[rnd]) & M
            t = (rl(t, _S1[j]) + e1) & M
            a1, e1, d1, c1, b1 = e1, d1, rl(c1, 10), b1, t
            t = (a2 + _f[4 - rnd](b2, c2, d2) + X[_R2[j]] + _K2[rnd]) & M
            t = (rl(t, _S2[j]) + e2) & M
            a2, e2, d2, c2, b2 = e2, d2, rl(c2, 10), b2, t
        t = (h1 + c1 + d2) & M
        h1 = (h2 + d1 + e2) & M
        h2 = (h3 + e1 + a2) & M
        h3 = (h4 + a1 + b2) & M
        h4 = (h0 + b1 + c2) & M
        h0 = t
    return struct.pack('<5L', h0, h1, h2, h3, h4)


@app.get("/api/ladder/preimage")
async def generate_preimage():
    """Generate a random 32-byte preimage and return its SHA256 and HASH160 hashes."""
    preimage = os.urandom(32)
    sha256_hash = hashlib.sha256(preimage).digest()
    hash160 = _ripemd160(sha256_hash)
    return {
        "preimage": preimage.hex(),
        "sha256": sha256_hash.hex(),
        "hash160": hash160.hex(),
    }


@app.post("/api/ladder/mine")
async def mine_blocks(request: Request):
    """Mine blocks on regtest (for local testing only)."""
    body = await request.body()
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}

    n_blocks = min(int(data.get("blocks", 1)), 200)  # cap at 200 for CSV satisfaction
    address = data.get("address", "")

    if not address:
        address = await rpc_call("getnewaddress", ["", "bech32"])

    result = await rpc_call("generatetoaddress", [n_blocks, address])
    return {"blocks_mined": len(result), "hashes": result}


# --- Entry point ---

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT)
