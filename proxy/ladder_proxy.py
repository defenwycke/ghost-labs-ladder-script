"""
Ladder Script Signet Proxy

Thin FastAPI service that wraps ghost-core RPC commands for the Ladder Script
Builder. Runs on the same VM as ghostd, proxying browser requests to localhost
RPC with rate limiting and input validation.

Endpoints:
  POST /api/ladder/create     - createrungtx (build v3 tx from JSON)
  POST /api/ladder/sign       - signrungtx (sign with wallet keys)
  POST /api/ladder/broadcast   - sendrawtransaction (push to signet)
  POST /api/ladder/decode      - decoderung (decode ladder hex)
  POST /api/ladder/validate    - validateladder (validate structure)
  GET  /api/ladder/tx/{txid}  - getrawtransaction (lookup tx)
  POST /api/ladder/faucet      - fund a test address from faucet wallet
  GET  /api/ladder/status      - proxy health + chain info
"""

import json
import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# --- Config ---

RPC_URL = os.environ.get("RPC_URL", "http://127.0.0.1:38332")
RPC_USER = os.environ.get("RPC_USER", "ghostrpc")
RPC_PASS = os.environ.get("RPC_PASS", "ghost_signet_rpc_2024")
FAUCET_AMOUNT = float(os.environ.get("FAUCET_AMOUNT", "0.001"))
FAUCET_COOLDOWN = int(os.environ.get("FAUCET_COOLDOWN", "300"))  # seconds per IP
RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", "30"))  # requests per minute
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS", "https://bitcoinghost.org,https://www.bitcoinghost.org"
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


async def rpc_call(method: str, params=None):
    if params is None:
        params = []
    payload = {
        "jsonrpc": "1.0",
        "id": "ladder-proxy",
        "method": method,
        "params": params,
    }
    try:
        resp = await _http_client.post(
            RPC_URL,
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
    if resp.status_code != 200:
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
        _check_rate_limit(ip)
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
    """Build a v3 ladder transaction from JSON spec."""
    body = await request.body()
    if len(body) > MAX_JSON_SIZE:
        raise HTTPException(400, "Request too large.")
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON.")

    if not isinstance(data, dict):
        raise HTTPException(400, "Request must be a JSON object.")

    result = await rpc_call("createrungtx", [json.dumps(data)])
    return {"hex": result}


@app.post("/api/ladder/sign")
async def sign_rungtx(request: Request):
    """Sign a v3 ladder transaction."""
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

    result = await rpc_call("signrungtx", [tx_hex])
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

    txid = await rpc_call("sendrawtransaction", [tx_hex])
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
    info = await rpc_call("getwalletinfo")
    return {
        "balance": info.get("balance"),
        "unconfirmed_balance": info.get("unconfirmed_balance"),
        "txcount": info.get("txcount"),
    }


@app.get("/api/ladder/wallet/address")
async def wallet_address():
    """Generate a new bech32 receiving address."""
    address = await rpc_call("getnewaddress", ["", "bech32"])
    return {"address": address}


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
        })
    return blocks


# --- Entry point ---

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=LISTEN_HOST, port=LISTEN_PORT)
