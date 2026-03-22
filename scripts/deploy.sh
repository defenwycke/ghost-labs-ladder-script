#!/bin/bash
set -euo pipefail

# Deploy Ladder Script components to production.
#
# Targets:
#   binary  — ghostd to signet node (ghost-labs / 85.9.213.194)
#   proxy   — ladder-proxy to signet node
#   web     — engine + block-docs to web server (ghost-web / 83.136.255.218)
#   all     — all of the above
#   smoke   — just run the smoke test
#
# Usage: ./scripts/deploy.sh [binary|proxy|web|all|smoke]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$ROOT/ghost-core/build"

SIGNET_HOST="ghost-labs"
WEB_HOST="ghost-web"
WEB_ROOT="/var/www/bitcoinghost/labs"
SMOKE_URL="https://bitcoinghost.org/api/ladder/status"

TARGET="${1:-all}"

# ── Helpers ──────────────────────────────────────────────────────────────

confirm() {
    local msg="$1"
    printf "\n%s [y/N] " "$msg"
    read -r answer
    case "$answer" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

deploy_file_to_web() {
    local local_path="$1"
    local remote_path="$2"
    cat "$local_path" | ssh "$WEB_HOST" "sudo tee $remote_path > /dev/null"
    ssh "$WEB_HOST" "sudo chown www-data:www-data $remote_path && sudo chmod 644 $remote_path"
}

# ── Deploy binary to signet node ─────────────────────────────────────────

deploy_binary() {
    # Find binary
    local binary=""
    for name in ghost ghostd; do
        if [ -f "$BUILD_DIR/bin/$name" ]; then
            binary="$BUILD_DIR/bin/$name"
            break
        fi
    done
    if [ -z "$binary" ]; then
        echo "ERROR: No binary found. Run ./scripts/build.sh first."
        exit 1
    fi

    local size
    size=$(stat -c%s "$binary")
    echo "=== Deploy binary to signet node ==="
    echo "  Binary: $binary ($(( size / 1024 / 1024 ))MB)"
    echo "  Target: $SIGNET_HOST"
    confirm "Stop ghostd, replace binary, restart, and load wallet?" || return 0

    echo ""
    echo "--- Stopping ghostd ---"
    ssh "$SIGNET_HOST" "ghost-cli -signet stop 2>/dev/null || true"
    sleep 3

    echo "--- Uploading binary ---"
    scp "$binary" "$SIGNET_HOST:/tmp/ghostd-new"

    echo "--- Replacing and restarting ---"
    ssh "$SIGNET_HOST" bash <<'REMOTE'
set -euo pipefail
sudo systemctl stop ghostd 2>/dev/null || true
sleep 2
sudo cp /tmp/ghostd-new /usr/local/bin/ghostd
sudo chmod 755 /usr/local/bin/ghostd
rm /tmp/ghostd-new
sudo systemctl start ghostd
echo "Waiting for ghostd to start..."
sleep 5
# Load wallet
ghost-cli -signet loadwallet "ladder-test" 2>/dev/null || echo "(wallet already loaded or not found)"
echo "ghostd restarted."
ghost-cli -signet getblockchaininfo | head -5
REMOTE

    echo ""
    echo "Binary deployed to signet node."
}

# ── Deploy proxy to signet node ──────────────────────────────────────────

deploy_proxy() {
    echo "=== Deploy ladder-proxy to signet node ==="
    confirm "Update and restart ladder-proxy on $SIGNET_HOST?" || return 0

    echo "--- Uploading proxy files ---"
    scp "$ROOT/proxy/ladder_proxy.py" \
        "$ROOT/proxy/requirements.txt" \
        "$ROOT/proxy/ladder-proxy.service" \
        "$SIGNET_HOST:/tmp/"

    ssh "$SIGNET_HOST" bash <<'REMOTE'
set -euo pipefail
sudo cp /tmp/ladder_proxy.py /opt/ghost/ladder-proxy/
sudo cp /tmp/requirements.txt /opt/ghost/ladder-proxy/
sudo chown -R ghost:ghost /opt/ghost/ladder-proxy
sudo -u ghost /opt/ghost/ladder-proxy/venv/bin/pip install -q -r /opt/ghost/ladder-proxy/requirements.txt
sudo cp /tmp/ladder-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart ladder-proxy
sleep 2
sudo systemctl status ladder-proxy --no-pager | head -10
REMOTE

    echo ""
    echo "Proxy deployed."
}

# ── Deploy engine + block-docs to web server ─────────────────────────────

deploy_web() {
    echo "=== Deploy engine + block-docs to web server ==="
    confirm "Deploy engine and block-docs to $WEB_HOST?" || return 0

    # Engine
    echo ""
    echo "--- Deploying ladder-engine ---"
    local engine="$ROOT/tools/ladder-engine/index.html"
    if [ -f "$engine" ]; then
        deploy_file_to_web "$engine" "$WEB_ROOT/engine/index.html"
        echo "  engine/index.html deployed"
    else
        echo "  WARNING: $engine not found, skipping"
    fi

    # Block-docs (deploy to BOTH paths)
    echo ""
    echo "--- Deploying block-docs ---"
    local block_docs="$ROOT/tools/block-docs"
    if [ -d "$block_docs" ]; then
        # Ensure remote directories exist
        ssh "$WEB_HOST" "sudo mkdir -p $WEB_ROOT/block-docs $WEB_ROOT/docs/blocks"

        local count=0
        for f in "$block_docs"/*.html "$block_docs"/*.css; do
            [ -f "$f" ] || continue
            local base
            base="$(basename "$f")"
            deploy_file_to_web "$f" "$WEB_ROOT/block-docs/$base"
            deploy_file_to_web "$f" "$WEB_ROOT/docs/blocks/$base"
            count=$((count + 1))
        done
        echo "  $count files deployed to both block-docs/ and docs/blocks/"
    else
        echo "  WARNING: $block_docs not found, skipping"
    fi

    # Docs SPA
    echo ""
    echo "--- Deploying docs SPA ---"
    local docs_index="$ROOT/tools/docs/index.html"
    if [ -f "$docs_index" ]; then
        deploy_file_to_web "$docs_index" "$WEB_ROOT/docs/index.html"
        echo "  docs/index.html deployed"
    fi

    # Landing page and other tools
    for page in ladder-script.html ladder-engine.html get-started.html \
                 rung-tx-anatomy.html patch-overview.html explorer.html; do
        local src="$ROOT/tools/$page"
        if [ -f "$src" ]; then
            deploy_file_to_web "$src" "$WEB_ROOT/$page"
            echo "  $page deployed"
        fi
    done

    echo ""
    echo "Web deployment complete."
}

# ── Smoke test ───────────────────────────────────────────────────────────

smoke_test() {
    echo "=== Smoke test ==="
    echo "  Checking: $SMOKE_URL"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$SMOKE_URL" 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ]; then
        echo "  Status: OK (HTTP 200)"
        curl -s "$SMOKE_URL" 2>/dev/null | python3 -m json.tool 2>/dev/null || curl -s "$SMOKE_URL"
    else
        echo "  Status: FAILED (HTTP $http_code)"
        return 1
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────

case "$TARGET" in
    binary)
        deploy_binary
        ;;
    proxy)
        deploy_proxy
        ;;
    web)
        deploy_web
        ;;
    smoke)
        smoke_test
        ;;
    all)
        deploy_binary
        deploy_proxy
        deploy_web
        echo ""
        smoke_test
        ;;
    *)
        echo "Usage: $0 [binary|proxy|web|all|smoke]"
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
