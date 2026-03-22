#!/bin/bash
set -euo pipefail

# Build Ladder Script ghostd binary.
# Syncs src/rung/ into ghost-core build tree, runs cmake, strips output.
#
# Usage: ./scripts/build.sh [--clean]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
SRC_RUNG="$ROOT/src/rung"
BUILD_RUNG="$ROOT/ghost-core/src/rung"
BUILD_DIR="$ROOT/ghost-core/build"
JOBS=2  # WSL2 OOM-kills at higher parallelism

# ── Parse args ──────────────────────────────────────────────────────────

CLEAN=0
for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=1 ;;
        *) echo "Unknown arg: $arg"; exit 1 ;;
    esac
done

# ── Step 1: Sync rung sources into ghost-core ───────────────────────────

echo "=== Syncing src/rung/ → ghost-core/src/rung/ ==="

changed=0
for f in "$SRC_RUNG"/*.h "$SRC_RUNG"/*.cpp; do
    [ -f "$f" ] || continue
    base="$(basename "$f")"
    dest="$BUILD_RUNG/$base"
    if [ ! -f "$dest" ] || ! diff -q "$f" "$dest" >/dev/null 2>&1; then
        cp "$f" "$dest"
        echo "  updated: $base"
        changed=1
    fi
done

# Also sync CMakeLists.txt
if ! diff -q "$SRC_RUNG/CMakeLists.txt" "$BUILD_RUNG/CMakeLists.txt" >/dev/null 2>&1; then
    cp "$SRC_RUNG/CMakeLists.txt" "$BUILD_RUNG/CMakeLists.txt"
    echo "  updated: CMakeLists.txt"
    changed=1
fi

if [ "$changed" -eq 0 ]; then
    echo "  (no changes)"
fi

# ── Step 2: Configure if needed ─────────────────────────────────────────

if [ "$CLEAN" -eq 1 ] || [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
    echo ""
    echo "=== Configuring cmake ==="
    if [ "$CLEAN" -eq 1 ] && [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
    cmake -S "$ROOT/ghost-core" -B "$BUILD_DIR" \
        -DBUILD_TESTING=OFF \
        -DWITH_MINIUPNPC=OFF \
        -DWITH_ZMQ=OFF \
        -DWITH_USDT=OFF
fi

# ── Step 3: Build ────────────────────────────────────────────────────────

echo ""
echo "=== Building with -j${JOBS} ==="
cmake --build "$BUILD_DIR" -j"$JOBS" --target ghostd

# ── Step 4: Strip binary ────────────────────────────────────────────────

BINARY="$BUILD_DIR/bin/ghostd"
if [ -f "$BINARY" ]; then
    echo ""
    echo "=== Stripping binary ==="
    SIZE_BEFORE=$(stat -c%s "$BINARY")
    strip "$BINARY"
    SIZE_AFTER=$(stat -c%s "$BINARY")
    echo "  $BINARY"
    echo "  ${SIZE_BEFORE} → ${SIZE_AFTER} bytes ($(( (SIZE_BEFORE - SIZE_AFTER) / 1024 ))KB saved)"
else
    # Try ghost naming
    BINARY="$BUILD_DIR/bin/ghost"
    if [ -f "$BINARY" ]; then
        echo ""
        echo "=== Stripping binary ==="
        SIZE_BEFORE=$(stat -c%s "$BINARY")
        strip "$BINARY"
        SIZE_AFTER=$(stat -c%s "$BINARY")
        echo "  $BINARY"
        echo "  ${SIZE_BEFORE} → ${SIZE_AFTER} bytes ($(( (SIZE_BEFORE - SIZE_AFTER) / 1024 ))KB saved)"
    else
        echo "WARNING: No binary found at $BUILD_DIR/bin/ghost or $BUILD_DIR/bin/ghostd"
        exit 1
    fi
fi

echo ""
echo "=== Build complete ==="
echo "Binary: $BINARY"
