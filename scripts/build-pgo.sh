#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Two-phase PGO build: instrument, profile on a representative workload,
# rebuild with profile data.
# Usage: scripts/build-pgo.sh <profiling-target-directory>
#
# Result binary: build/pgo/src/bc-hash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
TARGET="${1:-}"
BUILD_DIR="$ROOT/build/pgo"

if [[ -z "$TARGET" ]]; then
    echo "usage: $(basename "$0") <profiling-target-directory>" >&2
    echo "       target must point at a representative file tree" >&2
    echo "       (hot paths exercised: walk parallel, hash parallel, hash mono)" >&2
    exit 2
fi

if [[ ! -d "$TARGET" ]]; then
    echo "error: profiling target '$TARGET' does not exist" >&2
    exit 1
fi

cd "$ROOT"

echo "=== Phase 1: instrumented build (b_pgo=generate) ==="
meson setup "$BUILD_DIR" --buildtype=release -Db_pgo=generate --wipe
meson compile -C "$BUILD_DIR"

echo ""
echo "=== Phase 2: profiling run on $TARGET ==="
# Representative runs to exercise hot paths:
# - SHA256 auto (walk parallel + hash parallel)
# - CRC32 auto (walk parallel + hash parallel, shorter algo)
# - SHA256 mono (sequential walk + sequential hash)
"$BUILD_DIR/src/bc-hash" hash --type=sha256 --output=/dev/null "$TARGET" > /dev/null
"$BUILD_DIR/src/bc-hash" hash --type=crc32  --output=/dev/null "$TARGET" > /dev/null
"$BUILD_DIR/src/bc-hash" --threads=0 hash --type=sha256 --output=/dev/null "$TARGET" > /dev/null

gcda_count="$(find "$BUILD_DIR" -name '*.gcda' | wc -l)"
echo "generated $gcda_count .gcda profile files"

echo ""
echo "=== Phase 3: optimized rebuild (b_pgo=use) ==="
meson configure "$BUILD_DIR" -Db_pgo=use
meson compile -C "$BUILD_DIR"

echo ""
echo "=== result ==="
ls -la "$BUILD_DIR/src/bc-hash"
echo ""
echo "Run the PGO binary: $BUILD_DIR/src/bc-hash"
echo "Expected wall-clock improvement vs plain release: ~3-4% warm on a"
echo "Zen 3-class CPU (results vary with microarch and workload)."
