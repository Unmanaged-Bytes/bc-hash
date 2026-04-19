#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Full bench — compares bc-hash (crc32, sha256, xxh3, xxh128) against
# single-file external references (xxhsum, sha256sum, cksum) via
# xargs-Pn, plus a correctness spot-check on N random files and
# sanity checks on the 'check', 'diff', and filter features.
#
# Default: warm-only (no sudo needed). Use --with-cold to also run cold
# iterations (requires sudo for drop_caches).
#
# Produces build/perf-logs/bench.log.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/build/release/src/bc-hash"
TARGET=""
WITH_COLD=0
WARM_RUNS="${WARM_RUNS:-10}"
COLD_RUNS="${COLD_RUNS:-3}"
REF_JOBS="${REF_JOBS:-16}"
CORRECTNESS_SAMPLES="${CORRECTNESS_SAMPLES:-8}"

usage() {
    cat <<EOF
usage: bench.sh [--with-cold] [--target <path>] <target-directory>

Runs a warm-cache benchmark of bc-hash vs xargs-P${REF_JOBS} references
(sha256sum, xxhsum, cksum) plus a round-trip of hash->check->diff and a
filter-gain measurement. Output: build/perf-logs/bench.log.

Options:
  --with-cold    also run cold-cache iterations (requires sudo for
                 drop_caches)
  --target PATH  alternate way to pass the target directory
  -h, --help     show this help

Environment variables: WARM_RUNS (default 10), COLD_RUNS (default 3),
REF_JOBS (default 16), CORRECTNESS_SAMPLES (default 8).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --with-cold)   WITH_COLD=1; shift ;;
        --target)      TARGET="$2"; shift 2 ;;
        -h|--help)     usage; exit 0 ;;
        *)             TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "error: missing target directory" >&2
    usage >&2
    exit 2
fi

OUT="$ROOT/build/perf-logs/bench.log"

if [[ $WITH_COLD -eq 1 && "$(id -u)" -ne 0 ]]; then
    exec sudo -E bash "$0" --with-cold --target "$TARGET"
fi

[[ -x "$BIN" ]] || { echo "missing release binary: $BIN (run: meson setup build/release --buildtype=release && meson compile -C build/release)" >&2; exit 1; }
[[ -d "$TARGET" ]] || { echo "missing target: $TARGET" >&2; exit 1; }

mkdir -p "$(dirname "$OUT")"
: > "$OUT"

log() { tee -a "$OUT"; }

echo "=== bc-hash bench @ $(git -C "$ROOT" rev-parse --short HEAD), target=$TARGET ===" | log
echo "warm runs=$WARM_RUNS  cold=$WITH_COLD  ref jobs=$REF_JOBS  correctness samples=$CORRECTNESS_SAMPLES" | log
echo "env: boost=$(cat /sys/devices/system/cpu/cpufreq/boost 2>/dev/null || echo ?)  governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo ?)  ASLR=$(cat /proc/sys/kernel/randomize_va_space)" | log
echo "file count: $(find "$TARGET" -type f | wc -l)  size: $(du -sh "$TARGET" | cut -f1)" | log
echo "" | log

# ------------------------------------------------------------------------------
# Correctness: pick N random files, hash each with bc-hash and the reference,
# compare the hex digests. bc-hash output is "HEX  PATH" on one line per file.
# ------------------------------------------------------------------------------
correctness_check() {
    local bc_algo="$1"
    local ref_cmd="$2"
    local ref_hex_awk="$3"
    echo "--- correctness $bc_algo vs $ref_cmd ---" | log

    local fail=0
    while IFS= read -r path; do
        local bc_hex ref_hex
        bc_hex="$("$BIN" hash --type="$bc_algo" --output=- "$path" 2>/dev/null | awk '{print $1}')"
        ref_hex="$($ref_cmd "$path" 2>/dev/null | awk "$ref_hex_awk")"
        if [[ "$bc_hex" == "$ref_hex" && -n "$bc_hex" ]]; then
            printf "  OK    %s  %s\n" "$bc_hex" "$path" | log
        else
            printf "  FAIL  bc=%s  ref=%s  %s\n" "$bc_hex" "$ref_hex" "$path" | log
            fail=1
        fi
    done < <(find "$TARGET" -type f -not -empty 2>/dev/null | shuf -n "$CORRECTNESS_SAMPLES")

    if [[ $fail -ne 0 ]]; then
        echo "  RESULT: FAIL" | log
        return 1
    fi
    echo "  RESULT: OK" | log
    return 0
}

correctness_check sha256 sha256sum '{print $1}'
correctness_check xxh3   "xxhsum -H3"   '{sub(/^XXH3_/,"",$1); print $1}'
correctness_check xxh128 "xxhsum -H128" '{print $1}'
echo "(crc32 correctness skipped — bc-hash uses CRC32C Castagnoli, cksum uses CRC-32 IEEE — validated via RFC vectors in tests)" | log
echo "" | log

# ------------------------------------------------------------------------------
# Throughput benchmarks
# ------------------------------------------------------------------------------
bench_bc_hash_warm() {
    local algo="$1"
    echo "--- warm bc-hash $algo ---" | log
    "$BIN" hash --type="$algo" --output=- "$TARGET" > /dev/null 2>&1
    "$BIN" hash --type="$algo" --output=- "$TARGET" > /dev/null 2>&1
    for i in $(seq 1 "$WARM_RUNS"); do
        local start end
        start="$(date +%s.%N)"
        "$BIN" hash --type="$algo" --output=- "$TARGET" > /dev/null 2>&1
        end="$(date +%s.%N)"
        awk -v s="$start" -v e="$end" -v a="$algo" -v r="$i" \
            'BEGIN { printf "warm bc-hash-%s run%d %.3f\n", a, r, e - s }' | log
    done
}

bench_bc_hash_cold() {
    local algo="$1"
    echo "--- cold bc-hash $algo ---" | log
    for i in $(seq 1 "$COLD_RUNS"); do
        sync
        echo 3 > /proc/sys/vm/drop_caches
        local start end
        start="$(date +%s.%N)"
        "$BIN" hash --type="$algo" --output=- "$TARGET" > /dev/null 2>&1
        end="$(date +%s.%N)"
        awk -v s="$start" -v e="$end" -v a="$algo" -v r="$i" \
            'BEGIN { printf "cold bc-hash-%s run%d %.3f\n", a, r, e - s }' | log
    done
}

bench_ref_warm() {
    local label="$1"; shift
    local cmd=("$@")
    echo "--- warm $label ---" | log
    find "$TARGET" -type f -print0 | xargs -0 -n 64 -P "$REF_JOBS" "${cmd[@]}" > /dev/null 2>&1
    find "$TARGET" -type f -print0 | xargs -0 -n 64 -P "$REF_JOBS" "${cmd[@]}" > /dev/null 2>&1
    for i in $(seq 1 "$WARM_RUNS"); do
        local start end
        start="$(date +%s.%N)"
        find "$TARGET" -type f -print0 | xargs -0 -n 64 -P "$REF_JOBS" "${cmd[@]}" > /dev/null 2>&1
        end="$(date +%s.%N)"
        awk -v s="$start" -v e="$end" -v l="$label" -v r="$i" \
            'BEGIN { printf "warm %s run%d %.3f\n", l, r, e - s }' | log
    done
}

bench_bc_hash_warm crc32
bench_bc_hash_warm sha256
bench_bc_hash_warm xxh3
bench_bc_hash_warm xxh128

if [[ $WITH_COLD -eq 1 ]]; then
    bench_bc_hash_cold crc32
    bench_bc_hash_cold sha256
    bench_bc_hash_cold xxh3
    bench_bc_hash_cold xxh128
fi

bench_ref_warm "xargs-P${REF_JOBS}-cksum"      cksum
bench_ref_warm "xargs-P${REF_JOBS}-sha256sum"  sha256sum
bench_ref_warm "xargs-P${REF_JOBS}-xxhsum-H3"  xxhsum -H3
bench_ref_warm "xargs-P${REF_JOBS}-xxhsum-H128" xxhsum -H128

# ------------------------------------------------------------------------------
# Feature sanity: hash -> check -> diff round-trip and filter gain
# ------------------------------------------------------------------------------
FEAT_DIR="$(mktemp -d)"
trap 'rm -rf "$FEAT_DIR"' EXIT

echo "--- round-trip: hash, check, diff on $TARGET ---" | log
"$BIN" hash --type=xxh3 --output="$FEAT_DIR/snap1.ndjson" "$TARGET" 2>/dev/null
check_code=0
"$BIN" check "$FEAT_DIR/snap1.ndjson" > /dev/null 2>"$FEAT_DIR/check.stderr" || check_code=$?
summary_line="$(cat "$FEAT_DIR/check.stderr")"
echo "  check exit=$check_code  $summary_line" | log

"$BIN" hash --type=xxh3 --output="$FEAT_DIR/snap2.ndjson" "$TARGET" 2>/dev/null
diff_code=0
"$BIN" diff "$FEAT_DIR/snap1.ndjson" "$FEAT_DIR/snap2.ndjson" > /dev/null 2>"$FEAT_DIR/diff.stderr" || diff_code=$?
echo "  diff exit=$diff_code  $(cat "$FEAT_DIR/diff.stderr")" | log
echo "" | log

echo "--- filter gain: prune first top-level subdir ---" | log
first_dir="$(find "$TARGET" -mindepth 1 -maxdepth 1 -type d | head -1)"
if [[ -n "$first_dir" ]]; then
    first_base="$(basename "$first_dir")"
    echo "  pruning basename='$first_base'" | log
    for i in $(seq 1 "$WARM_RUNS"); do
        start="$(date +%s.%N)"
        "$BIN" hash --type=xxh3 --output=- "$TARGET" > /dev/null 2>&1
        end="$(date +%s.%N)"
        awk -v s="$start" -v e="$end" -v r="$i" 'BEGIN { printf "warm filter-off run%d %.3f\n", r, e - s }' | log
    done
    for i in $(seq 1 "$WARM_RUNS"); do
        start="$(date +%s.%N)"
        "$BIN" hash --type=xxh3 --exclude="$first_base" --output=- "$TARGET" > /dev/null 2>&1
        end="$(date +%s.%N)"
        awk -v s="$start" -v e="$end" -v r="$i" -v p="$first_base" 'BEGIN { printf "warm filter-prune-%s run%d %.3f\n", p, r, e - s }' | log
    done
else
    echo "  no subdir in $TARGET, skipping" | log
fi

echo "" | log
echo "=== summary (mean +/- stddev, seconds) ===" | log
awk '
$1 ~ /^(warm|cold)$/ && NF == 4 {
    key = $1 " " $2
    sum[key] += $4
    sumsq[key] += $4 * $4
    n[key] += 1
}
END {
    for (k in sum) {
        mean = sum[k] / n[k]
        variance = (sumsq[k] / n[k]) - mean * mean
        if (variance < 0) variance = 0
        stddev = sqrt(variance)
        printf "%-50s  mean=%.3f s  sd=%.3f s  n=%d\n", k, mean, stddev, n[k]
    }
}
' "$OUT" | sort | log
