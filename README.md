# bc-hash

[![ci](https://github.com/Unmanaged-Bytes/bc-hash/actions/workflows/ci.yml/badge.svg)](https://github.com/Unmanaged-Bytes/bc-hash/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Language: C11](https://img.shields.io/badge/language-C11-informational)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey)

> **Scope.** Personal project, shipping the CLI front-end of the
> `bc-*` ecosystem. Published here for transparency and reuse, not
> as a hardened product.
>
> **Support.** Issues and PRs are welcome but handled on a best-effort
> basis, whenever I have spare time — this is not a priority project
> and there is no SLA. Do not rely on a timely response.

Parallel file-tree hashing for large filesystems — walks directories and
computes digests in parallel, with batched I/O via `io_uring` when available.
On a warm-cache corpus of ~650k files / 19 GB, 1.5×–1.7× faster than
`find | xargs -P16 <tool>` for sha256, crc32c, xxh3, and xxh128.

Built to replace ad-hoc `find | xargs -P$(nproc) sha256sum` pipelines with
a single binary that also supports verifying and diffing digest snapshots.

## At a glance

```
$ bc-hash hash --type=sha256 /data
0b7e1391...  /data/file1
5f5d584c...  /data/subdir/file2
...
```

Benchmark, warm cache, Ryzen 7 5700G, 10 runs, stable env (boost=0,
governor=performance), 653 591 files / 19 GB:

| Algorithm | bc-hash | `xargs -P16` reference | Speedup |
|---|---:|---:|---:|
| sha256 | **7.31 s** (σ 0.29) | `sha256sum` 11.97 s (σ 0.02) | 1.64× |
| crc32c | **6.67 s** (σ 0.34) | `cksum` 11.42 s (σ 0.01) | 1.71× |
| xxh3 | **6.77 s** (σ 0.29) | `xxhsum -H3` 10.72 s (σ 0.05) | 1.58× |
| xxh128 | **6.90 s** (σ 0.24) | `xxhsum -H128` 10.73 s (σ 0.03) | 1.56× |


## Features

- **SHA-256** (SHA-NI accelerated on supported CPUs) and **CRC32C** (SSE4.2).
- Parallel recursive walk via a lock-free MPMC queue of directories plus
  per-worker file accumulators.
- Batched I/O via **io_uring** with direct-fd slots; synchronous
  fallback when liburing is missing.
- **Adaptive dispatch**: runs single-threaded on small workloads (break-even
  ~50 files / ~1 MB on Zen 3), parallel on larger ones. Decision uses
  hardware constants auto-measured and cached under
  `$XDG_CACHE_HOME/bc-hash/throughput.txt`.
- `--threads=auto|0|N` to force a specific mode.

## Install (Debian 13 trixie — production)

Install the six sibling libraries first (each from its own GitHub
Release), then download and install the `bc-hash` `.deb`:

```bash
for pkg in libbc-core-dev libbc-allocators-dev libbc-containers-dev \
           libbc-io-dev libbc-concurrency-dev libbc-runtime-dev; do
  sudo apt install "./${pkg}_X.Y.Z-1_amd64.deb"
done
sudo apt install ./bc-hash_X.Y.Z-1_amd64.deb
bc-hash --version
```

The package installs the `bc-hash` binary to `/usr/bin/bc-hash`.

## Development build (from source)

Requirements:

- `meson >= 1.0`, `ninja-build`, `pkg-config`
- `libxxhash-dev (>= 0.8.0)`, `liburing-dev (>= 2.5)`
- The six `libbc-*-dev` sibling packages installed
- `libcmocka-dev` for the test suite

```bash
meson setup build/debug --buildtype=debug -Dtests=true
meson compile -C build/debug
meson test -C build/debug
# binary at: build/debug/src/bc-hash
```

## Usage

```
bc-hash [global options] <command> [command options] [arguments...]

global options:
  --threads=auto|0|N    worker count (default: auto)
  --help                print global help
  --version             print version

commands:
  hash     compute hashes for files and directories
  check    verify files against a digest file
  diff     compare two digest files
```

## Performance

All measurements taken on a Ryzen 7 5700G, DDR4-3200, NVMe, stable env
(boost disabled, performance governor, ASLR off).

### Throughput (warm cache, 10 runs, 653 591 files / 19 GB)

| Algorithm | bc-hash | `xargs -P16` reference | Speedup |
|---|---:|---:|---:|
| sha256 | 7.31 s (σ 0.29) | sha256sum 11.97 s | 1.64× |
| crc32c | 6.67 s (σ 0.34) | cksum 11.42 s | 1.71× |
| xxh3 | 6.77 s (σ 0.29) | xxhsum -H3 10.72 s | 1.58× |
| xxh128 | 6.90 s (σ 0.24) | xxhsum -H128 10.73 s | 1.56× |

### Notes

Non-crypto algorithms (crc32c/xxh3/xxh128) all converge around ~6.7 s
wall — on this corpus the work is syscall-bound, not compute-bound.
SHA-256 stays compute-bound despite SHA-NI hardware acceleration, so
picking a non-crypto algorithm when you don't need cryptographic
collision resistance costs nothing.

Reproduce with `scripts/bench.sh <target-directory>` (warm only, no
sudo) or `scripts/bench.sh --with-cold <target>` (requires sudo for
drop_caches). Full methodology, corpus details, and interpretation in
[`docs/benchmarks.md`](docs/benchmarks.md).

## Architecture

bc-hash implements the **parallel-walk-plus-process**

```
Phase A (parallel)         Phase B (main)         Phase C (parallel)
──────────────────        ───────────────       ─────────────────────
N workers walk FS          merge per-worker      N workers hash via
via MPMC queue of          vectors → global      io_uring batched
directories + per-         entries, flush        (32 slots per ring,
worker vectors (zero       errors to stderr      ring per worker)
shared allocation).
         │                        │                       │
         └── dispatch_and_wait ───┴── dispatch_and_wait ──┘
```

Adaptive decision at startup chooses mono or multi based on (file_count,
total_bytes) and hardware constants (single-thread throughput, parallel
startup cold-cost, per-file warm cost) — see
`src/bench/bc_hash_dispatch_decision.c`.

## Limitations

- Symlinks are never followed (`O_NOFOLLOW` everywhere). To hash what a
  symlink points to, pass the resolved path explicitly.
- Hidden files (names starting with `.`) are silently filtered. No override
  in the CLI.
- `bc-hash` builds the full entry list in memory before hashing. On a
  32 GB RAM box, this handles a few million files comfortably; beyond that,
  a streaming architecture would be required.

## License

MIT — see `LICENSE`.


