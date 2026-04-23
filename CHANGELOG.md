# Changelog

All notable changes to bc-hash are documented here.

## [1.2.0]

### Added

- **`--format` option** to select output format explicitly: `auto` (default),
  `simple`, `json`, `hrbl`. Auto picks by destination: stdout → simple,
  `*.hrbl` file → hrbl, other file → json (preserves 1.1.x behavior).
- **HRBL binary output** via new `output/bc_hash_output_hrbl.c`. Writes a
  single `.hrbl` block rooted at `bc_hash` with summary fields
  (`algorithm`, `files_total`, `files_ok`, `bytes_total`, `wall_ms`,
  `worker_count`, `dispatch_mode`, `schema_version`, `tool_version`,
  `started_at_unix_ms`) and a `files` sub-block keyed by absolute path
  holding `ok`, `digest_hex`, `size_bytes` (or `errno`, `error_message`
  on failure). Integrity-checked via `bc-hrbl verify`, programmatically
  navigable via the bc-hrbl reader API.

### Dependencies

- Build now depends on `libbc-hrbl-dev (>= 1.0.0)`.

## [1.0.2]

### Changed

- **Build with `-march=x86-64-v3`** (AVX2 + FMA + BMI2): enables the
  xxhash AVX2 accumulation path at runtime on Zen 3 / Haswell+ hosts.

### Performance

- **io_uring: batch CQE drain via `io_uring_peek_batch_cqe`** instead
  of one-by-one `wait_cqe`. xxh128 -12.5 %, variance reduced 16× on the
  148 k files / 3.2 GB warm-cache benchmark.

### Fixed

- **Benchmarks**: dropped `cksum` reference (CRC-32 IEEE is not CRC32C,
  comparison was misleading). Fixed `REF_JOBS` default to 8 physical
  cores. Fixed SIGPIPE on `find | head -1` in the filter-gain section.
- **Build**: dropped stale `benchmarks` meson option — no
  `benchmarks/` subdirectory, bench is driven by `scripts/bench.sh`.

## [1.0.1]

### Changed

- Rebuilt against libbc-concurrency 1.0.2, which replaces atomic +
  futex worker signaling with pthread_mutex + condition variables to
  close residual ThreadSanitizer data races on gcc 13 / ubuntu-24.04.
  bc-hash statically links libbc-concurrency, so consuming the fix
  requires a fresh build.

### Fixed

- Debian hardening build: assign the cache-warmup `read(2)` return
  value instead of discarding it, to satisfy
  `-Werror=unused-result` under `-D_FORTIFY_SOURCE=2`.

## [1.0.0]

Initial public release.

### Added
- `bc-hash hash --type=crc32|sha256|xxh3|xxh128 <path>...`
  — parallel file-tree hashing with `io_uring` batched I/O when
  available, synchronous fallback otherwise.
- `bc-hash check <digest-file>` — verify files against a digest file
  produced by bc-hash or any `sha256sum` / `xxhsum` compatible tool.
  Auto-detects algorithm from hex length or NDJSON header. Exit codes
  `0` all OK, `1` any FAILED or MISSING, `2` format error.
- `bc-hash diff <a> <b>` — compare two digest files; reports per-path
  `ADDED` / `REMOVED` / `MODIFIED` lines and a summary. Refuses
  cross-algorithm diffs.
- `--include=GLOB` / `--exclude=GLOB` filters on the `hash` command.
  Basename-matched via `fnmatch`, repeatable, with directory prune on
  `--exclude` match for large wins on noise-heavy subtrees.
- `--threads=auto|0|N` global option selecting worker count; `0`
  forces single-threaded, `N` forces N effective workers.
- Output format is determined by destination: `--output=-` emits
  `sha256sum`-compatible simple format on stdout; `--output=PATH`
  writes NDJSON (header, per-file entries, summary) to the file.
- Graceful handling of `SIGINT` / `SIGTERM` mid-walk or mid-hash,
  exit code 130.


[1.0.0]: https://github.com/Unmanaged-Bytes/bc-hash/releases/tag/v1.0.0
[1.0.1]: https://github.com/Unmanaged-Bytes/bc-hash/releases/tag/v1.0.1
[1.0.2]: https://github.com/Unmanaged-Bytes/bc-hash/releases/tag/v1.0.2
