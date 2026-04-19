# Changelog

All notable changes to bc-hash are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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


[1.0.0]: https://github.com/OWNER/bc-hash/releases/tag/v1.0.0
