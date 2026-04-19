# bc-hash — project context

Parallel file-tree hashing CLI. Walks directory trees and computes
SHA-256 (SHA-NI accelerated), CRC32C (SSE4.2), xxh3 or xxh128 digests
with a lock-free MPMC directory queue, batched I/O via io_uring when
available, and adaptive single-threaded / multi-threaded dispatch.
Supports `hash`, `check`, and `diff` subcommands.

## Invariants (do not break)

- **No comments in `.c` files** — code names itself. Public / internal
  `.h` may carry one-line contracts if the signature is insufficient.
- **No defensive null-checks at function entry.** Return `false`
  on legitimate failure; never assert in production paths.
- **SPDX-License-Identifier: MIT** header on every `.c` and `.h`.
- **Strict C11** with `-Wall -Wextra -Wpedantic -Werror`.
- **Sanitizers (asan/tsan/ubsan/memcheck) stay green** in CI.
- **cppcheck stays clean**; never edit `cppcheck-suppressions.txt`
  to hide real findings.
- **Adaptive dispatch decision is cached**, not re-measured per run.
  Cache at `$XDG_CACHE_HOME/bc-hash/throughput.txt`.
- **Graceful signal handling** — SIGINT / SIGTERM must exit in
  under 30 ms with code 130.
