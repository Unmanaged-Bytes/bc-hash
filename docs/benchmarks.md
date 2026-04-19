# Benchmarks

## Methodology

- Warm measurements: the target tree is read once before the first
  timed run so filesystem caches are hot. Ten timed runs per data
  point; the first two are discarded as further warmup.
- Cold measurements: `sync && echo 3 > /proc/sys/vm/drop_caches`
  before each run. Requires root.
- References are invoked as `find <target> -type f -print0 | xargs -0
  -P<jobs> <tool>` to match bc-hash's "one tool, one corpus"
  invocation shape; `xargs -P` is the closest fair baseline because
  it keeps a worker pool alive rather than spawning one process per
  file (which dominates `parallel` and biases results unfairly).
- The reproducer lives at `scripts/bench.sh`.

## v1.0.0 baseline

Corpus: 653 591 non-empty files / 19 GB (mixed small and medium
source/config/object files, representative of a typical developer
workstation tree).

Host: Ryzen 7 5700G (8c/16t), 32 GB DDR4-3200, NVMe, Debian 13.

Environment: `boost=0  governor=performance  ASLR=0` (the
`scripts/perf-tuning-setup.sh` helper applies these, but the values
are what matter).

Build: release + LTO (`meson setup build/release --buildtype=release`
then `meson compile -C build/release`).

### Throughput (warm, mean ± stddev over 10 runs)

| Algorithm | bc-hash          | xargs -P16 reference           | Speedup |
|-----------|-----------------:|-------------------------------:|--------:|
| crc32c    | 6.67 s (σ 0.34)  | `cksum`        11.42 s (σ 0.01) | 1.71×   |
| sha256    | 7.31 s (σ 0.29)  | `sha256sum`    11.97 s (σ 0.02) | 1.64×   |
| xxh3      | 6.77 s (σ 0.29)  | `xxhsum -H3`   10.72 s (σ 0.05) | 1.58×   |
| xxh128    | 6.90 s (σ 0.24)  | `xxhsum -H128` 10.73 s (σ 0.03) | 1.56×   |

### Filter directory prune (xxh3, warm)

| Filter                    | wall (s) |
|---------------------------|---------:|
| no filter                 | 6.57     |
| `--exclude=<largest-dir>` | 0.43     |

15× speedup when the excluded subtree dominates the corpus
(representative of excluding `.git`, `node_modules`, `target`, etc.
in real-world usage).
