# SPDX-License-Identifier: MIT

bc_hash_throughput_sources = files(
  'bench/bc_hash_throughput.c',
  'bench/bc_hash_throughput_cache.c',
)

bc_hash_dispatch_decision_sources = files(
  'bench/bc_hash_dispatch_decision.c',
)

bc_hash_sources = [
  'bc_hash_main.c',
  'cli/bc_hash_cli_spec.c',
  'discovery/bc_hash_discovery_walk.c',
  'discovery/bc_hash_discovery_walk_parallel.c',
  'discovery/bc_hash_discovery_glob.c',
  'worker/bc_hash_worker_dispatch.c',
  'worker/bc_hash_worker_reader.c',
  'output/bc_hash_output_simple.c',
  'output/bc_hash_output_json.c',
  'error/bc_hash_error_collector.c',
  'verify/bc_hash_verify_parse.c',
  'verify/bc_hash_verify_run.c',
  'diff/bc_hash_diff.c',
  'filter/bc_hash_filter.c',
  bc_hash_throughput_sources,
  bc_hash_dispatch_decision_sources,
]

if liburing_dep.found()
  bc_hash_sources += 'worker/bc_hash_worker_batch_uring.c'
else
  bc_hash_sources += 'worker/bc_hash_worker_batch_sync.c'
endif

cc = meson.get_compiler('c')
libm_dep = cc.find_library('m', required : true)

bc_hash_version_c_arg = '-DBC_HASH_VERSION_STRING="@0@"'.format(meson.project_version())

bc_hash_bin = executable('bc-hash',
  bc_hash_sources,
  include_directories : [bc_hash_internal_inc],
  dependencies : bc_hash_deps + [libm_dep],
  c_args : lto_c_args + [bc_hash_version_c_arg],
  link_args : lto_link_args,
  install : true,
)
