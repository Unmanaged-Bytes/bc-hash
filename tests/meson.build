# SPDX-License-Identifier: MIT

cmocka_dep = dependency('cmocka')

fixtures_directory = meson.current_build_dir() / 'fixtures'

test_bc_hash_end_to_end = executable('test_bc_hash_end_to_end',
  'test_bc_hash_end_to_end.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_HASH_TEST_BINARY_PATH="' + bc_hash_bin.full_path() + '"',
    '-DBC_HASH_TEST_FIXTURES_DIRECTORY="' + fixtures_directory + '"',
  ],
)

test('bc_hash_end_to_end', test_bc_hash_end_to_end, depends : [bc_hash_bin], timeout : 120)

if liburing_dep.found()
  test_bc_hash_reader_uring_stress = executable('test_bc_hash_reader_uring_stress',
    'test_bc_hash_reader_uring_stress.c',
    dependencies : [cmocka_dep],
    c_args : [
      '-DBC_HASH_TEST_BINARY_PATH="' + bc_hash_bin.full_path() + '"',
    ],
  )
  test('bc_hash_reader_uring_stress', test_bc_hash_reader_uring_stress, depends : [bc_hash_bin], timeout : 180)
endif

test_bc_hash_throughput = executable('test_bc_hash_throughput',
  'test_bc_hash_throughput.c',
  bc_hash_throughput_sources,
  include_directories : [bc_hash_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_concurrency_dep],
)
test('bc_hash_throughput', test_bc_hash_throughput, timeout : 60)

test_bc_hash_dispatch_decision = executable('test_bc_hash_dispatch_decision',
  'test_bc_hash_dispatch_decision.c',
  bc_hash_dispatch_decision_sources,
  include_directories : [bc_hash_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_concurrency_dep],
  link_args : ['-lm'],
)
test('bc_hash_dispatch_decision', test_bc_hash_dispatch_decision)

test_bc_hash_filter_unit = executable('test_bc_hash_filter_unit',
  'test_bc_hash_filter_unit.c',
  '../src/filter/bc_hash_filter.c',
  include_directories : [bc_hash_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep],
)
test('bc_hash_filter_unit', test_bc_hash_filter_unit)

test_bc_hash_verify_parse_unit = executable('test_bc_hash_verify_parse_unit',
  'test_bc_hash_verify_parse_unit.c',
  '../src/verify/bc_hash_verify_parse.c',
  include_directories : [bc_hash_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_containers_dep, bc_concurrency_dep],
)
test('bc_hash_verify_parse_unit', test_bc_hash_verify_parse_unit)

test_bc_hash_cli_spec_unit = executable('test_bc_hash_cli_spec_unit',
  'test_bc_hash_cli_spec_unit.c',
  '../src/cli/bc_hash_cli_spec.c',
  include_directories : [bc_hash_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_runtime_dep],
)
test('bc_hash_cli_spec_unit', test_bc_hash_cli_spec_unit)


test_bc_hash_output_unit = executable('test_bc_hash_output_unit',
  'test_bc_hash_output_unit.c',
  '../src/output/bc_hash_output_simple.c',
  '../src/output/bc_hash_output_json.c',
  '../src/output/bc_hash_output_hrbl.c',
  include_directories : [bc_hash_internal_inc],
  dependencies : [cmocka_dep, bc_core_dep, bc_allocators_dep, bc_containers_dep, bc_hrbl_dep],
)
test('bc_hash_output_unit', test_bc_hash_output_unit)

test_bc_hash_output_json = executable('test_bc_hash_output_json',
  'test_bc_hash_output_json.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_HASH_TEST_BINARY_PATH="' + bc_hash_bin.full_path() + '"',
    '-DBC_HASH_TEST_FIXTURES_DIRECTORY="' + fixtures_directory + '"',
  ],
)
test('bc_hash_output_json', test_bc_hash_output_json, depends : [bc_hash_bin], timeout : 120)

test_bc_hash_check = executable('test_bc_hash_check',
  'test_bc_hash_check.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_HASH_TEST_BINARY_PATH="' + bc_hash_bin.full_path() + '"',
    '-DBC_HASH_TEST_FIXTURES_DIRECTORY="' + fixtures_directory + '"',
  ],
)
test('bc_hash_check', test_bc_hash_check, depends : [bc_hash_bin], timeout : 120)

test_bc_hash_diff = executable('test_bc_hash_diff',
  'test_bc_hash_diff.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_HASH_TEST_BINARY_PATH="' + bc_hash_bin.full_path() + '"',
    '-DBC_HASH_TEST_FIXTURES_DIRECTORY="' + fixtures_directory + '"',
  ],
)
test('bc_hash_diff', test_bc_hash_diff, depends : [bc_hash_bin], timeout : 120)

test_bc_hash_filter = executable('test_bc_hash_filter',
  'test_bc_hash_filter.c',
  dependencies : [cmocka_dep],
  c_args : [
    '-DBC_HASH_TEST_BINARY_PATH="' + bc_hash_bin.full_path() + '"',
    '-DBC_HASH_TEST_FIXTURES_DIRECTORY="' + fixtures_directory + '"',
  ],
)
test('bc_hash_filter', test_bc_hash_filter, depends : [bc_hash_bin], timeout : 120)
