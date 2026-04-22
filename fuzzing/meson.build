# SPDX-License-Identifier: MIT

fuzzer_c_args = []
fuzzer_link_args = []
if cc.get_id() == 'clang'
    fuzzer_c_args += ['-fsanitize=fuzzer', '-DBC_FUZZ_LIBFUZZER']
    fuzzer_link_args += ['-fsanitize=fuzzer']
endif

bc_hash_fuzz_cli_sources = [
    '../src/cli/bc_hash_cli_spec.c',
    '../src/filter/bc_hash_filter.c',
]

bc_hash_fuzz_verify_sources = [
    '../src/verify/bc_hash_verify_parse.c',
]

executable('fuzz_bc_hash_cli_parse',
    'fuzz_bc_hash_cli_parse.c',
    bc_hash_fuzz_cli_sources,
    include_directories : [bc_hash_internal_inc],
    dependencies : bc_hash_deps,
    c_args : fuzzer_c_args,
    link_args : fuzzer_link_args,
)

executable('fuzz_bc_hash_verify_parse',
    'fuzz_bc_hash_verify_parse.c',
    bc_hash_fuzz_verify_sources,
    include_directories : [bc_hash_internal_inc],
    dependencies : bc_hash_deps,
    c_args : fuzzer_c_args,
    link_args : fuzzer_link_args,
)
