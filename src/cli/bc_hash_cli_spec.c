// SPDX-License-Identifier: MIT

#include "bc_hash_cli_internal.h"
#include "bc_hash_strings_internal.h"

#include "bc_core.h"
#include "bc_runtime.h"
#include "bc_runtime_cli.h"

#include <stdlib.h>

static const char* const bc_hash_algorithm_values[] = {"crc32", "sha256", "xxh3", "xxh128", NULL};

static const bc_runtime_cli_option_spec_t bc_hash_global_options[] = {
    {
        .long_name = "threads",
        .type = BC_RUNTIME_CLI_OPTION_STRING,
        .default_value = "auto",
        .value_placeholder = "auto|0|N",
        .help_summary = "worker count: auto, 0 (single-thread), or N",
    },
};

static const bc_runtime_cli_option_spec_t bc_hash_hash_options[] = {
    {
        .long_name = "type",
        .type = BC_RUNTIME_CLI_OPTION_ENUM,
        .allowed_values = bc_hash_algorithm_values,
        .required = true,
        .value_placeholder = "ALGO",
        .help_summary = "hash algorithm",
    },
    {
        .long_name = "output",
        .type = BC_RUNTIME_CLI_OPTION_STRING,
        .default_value = "auto",
        .value_placeholder = "auto|-|PATH",
        .help_summary = "output destination (file -> json, stdout -> sha256sum-style)",
    },
    {
        .long_name = "include",
        .type = BC_RUNTIME_CLI_OPTION_LIST,
        .value_placeholder = "GLOB",
        .help_summary = "only include files whose basename matches",
    },
    {
        .long_name = "exclude",
        .type = BC_RUNTIME_CLI_OPTION_LIST,
        .value_placeholder = "GLOB",
        .help_summary = "skip files or directories whose basename matches",
    },
};

static const bc_runtime_cli_command_spec_t bc_hash_commands[] = {
    {
        .name = "hash",
        .summary = "compute hashes for files and directories",
        .options = bc_hash_hash_options,
        .option_count = sizeof(bc_hash_hash_options) / sizeof(bc_hash_hash_options[0]),
        .positional_usage = "<path>...",
        .positional_min = 1,
        .positional_max = 0,
    },
    {
        .name = "check",
        .summary = "verify files against a digest file",
        .options = NULL,
        .option_count = 0,
        .positional_usage = "<digest-file>",
        .positional_min = 1,
        .positional_max = 1,
    },
    {
        .name = "diff",
        .summary = "compare two digest files",
        .options = NULL,
        .option_count = 0,
        .positional_usage = "<digest-a> <digest-b>",
        .positional_min = 2,
        .positional_max = 2,
    },
};

static const bc_runtime_cli_program_spec_t bc_hash_program_spec_value = {
    .program_name = "bc-hash",
    .version = "1.0.0",
    .summary = "parallel file-tree hashing",
    .global_options = bc_hash_global_options,
    .global_option_count = sizeof(bc_hash_global_options) / sizeof(bc_hash_global_options[0]),
    .commands = bc_hash_commands,
    .command_count = sizeof(bc_hash_commands) / sizeof(bc_hash_commands[0]),
};

const bc_runtime_cli_program_spec_t* bc_hash_cli_program_spec(void)
{
    return &bc_hash_program_spec_value;
}

static bool bc_hash_cli_bind_algorithm(const char* value, bc_hash_algorithm_t* out_algorithm)
{
    if (bc_hash_strings_equal(value, "crc32")) {
        *out_algorithm = BC_HASH_ALGORITHM_CRC32;
        return true;
    }
    if (bc_hash_strings_equal(value, "sha256")) {
        *out_algorithm = BC_HASH_ALGORITHM_SHA256;
        return true;
    }
    if (bc_hash_strings_equal(value, "xxh3")) {
        *out_algorithm = BC_HASH_ALGORITHM_XXH3;
        return true;
    }
    if (bc_hash_strings_equal(value, "xxh128")) {
        *out_algorithm = BC_HASH_ALGORITHM_XXH128;
        return true;
    }
    return false;
}

static bool bc_hash_cli_bind_threads(const char* value, bc_hash_threads_mode_t* out_mode, size_t* out_explicit_worker_count)
{
    if (bc_hash_strings_equal(value, "auto")) {
        *out_mode = BC_HASH_THREADS_MODE_AUTO;
        *out_explicit_worker_count = 0;
        return true;
    }
    if (value[0] == '\0') {
        return false;
    }
    char* end_pointer = NULL;
    unsigned long parsed_value = strtoul(value, &end_pointer, 10);
    if (end_pointer == value || *end_pointer != '\0') {
        return false;
    }
    if (parsed_value == 0) {
        *out_mode = BC_HASH_THREADS_MODE_MONO;
        *out_explicit_worker_count = 0;
        return true;
    }
    *out_mode = BC_HASH_THREADS_MODE_EXPLICIT;
    *out_explicit_worker_count = (size_t)parsed_value;
    return true;
}

static bool bc_hash_cli_bind_output(const char* value, bc_hash_output_destination_mode_t* out_mode, const char** out_path)
{
    if (bc_hash_strings_equal(value, "auto")) {
        *out_mode = BC_HASH_OUTPUT_DESTINATION_AUTO;
        *out_path = NULL;
        return true;
    }
    if (bc_hash_strings_equal(value, "-")) {
        *out_mode = BC_HASH_OUTPUT_DESTINATION_STDOUT;
        *out_path = NULL;
        return true;
    }
    if (value[0] == '\0') {
        return false;
    }
    *out_mode = BC_HASH_OUTPUT_DESTINATION_FILE;
    *out_path = value;
    return true;
}

bool bc_hash_cli_bind_global_threads(const bc_runtime_config_store_t* store, bc_hash_threads_mode_t* out_mode, size_t* out_explicit_worker_count)
{
    const char* threads_value = NULL;
    if (!bc_runtime_config_store_get_string(store, "global.threads", &threads_value)) {
        fputs("bc-hash: internal error: missing global.threads\n", stderr);
        return false;
    }
    if (!bc_hash_cli_bind_threads(threads_value, out_mode, out_explicit_worker_count)) {
        fprintf(stderr, "bc-hash: invalid value for --threads: '%s'\n", threads_value);
        return false;
    }
    return true;
}

bool bc_hash_cli_bind_options(const bc_runtime_config_store_t* store, const bc_runtime_cli_parsed_t* parsed, bc_hash_cli_options_t* out_options)
{
    bc_core_zero(out_options, sizeof(*out_options));

    if (!bc_hash_cli_bind_global_threads(store, &out_options->threads_mode, &out_options->explicit_worker_count)) {
        return false;
    }

    const char* type_value = NULL;
    if (!bc_runtime_config_store_get_string(store, "hash.type", &type_value)) {
        fputs("bc-hash: internal error: missing hash.type\n", stderr);
        return false;
    }
    if (!bc_hash_cli_bind_algorithm(type_value, &out_options->algorithm)) {
        fprintf(stderr, "bc-hash: invalid value for --type: '%s'\n", type_value);
        return false;
    }

    const char* output_value = NULL;
    if (!bc_runtime_config_store_get_string(store, "hash.output", &output_value)) {
        fputs("bc-hash: internal error: missing hash.output\n", stderr);
        return false;
    }
    if (!bc_hash_cli_bind_output(output_value, &out_options->output_destination_mode, &out_options->output_destination_path)) {
        fprintf(stderr, "bc-hash: invalid value for --output: '%s'\n", output_value);
        return false;
    }

    const char* include_value = NULL;
    if (bc_runtime_config_store_get_string(store, "hash.include", &include_value)) {
        out_options->include_list = include_value;
    }
    const char* exclude_value = NULL;
    if (bc_runtime_config_store_get_string(store, "hash.exclude", &exclude_value)) {
        out_options->exclude_list = exclude_value;
    }

    out_options->positional_argument_count = (int)parsed->positional_count;
    out_options->positional_argument_values = parsed->positional_values;
    return true;
}
