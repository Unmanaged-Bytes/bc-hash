// SPDX-License-Identifier: MIT

#include "bc_hash_cli_internal.h"
#include "bc_hash_strings_internal.h"

#include "bc_core.h"
#include "bc_core_parse.h"
#include "bc_runtime.h"
#include "bc_runtime_cli.h"

#define BC_HASH_CLI_SPEC_STDERR_BUFFER_BYTES ((size_t)512)

static void bc_hash_cli_spec_emit_stderr_cstring(const char* message)
{
    char stderr_buffer[BC_HASH_CLI_SPEC_STDERR_BUFFER_BYTES];
    bc_core_writer_t stderr_writer;
    if (!bc_core_writer_init_standard_error(&stderr_writer, stderr_buffer, sizeof(stderr_buffer))) {
        return;
    }
    (void)bc_core_writer_write_cstring(&stderr_writer, message);
    (void)bc_core_writer_destroy(&stderr_writer);
}

static void bc_hash_cli_spec_emit_stderr_invalid(const char* option, const char* value)
{
    char stderr_buffer[BC_HASH_CLI_SPEC_STDERR_BUFFER_BYTES];
    bc_core_writer_t stderr_writer;
    if (!bc_core_writer_init_standard_error(&stderr_writer, stderr_buffer, sizeof(stderr_buffer))) {
        return;
    }
    (void)bc_core_writer_write_cstring(&stderr_writer, "bc-hash: invalid value for ");
    (void)bc_core_writer_write_cstring(&stderr_writer, option);
    (void)bc_core_writer_write_cstring(&stderr_writer, ": '");
    (void)bc_core_writer_write_cstring(&stderr_writer, value);
    (void)bc_core_writer_write_cstring(&stderr_writer, "'\n");
    (void)bc_core_writer_destroy(&stderr_writer);
}

static const char* const bc_hash_algorithm_values[] = {"crc32", "sha256", "xxh3", "xxh128", NULL};

static const char* const bc_hash_format_values[] = {"auto", "simple", "json", "hrbl", NULL};

static const bc_runtime_cli_option_spec_t bc_hash_global_options[] = {
    {
        .long_name = "threads",
        .type = BC_RUNTIME_CLI_OPTION_STRING,
        .default_value = "auto",
        .value_placeholder = "mono|auto|io|N",
        .help_summary = "thread mode: mono (single-thread, alias 0), auto (CPU-bound, physical cores - 1, default), io (I/O-bound, logical processors - 1, oversubscribe), or N (1..logical_cpu_count)",
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
        .help_summary = "output destination (auto: stdout for <=20 files else ./bc-hash-<algo>.<ext>)",
    },
    {
        .long_name = "format",
        .type = BC_RUNTIME_CLI_OPTION_ENUM,
        .allowed_values = bc_hash_format_values,
        .default_value = "auto",
        .value_placeholder = "auto|simple|json|hrbl",
        .help_summary = "output format (auto picks by destination; hrbl is binary)",
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

#ifndef BC_HASH_VERSION_STRING
#define BC_HASH_VERSION_STRING "0.0.0-unversioned"
#endif

static const bc_runtime_cli_program_spec_t bc_hash_program_spec_value = {
    .program_name = "bc-hash",
    .version = BC_HASH_VERSION_STRING,
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
    if (bc_hash_strings_equal(value, "mono")) {
        *out_mode = BC_HASH_THREADS_MODE_MONO;
        *out_explicit_worker_count = 0;
        return true;
    }
    if (bc_hash_strings_equal(value, "auto")) {
        *out_mode = BC_HASH_THREADS_MODE_AUTO;
        *out_explicit_worker_count = 0;
        return true;
    }
    if (bc_hash_strings_equal(value, "io")) {
        *out_mode = BC_HASH_THREADS_MODE_IO;
        *out_explicit_worker_count = 0;
        return true;
    }
    size_t value_length = 0;
    (void)bc_core_length(value, '\0', &value_length);
    if (value_length == 0) {
        return false;
    }
    uint64_t parsed_value = 0;
    size_t consumed = 0;
    if (!bc_core_parse_unsigned_integer_64_decimal(value, value_length, &parsed_value, &consumed)) {
        return false;
    }
    if (consumed != value_length) {
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

static bool bc_hash_cli_bind_format(const char* value, bc_hash_output_format_mode_t* out_mode, bc_hash_output_format_t* out_format)
{
    if (bc_hash_strings_equal(value, "auto")) {
        *out_mode = BC_HASH_OUTPUT_FORMAT_MODE_AUTO;
        *out_format = BC_HASH_OUTPUT_FORMAT_SIMPLE;
        return true;
    }
    if (bc_hash_strings_equal(value, "simple")) {
        *out_mode = BC_HASH_OUTPUT_FORMAT_MODE_EXPLICIT;
        *out_format = BC_HASH_OUTPUT_FORMAT_SIMPLE;
        return true;
    }
    if (bc_hash_strings_equal(value, "json")) {
        *out_mode = BC_HASH_OUTPUT_FORMAT_MODE_EXPLICIT;
        *out_format = BC_HASH_OUTPUT_FORMAT_JSON;
        return true;
    }
    if (bc_hash_strings_equal(value, "hrbl")) {
        *out_mode = BC_HASH_OUTPUT_FORMAT_MODE_EXPLICIT;
        *out_format = BC_HASH_OUTPUT_FORMAT_HRBL;
        return true;
    }
    return false;
}

bool bc_hash_cli_bind_global_threads(const bc_runtime_config_store_t* store, bc_hash_threads_mode_t* out_mode,
                                     size_t* out_explicit_worker_count)
{
    const char* threads_value = NULL;
    if (!bc_runtime_config_store_get_string(store, "global.threads", &threads_value)) {
        bc_hash_cli_spec_emit_stderr_cstring("bc-hash: internal error: missing global.threads\n");
        return false;
    }
    if (!bc_hash_cli_bind_threads(threads_value, out_mode, out_explicit_worker_count)) {
        bc_hash_cli_spec_emit_stderr_invalid("--threads", threads_value);
        return false;
    }
    return true;
}

bool bc_hash_cli_bind_options(const bc_runtime_config_store_t* store, const bc_runtime_cli_parsed_t* parsed,
                              bc_hash_cli_options_t* out_options)
{
    bc_core_zero(out_options, sizeof(*out_options));

    if (!bc_hash_cli_bind_global_threads(store, &out_options->threads_mode, &out_options->explicit_worker_count)) {
        return false;
    }

    const char* type_value = NULL;
    if (!bc_runtime_config_store_get_string(store, "hash.type", &type_value)) {
        bc_hash_cli_spec_emit_stderr_cstring("bc-hash: internal error: missing hash.type\n");
        return false;
    }
    if (!bc_hash_cli_bind_algorithm(type_value, &out_options->algorithm)) {
        bc_hash_cli_spec_emit_stderr_invalid("--type", type_value);
        return false;
    }

    const char* output_value = NULL;
    if (!bc_runtime_config_store_get_string(store, "hash.output", &output_value)) {
        bc_hash_cli_spec_emit_stderr_cstring("bc-hash: internal error: missing hash.output\n");
        return false;
    }
    if (!bc_hash_cli_bind_output(output_value, &out_options->output_destination_mode, &out_options->output_destination_path)) {
        bc_hash_cli_spec_emit_stderr_invalid("--output", output_value);
        return false;
    }

    const char* format_value = NULL;
    if (!bc_runtime_config_store_get_string(store, "hash.format", &format_value)) {
        bc_hash_cli_spec_emit_stderr_cstring("bc-hash: internal error: missing hash.format\n");
        return false;
    }
    if (!bc_hash_cli_bind_format(format_value, &out_options->output_format_mode, &out_options->output_format)) {
        bc_hash_cli_spec_emit_stderr_invalid("--format", format_value);
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
