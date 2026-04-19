// SPDX-License-Identifier: MIT

#include "bc_hash_cli_internal.h"
#include "bc_hash_diff_internal.h"
#include "bc_hash_discovery_internal.h"
#include "bc_hash_dispatch_decision_internal.h"
#include "bc_hash_error_internal.h"
#include "bc_hash_filter_internal.h"
#include "bc_hash_output_internal.h"
#include "bc_hash_throughput_internal.h"
#include "bc_hash_types_internal.h"
#include "bc_hash_verify_internal.h"
#include "bc_hash_worker_internal.h"

#include "bc_allocators.h"
#include "bc_allocators_pool.h"
#include "bc_concurrency.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_runtime.h"
#include "bc_runtime_cli.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define BC_HASH_APPLICATION_ENTRY_INITIAL_CAPACITY 128
#define BC_HASH_APPLICATION_ENTRY_MAX_CAPACITY (1ULL << 28)
#define BC_HASH_OUTPUT_STDOUT_THRESHOLD ((size_t)20)
#define BC_HASH_OUTPUT_BUFFER_BYTES ((size_t)(64 * 1024))
#ifndef BC_HASH_VERSION_STRING
#define BC_HASH_VERSION_STRING "0.0.0-unversioned"
#endif

static uint64_t bc_hash_main_realtime_unix_ms(void)
{
    struct timespec now_realtime;
    if (clock_gettime(CLOCK_REALTIME, &now_realtime) != 0) {
        return 0;
    }
    return (uint64_t)now_realtime.tv_sec * 1000u + (uint64_t)(now_realtime.tv_nsec / 1000000);
}

static uint64_t bc_hash_main_monotonic_ms(void)
{
    struct timespec now_monotonic;
    if (clock_gettime(CLOCK_MONOTONIC, &now_monotonic) != 0) {
        return 0;
    }
    return (uint64_t)now_monotonic.tv_sec * 1000u + (uint64_t)(now_monotonic.tv_nsec / 1000000);
}

typedef struct bc_hash_application_state {
    const bc_runtime_cli_parsed_t* parsed;
    const char* digest_file_path;
    const char* diff_path_a;
    const char* diff_path_b;
    bc_hash_cli_options_t cli_options;
    bc_containers_vector_t* entries;
    bc_hash_result_entry_t* results;
    bc_containers_vector_t* expectations;
    bc_hash_algorithm_t detected_algorithm;
    bc_hash_filter_t* filter;
    bc_hash_error_collector_t* errors;
    int exit_code;
} bc_hash_application_state_t;

static bool bc_hash_application_is_check(const bc_hash_application_state_t* state)
{
    return state->parsed != NULL && state->parsed->command != NULL && strcmp(state->parsed->command->name, "check") == 0;
}

static bool bc_hash_application_is_diff(const bc_hash_application_state_t* state)
{
    return state->parsed != NULL && state->parsed->command != NULL && strcmp(state->parsed->command->name, "diff") == 0;
}

static bool bc_hash_application_init(const bc_runtime_t* application, void* user_data)
{
    bc_hash_application_state_t* state = (bc_hash_application_state_t*)user_data;

    bc_allocators_context_t* memory_context = NULL;
    if (!bc_runtime_memory_context(application, &memory_context)) {
        state->exit_code = 1;
        return false;
    }

    if (!bc_hash_error_collector_create(memory_context, &state->errors)) {
        state->exit_code = 1;
        return false;
    }

    if (bc_hash_application_is_check(state)) {
        if (!bc_containers_vector_create(memory_context, sizeof(bc_hash_verify_expectation_t), BC_HASH_APPLICATION_ENTRY_INITIAL_CAPACITY,
                                         BC_HASH_APPLICATION_ENTRY_MAX_CAPACITY, &state->expectations)) {
            state->exit_code = 1;
            return false;
        }
        return true;
    }

    if (bc_hash_application_is_diff(state)) {
        return true;
    }

    if (!bc_containers_vector_create(memory_context, sizeof(bc_hash_file_entry_t), BC_HASH_APPLICATION_ENTRY_INITIAL_CAPACITY,
                                     BC_HASH_APPLICATION_ENTRY_MAX_CAPACITY, &state->entries)) {
        state->exit_code = 1;
        return false;
    }

    if (state->cli_options.include_list != NULL || state->cli_options.exclude_list != NULL) {
        if (!bc_hash_filter_create(memory_context, state->cli_options.include_list, state->cli_options.exclude_list, &state->filter)) {
            state->exit_code = 1;
            return false;
        }
    }

    return true;
}

static bool bc_hash_check_run(const bc_runtime_t* application, bc_hash_application_state_t* state)
{
    bc_allocators_context_t* memory_context = NULL;
    if (!bc_runtime_memory_context(application, &memory_context)) {
        state->exit_code = 1;
        return false;
    }

    bc_concurrency_context_t* concurrency_context = NULL;
    if (!bc_runtime_parallel_context(application, &concurrency_context)) {
        state->exit_code = 1;
        return false;
    }

    bc_concurrency_signal_handler_t* signal_handler = NULL;
    bc_runtime_signal_handler(application, &signal_handler);

    bc_hash_verify_parse_status_t parse_status =
        bc_hash_verify_parse_digest_file(memory_context, state->digest_file_path, state->expectations, &state->detected_algorithm);
    if (parse_status == BC_HASH_VERIFY_PARSE_STATUS_IO_ERROR) {
        fprintf(stderr, "bc-hash: cannot read digest file '%s'\n", state->digest_file_path);
        state->exit_code = 2;
        return false;
    }
    if (parse_status == BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR) {
        fprintf(stderr, "bc-hash: malformed digest file '%s'\n", state->digest_file_path);
        state->exit_code = 2;
        return false;
    }

    int verify_exit_code = 0;
    if (!bc_hash_verify_run(memory_context, concurrency_context, signal_handler, state->detected_algorithm, state->expectations,
                            state->errors, &verify_exit_code)) {
        state->exit_code = 1;
        return false;
    }

    bc_hash_error_collector_flush_to_stderr(state->errors);
    state->exit_code = verify_exit_code;
    return true;
}

static bool bc_hash_diff_application_run(const bc_runtime_t* application, bc_hash_application_state_t* state)
{
    bc_allocators_context_t* memory_context = NULL;
    if (!bc_runtime_memory_context(application, &memory_context)) {
        state->exit_code = 1;
        return false;
    }

    int diff_exit_code = 0;
    if (!bc_hash_diff_run(memory_context, state->diff_path_a, state->diff_path_b, &diff_exit_code)) {
        state->exit_code = 1;
        return false;
    }
    state->exit_code = diff_exit_code;
    return true;
}

static bool bc_hash_application_run(const bc_runtime_t* application, void* user_data)
{
    bc_hash_application_state_t* state = (bc_hash_application_state_t*)user_data;

    if (bc_hash_application_is_check(state)) {
        return bc_hash_check_run(application, state);
    }

    if (bc_hash_application_is_diff(state)) {
        return bc_hash_diff_application_run(application, state);
    }

    uint64_t started_at_unix_ms = bc_hash_main_realtime_unix_ms();
    uint64_t started_at_monotonic_ms = bc_hash_main_monotonic_ms();

    bc_allocators_context_t* memory_context = NULL;
    if (!bc_runtime_memory_context(application, &memory_context)) {
        state->exit_code = 1;
        return false;
    }

    bc_concurrency_context_t* concurrency_context = NULL;
    if (!bc_runtime_parallel_context(application, &concurrency_context)) {
        state->exit_code = 1;
        return false;
    }

    const char* const* positional_argument_values = state->cli_options.positional_argument_values;
    size_t positional_argument_count = (size_t)state->cli_options.positional_argument_count;

    bc_concurrency_signal_handler_t* signal_handler = NULL;
    bc_runtime_signal_handler(application, &signal_handler);

    size_t discovery_worker_count = bc_concurrency_effective_worker_count(concurrency_context);
    bool discovery_ok;
    if (discovery_worker_count >= 2) {
        discovery_ok = bc_hash_discovery_expand_parallel(memory_context, concurrency_context, state->entries, state->errors,
                                                        signal_handler, state->filter, positional_argument_values, positional_argument_count);
    } else {
        discovery_ok = bc_hash_discovery_expand(memory_context, state->entries, state->errors, signal_handler, state->filter,
                                                positional_argument_values, positional_argument_count);
    }
    if (!discovery_ok) {
        state->exit_code = 1;
        return false;
    }

    bool interrupted_after_discovery = false;
    bc_runtime_should_stop(application, &interrupted_after_discovery);
    if (interrupted_after_discovery) {
        fputs("bc-hash: interrupted by signal, aborting before hash phase\n", stderr);
        state->exit_code = 130;
        return false;
    }

    size_t entry_count = bc_containers_vector_length(state->entries);
    if (entry_count == 0) {
        bc_hash_error_collector_flush_to_stderr(state->errors);
        state->exit_code = bc_hash_error_collector_count(state->errors) == 0 ? 0 : 1;
        return true;
    }

    size_t results_bytes = entry_count * sizeof(bc_hash_result_entry_t);
    if (!bc_allocators_pool_allocate(memory_context, results_bytes, (void**)&state->results)) {
        state->exit_code = 1;
        return false;
    }
    bc_core_zero(state->results, results_bytes);

    size_t effective_worker_count = bc_concurrency_effective_worker_count(concurrency_context);
    bool should_go_multithread;
    if (effective_worker_count < 2) {
        should_go_multithread = false;
    } else if (state->cli_options.threads_mode == BC_HASH_THREADS_MODE_EXPLICIT) {
        should_go_multithread = true;
    } else {
        size_t total_bytes = 0;
        for (size_t index = 0; index < entry_count; ++index) {
            bc_hash_file_entry_t entry;
            if (bc_containers_vector_get(state->entries, index, &entry)) {
                total_bytes += entry.file_size;
            }
        }
        bc_hash_throughput_constants_t throughput_constants;
        if (bc_hash_throughput_get_or_measure(concurrency_context, &throughput_constants)) {
            should_go_multithread = bc_hash_dispatch_decision_should_go_multithread(entry_count, total_bytes, &throughput_constants,
                                                                                    effective_worker_count);
        } else {
            should_go_multithread = true;
        }
    }

    bool dispatch_ok;
    if (should_go_multithread) {
        dispatch_ok = bc_hash_worker_dispatch_all(concurrency_context, state->cli_options.algorithm, state->entries, state->results,
                                                  state->errors, memory_context, signal_handler);
    } else {
        dispatch_ok = bc_hash_worker_dispatch_sequential(state->cli_options.algorithm, state->entries, state->results, state->errors,
                                                         memory_context, signal_handler);
    }
    if (!dispatch_ok) {
        state->exit_code = 1;
        return false;
    }

    bool interrupted_after_hash = false;
    bc_runtime_should_stop(application, &interrupted_after_hash);
    if (interrupted_after_hash) {
        fputs("bc-hash: interrupted by signal, partial results may be written\n", stderr);
    }

    FILE* output_stream = stdout;
    FILE* opened_output_file = NULL;
    char auto_output_path[256];
    const char* output_destination_label = NULL;
    char output_buffer[BC_HASH_OUTPUT_BUFFER_BYTES];

    if (state->cli_options.output_destination_mode == BC_HASH_OUTPUT_DESTINATION_FILE) {
        opened_output_file = fopen(state->cli_options.output_destination_path, "w");
        if (opened_output_file == NULL) {
            fprintf(stderr, "bc-hash: cannot open --output path '%s'\n", state->cli_options.output_destination_path);
            state->exit_code = 1;
            return false;
        }
        output_stream = opened_output_file;
        output_destination_label = state->cli_options.output_destination_path;
    } else if (state->cli_options.output_destination_mode == BC_HASH_OUTPUT_DESTINATION_AUTO) {
        bool stdout_is_terminal = isatty(fileno(stdout)) != 0;
        if (stdout_is_terminal && entry_count > BC_HASH_OUTPUT_STDOUT_THRESHOLD) {
            const char* algorithm_name;
            switch (state->cli_options.algorithm) {
                case BC_HASH_ALGORITHM_CRC32:
                    algorithm_name = "crc32";
                    break;
                case BC_HASH_ALGORITHM_XXH3:
                    algorithm_name = "xxh3";
                    break;
                case BC_HASH_ALGORITHM_XXH128:
                    algorithm_name = "xxh128";
                    break;
                case BC_HASH_ALGORITHM_SHA256:
                default:
                    algorithm_name = "sha256";
                    break;
            }
            snprintf(auto_output_path, sizeof(auto_output_path), "./bc-hash-%s.ndjson", algorithm_name);
            opened_output_file = fopen(auto_output_path, "w");
            if (opened_output_file == NULL) {
                fprintf(stderr, "bc-hash: cannot open default output path '%s', falling back to stdout\n", auto_output_path);
            } else {
                output_stream = opened_output_file;
                output_destination_label = auto_output_path;
            }
        }
    }

    (void)setvbuf(output_stream, output_buffer, _IOFBF, sizeof(output_buffer));

    bc_hash_output_format_t output_format = opened_output_file != NULL ? BC_HASH_OUTPUT_FORMAT_JSON : BC_HASH_OUTPUT_FORMAT_SIMPLE;

    bc_hash_output_context_t output_context = {
        .started_at_unix_ms = started_at_unix_ms,
        .wall_ms = bc_hash_main_monotonic_ms() - started_at_monotonic_ms,
        .worker_count = effective_worker_count,
        .dispatch_mode = should_go_multithread ? "parallel" : "sequential",
        .tool_version = BC_HASH_VERSION_STRING,
    };
    bc_hash_output_write(output_stream, output_format, state->cli_options.algorithm, state->entries, state->results, &output_context);

    if (opened_output_file != NULL) {
        fflush(opened_output_file);
        fclose(opened_output_file);
    } else {
        fflush(stdout);
    }

    if (output_destination_label != NULL) {
        size_t success_count = 0;
        for (size_t index = 0; index < entry_count; ++index) {
            if (state->results[index].success) {
                success_count += 1;
            }
        }
        fprintf(stderr, "bc-hash: hashed %zu files, %zu written to %s\n", entry_count, success_count, output_destination_label);
    }

    bc_hash_error_collector_flush_to_stderr(state->errors);

    size_t error_count = bc_hash_error_collector_count(state->errors);
    state->exit_code = error_count == 0 ? 0 : 1;
    return true;
}

static void bc_hash_application_cleanup(const bc_runtime_t* application, void* user_data)
{
    bc_hash_application_state_t* state = (bc_hash_application_state_t*)user_data;

    bc_allocators_context_t* memory_context = NULL;
    if (!bc_runtime_memory_context(application, &memory_context)) {
        return;
    }

    if (state->results != NULL) {
        bc_allocators_pool_free(memory_context, state->results);
        state->results = NULL;
    }

    if (state->entries != NULL) {
        bc_containers_vector_destroy(memory_context, state->entries);
        state->entries = NULL;
    }

    if (state->expectations != NULL) {
        bc_containers_vector_destroy(memory_context, state->expectations);
        state->expectations = NULL;
    }

    if (state->filter != NULL) {
        bc_hash_filter_destroy(memory_context, state->filter);
        state->filter = NULL;
    }

    if (state->errors != NULL) {
        bc_hash_error_collector_destroy(memory_context, state->errors);
        state->errors = NULL;
    }
}

int main(int argument_count, char** argument_values)
{
    const bc_runtime_cli_program_spec_t* spec = bc_hash_cli_program_spec();

    bc_allocators_context_config_t cli_memory_config = {.tracking_enabled = true};
    bc_allocators_context_t* cli_memory_context = NULL;
    if (!bc_allocators_context_create(&cli_memory_config, &cli_memory_context)) {
        fputs("bc-hash: failed to initialize CLI memory context\n", stderr);
        return 1;
    }

    bc_runtime_config_store_t* cli_store = NULL;
    if (!bc_runtime_config_store_create(cli_memory_context, &cli_store)) {
        fputs("bc-hash: failed to initialize CLI config store\n", stderr);
        bc_allocators_context_destroy(cli_memory_context);
        return 1;
    }

    bc_runtime_cli_parsed_t parsed;
    bc_runtime_cli_parse_status_t parse_status =
        bc_runtime_cli_parse(spec, argument_count, (const char* const*)argument_values, cli_store, &parsed, stderr);

    if (parse_status == BC_RUNTIME_CLI_PARSE_HELP_GLOBAL) {
        bc_runtime_cli_print_help_global(spec, stdout);
        bc_runtime_config_store_destroy(cli_memory_context, cli_store);
        bc_allocators_context_destroy(cli_memory_context);
        return 0;
    }
    if (parse_status == BC_RUNTIME_CLI_PARSE_HELP_COMMAND) {
        bc_runtime_cli_print_help_command(spec, parsed.command, stdout);
        bc_runtime_config_store_destroy(cli_memory_context, cli_store);
        bc_allocators_context_destroy(cli_memory_context);
        return 0;
    }
    if (parse_status == BC_RUNTIME_CLI_PARSE_VERSION) {
        bc_runtime_cli_print_version(spec, stdout);
        bc_runtime_config_store_destroy(cli_memory_context, cli_store);
        bc_allocators_context_destroy(cli_memory_context);
        return 0;
    }
    if (parse_status == BC_RUNTIME_CLI_PARSE_ERROR) {
        bc_runtime_config_store_destroy(cli_memory_context, cli_store);
        bc_allocators_context_destroy(cli_memory_context);
        return 2;
    }

    bc_hash_application_state_t state;
    bc_core_zero(&state, sizeof(state));
    state.parsed = &parsed;

    bc_hash_threads_mode_t threads_mode = BC_HASH_THREADS_MODE_AUTO;
    size_t explicit_worker_count = 0;

    if (strcmp(parsed.command->name, "check") == 0) {
        if (parsed.positional_count != 1) {
            fputs("bc-hash: check requires exactly one digest file argument\n", stderr);
            bc_runtime_config_store_destroy(cli_memory_context, cli_store);
            bc_allocators_context_destroy(cli_memory_context);
            return 2;
        }
        state.digest_file_path = parsed.positional_values[0];
        if (!bc_hash_cli_bind_global_threads(cli_store, &threads_mode, &explicit_worker_count)) {
            bc_runtime_config_store_destroy(cli_memory_context, cli_store);
            bc_allocators_context_destroy(cli_memory_context);
            return 2;
        }
    } else if (strcmp(parsed.command->name, "diff") == 0) {
        if (parsed.positional_count != 2) {
            fputs("bc-hash: diff requires exactly two digest file arguments\n", stderr);
            bc_runtime_config_store_destroy(cli_memory_context, cli_store);
            bc_allocators_context_destroy(cli_memory_context);
            return 2;
        }
        state.diff_path_a = parsed.positional_values[0];
        state.diff_path_b = parsed.positional_values[1];
        if (!bc_hash_cli_bind_global_threads(cli_store, &threads_mode, &explicit_worker_count)) {
            bc_runtime_config_store_destroy(cli_memory_context, cli_store);
            bc_allocators_context_destroy(cli_memory_context);
            return 2;
        }
    } else {
        if (!bc_hash_cli_bind_options(cli_store, &parsed, &state.cli_options)) {
            bc_runtime_config_store_destroy(cli_memory_context, cli_store);
            bc_allocators_context_destroy(cli_memory_context);
            return 2;
        }
        threads_mode = state.cli_options.threads_mode;
        explicit_worker_count = state.cli_options.explicit_worker_count;
    }

    bc_concurrency_config_t parallel_config;
    bc_core_zero(&parallel_config, sizeof(parallel_config));
    if (threads_mode == BC_HASH_THREADS_MODE_MONO) {
        parallel_config.worker_count_explicit = true;
        parallel_config.worker_count = 0;
    } else if (threads_mode == BC_HASH_THREADS_MODE_EXPLICIT) {
        parallel_config.worker_count_explicit = true;
        parallel_config.worker_count = explicit_worker_count >= 1 ? explicit_worker_count - 1 : 0;
    }

    bc_runtime_config_t runtime_config = {
        .max_pool_memory = 0,
        .memory_tracking_enabled = true,
        .log_level = BC_RUNTIME_LOG_LEVEL_WARN,
        .config_file_path = NULL,
        .argument_count = 0,
        .argument_values = NULL,
        .parallel_config = &parallel_config,
    };
    bc_runtime_callbacks_t runtime_callbacks = {
        .init = bc_hash_application_init,
        .run = bc_hash_application_run,
        .cleanup = bc_hash_application_cleanup,
    };

    bc_runtime_t* runtime = NULL;
    if (!bc_runtime_create(&runtime_config, &runtime_callbacks, &state, &runtime)) {
        fputs("bc-hash: failed to initialize runtime\n", stderr);
        bc_runtime_config_store_destroy(cli_memory_context, cli_store);
        bc_allocators_context_destroy(cli_memory_context);
        return 1;
    }

    bc_runtime_run(runtime);
    bc_runtime_destroy(runtime);

    bc_runtime_config_store_destroy(cli_memory_context, cli_store);
    bc_allocators_context_destroy(cli_memory_context);

    return state.exit_code;
}
