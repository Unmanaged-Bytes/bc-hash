// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <stdbool.h>
#include <string.h>

#include "bc_allocators.h"
#include "bc_hash_cli_internal.h"
#include "bc_runtime.h"
#include "bc_runtime_cli.h"

extern bool bc_runtime_config_store_set(bc_runtime_config_store_t* store, const char* key, const char* value);
extern bool bc_runtime_config_store_sort(bc_runtime_config_store_t* store);

struct fixture {
    bc_allocators_context_t* memory_context;
    bc_runtime_config_store_t* store;
};

static int setup(void** state)
{
    struct fixture* fixture = test_calloc(1, sizeof(*fixture));
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    if (!bc_allocators_context_create(&config, &fixture->memory_context)) {
        test_free(fixture);
        return -1;
    }
    if (!bc_runtime_config_store_create(fixture->memory_context, &fixture->store)) {
        bc_allocators_context_destroy(fixture->memory_context);
        test_free(fixture);
        return -1;
    }
    *state = fixture;
    return 0;
}

static int teardown(void** state)
{
    struct fixture* fixture = *state;
    bc_runtime_config_store_destroy(fixture->memory_context, fixture->store);
    bc_allocators_context_destroy(fixture->memory_context);
    test_free(fixture);
    return 0;
}

static void populate_hash_defaults(bc_runtime_config_store_t* store, const char* type_value, const char* output_value, const char* threads_value)
{
    const char* argv_template[8] = {"prog", NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    char type_argument[64];
    char output_argument[128];
    char threads_argument[64];
    int argument_count = 1;
    snprintf(type_argument, sizeof(type_argument), "--type=%s", type_value);
    argv_template[argument_count++] = type_argument;
    if (output_value != NULL) {
        snprintf(output_argument, sizeof(output_argument), "--output=%s", output_value);
        argv_template[argument_count++] = output_argument;
    }
    if (threads_value != NULL) {
        snprintf(threads_argument, sizeof(threads_argument), "--threads=%s", threads_value);
        argv_template[argument_count++] = threads_argument;
    }
    const bc_runtime_cli_program_spec_t* spec = bc_hash_cli_program_spec();
    bc_runtime_cli_parsed_t parsed;
    FILE* error_stream = fmemopen(NULL, 4096, "w");
    (void)bc_runtime_cli_parse(spec, argument_count, argv_template, store, &parsed, error_stream);
    if (error_stream != NULL) {
        fclose(error_stream);
    }
}

static void test_bind_global_threads_auto(void** state)
{
    struct fixture* fixture = *state;
    const char* argv[] = {"bc-hash", "hash", "--type=sha256", "/path"};
    bc_runtime_cli_parsed_t parsed;
    FILE* err = fmemopen(NULL, 4096, "w");
    assert_int_equal(bc_runtime_cli_parse(bc_hash_cli_program_spec(), 4, argv, fixture->store, &parsed, err), BC_RUNTIME_CLI_PARSE_OK);
    fclose(err);

    bc_hash_threads_mode_t mode = BC_HASH_THREADS_MODE_EXPLICIT;
    size_t count = 99;
    assert_true(bc_hash_cli_bind_global_threads(fixture->store, &mode, &count));
    assert_int_equal(mode, BC_HASH_THREADS_MODE_AUTO);
    assert_int_equal(count, 0);
}

static void test_bind_global_threads_mono(void** state)
{
    struct fixture* fixture = *state;
    const char* argv[] = {"bc-hash", "--threads=0", "hash", "--type=sha256", "/path"};
    bc_runtime_cli_parsed_t parsed;
    FILE* err = fmemopen(NULL, 4096, "w");
    assert_int_equal(bc_runtime_cli_parse(bc_hash_cli_program_spec(), 5, argv, fixture->store, &parsed, err), BC_RUNTIME_CLI_PARSE_OK);
    fclose(err);

    bc_hash_threads_mode_t mode = BC_HASH_THREADS_MODE_AUTO;
    size_t count = 99;
    assert_true(bc_hash_cli_bind_global_threads(fixture->store, &mode, &count));
    assert_int_equal(mode, BC_HASH_THREADS_MODE_MONO);
    assert_int_equal(count, 0);
}

static void test_bind_global_threads_explicit(void** state)
{
    struct fixture* fixture = *state;
    const char* argv[] = {"bc-hash", "--threads=7", "hash", "--type=sha256", "/path"};
    bc_runtime_cli_parsed_t parsed;
    FILE* err = fmemopen(NULL, 4096, "w");
    assert_int_equal(bc_runtime_cli_parse(bc_hash_cli_program_spec(), 5, argv, fixture->store, &parsed, err), BC_RUNTIME_CLI_PARSE_OK);
    fclose(err);

    bc_hash_threads_mode_t mode = BC_HASH_THREADS_MODE_AUTO;
    size_t count = 0;
    assert_true(bc_hash_cli_bind_global_threads(fixture->store, &mode, &count));
    assert_int_equal(mode, BC_HASH_THREADS_MODE_EXPLICIT);
    assert_int_equal(count, 7);
}

static void test_bind_options_output_stdout(void** state)
{
    struct fixture* fixture = *state;
    const char* argv[] = {"bc-hash", "hash", "--type=sha256", "--output=-", "/path"};
    bc_runtime_cli_parsed_t parsed;
    FILE* err = fmemopen(NULL, 4096, "w");
    assert_int_equal(bc_runtime_cli_parse(bc_hash_cli_program_spec(), 5, argv, fixture->store, &parsed, err), BC_RUNTIME_CLI_PARSE_OK);
    fclose(err);

    bc_hash_cli_options_t options;
    assert_true(bc_hash_cli_bind_options(fixture->store, &parsed, &options));
    assert_int_equal(options.output_destination_mode, BC_HASH_OUTPUT_DESTINATION_STDOUT);
    assert_int_equal(options.algorithm, BC_HASH_ALGORITHM_SHA256);
}

static void test_bind_options_output_path(void** state)
{
    struct fixture* fixture = *state;
    const char* argv[] = {"bc-hash", "hash", "--type=crc32", "--output=/tmp/out.json", "/path"};
    bc_runtime_cli_parsed_t parsed;
    FILE* err = fmemopen(NULL, 4096, "w");
    assert_int_equal(bc_runtime_cli_parse(bc_hash_cli_program_spec(), 5, argv, fixture->store, &parsed, err), BC_RUNTIME_CLI_PARSE_OK);
    fclose(err);

    bc_hash_cli_options_t options;
    assert_true(bc_hash_cli_bind_options(fixture->store, &parsed, &options));
    assert_int_equal(options.output_destination_mode, BC_HASH_OUTPUT_DESTINATION_FILE);
    assert_string_equal(options.output_destination_path, "/tmp/out.json");
    assert_int_equal(options.algorithm, BC_HASH_ALGORITHM_CRC32);
}

static void test_bind_options_output_auto(void** state)
{
    struct fixture* fixture = *state;
    const char* argv[] = {"bc-hash", "hash", "--type=xxh3", "/path"};
    bc_runtime_cli_parsed_t parsed;
    FILE* err = fmemopen(NULL, 4096, "w");
    assert_int_equal(bc_runtime_cli_parse(bc_hash_cli_program_spec(), 4, argv, fixture->store, &parsed, err), BC_RUNTIME_CLI_PARSE_OK);
    fclose(err);

    bc_hash_cli_options_t options;
    assert_true(bc_hash_cli_bind_options(fixture->store, &parsed, &options));
    assert_int_equal(options.output_destination_mode, BC_HASH_OUTPUT_DESTINATION_AUTO);
    assert_int_equal(options.algorithm, BC_HASH_ALGORITHM_XXH3);
}

static void test_bind_options_all_algorithms(void** state)
{
    struct fixture* fixture = *state;
    const char* cases[4][2] = {
        {"crc32", NULL},
        {"sha256", NULL},
        {"xxh3", NULL},
        {"xxh128", NULL},
    };
    const bc_hash_algorithm_t expected[4] = {BC_HASH_ALGORITHM_CRC32, BC_HASH_ALGORITHM_SHA256, BC_HASH_ALGORITHM_XXH3, BC_HASH_ALGORITHM_XXH128};
    for (size_t i = 0; i < 4; i++) {
        bc_runtime_config_store_t* local_store = NULL;
        assert_true(bc_runtime_config_store_create(fixture->memory_context, &local_store));
        char type_argument[64];
        snprintf(type_argument, sizeof(type_argument), "--type=%s", cases[i][0]);
        const char* argv[] = {"bc-hash", "hash", type_argument, "/path"};
        bc_runtime_cli_parsed_t parsed;
        FILE* err = fmemopen(NULL, 4096, "w");
        assert_int_equal(bc_runtime_cli_parse(bc_hash_cli_program_spec(), 4, argv, local_store, &parsed, err), BC_RUNTIME_CLI_PARSE_OK);
        fclose(err);

        bc_hash_cli_options_t options;
        assert_true(bc_hash_cli_bind_options(local_store, &parsed, &options));
        assert_int_equal(options.algorithm, expected[i]);
        bc_runtime_config_store_destroy(fixture->memory_context, local_store);
    }
}

static void test_bind_options_include_and_exclude_propagated(void** state)
{
    struct fixture* fixture = *state;
    const char* argv[] = {"bc-hash", "hash", "--type=sha256", "--include=*.c", "--exclude=*.tmp", "--exclude=.git", "/path"};
    bc_runtime_cli_parsed_t parsed;
    FILE* err = fmemopen(NULL, 4096, "w");
    assert_int_equal(bc_runtime_cli_parse(bc_hash_cli_program_spec(), 7, argv, fixture->store, &parsed, err), BC_RUNTIME_CLI_PARSE_OK);
    fclose(err);

    bc_hash_cli_options_t options;
    assert_true(bc_hash_cli_bind_options(fixture->store, &parsed, &options));
    assert_string_equal(options.include_list, "*.c");
    assert_string_equal(options.exclude_list, "*.tmp\n.git");
}

static void test_bind_options_missing_threads_fails(void** state)
{
    struct fixture* fixture = *state;
    bc_runtime_config_store_sort(fixture->store);
    bc_hash_threads_mode_t mode;
    size_t count;
    assert_false(bc_hash_cli_bind_global_threads(fixture->store, &mode, &count));
}

static void test_bind_options_invalid_threads_fails(void** state)
{
    struct fixture* fixture = *state;
    assert_true(bc_runtime_config_store_set(fixture->store, "global.threads", "not-a-number"));
    bc_runtime_config_store_sort(fixture->store);
    bc_hash_threads_mode_t mode;
    size_t count;
    assert_false(bc_hash_cli_bind_global_threads(fixture->store, &mode, &count));
}

static void test_bind_options_invalid_threads_trailing_garbage(void** state)
{
    struct fixture* fixture = *state;
    assert_true(bc_runtime_config_store_set(fixture->store, "global.threads", "7xyz"));
    bc_runtime_config_store_sort(fixture->store);
    bc_hash_threads_mode_t mode;
    size_t count;
    assert_false(bc_hash_cli_bind_global_threads(fixture->store, &mode, &count));
}

static void test_bind_options_empty_threads_fails(void** state)
{
    struct fixture* fixture = *state;
    assert_true(bc_runtime_config_store_set(fixture->store, "global.threads", ""));
    bc_runtime_config_store_sort(fixture->store);
    bc_hash_threads_mode_t mode;
    size_t count;
    assert_false(bc_hash_cli_bind_global_threads(fixture->store, &mode, &count));
}

static void test_bind_options_missing_type_fails(void** state)
{
    struct fixture* fixture = *state;
    bc_runtime_cli_parsed_t parsed = {.command = NULL, .positional_values = NULL, .positional_count = 0};
    assert_true(bc_runtime_config_store_set(fixture->store, "global.threads", "auto"));
    bc_runtime_config_store_sort(fixture->store);
    bc_hash_cli_options_t options;
    assert_false(bc_hash_cli_bind_options(fixture->store, &parsed, &options));
}

static void test_bind_options_invalid_type_fails(void** state)
{
    struct fixture* fixture = *state;
    assert_true(bc_runtime_config_store_set(fixture->store, "global.threads", "auto"));
    assert_true(bc_runtime_config_store_set(fixture->store, "hash.type", "md5"));
    bc_runtime_config_store_sort(fixture->store);
    bc_runtime_cli_parsed_t parsed = {.command = NULL, .positional_values = NULL, .positional_count = 0};
    bc_hash_cli_options_t options;
    assert_false(bc_hash_cli_bind_options(fixture->store, &parsed, &options));
}

static void test_bind_options_missing_output_fails(void** state)
{
    struct fixture* fixture = *state;
    assert_true(bc_runtime_config_store_set(fixture->store, "global.threads", "auto"));
    assert_true(bc_runtime_config_store_set(fixture->store, "hash.type", "sha256"));
    bc_runtime_config_store_sort(fixture->store);
    bc_runtime_cli_parsed_t parsed = {.command = NULL, .positional_values = NULL, .positional_count = 0};
    bc_hash_cli_options_t options;
    assert_false(bc_hash_cli_bind_options(fixture->store, &parsed, &options));
}

static void test_bind_options_empty_output_fails(void** state)
{
    struct fixture* fixture = *state;
    assert_true(bc_runtime_config_store_set(fixture->store, "global.threads", "auto"));
    assert_true(bc_runtime_config_store_set(fixture->store, "hash.type", "sha256"));
    assert_true(bc_runtime_config_store_set(fixture->store, "hash.output", ""));
    bc_runtime_config_store_sort(fixture->store);
    bc_runtime_cli_parsed_t parsed = {.command = NULL, .positional_values = NULL, .positional_count = 0};
    bc_hash_cli_options_t options;
    assert_false(bc_hash_cli_bind_options(fixture->store, &parsed, &options));
}

static void test_bind_options_bad_threads_propagates(void** state)
{
    struct fixture* fixture = *state;
    assert_true(bc_runtime_config_store_set(fixture->store, "global.threads", "bogus"));
    assert_true(bc_runtime_config_store_set(fixture->store, "hash.type", "sha256"));
    assert_true(bc_runtime_config_store_set(fixture->store, "hash.output", "-"));
    bc_runtime_config_store_sort(fixture->store);
    bc_runtime_cli_parsed_t parsed = {.command = NULL, .positional_values = NULL, .positional_count = 0};
    bc_hash_cli_options_t options;
    assert_false(bc_hash_cli_bind_options(fixture->store, &parsed, &options));
}

int main(void)
{
    (void)populate_hash_defaults;
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_bind_global_threads_auto, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_global_threads_mono, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_global_threads_explicit, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_output_stdout, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_output_path, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_output_auto, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_all_algorithms, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_include_and_exclude_propagated, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_missing_threads_fails, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_invalid_threads_fails, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_invalid_threads_trailing_garbage, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_empty_threads_fails, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_missing_type_fails, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_invalid_type_fails, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_missing_output_fails, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_empty_output_fails, setup, teardown),
        cmocka_unit_test_setup_teardown(test_bind_options_bad_threads_propagates, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
