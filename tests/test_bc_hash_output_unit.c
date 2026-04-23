// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "bc_allocators.h"
#include "bc_containers_vector.h"
#include "bc_hash_output_internal.h"
#include "bc_hash_types_internal.h"
#include "bc_hrbl.h"

struct fixture {
    bc_allocators_context_t* memory_context;
    bc_containers_vector_t* entries;
};

static int setup(void** state)
{
    struct fixture* fixture = test_calloc(1, sizeof(*fixture));
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    if (!bc_allocators_context_create(&config, &fixture->memory_context)) {
        test_free(fixture);
        return -1;
    }
    if (!bc_containers_vector_create(fixture->memory_context, sizeof(bc_hash_file_entry_t), 16, 256, &fixture->entries)) {
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
    bc_containers_vector_destroy(fixture->memory_context, fixture->entries);
    bc_allocators_context_destroy(fixture->memory_context);
    test_free(fixture);
    return 0;
}

static void push_entry(bc_containers_vector_t* entries, bc_allocators_context_t* memory_context, char* path, size_t size)
{
    bc_hash_file_entry_t entry = {.absolute_path = path, .absolute_path_length = strlen(path), .file_size = size};
    bc_containers_vector_push(memory_context, entries, &entry);
}

static void test_simple_skips_unsuccessful_entries(void** state)
{
    struct fixture* fixture = *state;
    push_entry(fixture->entries, fixture->memory_context, "/a", 3);
    push_entry(fixture->entries, fixture->memory_context, "/b", 3);

    bc_hash_result_entry_t results[2] = {0};
    results[0].success = true;
    for (size_t i = 0; i < 32; i++) results[0].sha256_digest[i] = (uint8_t)i;
    results[1].success = false;
    results[1].errno_value = ENOENT;

    char buffer[1024];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_SIMPLE, BC_HASH_ALGORITHM_SHA256, fixture->entries, results, NULL);
    fclose(stream);
    assert_non_null(strstr(buffer, "/a"));
    assert_null(strstr(buffer, "/b"));
}

static void test_simple_crc32(void** state)
{
    struct fixture* fixture = *state;
    push_entry(fixture->entries, fixture->memory_context, "/a", 3);
    bc_hash_result_entry_t results[1] = {0};
    results[0].success = true;
    results[0].crc32_value = 0xdeadbeefu;

    char buffer[256];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_SIMPLE, BC_HASH_ALGORITHM_CRC32, fixture->entries, results, NULL);
    fclose(stream);
    assert_non_null(strstr(buffer, "deadbeef"));
}

static void test_simple_xxh3(void** state)
{
    struct fixture* fixture = *state;
    push_entry(fixture->entries, fixture->memory_context, "/a", 3);
    bc_hash_result_entry_t results[1] = {0};
    results[0].success = true;
    for (size_t i = 0; i < BC_HASH_XXH3_DIGEST_SIZE; i++) results[0].xxh3_digest[i] = (uint8_t)(0x10 + i);

    char buffer[256];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_SIMPLE, BC_HASH_ALGORITHM_XXH3, fixture->entries, results, NULL);
    fclose(stream);
    assert_non_null(strstr(buffer, "1011121314151617"));
}

static void test_simple_xxh128(void** state)
{
    struct fixture* fixture = *state;
    push_entry(fixture->entries, fixture->memory_context, "/a", 3);
    bc_hash_result_entry_t results[1] = {0};
    results[0].success = true;
    for (size_t i = 0; i < BC_HASH_XXH128_DIGEST_SIZE; i++) results[0].xxh128_digest[i] = (uint8_t)(0xA0 + i);

    char buffer[256];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_SIMPLE, BC_HASH_ALGORITHM_XXH128, fixture->entries, results, NULL);
    fclose(stream);
    assert_non_null(strstr(buffer, "a0a1a2a3"));
}

static void test_json_crc32(void** state)
{
    struct fixture* fixture = *state;
    push_entry(fixture->entries, fixture->memory_context, "/a", 4);
    bc_hash_result_entry_t results[1] = {0};
    results[0].success = true;
    results[0].crc32_value = 0x12345678u;

    char buffer[2048];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_context_t context = {.tool_version = "test", .dispatch_mode = "parallel", .started_at_unix_ms = 1000, .wall_ms = 5,
                                         .worker_count = 2};
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_JSON, BC_HASH_ALGORITHM_CRC32, fixture->entries, results, &context);
    fclose(stream);
    assert_non_null(strstr(buffer, "\"algorithm\":\"crc32\""));
    assert_non_null(strstr(buffer, "\"digest\":\"12345678\""));
}

static void test_json_error_entry_emitted(void** state)
{
    struct fixture* fixture = *state;
    push_entry(fixture->entries, fixture->memory_context, "/a", 3);
    push_entry(fixture->entries, fixture->memory_context, "/b", 3);
    bc_hash_result_entry_t results[2] = {0};
    results[0].success = true;
    for (size_t i = 0; i < 32; i++) results[0].sha256_digest[i] = (uint8_t)i;
    results[1].success = false;
    results[1].errno_value = EIO;

    char buffer[2048];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_context_t context = {.tool_version = "test", .dispatch_mode = "sequential"};
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_JSON, BC_HASH_ALGORITHM_SHA256, fixture->entries, results, &context);
    fclose(stream);
    assert_non_null(strstr(buffer, "\"ok\":true"));
    assert_non_null(strstr(buffer, "\"ok\":false"));
    assert_non_null(strstr(buffer, "\"files_error\":1"));
    assert_non_null(strstr(buffer, "\"files_ok\":1"));
}

static void test_json_path_escape_all_chars(void** state)
{
    struct fixture* fixture = *state;
    char* weird_path = test_malloc(16);
    weird_path[0] = '/';
    weird_path[1] = '"';
    weird_path[2] = '\\';
    weird_path[3] = '\b';
    weird_path[4] = '\f';
    weird_path[5] = '\n';
    weird_path[6] = '\r';
    weird_path[7] = '\t';
    weird_path[8] = 0x01;
    weird_path[9] = '\0';
    push_entry(fixture->entries, fixture->memory_context, weird_path, 3);

    bc_hash_result_entry_t results[1] = {0};
    results[0].success = true;
    for (size_t i = 0; i < 32; i++) results[0].sha256_digest[i] = 0;

    char buffer[2048];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_context_t context = {.tool_version = "test", .dispatch_mode = "sequential"};
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_JSON, BC_HASH_ALGORITHM_SHA256, fixture->entries, results, &context);
    fclose(stream);
    assert_non_null(strstr(buffer, "\\\""));
    assert_non_null(strstr(buffer, "\\\\"));
    assert_non_null(strstr(buffer, "\\b"));
    assert_non_null(strstr(buffer, "\\f"));
    assert_non_null(strstr(buffer, "\\n"));
    assert_non_null(strstr(buffer, "\\r"));
    assert_non_null(strstr(buffer, "\\t"));
    assert_non_null(strstr(buffer, "\\u0001"));
    test_free(weird_path);
}

static void test_json_null_context_uses_defaults(void** state)
{
    struct fixture* fixture = *state;
    push_entry(fixture->entries, fixture->memory_context, "/a", 3);
    bc_hash_result_entry_t results[1] = {0};
    results[0].success = true;

    char buffer[2048];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_JSON, BC_HASH_ALGORITHM_SHA256, fixture->entries, results, NULL);
    fclose(stream);
    assert_non_null(strstr(buffer, "\"type\":\"header\""));
    assert_non_null(strstr(buffer, "\"type\":\"summary\""));
    assert_non_null(strstr(buffer, "\"mode\":\"unknown\""));
}

static void test_hrbl_magic_and_roundtrip(void** state)
{
    struct fixture* fixture = *state;
    push_entry(fixture->entries, fixture->memory_context, "/a.txt", 4);
    push_entry(fixture->entries, fixture->memory_context, "/b.log", 0);
    bc_hash_result_entry_t results[2] = {0};
    results[0].success = true;
    for (size_t i = 0; i < 32; i++) results[0].sha256_digest[i] = (uint8_t)(i + 1);
    results[1].success = false;
    results[1].errno_value = ENOENT;

    char buffer[8192];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_context_t context = {.tool_version = "1.2.0", .dispatch_mode = "parallel",
                                        .started_at_unix_ms = 1700000000000ULL, .wall_ms = 42, .worker_count = 8};
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_HRBL, BC_HASH_ALGORITHM_SHA256, fixture->entries, results, &context);
    long written = ftell(stream);
    fclose(stream);
    assert_true(written > 128);
    assert_int_equal((unsigned char)buffer[0], 'H');
    assert_int_equal((unsigned char)buffer[1], 'R');
    assert_int_equal((unsigned char)buffer[2], 'B');
    assert_int_equal((unsigned char)buffer[3], 'L');

    bc_hrbl_reader_t* reader = NULL;
    assert_true(bc_hrbl_reader_open_buffer(fixture->memory_context, buffer, (size_t)written, &reader));

    bc_hrbl_value_ref_t algorithm;
    assert_true(bc_hrbl_reader_find(reader, "bc_hash.algorithm", 17, &algorithm));
    const char* algorithm_data = NULL;
    size_t algorithm_length = 0;
    assert_true(bc_hrbl_reader_get_string(&algorithm, &algorithm_data, &algorithm_length));
    assert_int_equal(algorithm_length, 6);
    assert_memory_equal(algorithm_data, "sha256", 6);

    bc_hrbl_value_ref_t files_ok;
    assert_true(bc_hrbl_reader_find(reader, "bc_hash.files_ok", 16, &files_ok));
    uint64_t files_ok_value = 0;
    assert_true(bc_hrbl_reader_get_uint64(&files_ok, &files_ok_value));
    assert_int_equal((int)files_ok_value, 1);

    bc_hrbl_value_ref_t files_error;
    assert_true(bc_hrbl_reader_find(reader, "bc_hash.files_error", 19, &files_error));
    uint64_t files_error_value = 0;
    assert_true(bc_hrbl_reader_get_uint64(&files_error, &files_error_value));
    assert_int_equal((int)files_error_value, 1);

    bc_hrbl_reader_destroy(reader);
}

static void test_hrbl_file_entry_ok_and_error(void** state)
{
    struct fixture* fixture = *state;
    push_entry(fixture->entries, fixture->memory_context, "ok_path", 100);
    push_entry(fixture->entries, fixture->memory_context, "bad_path", 0);
    bc_hash_result_entry_t results[2] = {0};
    results[0].success = true;
    for (size_t i = 0; i < BC_HASH_XXH3_DIGEST_SIZE; i++) results[0].xxh3_digest[i] = (uint8_t)(0xC0 + i);
    results[1].success = false;
    results[1].errno_value = EACCES;

    char buffer[4096];
    FILE* stream = fmemopen(buffer, sizeof(buffer), "w");
    bc_hash_output_context_t context = {.tool_version = "1.2.0", .dispatch_mode = "sequential"};
    bc_hash_output_write(stream, BC_HASH_OUTPUT_FORMAT_HRBL, BC_HASH_ALGORITHM_XXH3, fixture->entries, results, &context);
    long written = ftell(stream);
    fclose(stream);

    bc_hrbl_reader_t* reader = NULL;
    assert_true(bc_hrbl_reader_open_buffer(fixture->memory_context, buffer, (size_t)written, &reader));

    bc_hrbl_value_ref_t ok_digest;
    assert_true(bc_hrbl_reader_find(reader, "bc_hash.files.ok_path.digest_hex", 32, &ok_digest));
    const char* digest_data = NULL;
    size_t digest_length = 0;
    assert_true(bc_hrbl_reader_get_string(&ok_digest, &digest_data, &digest_length));
    assert_int_equal(digest_length, BC_HASH_XXH3_HEX_LENGTH);
    assert_memory_equal(digest_data, "c0c1c2c3c4c5c6c7", BC_HASH_XXH3_HEX_LENGTH);

    bc_hrbl_value_ref_t bad_ok;
    assert_true(bc_hrbl_reader_find(reader, "bc_hash.files.bad_path.ok", 25, &bad_ok));
    bool bad_ok_value = true;
    assert_true(bc_hrbl_reader_get_bool(&bad_ok, &bad_ok_value));
    assert_false(bad_ok_value);

    bc_hrbl_value_ref_t bad_errno;
    assert_true(bc_hrbl_reader_find(reader, "bc_hash.files.bad_path.errno", 28, &bad_errno));
    int64_t errno_value = 0;
    assert_true(bc_hrbl_reader_get_int64(&bad_errno, &errno_value));
    assert_int_equal((int)errno_value, EACCES);

    bc_hrbl_reader_destroy(reader);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_simple_skips_unsuccessful_entries, setup, teardown),
        cmocka_unit_test_setup_teardown(test_simple_crc32, setup, teardown),
        cmocka_unit_test_setup_teardown(test_simple_xxh3, setup, teardown),
        cmocka_unit_test_setup_teardown(test_simple_xxh128, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_crc32, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_error_entry_emitted, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_path_escape_all_chars, setup, teardown),
        cmocka_unit_test_setup_teardown(test_json_null_context_uses_defaults, setup, teardown),
        cmocka_unit_test_setup_teardown(test_hrbl_magic_and_roundtrip, setup, teardown),
        cmocka_unit_test_setup_teardown(test_hrbl_file_entry_ok_and_error, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
