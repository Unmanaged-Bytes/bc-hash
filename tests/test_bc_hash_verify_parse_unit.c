// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bc_allocators.h"
#include "bc_containers_vector.h"
#include "bc_hash_verify_internal.h"

struct fixture {
    bc_allocators_context_t* memory_context;
    bc_containers_vector_t* vector;
    char digest_path[256];
};

static int setup(void** state)
{
    struct fixture* fixture = test_calloc(1, sizeof(*fixture));
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    if (!bc_allocators_context_create(&config, &fixture->memory_context)) {
        test_free(fixture);
        return -1;
    }
    if (!bc_containers_vector_create(fixture->memory_context, sizeof(bc_hash_verify_expectation_t), 16, 65536, &fixture->vector)) {
        bc_allocators_context_destroy(fixture->memory_context);
        test_free(fixture);
        return -1;
    }
    snprintf(fixture->digest_path, sizeof(fixture->digest_path), "/tmp/bc_hash_verify_unit_XXXXXX");
    int fd = mkstemp(fixture->digest_path);
    if (fd < 0) {
        bc_containers_vector_destroy(fixture->memory_context, fixture->vector);
        bc_allocators_context_destroy(fixture->memory_context);
        test_free(fixture);
        return -1;
    }
    close(fd);
    *state = fixture;
    return 0;
}

static int teardown(void** state)
{
    struct fixture* fixture = *state;
    unlink(fixture->digest_path);
    bc_containers_vector_destroy(fixture->memory_context, fixture->vector);
    bc_allocators_context_destroy(fixture->memory_context);
    test_free(fixture);
    return 0;
}

static int write_string(const char* path, const char* content)
{
    FILE* file = fopen(path, "w");
    if (file == NULL) {
        return -1;
    }
    size_t length = strlen(content);
    size_t written = fwrite(content, 1, length, file);
    fclose(file);
    return (written == length) ? 0 : -1;
}

static void test_parse_io_error_on_missing_file(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    unlink(fixture->digest_path);
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_IO_ERROR);
}

static void test_parse_empty_file_format_error(void** state)
{
    struct fixture* fixture = *state;
    assert_int_equal(write_string(fixture->digest_path, ""), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR);
}

static void test_parse_comment_lines_ignored(void** state)
{
    struct fixture* fixture = *state;
    const char* content =
        "# this is a comment\n"
        "   \n"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /path/a\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_OK);
    assert_int_equal(algorithm, BC_HASH_ALGORITHM_SHA256);
    assert_int_equal(bc_containers_vector_length(fixture->vector), 1);
}

static void test_parse_crlf_line_endings(void** state)
{
    struct fixture* fixture = *state;
    const char* content = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /path/a\r\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_OK);
    assert_int_equal(bc_containers_vector_length(fixture->vector), 1);
}

static void test_parse_binary_marker_asterisk(void** state)
{
    struct fixture* fixture = *state;
    const char* content = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad *path\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_OK);
}

static void test_parse_inconsistent_hex_length_rejected(void** state)
{
    struct fixture* fixture = *state;
    const char* content =
        "364b3fb7  /path/a\n"
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /path/b\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR);
}

static void test_parse_invalid_hex_length_rejected(void** state)
{
    struct fixture* fixture = *state;
    const char* content = "abc123  /path\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR);
}

static void test_parse_missing_separator_rejected(void** state)
{
    struct fixture* fixture = *state;
    const char* content = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad/path\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR);
}

static void test_parse_ndjson_with_all_escapes(void** state)
{
    struct fixture* fixture = *state;
    const char* content =
        "{\"type\":\"header\",\"tool\":\"bc-hash\",\"version\":\"1.0.0\",\"schema_version\":1,\"algorithm\":\"sha256\","
        "\"started_at\":\"2026-04-18T00:00:00Z\"}\n"
        "{\"type\":\"entry\",\"path\":\"/p/quote\\\"\\\\back\\/slash\\b\\f\\n\\r\\ttab\\u00e9eu\","
        "\"digest\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_CRC32;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_OK);
    assert_int_equal(algorithm, BC_HASH_ALGORITHM_SHA256);
    assert_int_equal(bc_containers_vector_length(fixture->vector), 1);
}

static void test_parse_ndjson_unicode_3byte_utf8(void** state)
{
    struct fixture* fixture = *state;
    const char* content =
        "{\"type\":\"header\",\"algorithm\":\"xxh3\"}\n"
        "{\"type\":\"entry\",\"path\":\"/p/\\u4e2d\",\"digest\":\"78af5f94892f3950\"}\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_OK);
    assert_int_equal(algorithm, BC_HASH_ALGORITHM_XXH3);
}

static void test_parse_ndjson_header_missing_algorithm(void** state)
{
    struct fixture* fixture = *state;
    const char* content =
        "{\"type\":\"header\",\"tool\":\"bc-hash\"}\n"
        "{\"type\":\"entry\",\"path\":\"/p\",\"digest\":\"78af5f94892f3950\"}\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR);
}

static void test_parse_ndjson_unknown_algorithm_rejected(void** state)
{
    struct fixture* fixture = *state;
    const char* content =
        "{\"type\":\"header\",\"algorithm\":\"md5\"}\n"
        "{\"type\":\"entry\",\"path\":\"/p\",\"digest\":\"abc\"}\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR);
}

static void test_parse_ndjson_entry_without_digest_tolerated(void** state)
{
    struct fixture* fixture = *state;
    const char* content =
        "{\"type\":\"header\",\"algorithm\":\"sha256\"}\n"
        "{\"type\":\"entry\",\"path\":\"/p\",\"ok\":false}\n"
        "{\"type\":\"entry\",\"path\":\"/q\",\"digest\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_OK);
    assert_int_equal(bc_containers_vector_length(fixture->vector), 1);
}

static void test_parse_ndjson_bad_escape_rejected(void** state)
{
    struct fixture* fixture = *state;
    const char* content =
        "{\"type\":\"header\",\"algorithm\":\"sha256\"}\n"
        "{\"type\":\"entry\",\"path\":\"/p\\q\",\"digest\":\"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"}\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR);
}

static void test_parse_simple_xxh128_derives_algo(void** state)
{
    struct fixture* fixture = *state;
    const char* content = "06b05ab6733a618578af5f94892f3950  /p\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_OK);
    assert_int_equal(algorithm, BC_HASH_ALGORITHM_XXH128);
}

static void test_parse_simple_crc32_derives_algo(void** state)
{
    struct fixture* fixture = *state;
    const char* content = "364b3fb7  /p\n";
    assert_int_equal(write_string(fixture->digest_path, content), 0);
    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bc_hash_verify_parse_status_t status =
        bc_hash_verify_parse_digest_file(fixture->memory_context, fixture->digest_path, fixture->vector, &algorithm);
    assert_int_equal(status, BC_HASH_VERIFY_PARSE_STATUS_OK);
    assert_int_equal(algorithm, BC_HASH_ALGORITHM_CRC32);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_parse_io_error_on_missing_file, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_empty_file_format_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_comment_lines_ignored, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_crlf_line_endings, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_binary_marker_asterisk, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_inconsistent_hex_length_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_invalid_hex_length_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_missing_separator_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_ndjson_with_all_escapes, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_ndjson_unicode_3byte_utf8, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_ndjson_header_missing_algorithm, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_ndjson_unknown_algorithm_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_ndjson_entry_without_digest_tolerated, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_ndjson_bad_escape_rejected, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_simple_xxh128_derives_algo, setup, teardown),
        cmocka_unit_test_setup_teardown(test_parse_simple_crc32_derives_algo, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
