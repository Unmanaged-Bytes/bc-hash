// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef BC_HASH_TEST_BINARY_PATH
#error "BC_HASH_TEST_BINARY_PATH must be defined"
#endif

#ifndef BC_HASH_TEST_FIXTURES_DIRECTORY
#error "BC_HASH_TEST_FIXTURES_DIRECTORY must be defined"
#endif

static int bc_hash_json_test_write_file(const char* absolute_path, const void* payload, size_t payload_size)
{
    int file_descriptor = open(absolute_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (file_descriptor < 0) {
        return -1;
    }
    ssize_t written = write(file_descriptor, payload, payload_size);
    close(file_descriptor);
    if (written < 0 || (size_t)written != payload_size) {
        return -1;
    }
    return 0;
}

static int bc_hash_json_test_ensure_directory(const char* absolute_path)
{
    if (mkdir(absolute_path, 0755) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int bc_hash_json_test_run(const char* type_value, const char* target_path, const char* output_path, int* out_exit_status)
{
    char type_argument[64];
    char output_argument[512];
    snprintf(type_argument, sizeof(type_argument), "--type=%s", type_value);
    snprintf(output_argument, sizeof(output_argument), "--output=%s", output_path);

    pid_t child_pid = fork();
    if (child_pid < 0) {
        return -1;
    }
    if (child_pid == 0) {
        int dev_null = open("/dev/null", O_WRONLY);
        if (dev_null >= 0) {
            dup2(dev_null, STDERR_FILENO);
            close(dev_null);
        }
        char* const execv_argv[] = {(char*)BC_HASH_TEST_BINARY_PATH,
                                    (char*)"hash",
                                    type_argument,
                                    output_argument,
                                    (char*)target_path,
                                    NULL};
        execv(BC_HASH_TEST_BINARY_PATH, execv_argv);
        _exit(127);
    }

    int child_status = 0;
    waitpid(child_pid, &child_status, 0);
    *out_exit_status = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1;
    return 0;
}

static int bc_hash_json_test_jq_empty(const char* absolute_path)
{
    char shell_command[1024];
    snprintf(shell_command, sizeof(shell_command), "jq empty < '%s' > /dev/null 2>&1", absolute_path);
    return system(shell_command);
}

static int bc_hash_json_test_jq_extract(const char* absolute_path, const char* jq_filter, char* out_buffer, size_t buffer_size)
{
    char shell_command[1024];
    snprintf(shell_command, sizeof(shell_command), "jq -r %s < '%s'", jq_filter, absolute_path);
    FILE* pipe = popen(shell_command, "r");
    if (pipe == NULL) {
        return -1;
    }
    size_t total_read = 0;
    while (total_read + 1 < buffer_size) {
        size_t bytes_read = fread(out_buffer + total_read, 1, buffer_size - 1 - total_read, pipe);
        if (bytes_read == 0) {
            break;
        }
        total_read += bytes_read;
    }
    out_buffer[total_read] = '\0';
    int status = pclose(pipe);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return -1;
    }
    return (int)total_read;
}

static void test_json_output_is_valid_ndjson_jq_empty(void** state)
{
    (void)state;
    const char* fixture_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_abc.bin";
    const char* output_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_output_smoke.ndjson";
    assert_int_equal(bc_hash_json_test_write_file(fixture_path, "abc", 3), 0);
    unlink(output_path);

    int exit_status = -1;
    assert_int_equal(bc_hash_json_test_run("sha256", fixture_path, output_path, &exit_status), 0);
    assert_int_equal(exit_status, 0);

    struct stat file_stat;
    assert_int_equal(stat(output_path, &file_stat), 0);
    assert_true(file_stat.st_size > 0);

    assert_int_equal(bc_hash_json_test_jq_empty(output_path), 0);
}

static void test_json_output_first_line_is_header_last_is_summary(void** state)
{
    (void)state;
    const char* fixture_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_struct.bin";
    const char* output_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_output_struct.ndjson";
    assert_int_equal(bc_hash_json_test_write_file(fixture_path, "abc", 3), 0);
    unlink(output_path);

    int exit_status = -1;
    assert_int_equal(bc_hash_json_test_run("sha256", fixture_path, output_path, &exit_status), 0);
    assert_int_equal(exit_status, 0);

    char head_buffer[256];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"header\") | .schema_version' | head -n1", head_buffer,
                                             sizeof(head_buffer)) >= 0);
    assert_non_null(strstr(head_buffer, "1"));

    char algo_buffer[256];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"header\") | .algorithm'", algo_buffer, sizeof(algo_buffer)) >= 0);
    assert_non_null(strstr(algo_buffer, "sha256"));

    char digest_buffer[256];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"entry\") | .digest'", digest_buffer,
                                             sizeof(digest_buffer)) >= 0);
    assert_non_null(strstr(digest_buffer, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    char summary_total_buffer[64];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"summary\") | .files_total'", summary_total_buffer,
                                             sizeof(summary_total_buffer)) >= 0);
    assert_non_null(strstr(summary_total_buffer, "1"));
}

static void test_json_output_counts_consistent(void** state)
{
    (void)state;
    const char* directory_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_counts_tree";
    const char* output_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_counts.ndjson";
    assert_int_equal(bc_hash_json_test_ensure_directory(directory_path), 0);
    assert_int_equal(bc_hash_json_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/json_counts_tree/a.bin", "abc", 3), 0);
    assert_int_equal(bc_hash_json_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/json_counts_tree/b.bin", "hello", 5), 0);
    assert_int_equal(bc_hash_json_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/json_counts_tree/c.bin", "world!", 6), 0);
    unlink(output_path);

    int exit_status = -1;
    assert_int_equal(bc_hash_json_test_run("sha256", directory_path, output_path, &exit_status), 0);
    assert_int_equal(exit_status, 0);

    char consistency_buffer[64];
    assert_true(bc_hash_json_test_jq_extract(output_path,
                                             "'select(.type==\"summary\") | (.files_total == (.files_ok + .files_error))'",
                                             consistency_buffer, sizeof(consistency_buffer)) >= 0);
    assert_non_null(strstr(consistency_buffer, "true"));

    char total_buffer[64];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"summary\") | .files_total'", total_buffer,
                                             sizeof(total_buffer)) >= 0);
    assert_non_null(strstr(total_buffer, "3"));
}

static void test_json_output_escapes_special_characters_in_path(void** state)
{
    (void)state;
    const char* directory_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_escape_tree";
    const char* output_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_escape.ndjson";
    assert_int_equal(bc_hash_json_test_ensure_directory(directory_path), 0);

    const char* quote_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_escape_tree/name_with_\"_quote.bin";
    const char* backslash_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_escape_tree/name_with_\\_backslash.bin";
    const char* control_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_escape_tree/name_with_\x01_ctrl.bin";
    const char* utf8_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_escape_tree/café_utf8.bin";
    const char* newline_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_escape_tree/name_with_\n_newline.bin";

    assert_int_equal(bc_hash_json_test_write_file(quote_path, "a", 1), 0);
    assert_int_equal(bc_hash_json_test_write_file(backslash_path, "a", 1), 0);
    assert_int_equal(bc_hash_json_test_write_file(control_path, "a", 1), 0);
    assert_int_equal(bc_hash_json_test_write_file(utf8_path, "a", 1), 0);
    assert_int_equal(bc_hash_json_test_write_file(newline_path, "a", 1), 0);
    unlink(output_path);

    int exit_status = -1;
    assert_int_equal(bc_hash_json_test_run("sha256", directory_path, output_path, &exit_status), 0);
    assert_int_equal(exit_status, 0);

    assert_int_equal(bc_hash_json_test_jq_empty(output_path), 0);

    char paths_buffer[4096];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"entry\") | .path'", paths_buffer, sizeof(paths_buffer)) >= 0);

    assert_non_null(strstr(paths_buffer, "name_with_\"_quote.bin"));
    assert_non_null(strstr(paths_buffer, "name_with_\\_backslash.bin"));
    assert_non_null(strstr(paths_buffer, "name_with_\x01_ctrl.bin"));
    assert_non_null(strstr(paths_buffer, "café_utf8.bin"));
    assert_non_null(strstr(paths_buffer, "name_with_\n_newline.bin"));
}

static int setup_check_jq_available(void** state)
{
    (void)state;
    if (system("command -v jq > /dev/null 2>&1") != 0) {
        fprintf(stderr, "jq not available, skipping bc-hash JSON output tests\n");
        return 1;
    }
    return 0;
}

static void test_json_output_xxh3_algorithm_and_digest_length(void** state)
{
    (void)state;
    const char* fixture_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_xxh3_abc.bin";
    const char* output_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_xxh3.ndjson";
    assert_int_equal(bc_hash_json_test_write_file(fixture_path, "abc", 3), 0);
    unlink(output_path);

    int exit_status = -1;
    assert_int_equal(bc_hash_json_test_run("xxh3", fixture_path, output_path, &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_int_equal(bc_hash_json_test_jq_empty(output_path), 0);

    char algo_buffer[256];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"header\") | .algorithm'", algo_buffer, sizeof(algo_buffer)) >= 0);
    assert_non_null(strstr(algo_buffer, "xxh3"));

    char digest_buffer[256];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"entry\") | .digest'", digest_buffer,
                                             sizeof(digest_buffer)) >= 0);
    assert_non_null(strstr(digest_buffer, "78af5f94892f3950"));
}

static void test_json_output_xxh128_algorithm_and_digest_length(void** state)
{
    (void)state;
    const char* fixture_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_xxh128_abc.bin";
    const char* output_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/json_xxh128.ndjson";
    assert_int_equal(bc_hash_json_test_write_file(fixture_path, "abc", 3), 0);
    unlink(output_path);

    int exit_status = -1;
    assert_int_equal(bc_hash_json_test_run("xxh128", fixture_path, output_path, &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_int_equal(bc_hash_json_test_jq_empty(output_path), 0);

    char algo_buffer[256];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"header\") | .algorithm'", algo_buffer, sizeof(algo_buffer)) >= 0);
    assert_non_null(strstr(algo_buffer, "xxh128"));

    char digest_buffer[256];
    assert_true(bc_hash_json_test_jq_extract(output_path, "'select(.type==\"entry\") | .digest'", digest_buffer,
                                             sizeof(digest_buffer)) >= 0);
    assert_non_null(strstr(digest_buffer, "06b05ab6733a618578af5f94892f3950"));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_json_output_is_valid_ndjson_jq_empty),
        cmocka_unit_test(test_json_output_first_line_is_header_last_is_summary),
        cmocka_unit_test(test_json_output_counts_consistent),
        cmocka_unit_test(test_json_output_escapes_special_characters_in_path),
        cmocka_unit_test(test_json_output_xxh3_algorithm_and_digest_length),
        cmocka_unit_test(test_json_output_xxh128_algorithm_and_digest_length),
    };
    return cmocka_run_group_tests(tests, setup_check_jq_available, NULL);
}
