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

#define BC_HASH_DIFF_TEST_BUFFER_SIZE 8192

static const char bc_hash_diff_test_sha256_abc[] = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
static const char bc_hash_diff_test_sha256_xyz[] = "3608bca1e44ea6c4d268eb6db02260269892c0b42b86bbf1e77a6fa16c3c9282";
static const char bc_hash_diff_test_xxh3_abc[] = "78af5f94892f3950";

static int bc_hash_diff_test_ensure_directory(const char* absolute_path)
{
    if (mkdir(absolute_path, 0755) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int bc_hash_diff_test_write_file(const char* absolute_path, const void* payload, size_t payload_size)
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

static int bc_hash_diff_test_write_string(const char* absolute_path, const char* text)
{
    return bc_hash_diff_test_write_file(absolute_path, text, strlen(text));
}

static int bc_hash_diff_test_run(const char* const* arguments, size_t argument_count, char* stdout_buffer, size_t stdout_buffer_size,
                                 char* stderr_buffer, size_t stderr_buffer_size, int* out_exit_status)
{
    int stdout_pipe[2];
    int stderr_pipe[2];
    if (pipe(stdout_pipe) != 0) {
        return -1;
    }
    if (pipe(stderr_pipe) != 0) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        return -1;
    }

    pid_t child_pid = fork();
    if (child_pid < 0) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        return -1;
    }

    if (child_pid == 0) {
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        char* argv_buffer[16];
        argv_buffer[0] = (char*)BC_HASH_TEST_BINARY_PATH;
        for (size_t index = 0; index < argument_count && index + 1 < 15; index++) {
            argv_buffer[index + 1] = (char*)arguments[index];
        }
        argv_buffer[argument_count + 1] = NULL;
        execv(BC_HASH_TEST_BINARY_PATH, argv_buffer);
        _exit(127);
    }

    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    size_t stdout_read = 0;
    while (stdout_read + 1 < stdout_buffer_size) {
        ssize_t bytes_read = read(stdout_pipe[0], stdout_buffer + stdout_read, stdout_buffer_size - 1 - stdout_read);
        if (bytes_read <= 0) {
            break;
        }
        stdout_read += (size_t)bytes_read;
    }
    stdout_buffer[stdout_read] = '\0';
    close(stdout_pipe[0]);

    size_t stderr_read = 0;
    while (stderr_read + 1 < stderr_buffer_size) {
        ssize_t bytes_read = read(stderr_pipe[0], stderr_buffer + stderr_read, stderr_buffer_size - 1 - stderr_read);
        if (bytes_read <= 0) {
            break;
        }
        stderr_read += (size_t)bytes_read;
    }
    stderr_buffer[stderr_read] = '\0';
    close(stderr_pipe[0]);

    int child_status = 0;
    waitpid(child_pid, &child_status, 0);
    *out_exit_status = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1;
    return 0;
}

static int bc_hash_diff_test_write_simple_line(char* buffer, size_t buffer_size, size_t* inout_offset, const char* hex, const char* path)
{
    int written = snprintf(buffer + *inout_offset, buffer_size - *inout_offset, "%s  %s\n", hex, path);
    if (written < 0 || (size_t)written >= buffer_size - *inout_offset) {
        return -1;
    }
    *inout_offset += (size_t)written;
    return 0;
}

static void test_diff_identical_exit_0(void** state)
{
    (void)state;
    const char* digest_a = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_identical_a.sha256";
    const char* digest_b = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_identical_b.sha256";
    char buffer[1024];
    size_t offset = 0;
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer, sizeof(buffer), &offset, bc_hash_diff_test_sha256_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer, sizeof(buffer), &offset, bc_hash_diff_test_sha256_abc, "/path/b"), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_a, buffer, offset), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_b, buffer, offset), 0);

    const char* argv[] = {"diff", digest_a, digest_b};
    char stdout_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    char stderr_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_diff_test_run(argv, 3, stdout_buffer, sizeof(stdout_buffer), stderr_buffer, sizeof(stderr_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 0);
    assert_null(strstr(stdout_buffer, "ADDED"));
    assert_null(strstr(stdout_buffer, "REMOVED"));
    assert_null(strstr(stdout_buffer, "MODIFIED"));
    assert_non_null(strstr(stderr_buffer, "0 added"));
    assert_non_null(strstr(stderr_buffer, "0 removed"));
    assert_non_null(strstr(stderr_buffer, "0 modified"));
}

static void test_diff_added_path(void** state)
{
    (void)state;
    const char* digest_a = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_added_a.sha256";
    const char* digest_b = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_added_b.sha256";
    char buffer_a[1024];
    char buffer_b[1024];
    size_t offset_a = 0;
    size_t offset_b = 0;
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_a, sizeof(buffer_a), &offset_a, bc_hash_diff_test_sha256_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_b, sizeof(buffer_b), &offset_b, bc_hash_diff_test_sha256_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_b, sizeof(buffer_b), &offset_b, bc_hash_diff_test_sha256_xyz, "/path/new"), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_a, buffer_a, offset_a), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_b, buffer_b, offset_b), 0);

    const char* argv[] = {"diff", digest_a, digest_b};
    char stdout_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    char stderr_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_diff_test_run(argv, 3, stdout_buffer, sizeof(stdout_buffer), stderr_buffer, sizeof(stderr_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 1);
    assert_non_null(strstr(stdout_buffer, "ADDED"));
    assert_non_null(strstr(stdout_buffer, "/path/new"));
    assert_non_null(strstr(stderr_buffer, "1 added"));
}

static void test_diff_removed_path(void** state)
{
    (void)state;
    const char* digest_a = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_removed_a.sha256";
    const char* digest_b = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_removed_b.sha256";
    char buffer_a[1024];
    char buffer_b[1024];
    size_t offset_a = 0;
    size_t offset_b = 0;
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_a, sizeof(buffer_a), &offset_a, bc_hash_diff_test_sha256_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_a, sizeof(buffer_a), &offset_a, bc_hash_diff_test_sha256_xyz, "/path/gone"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_b, sizeof(buffer_b), &offset_b, bc_hash_diff_test_sha256_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_a, buffer_a, offset_a), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_b, buffer_b, offset_b), 0);

    const char* argv[] = {"diff", digest_a, digest_b};
    char stdout_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    char stderr_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_diff_test_run(argv, 3, stdout_buffer, sizeof(stdout_buffer), stderr_buffer, sizeof(stderr_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 1);
    assert_non_null(strstr(stdout_buffer, "REMOVED"));
    assert_non_null(strstr(stdout_buffer, "/path/gone"));
    assert_non_null(strstr(stderr_buffer, "1 removed"));
}

static void test_diff_modified_path(void** state)
{
    (void)state;
    const char* digest_a = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_modified_a.sha256";
    const char* digest_b = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_modified_b.sha256";
    char buffer_a[1024];
    char buffer_b[1024];
    size_t offset_a = 0;
    size_t offset_b = 0;
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_a, sizeof(buffer_a), &offset_a, bc_hash_diff_test_sha256_abc, "/path/x"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_b, sizeof(buffer_b), &offset_b, bc_hash_diff_test_sha256_xyz, "/path/x"), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_a, buffer_a, offset_a), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_b, buffer_b, offset_b), 0);

    const char* argv[] = {"diff", digest_a, digest_b};
    char stdout_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    char stderr_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_diff_test_run(argv, 3, stdout_buffer, sizeof(stdout_buffer), stderr_buffer, sizeof(stderr_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 1);
    assert_non_null(strstr(stdout_buffer, "MODIFIED"));
    assert_non_null(strstr(stdout_buffer, "/path/x"));
    assert_non_null(strstr(stdout_buffer, bc_hash_diff_test_sha256_abc));
    assert_non_null(strstr(stdout_buffer, bc_hash_diff_test_sha256_xyz));
    assert_non_null(strstr(stderr_buffer, "1 modified"));
}

static void test_diff_mixed_summary_counts(void** state)
{
    (void)state;
    const char* digest_a = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_mixed_a.sha256";
    const char* digest_b = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_mixed_b.sha256";
    char buffer_a[2048];
    char buffer_b[2048];
    size_t offset_a = 0;
    size_t offset_b = 0;
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_a, sizeof(buffer_a), &offset_a, bc_hash_diff_test_sha256_abc, "/p/kept"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_a, sizeof(buffer_a), &offset_a, bc_hash_diff_test_sha256_abc, "/p/removed"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_a, sizeof(buffer_a), &offset_a, bc_hash_diff_test_sha256_abc, "/p/edit"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_b, sizeof(buffer_b), &offset_b, bc_hash_diff_test_sha256_abc, "/p/kept"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_b, sizeof(buffer_b), &offset_b, bc_hash_diff_test_sha256_xyz, "/p/edit"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_b, sizeof(buffer_b), &offset_b, bc_hash_diff_test_sha256_xyz, "/p/new"), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_a, buffer_a, offset_a), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_b, buffer_b, offset_b), 0);

    const char* argv[] = {"diff", digest_a, digest_b};
    char stdout_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    char stderr_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_diff_test_run(argv, 3, stdout_buffer, sizeof(stdout_buffer), stderr_buffer, sizeof(stderr_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 1);
    assert_non_null(strstr(stderr_buffer, "1 added"));
    assert_non_null(strstr(stderr_buffer, "1 removed"));
    assert_non_null(strstr(stderr_buffer, "1 modified"));
    assert_non_null(strstr(stderr_buffer, "1 unchanged"));
}

static void test_diff_cross_algo_refused(void** state)
{
    (void)state;
    const char* digest_a = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_cross_a.sha256";
    const char* digest_b = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_cross_b.xxh3";
    char buffer_a[1024];
    char buffer_b[1024];
    size_t offset_a = 0;
    size_t offset_b = 0;
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_a, sizeof(buffer_a), &offset_a, bc_hash_diff_test_sha256_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_b, sizeof(buffer_b), &offset_b, bc_hash_diff_test_xxh3_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_a, buffer_a, offset_a), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_b, buffer_b, offset_b), 0);

    const char* argv[] = {"diff", digest_a, digest_b};
    char stdout_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    char stderr_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_diff_test_run(argv, 3, stdout_buffer, sizeof(stdout_buffer), stderr_buffer, sizeof(stderr_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 2);
}

static void test_diff_mixed_simple_and_ndjson(void** state)
{
    (void)state;
    const char* digest_a = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_mixed_format_a.sha256";
    const char* digest_b = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_mixed_format_b.ndjson";
    char buffer_a[1024];
    size_t offset_a = 0;
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer_a, sizeof(buffer_a), &offset_a, bc_hash_diff_test_sha256_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_a, buffer_a, offset_a), 0);

    char ndjson_buffer[2048];
    int written = snprintf(ndjson_buffer, sizeof(ndjson_buffer),
                           "{\"type\":\"header\",\"tool\":\"bc-hash\",\"version\":\"1.0.0\",\"schema_version\":1,\"algorithm\":\"sha256\","
                           "\"started_at\":\"2026-04-18T00:00:00Z\"}\n"
                           "{\"type\":\"entry\",\"path\":\"/path/a\",\"digest\":\"%s\",\"size_bytes\":3,\"ok\":true}\n"
                           "{\"type\":\"entry\",\"path\":\"/path/new\",\"digest\":\"%s\",\"size_bytes\":3,\"ok\":true}\n",
                           bc_hash_diff_test_sha256_abc, bc_hash_diff_test_sha256_xyz);
    assert_true(written > 0 && (size_t)written < sizeof(ndjson_buffer));
    assert_int_equal(bc_hash_diff_test_write_file(digest_b, ndjson_buffer, (size_t)written), 0);

    const char* argv[] = {"diff", digest_a, digest_b};
    char stdout_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    char stderr_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_diff_test_run(argv, 3, stdout_buffer, sizeof(stdout_buffer), stderr_buffer, sizeof(stderr_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 1);
    assert_non_null(strstr(stdout_buffer, "ADDED"));
    assert_non_null(strstr(stdout_buffer, "/path/new"));
    assert_non_null(strstr(stderr_buffer, "1 added"));
}

static void test_diff_missing_input_exit_2(void** state)
{
    (void)state;
    const char* digest_a = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_missing_a.sha256";
    const char* digest_b = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_missing_b.sha256";
    char buffer[512];
    size_t offset = 0;
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer, sizeof(buffer), &offset, bc_hash_diff_test_sha256_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_a, buffer, offset), 0);
    unlink(digest_b);

    const char* argv[] = {"diff", digest_a, digest_b};
    char stdout_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    char stderr_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_diff_test_run(argv, 3, stdout_buffer, sizeof(stdout_buffer), stderr_buffer, sizeof(stderr_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 2);
}

static void test_diff_malformed_input_exit_2(void** state)
{
    (void)state;
    const char* digest_a = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_malformed_a.sha256";
    const char* digest_b = BC_HASH_TEST_FIXTURES_DIRECTORY "/diff_malformed_b.sha256";
    assert_int_equal(bc_hash_diff_test_write_string(digest_a, "not-a-valid-digest-line"), 0);
    char buffer[512];
    size_t offset = 0;
    assert_int_equal(bc_hash_diff_test_write_simple_line(buffer, sizeof(buffer), &offset, bc_hash_diff_test_sha256_abc, "/path/a"), 0);
    assert_int_equal(bc_hash_diff_test_write_file(digest_b, buffer, offset), 0);

    const char* argv[] = {"diff", digest_a, digest_b};
    char stdout_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    char stderr_buffer[BC_HASH_DIFF_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_diff_test_run(argv, 3, stdout_buffer, sizeof(stdout_buffer), stderr_buffer, sizeof(stderr_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 2);
}

int main(void)
{
    bc_hash_diff_test_ensure_directory(BC_HASH_TEST_FIXTURES_DIRECTORY);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_diff_identical_exit_0),
        cmocka_unit_test(test_diff_added_path),
        cmocka_unit_test(test_diff_removed_path),
        cmocka_unit_test(test_diff_modified_path),
        cmocka_unit_test(test_diff_mixed_summary_counts),
        cmocka_unit_test(test_diff_cross_algo_refused),
        cmocka_unit_test(test_diff_mixed_simple_and_ndjson),
        cmocka_unit_test(test_diff_missing_input_exit_2),
        cmocka_unit_test(test_diff_malformed_input_exit_2),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
