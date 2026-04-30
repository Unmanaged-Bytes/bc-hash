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

#define BC_HASH_CHECK_TEST_BUFFER_SIZE 8192

static int bc_hash_check_test_ensure_directory(const char* absolute_path)
{
    if (mkdir(absolute_path, 0755) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int bc_hash_check_test_write_file(const char* absolute_path, const void* payload, size_t payload_size)
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

static int bc_hash_check_test_run(const char* const* arguments, size_t argument_count, char* stdout_buffer, size_t stdout_buffer_size,
                                  int* out_exit_status)
{
    int stdout_pipe[2];
    if (pipe(stdout_pipe) != 0) {
        return -1;
    }

    pid_t child_pid = fork();
    if (child_pid < 0) {
        close(stdout_pipe[0]);
        close(stdout_pipe[1]);
        return -1;
    }

    if (child_pid == 0) {
        close(stdout_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdout_pipe[1]);

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
    size_t total_read = 0;
    while (total_read + 1 < stdout_buffer_size) {
        ssize_t bytes_read = read(stdout_pipe[0], stdout_buffer + total_read, stdout_buffer_size - 1 - total_read);
        if (bytes_read <= 0) {
            break;
        }
        total_read += (size_t)bytes_read;
    }
    stdout_buffer[total_read] = '\0';
    close(stdout_pipe[0]);

    int child_status = 0;
    waitpid(child_pid, &child_status, 0);
    *out_exit_status = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1;
    return 0;
}

static int bc_hash_check_test_write_digest_simple(const char* digest_path, const char* hex, const char* target_path)
{
    char buffer[4096];
    int written = snprintf(buffer, sizeof(buffer), "%s  %s\n", hex, target_path);
    if (written < 0 || (size_t)written >= sizeof(buffer)) {
        return -1;
    }
    return bc_hash_check_test_write_file(digest_path, buffer, (size_t)written);
}

static void test_check_simple_sha256_all_ok(void** state)
{
    (void)state;
    const char* target_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_abc.bin";
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_abc.sha256";
    assert_int_equal(bc_hash_check_test_write_file(target_path, "abc", 3), 0);
    assert_int_equal(bc_hash_check_test_write_digest_simple(digest_path, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                                                            target_path),
                     0);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "OK"));
    assert_non_null(strstr(output_buffer, target_path));
}

static void test_check_simple_altered_file_failed(void** state)
{
    (void)state;
    const char* target_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_altered.bin";
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_altered.sha256";
    assert_int_equal(bc_hash_check_test_write_file(target_path, "abc", 3), 0);
    assert_int_equal(bc_hash_check_test_write_digest_simple(digest_path, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                                                            target_path),
                     0);
    assert_int_equal(bc_hash_check_test_write_file(target_path, "xyz", 3), 0);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 1);
    assert_non_null(strstr(output_buffer, "FAILED"));
}

static void test_check_missing_file(void** state)
{
    (void)state;
    const char* target_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_not_there.bin";
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_missing.sha256";
    unlink(target_path);
    assert_int_equal(bc_hash_check_test_write_digest_simple(digest_path, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                                                            target_path),
                     0);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 1);
    assert_non_null(strstr(output_buffer, "MISSING"));
}

static void test_check_algorithm_detected_from_hex_length_crc32(void** state)
{
    (void)state;
    const char* target_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_crc32.bin";
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_crc32.digest";
    assert_int_equal(bc_hash_check_test_write_file(target_path, "abc", 3), 0);
    assert_int_equal(bc_hash_check_test_write_digest_simple(digest_path, "364b3fb7", target_path), 0);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "OK"));
}

static void test_check_algorithm_detected_from_hex_length_xxh3(void** state)
{
    (void)state;
    const char* target_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_xxh3.bin";
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_xxh3.digest";
    assert_int_equal(bc_hash_check_test_write_file(target_path, "abc", 3), 0);
    assert_int_equal(bc_hash_check_test_write_digest_simple(digest_path, "78af5f94892f3950", target_path), 0);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "OK"));
}

static void test_check_algorithm_detected_from_hex_length_xxh128(void** state)
{
    (void)state;
    const char* target_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_xxh128.bin";
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_xxh128.digest";
    assert_int_equal(bc_hash_check_test_write_file(target_path, "abc", 3), 0);
    assert_int_equal(bc_hash_check_test_write_digest_simple(digest_path, "06b05ab6733a618578af5f94892f3950", target_path), 0);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "OK"));
}

static void test_check_ndjson_roundtrip(void** state)
{
    (void)state;
    const char* target_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_ndjson.bin";
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_ndjson.ndjson";
    assert_int_equal(bc_hash_check_test_write_file(target_path, "abc", 3), 0);

    char ndjson_buffer[2048];
    int written = snprintf(ndjson_buffer, sizeof(ndjson_buffer),
                           "{\"type\":\"header\",\"tool\":\"bc-hash\",\"version\":\"1.0.0\",\"schema_version\":1,\"algorithm\":\"sha256\","
                           "\"started_at\":\"2026-04-18T00:00:00Z\"}\n"
                           "{\"type\":\"entry\",\"path\":\"%s\",\"digest\":\""
                           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\",\"size_bytes\":3,\"ok\":true}\n"
                           "{\"type\":\"summary\",\"files_total\":1,\"files_ok\":1,\"files_error\":0}\n",
                           target_path);
    assert_true(written > 0 && (size_t)written < sizeof(ndjson_buffer));
    assert_int_equal(bc_hash_check_test_write_file(digest_path, ndjson_buffer, (size_t)written), 0);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "OK"));
}

static void test_check_malformed_digest_file_exit_2(void** state)
{
    (void)state;
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_malformed.digest";
    assert_int_equal(bc_hash_check_test_write_file(digest_path, "garbage-with-odd-length", 23), 0);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 2);
}

static void test_check_missing_digest_file_exit_2(void** state)
{
    (void)state;
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_does_not_exist.digest";
    unlink(digest_path);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 2);
}

static void test_check_summary_counts(void** state)
{
    (void)state;
    const char* dir_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_mix";
    const char* file_ok = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_mix/ok.bin";
    const char* file_failed = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_mix/altered.bin";
    const char* file_missing = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_mix/gone.bin";
    const char* digest_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/check_mix.sha256";
    assert_int_equal(bc_hash_check_test_ensure_directory(dir_path), 0);
    assert_int_equal(bc_hash_check_test_write_file(file_ok, "abc", 3), 0);
    assert_int_equal(bc_hash_check_test_write_file(file_failed, "xyz", 3), 0);
    unlink(file_missing);

    char buffer[4096];
    int written = snprintf(buffer, sizeof(buffer),
                           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  %s\n"
                           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  %s\n"
                           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  %s\n",
                           file_ok, file_failed, file_missing);
    assert_true(written > 0 && (size_t)written < sizeof(buffer));
    assert_int_equal(bc_hash_check_test_write_file(digest_path, buffer, (size_t)written), 0);

    const char* argv[] = {"check", digest_path};
    char output_buffer[BC_HASH_CHECK_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_check_test_run(argv, 2, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 1);
    assert_non_null(strstr(output_buffer, "OK"));
    assert_non_null(strstr(output_buffer, "FAILED"));
    assert_non_null(strstr(output_buffer, "MISSING"));
}

int main(void)
{
    bc_hash_check_test_ensure_directory(BC_HASH_TEST_FIXTURES_DIRECTORY);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_check_simple_sha256_all_ok),
        cmocka_unit_test(test_check_simple_altered_file_failed),
        cmocka_unit_test(test_check_missing_file),
        cmocka_unit_test(test_check_algorithm_detected_from_hex_length_crc32),
        cmocka_unit_test(test_check_algorithm_detected_from_hex_length_xxh3),
        cmocka_unit_test(test_check_algorithm_detected_from_hex_length_xxh128),
        cmocka_unit_test(test_check_ndjson_roundtrip),
        cmocka_unit_test(test_check_malformed_digest_file_exit_2),
        cmocka_unit_test(test_check_missing_digest_file_exit_2),
        cmocka_unit_test(test_check_summary_counts),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
