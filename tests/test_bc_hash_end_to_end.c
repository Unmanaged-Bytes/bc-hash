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

#define BC_HASH_TEST_OUTPUT_BUFFER_SIZE 4096

static int bc_hash_test_write_file(const char* absolute_path, const void* payload, size_t payload_size)
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

static int bc_hash_test_ensure_directory(const char* absolute_path)
{
    if (mkdir(absolute_path, 0755) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int bc_hash_test_run_capture_with_threads(const char* type_value, const char* target_path, const char* threads_value,
                                                 char* stdout_buffer, size_t stdout_buffer_size, int* out_exit_status)
{
    char type_argument[64];
    snprintf(type_argument, sizeof(type_argument), "--type=%s", type_value);

    char threads_argument[64];
    if (threads_value != NULL) {
        snprintf(threads_argument, sizeof(threads_argument), "--threads=%s", threads_value);
    }

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
        if (threads_value != NULL) {
            char* const execv_argv[] = {(char*)BC_HASH_TEST_BINARY_PATH, threads_argument, "hash", type_argument, (char*)target_path, NULL};
            execv(BC_HASH_TEST_BINARY_PATH, execv_argv);
        } else {
            char* const execv_argv[] = {(char*)BC_HASH_TEST_BINARY_PATH, "hash", type_argument, (char*)target_path, NULL};
            execv(BC_HASH_TEST_BINARY_PATH, execv_argv);
        }
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

static int bc_hash_test_run_capture(const char* type_value, const char* target_path, char* stdout_buffer, size_t stdout_buffer_size,
                                    int* out_exit_status)
{
    return bc_hash_test_run_capture_with_threads(type_value, target_path, NULL, stdout_buffer, stdout_buffer_size, out_exit_status);
}

static void test_empty_file_is_skipped_from_output(void** state)
{
    (void)state;
    const char* empty_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/empty.bin";
    assert_int_equal(bc_hash_test_write_file(empty_path, "", 0), 0);

    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture("sha256", empty_path, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_null(strstr(output_buffer, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    assert_null(strstr(output_buffer, "empty.bin"));
}

static void test_empty_files_are_filtered_from_directory_walk(void** state)
{
    (void)state;
    const char* directory_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/skip_empty_tree";
    assert_int_equal(bc_hash_test_ensure_directory(directory_path), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/skip_empty_tree/content.bin", "abc", 3), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/skip_empty_tree/empty_a.bin", "", 0), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/skip_empty_tree/empty_b.bin", "", 0), 0);

    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture("sha256", directory_path, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "content.bin"));
    assert_non_null(strstr(output_buffer, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    assert_null(strstr(output_buffer, "empty_a.bin"));
    assert_null(strstr(output_buffer, "empty_b.bin"));
    assert_null(strstr(output_buffer, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

static void test_sha256_abc_matches_rfc_vector(void** state)
{
    (void)state;
    const char* abc_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/abc.bin";
    assert_int_equal(bc_hash_test_write_file(abc_path, "abc", 3), 0);

    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture("sha256", abc_path, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

static void test_crc32c_abc_matches_castagnoli_vector(void** state)
{
    (void)state;
    const char* abc_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/abc.bin";
    assert_int_equal(bc_hash_test_write_file(abc_path, "abc", 3), 0);

    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture("crc32", abc_path, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "364b3fb7"));
}

static void test_directory_recursion_hashes_all_files_and_skips_hidden_and_symlinks(void** state)
{
    (void)state;
    const char* directory_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/tree";
    const char* nested_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/tree/nested";
    assert_int_equal(bc_hash_test_ensure_directory(directory_path), 0);
    assert_int_equal(bc_hash_test_ensure_directory(nested_path), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/tree/file_a.bin", "abc", 3), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/tree/nested/file_b.bin", "abc", 3), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/tree/.hidden.bin", "abc", 3), 0);

    unlink(BC_HASH_TEST_FIXTURES_DIRECTORY "/tree/link_to_file.bin");
    int _sl_rc = symlink(BC_HASH_TEST_FIXTURES_DIRECTORY "/tree/file_a.bin", BC_HASH_TEST_FIXTURES_DIRECTORY "/tree/link_to_file.bin");
    (void)_sl_rc;

    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture("sha256", directory_path, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);

    assert_non_null(strstr(output_buffer, "file_a.bin"));
    assert_non_null(strstr(output_buffer, "file_b.bin"));
    assert_null(strstr(output_buffer, ".hidden.bin"));
    assert_null(strstr(output_buffer, "link_to_file.bin"));
}

static void test_xxh3_abc_matches_reference_vector(void** state)
{
    (void)state;
    const char* abc_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/abc.bin";
    assert_int_equal(bc_hash_test_write_file(abc_path, "abc", 3), 0);

    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture("xxh3", abc_path, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "78af5f94892f3950"));
}

static void test_xxh128_abc_matches_reference_vector(void** state)
{
    (void)state;
    const char* abc_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/abc.bin";
    assert_int_equal(bc_hash_test_write_file(abc_path, "abc", 3), 0);

    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture("xxh128", abc_path, output_buffer, sizeof(output_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "06b05ab6733a618578af5f94892f3950"));
}

static void test_missing_file_reports_error_and_continues_other_files(void** state)
{
    (void)state;
    const char* abc_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/abc.bin";
    assert_int_equal(bc_hash_test_write_file(abc_path, "abc", 3), 0);

    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;

    char type_argument[64];
    snprintf(type_argument, sizeof(type_argument), "--type=%s", "sha256");

    int stdout_pipe[2];
    assert_int_equal(pipe(stdout_pipe), 0);

    pid_t child_pid = fork();
    assert_true(child_pid >= 0);

    if (child_pid == 0) {
        close(stdout_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        close(stdout_pipe[1]);
        char* const execv_argv[] = {(char*)BC_HASH_TEST_BINARY_PATH, "hash", type_argument, "/nope/does-not-exist", (char*)abc_path, NULL};
        execv(BC_HASH_TEST_BINARY_PATH, execv_argv);
        _exit(127);
    }

    close(stdout_pipe[1]);
    size_t total_read = 0;
    while (total_read + 1 < sizeof(output_buffer)) {
        ssize_t bytes_read = read(stdout_pipe[0], output_buffer + total_read, sizeof(output_buffer) - 1 - total_read);
        if (bytes_read <= 0) {
            break;
        }
        total_read += (size_t)bytes_read;
    }
    output_buffer[total_read] = '\0';
    close(stdout_pipe[0]);

    int child_status = 0;
    waitpid(child_pid, &child_status, 0);
    exit_status = WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1;

    assert_int_equal(exit_status, 1);
    assert_non_null(strstr(output_buffer, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

static void test_sequential_walk_mono_thread(void** state)
{
    (void)state;
    const char* directory_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/mono_tree";
    const char* nested_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/mono_tree/nested";
    assert_int_equal(bc_hash_test_ensure_directory(directory_path), 0);
    assert_int_equal(bc_hash_test_ensure_directory(nested_path), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/mono_tree/root.bin", "abc", 3), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/mono_tree/nested/leaf.bin", "abc", 3), 0);

    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture_with_threads("sha256", directory_path, "0", output_buffer, sizeof(output_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "root.bin"));
    assert_non_null(strstr(output_buffer, "leaf.bin"));
    assert_non_null(strstr(output_buffer, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

static void test_sequential_walk_missing_path_mono(void** state)
{
    (void)state;
    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture_with_threads("sha256", "/nope/does-not-exist", "0", output_buffer, sizeof(output_buffer),
                                                           &exit_status),
                     0);
    assert_int_equal(exit_status, 1);
}

static void test_sequential_walk_glob_pattern_mono(void** state)
{
    (void)state;
    const char* directory_path = BC_HASH_TEST_FIXTURES_DIRECTORY "/mono_glob";
    assert_int_equal(bc_hash_test_ensure_directory(directory_path), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/mono_glob/alpha.c", "abc", 3), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/mono_glob/beta.c", "abc", 3), 0);
    assert_int_equal(bc_hash_test_write_file(BC_HASH_TEST_FIXTURES_DIRECTORY "/mono_glob/ignore.h", "abc", 3), 0);

    char glob_pattern[512];
    snprintf(glob_pattern, sizeof(glob_pattern), "%s/*.c", directory_path);
    char output_buffer[BC_HASH_TEST_OUTPUT_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_test_run_capture_with_threads("sha256", glob_pattern, "0", output_buffer, sizeof(output_buffer), &exit_status),
                     0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(output_buffer, "alpha.c"));
    assert_non_null(strstr(output_buffer, "beta.c"));
    assert_null(strstr(output_buffer, "ignore.h"));
}

int main(void)
{
    bc_hash_test_ensure_directory(BC_HASH_TEST_FIXTURES_DIRECTORY);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_empty_file_is_skipped_from_output),
        cmocka_unit_test(test_empty_files_are_filtered_from_directory_walk),
        cmocka_unit_test(test_sha256_abc_matches_rfc_vector),
        cmocka_unit_test(test_crc32c_abc_matches_castagnoli_vector),
        cmocka_unit_test(test_xxh3_abc_matches_reference_vector),
        cmocka_unit_test(test_xxh128_abc_matches_reference_vector),
        cmocka_unit_test(test_directory_recursion_hashes_all_files_and_skips_hidden_and_symlinks),
        cmocka_unit_test(test_missing_file_reports_error_and_continues_other_files),
        cmocka_unit_test(test_sequential_walk_mono_thread),
        cmocka_unit_test(test_sequential_walk_missing_path_mono),
        cmocka_unit_test(test_sequential_walk_glob_pattern_mono),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
