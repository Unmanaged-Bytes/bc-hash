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

#define BC_HASH_FILTER_TEST_BUFFER_SIZE 8192

static int bc_hash_filter_test_ensure_directory(const char* absolute_path)
{
    if (mkdir(absolute_path, 0755) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int bc_hash_filter_test_write_file(const char* absolute_path, const void* payload, size_t payload_size)
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

static int bc_hash_filter_test_run(const char* const* arguments, size_t argument_count, char* stdout_buffer, size_t stdout_buffer_size,
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

        char* argv_buffer[32];
        argv_buffer[0] = (char*)BC_HASH_TEST_BINARY_PATH;
        for (size_t index = 0; index < argument_count && index + 1 < 31; index++) {
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

static int bc_hash_filter_test_setup_corpus(const char* root)
{
    if (bc_hash_filter_test_ensure_directory(root) != 0) {
        return -1;
    }
    char path_buffer[512];
    snprintf(path_buffer, sizeof(path_buffer), "%s/a.c", root);
    if (bc_hash_filter_test_write_file(path_buffer, "abc", 3) != 0) return -1;
    snprintf(path_buffer, sizeof(path_buffer), "%s/b.c", root);
    if (bc_hash_filter_test_write_file(path_buffer, "def", 3) != 0) return -1;
    snprintf(path_buffer, sizeof(path_buffer), "%s/x.tmp", root);
    if (bc_hash_filter_test_write_file(path_buffer, "tmp", 3) != 0) return -1;
    snprintf(path_buffer, sizeof(path_buffer), "%s/y.log", root);
    if (bc_hash_filter_test_write_file(path_buffer, "log", 3) != 0) return -1;
    snprintf(path_buffer, sizeof(path_buffer), "%s/.git", root);
    if (bc_hash_filter_test_ensure_directory(path_buffer) != 0) return -1;
    snprintf(path_buffer, sizeof(path_buffer), "%s/.git/config", root);
    if (bc_hash_filter_test_write_file(path_buffer, "[core]", 6) != 0) return -1;
    snprintf(path_buffer, sizeof(path_buffer), "%s/node_modules", root);
    if (bc_hash_filter_test_ensure_directory(path_buffer) != 0) return -1;
    snprintf(path_buffer, sizeof(path_buffer), "%s/node_modules/index.js", root);
    if (bc_hash_filter_test_write_file(path_buffer, "nope", 4) != 0) return -1;
    return 0;
}

static void test_filter_no_filter_all_files(void** state)
{
    (void)state;
    const char* root = BC_HASH_TEST_FIXTURES_DIRECTORY "/filter_all";
    assert_int_equal(bc_hash_filter_test_setup_corpus(root), 0);

    const char* argv[] = {"hash", "--type=sha256", "--output=-", root};
    char stdout_buffer[BC_HASH_FILTER_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_filter_test_run(argv, 4, stdout_buffer, sizeof(stdout_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(stdout_buffer, "a.c"));
    assert_non_null(strstr(stdout_buffer, "x.tmp"));
    assert_non_null(strstr(stdout_buffer, "y.log"));
    assert_non_null(strstr(stdout_buffer, "node_modules/index.js"));
}

static void test_filter_exclude_single_pattern(void** state)
{
    (void)state;
    const char* root = BC_HASH_TEST_FIXTURES_DIRECTORY "/filter_exc1";
    assert_int_equal(bc_hash_filter_test_setup_corpus(root), 0);

    const char* argv[] = {"hash", "--type=sha256", "--exclude=*.tmp", "--output=-", root};
    char stdout_buffer[BC_HASH_FILTER_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_filter_test_run(argv, 5, stdout_buffer, sizeof(stdout_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(stdout_buffer, "a.c"));
    assert_non_null(strstr(stdout_buffer, "y.log"));
    assert_null(strstr(stdout_buffer, "x.tmp"));
}

static void test_filter_exclude_multiple_patterns(void** state)
{
    (void)state;
    const char* root = BC_HASH_TEST_FIXTURES_DIRECTORY "/filter_exc2";
    assert_int_equal(bc_hash_filter_test_setup_corpus(root), 0);

    const char* argv[] = {"hash", "--type=sha256", "--exclude=*.tmp", "--exclude=*.log", "--output=-", root};
    char stdout_buffer[BC_HASH_FILTER_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_filter_test_run(argv, 6, stdout_buffer, sizeof(stdout_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(stdout_buffer, "a.c"));
    assert_null(strstr(stdout_buffer, "x.tmp"));
    assert_null(strstr(stdout_buffer, "y.log"));
}

static void test_filter_include_only_c_files(void** state)
{
    (void)state;
    const char* root = BC_HASH_TEST_FIXTURES_DIRECTORY "/filter_inc1";
    assert_int_equal(bc_hash_filter_test_setup_corpus(root), 0);

    const char* argv[] = {"hash", "--type=sha256", "--include=*.c", "--output=-", root};
    char stdout_buffer[BC_HASH_FILTER_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_filter_test_run(argv, 5, stdout_buffer, sizeof(stdout_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(stdout_buffer, "a.c"));
    assert_non_null(strstr(stdout_buffer, "b.c"));
    assert_null(strstr(stdout_buffer, "x.tmp"));
    assert_null(strstr(stdout_buffer, "y.log"));
    assert_null(strstr(stdout_buffer, "config"));
}

static void test_filter_include_plus_exclude(void** state)
{
    (void)state;
    const char* root = BC_HASH_TEST_FIXTURES_DIRECTORY "/filter_mix";
    assert_int_equal(bc_hash_filter_test_setup_corpus(root), 0);

    const char* argv[] = {"hash", "--type=sha256", "--include=*.c", "--exclude=b.c", "--output=-", root};
    char stdout_buffer[BC_HASH_FILTER_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_filter_test_run(argv, 6, stdout_buffer, sizeof(stdout_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(stdout_buffer, "a.c"));
    assert_null(strstr(stdout_buffer, "b.c"));
}

static void test_filter_directory_prune(void** state)
{
    (void)state;
    const char* root = BC_HASH_TEST_FIXTURES_DIRECTORY "/filter_dirprune";
    assert_int_equal(bc_hash_filter_test_setup_corpus(root), 0);

    const char* argv[] = {"hash", "--type=sha256", "--exclude=.git", "--exclude=node_modules", "--output=-", root};
    char stdout_buffer[BC_HASH_FILTER_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_filter_test_run(argv, 6, stdout_buffer, sizeof(stdout_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(stdout_buffer, "a.c"));
    assert_null(strstr(stdout_buffer, "config"));
    assert_null(strstr(stdout_buffer, "node_modules"));
    assert_null(strstr(stdout_buffer, "index.js"));
}

static void test_filter_basename_only_not_path(void** state)
{
    (void)state;
    const char* root = BC_HASH_TEST_FIXTURES_DIRECTORY "/filter_basename";
    assert_int_equal(bc_hash_filter_test_setup_corpus(root), 0);

    const char* argv[] = {"hash", "--type=sha256", "--exclude=some_dir/a.c", "--output=-", root};
    char stdout_buffer[BC_HASH_FILTER_TEST_BUFFER_SIZE];
    int exit_status = -1;
    assert_int_equal(bc_hash_filter_test_run(argv, 5, stdout_buffer, sizeof(stdout_buffer), &exit_status), 0);
    assert_int_equal(exit_status, 0);
    assert_non_null(strstr(stdout_buffer, "a.c"));
    assert_non_null(strstr(stdout_buffer, "b.c"));
}

int main(void)
{
    bc_hash_filter_test_ensure_directory(BC_HASH_TEST_FIXTURES_DIRECTORY);

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_filter_no_filter_all_files),
        cmocka_unit_test(test_filter_exclude_single_pattern),
        cmocka_unit_test(test_filter_exclude_multiple_patterns),
        cmocka_unit_test(test_filter_include_only_c_files),
        cmocka_unit_test(test_filter_include_plus_exclude),
        cmocka_unit_test(test_filter_directory_prune),
        cmocka_unit_test(test_filter_basename_only_not_path),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
