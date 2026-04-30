// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
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

#define BC_HASH_URING_STRESS_DIRECTORY_COUNT 12
#define BC_HASH_URING_STRESS_FILES_PER_DIRECTORY 5000
#define BC_HASH_URING_STRESS_FORK_COUNT 30

static int bc_hash_uring_stress_ensure_directory(const char* absolute_path)
{
    if (mkdir(absolute_path, 0755) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int bc_hash_uring_stress_write_file(const char* absolute_path, const void* payload, size_t payload_size)
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

static bool bc_hash_uring_stress_generate_fixture(const char* fixture_root)
{
    if (bc_hash_uring_stress_ensure_directory(fixture_root) != 0) {
        return false;
    }
    for (size_t directory_index = 0; directory_index < BC_HASH_URING_STRESS_DIRECTORY_COUNT; ++directory_index) {
        char directory_path[1024];
        int directory_path_length = snprintf(directory_path, sizeof(directory_path), "%s/d%zu", fixture_root, directory_index);
        if (directory_path_length < 0 || (size_t)directory_path_length >= sizeof(directory_path)) {
            return false;
        }
        if (bc_hash_uring_stress_ensure_directory(directory_path) != 0) {
            return false;
        }
        for (size_t file_index = 0; file_index < BC_HASH_URING_STRESS_FILES_PER_DIRECTORY; ++file_index) {
            char file_path[1200];
            int file_path_length = snprintf(file_path, sizeof(file_path), "%s/f%zu", directory_path, file_index);
            if (file_path_length < 0 || (size_t)file_path_length >= sizeof(file_path)) {
                return false;
            }
            char payload[64];
            int payload_length = snprintf(payload, sizeof(payload), "c%zu-%zu", directory_index, file_index);
            if (payload_length < 0 || (size_t)payload_length >= sizeof(payload)) {
                return false;
            }
            if (bc_hash_uring_stress_write_file(file_path, payload, (size_t)payload_length) != 0) {
                return false;
            }
        }
    }
    return true;
}

static int bc_hash_uring_stress_spawn_and_wait(const char* fixture_root)
{
    pid_t child_pid = fork();
    if (child_pid < 0) {
        return -1;
    }
    if (child_pid == 0) {
        int devnull_fd = open("/dev/null", O_WRONLY);
        if (devnull_fd >= 0) {
            dup2(devnull_fd, STDOUT_FILENO);
            close(devnull_fd);
        }
        char* const execv_argv[] = {
            (char*)BC_HASH_TEST_BINARY_PATH, (char*)"hash", (char*)"--type=crc32", (char*)"--output=-", (char*)fixture_root, NULL};
        execv(BC_HASH_TEST_BINARY_PATH, execv_argv);
        _exit(127);
    }
    int child_status = 0;
    if (waitpid(child_pid, &child_status, 0) < 0) {
        return -1;
    }
    if (!WIFEXITED(child_status)) {
        return -1;
    }
    return WEXITSTATUS(child_status);
}

static void bc_hash_uring_stress_remove_fixture(const char* fixture_root)
{
    for (size_t directory_index = 0; directory_index < BC_HASH_URING_STRESS_DIRECTORY_COUNT; ++directory_index) {
        char directory_path[1024];
        int directory_path_length = snprintf(directory_path, sizeof(directory_path), "%s/d%zu", fixture_root, directory_index);
        if (directory_path_length < 0 || (size_t)directory_path_length >= sizeof(directory_path)) {
            continue;
        }
        for (size_t file_index = 0; file_index < BC_HASH_URING_STRESS_FILES_PER_DIRECTORY; ++file_index) {
            char file_path[1200];
            int file_path_length = snprintf(file_path, sizeof(file_path), "%s/f%zu", directory_path, file_index);
            if (file_path_length < 0 || (size_t)file_path_length >= sizeof(file_path)) {
                continue;
            }
            unlink(file_path);
        }
        rmdir(directory_path);
    }
    rmdir(fixture_root);
}

static void test_reader_uring_repeated_binary_runs_never_return_bad_file_descriptor(void** state)
{
    (void)state;
    char fixture_root[512];
    snprintf(fixture_root, sizeof(fixture_root), "/tmp/bc_hash_uring_stress_%d", (int)getpid());
    assert_true(bc_hash_uring_stress_generate_fixture(fixture_root));

    size_t failure_count = 0;
    for (size_t fork_index = 0; fork_index < BC_HASH_URING_STRESS_FORK_COUNT; ++fork_index) {
        int exit_status = bc_hash_uring_stress_spawn_and_wait(fixture_root);
        if (exit_status != 0) {
            failure_count += 1;
        }
    }

    bc_hash_uring_stress_remove_fixture(fixture_root);

    if (failure_count > 0) {
        fprintf(stderr, "bc-hash uring stress: %zu / %d binary runs failed on fixture %s\n", failure_count, BC_HASH_URING_STRESS_FORK_COUNT,
                fixture_root);
    }
    assert_int_equal(failure_count, 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_reader_uring_repeated_binary_runs_never_return_bad_file_descriptor),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
