// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<valgrind/valgrind.h>)
#include <valgrind/valgrind.h>
#define BC_HASH_TEST_HAS_VALGRIND_HEADER 1
#endif
#endif

#include "bc_allocators.h"
#include "bc_concurrency.h"
#include "bc_hash_throughput_internal.h"

static bool bc_hash_test_under_valgrind(void)
{
#if defined(BC_HASH_TEST_HAS_VALGRIND_HEADER)
    return RUNNING_ON_VALGRIND != 0;
#else
    return false;
#endif
}

static void test_measure_returns_reasonable_hashing_throughputs(void** state)
{
    (void)state;
    if (bc_hash_test_under_valgrind()) {
        skip();
    }
    bc_allocators_context_t* memory = NULL;
    assert_true(bc_allocators_context_create(NULL, &memory));
    bc_concurrency_context_t* concurrency = NULL;
    assert_true(bc_concurrency_create(memory, NULL, &concurrency));

    bc_hash_throughput_constants_t constants;
    assert_true(bc_hash_throughput_measure(concurrency, &constants));

    assert_true(constants.sha256_gigabytes_per_second > 0.1);
    assert_true(constants.sha256_gigabytes_per_second < 20.0);
    assert_true(constants.crc32c_gigabytes_per_second > 0.1);
    assert_true(constants.crc32c_gigabytes_per_second < 50.0);
    assert_true(constants.memory_bandwidth_gigabytes_per_second > 1.0);
    assert_true(constants.memory_bandwidth_gigabytes_per_second < 200.0);
    assert_true(constants.parallel_startup_overhead_microseconds >= 0.0);
    assert_true(constants.parallel_startup_overhead_microseconds < 100000.0);
    assert_true(constants.per_file_cost_warm_microseconds > 0.0);
    assert_true(constants.per_file_cost_warm_microseconds < 100000.0);

    bc_concurrency_destroy(concurrency);
    bc_allocators_context_destroy(memory);
}

static void test_cache_store_then_load_round_trips_constants(void** state)
{
    (void)state;
    char cache_path[] = "/tmp/bc_hash_throughput_cache_roundtrip_XXXXXX";
    int temp_fd = mkstemp(cache_path);
    assert_true(temp_fd >= 0);
    close(temp_fd);
    unlink(cache_path);

    bc_hash_throughput_constants_t original_constants = {
        .sha256_gigabytes_per_second = 1.65,
        .crc32c_gigabytes_per_second = 8.2,
        .memory_bandwidth_gigabytes_per_second = 34.7,
        .parallel_startup_overhead_microseconds = 350.0,
        .per_file_cost_warm_microseconds = 120.0,
    };

    assert_true(bc_hash_throughput_cache_store(cache_path, &original_constants));

    bc_hash_throughput_constants_t reloaded_constants;
    assert_true(bc_hash_throughput_cache_load(cache_path, &reloaded_constants));

    assert_true(reloaded_constants.sha256_gigabytes_per_second - original_constants.sha256_gigabytes_per_second < 0.001);
    assert_true(reloaded_constants.crc32c_gigabytes_per_second - original_constants.crc32c_gigabytes_per_second < 0.001);
    assert_true(reloaded_constants.memory_bandwidth_gigabytes_per_second - original_constants.memory_bandwidth_gigabytes_per_second < 0.001);
    assert_true(reloaded_constants.parallel_startup_overhead_microseconds - original_constants.parallel_startup_overhead_microseconds < 0.001);
    assert_true(reloaded_constants.per_file_cost_warm_microseconds - original_constants.per_file_cost_warm_microseconds < 0.001);

    unlink(cache_path);
}

static void test_cache_load_returns_false_when_cpu_model_mismatches(void** state)
{
    (void)state;
    char cache_path[] = "/tmp/bc_hash_throughput_cache_invalid_XXXXXX";
    int temp_fd = mkstemp(cache_path);
    assert_true(temp_fd >= 0);
    FILE* stream = fdopen(temp_fd, "w");
    assert_non_null(stream);
    fprintf(stream,
            "cpu_model=Fabricated CPU Model That Does Not Exist\n"
            "microcode=0xdeadbeef\n"
            "kernel_version=99.99.99-fake\n"
            "sha256_gbps=1.0\n"
            "crc32c_gbps=1.0\n"
            "mem_bw_gbps=1.0\n"
            "parallel_startup_us=1.0\n"
            "per_file_cost_us=1.0\n");
    fclose(stream);

    bc_hash_throughput_constants_t constants;
    assert_false(bc_hash_throughput_cache_load(cache_path, &constants));

    unlink(cache_path);
}

static void test_cache_load_returns_false_when_file_missing(void** state)
{
    (void)state;
    bc_hash_throughput_constants_t constants;
    assert_false(bc_hash_throughput_cache_load("/tmp/bc_hash_cache_definitely_nonexistent_3f7a9e21c8b4d5e6.txt", &constants));
}

static void test_cache_load_returns_false_when_keys_are_missing_in_cache_file(void** state)
{
    (void)state;
    char cache_path[] = "/tmp/bc_hash_throughput_cache_partial_XXXXXX";
    int temp_fd = mkstemp(cache_path);
    assert_true(temp_fd >= 0);
    FILE* stream = fdopen(temp_fd, "w");
    assert_non_null(stream);
    fprintf(stream, "sha256_gbps=1.65\n");
    fclose(stream);

    bc_hash_throughput_constants_t constants;
    assert_false(bc_hash_throughput_cache_load(cache_path, &constants));

    unlink(cache_path);
}

static void test_read_host_signature_populates_cpu_and_kernel_fields(void** state)
{
    (void)state;
    char cpu_model[256];
    char microcode[256];
    char kernel_version[256];
    assert_true(bc_hash_throughput_cache_read_host_signature(cpu_model, sizeof(cpu_model), microcode, sizeof(microcode), kernel_version,
                                                             sizeof(kernel_version)));
    assert_true(strlen(cpu_model) > 0);
    assert_true(strlen(kernel_version) > 0);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_measure_returns_reasonable_hashing_throughputs),
        cmocka_unit_test(test_cache_store_then_load_round_trips_constants),
        cmocka_unit_test(test_cache_load_returns_false_when_cpu_model_mismatches),
        cmocka_unit_test(test_cache_load_returns_false_when_file_missing),
        cmocka_unit_test(test_cache_load_returns_false_when_keys_are_missing_in_cache_file),
        cmocka_unit_test(test_read_host_signature_populates_cpu_and_kernel_fields),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
