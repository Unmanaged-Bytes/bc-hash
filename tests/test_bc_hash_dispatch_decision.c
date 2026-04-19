// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "bc_hash_dispatch_decision_internal.h"
#include "bc_hash_throughput_internal.h"

static bc_hash_throughput_constants_t default_throughput_constants(void)
{
    bc_hash_throughput_constants_t constants = {
        .sha256_gigabytes_per_second = 1.65,
        .crc32c_gigabytes_per_second = 11.4,
        .memory_bandwidth_gigabytes_per_second = 33.0,
        .parallel_startup_overhead_microseconds = 1.3,
        .per_file_cost_warm_microseconds = 4.0,
    };
    return constants;
}

static void test_empty_file_list_chooses_mono(void** state)
{
    (void)state;
    bc_hash_throughput_constants_t constants = default_throughput_constants();
    assert_false(bc_hash_dispatch_decision_should_go_multithread(0, 0, &constants, 8));
}

static void test_single_worker_chooses_mono(void** state)
{
    (void)state;
    bc_hash_throughput_constants_t constants = default_throughput_constants();
    assert_false(bc_hash_dispatch_decision_should_go_multithread(10000, 10 * 1024 * 1024, &constants, 1));
}

static void test_tiny_workload_chooses_mono(void** state)
{
    (void)state;
    bc_hash_throughput_constants_t constants = default_throughput_constants();
    constants.parallel_startup_overhead_microseconds = 500.0;
    assert_false(bc_hash_dispatch_decision_should_go_multithread(3, 300, &constants, 8));
}

static void test_workload_below_startup_breakeven_chooses_mono(void** state)
{
    (void)state;
    bc_hash_throughput_constants_t constants = default_throughput_constants();
    constants.parallel_startup_overhead_microseconds = 100.0;
    constants.per_file_cost_warm_microseconds = 10.0;
    assert_false(bc_hash_dispatch_decision_should_go_multithread(5, 500, &constants, 8));
}

static void test_large_total_bytes_single_file_chooses_multi(void** state)
{
    (void)state;
    bc_hash_throughput_constants_t constants = default_throughput_constants();
    assert_true(bc_hash_dispatch_decision_should_go_multithread(1, (size_t)100 * 1024 * 1024, &constants, 8));
}

static void test_many_small_files_chooses_multi(void** state)
{
    (void)state;
    bc_hash_throughput_constants_t constants = default_throughput_constants();
    assert_true(bc_hash_dispatch_decision_should_go_multithread(10000, 10000 * 100, &constants, 8));
}

static void test_zero_throughput_defaults_to_multi(void** state)
{
    (void)state;
    bc_hash_throughput_constants_t constants = default_throughput_constants();
    constants.sha256_gigabytes_per_second = 0.0;
    assert_true(bc_hash_dispatch_decision_should_go_multithread(1000, 100 * 1024, &constants, 8));
}

static void test_optimal_worker_count_memory_bound_capped_by_memory_bandwidth(void** state)
{
    (void)state;
    size_t optimal = bc_hash_dispatch_decision_optimal_worker_count(11.4, 33.0, 8);
    assert_int_equal(optimal, 3);
}

static void test_optimal_worker_count_compute_bound_capped_by_physical_cores(void** state)
{
    (void)state;
    size_t optimal = bc_hash_dispatch_decision_optimal_worker_count(1.65, 33.0, 8);
    assert_int_equal(optimal, 7);
}

static void test_optimal_worker_count_returns_compute_bound_on_missing_data(void** state)
{
    (void)state;
    size_t optimal = bc_hash_dispatch_decision_optimal_worker_count(0.0, 33.0, 8);
    assert_int_equal(optimal, 7);
}

static void test_optimal_worker_count_single_core_returns_one(void** state)
{
    (void)state;
    size_t optimal = bc_hash_dispatch_decision_optimal_worker_count(1.65, 33.0, 1);
    assert_int_equal(optimal, 1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_empty_file_list_chooses_mono),
        cmocka_unit_test(test_single_worker_chooses_mono),
        cmocka_unit_test(test_tiny_workload_chooses_mono),
        cmocka_unit_test(test_workload_below_startup_breakeven_chooses_mono),
        cmocka_unit_test(test_large_total_bytes_single_file_chooses_multi),
        cmocka_unit_test(test_many_small_files_chooses_multi),
        cmocka_unit_test(test_zero_throughput_defaults_to_multi),
        cmocka_unit_test(test_optimal_worker_count_memory_bound_capped_by_memory_bandwidth),
        cmocka_unit_test(test_optimal_worker_count_compute_bound_capped_by_physical_cores),
        cmocka_unit_test(test_optimal_worker_count_returns_compute_bound_on_missing_data),
        cmocka_unit_test(test_optimal_worker_count_single_core_returns_one),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
