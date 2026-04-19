// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "bc_allocators.h"
#include "bc_hash_error_internal.h"

struct fixture {
    bc_allocators_context_t* memory_context;
    bc_hash_error_collector_t* collector;
};

static int setup(void** state)
{
    struct fixture* fixture = test_calloc(1, sizeof(*fixture));
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    if (!bc_allocators_context_create(&config, &fixture->memory_context)) {
        test_free(fixture);
        return -1;
    }
    if (!bc_hash_error_collector_create(fixture->memory_context, &fixture->collector)) {
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
    bc_hash_error_collector_destroy(fixture->memory_context, fixture->collector);
    bc_allocators_context_destroy(fixture->memory_context);
    test_free(fixture);
    return 0;
}

static void test_empty_collector_count_zero(void** state)
{
    const struct fixture* fixture = *state;
    assert_int_equal(bc_hash_error_collector_count(fixture->collector), 0);
}

static void test_record_single_error(void** state)
{
    struct fixture* fixture = *state;
    assert_true(bc_hash_error_collector_record(fixture->collector, fixture->memory_context, "/path/a", "open", ENOENT));
    assert_int_equal(bc_hash_error_collector_count(fixture->collector), 1);
}

static void test_record_many_errors_grows(void** state)
{
    struct fixture* fixture = *state;
    for (size_t index = 0; index < 64; index++) {
        char path[32];
        snprintf(path, sizeof(path), "/path/%zu", index);
        assert_true(bc_hash_error_collector_record(fixture->collector, fixture->memory_context, path, "stat", EACCES));
    }
    assert_int_equal(bc_hash_error_collector_count(fixture->collector), 64);
}

static void test_flush_to_stderr_returns_true(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_error_collector_record(fixture->collector, fixture->memory_context, "/a", "read", EIO);
    bc_hash_error_collector_record(fixture->collector, fixture->memory_context, "/b", "open", EPERM);
    assert_true(bc_hash_error_collector_flush_to_stderr(fixture->collector));
}

static void test_flush_empty_returns_true(void** state)
{
    const struct fixture* fixture = *state;
    assert_true(bc_hash_error_collector_flush_to_stderr(fixture->collector));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_empty_collector_count_zero, setup, teardown),
        cmocka_unit_test_setup_teardown(test_record_single_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_record_many_errors_grows, setup, teardown),
        cmocka_unit_test_setup_teardown(test_flush_to_stderr_returns_true, setup, teardown),
        cmocka_unit_test_setup_teardown(test_flush_empty_returns_true, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
