// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <stdbool.h>

#include "bc_allocators.h"
#include "bc_hash_filter_internal.h"

struct fixture {
    bc_allocators_context_t* memory_context;
};

static int setup(void** state)
{
    struct fixture* fixture = test_calloc(1, sizeof(*fixture));
    bc_allocators_context_config_t config = {.tracking_enabled = true};
    if (!bc_allocators_context_create(&config, &fixture->memory_context)) {
        test_free(fixture);
        return -1;
    }
    *state = fixture;
    return 0;
}

static int teardown(void** state)
{
    struct fixture* fixture = *state;
    bc_allocators_context_destroy(fixture->memory_context);
    test_free(fixture);
    return 0;
}

static void test_null_filter_accepts_everything(void** state)
{
    (void)state;
    assert_true(bc_hash_filter_accepts_file(NULL, "anything.tmp"));
    assert_true(bc_hash_filter_accepts_directory(NULL, ".git"));
}

static void test_empty_filter_accepts_everything(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_filter_t* filter = NULL;
    assert_true(bc_hash_filter_create(fixture->memory_context, NULL, NULL, &filter));
    assert_true(bc_hash_filter_accepts_file(filter, "anything.tmp"));
    assert_true(bc_hash_filter_accepts_directory(filter, ".git"));
    bc_hash_filter_destroy(fixture->memory_context, filter);
}

static void test_empty_strings_behave_like_null(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_filter_t* filter = NULL;
    assert_true(bc_hash_filter_create(fixture->memory_context, "", "", &filter));
    assert_true(bc_hash_filter_accepts_file(filter, "x.c"));
    assert_true(bc_hash_filter_accepts_directory(filter, "src"));
    bc_hash_filter_destroy(fixture->memory_context, filter);
}

static void test_single_exclude_file(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_filter_t* filter = NULL;
    assert_true(bc_hash_filter_create(fixture->memory_context, NULL, "*.tmp", &filter));
    assert_false(bc_hash_filter_accepts_file(filter, "a.tmp"));
    assert_true(bc_hash_filter_accepts_file(filter, "a.c"));
    bc_hash_filter_destroy(fixture->memory_context, filter);
}

static void test_multiple_excludes(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_filter_t* filter = NULL;
    assert_true(bc_hash_filter_create(fixture->memory_context, NULL, "*.tmp\n*.log\n.git", &filter));
    assert_false(bc_hash_filter_accepts_file(filter, "a.tmp"));
    assert_false(bc_hash_filter_accepts_file(filter, "a.log"));
    assert_true(bc_hash_filter_accepts_file(filter, "a.c"));
    assert_false(bc_hash_filter_accepts_directory(filter, ".git"));
    assert_true(bc_hash_filter_accepts_directory(filter, "src"));
    bc_hash_filter_destroy(fixture->memory_context, filter);
}

static void test_include_gates_file(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_filter_t* filter = NULL;
    assert_true(bc_hash_filter_create(fixture->memory_context, "*.c", NULL, &filter));
    assert_true(bc_hash_filter_accepts_file(filter, "main.c"));
    assert_false(bc_hash_filter_accepts_file(filter, "util.h"));
    bc_hash_filter_destroy(fixture->memory_context, filter);
}

static void test_include_never_gates_directory(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_filter_t* filter = NULL;
    assert_true(bc_hash_filter_create(fixture->memory_context, "*.c", NULL, &filter));
    assert_true(bc_hash_filter_accepts_directory(filter, "src"));
    assert_true(bc_hash_filter_accepts_directory(filter, ".git"));
    bc_hash_filter_destroy(fixture->memory_context, filter);
}

static void test_include_plus_exclude_intersection(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_filter_t* filter = NULL;
    assert_true(bc_hash_filter_create(fixture->memory_context, "*.c", "util.c", &filter));
    assert_true(bc_hash_filter_accepts_file(filter, "main.c"));
    assert_false(bc_hash_filter_accepts_file(filter, "util.c"));
    assert_false(bc_hash_filter_accepts_file(filter, "data.h"));
    bc_hash_filter_destroy(fixture->memory_context, filter);
}

static void test_multiple_includes_any_matches(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_filter_t* filter = NULL;
    assert_true(bc_hash_filter_create(fixture->memory_context, "*.c\n*.h", NULL, &filter));
    assert_true(bc_hash_filter_accepts_file(filter, "main.c"));
    assert_true(bc_hash_filter_accepts_file(filter, "util.h"));
    assert_false(bc_hash_filter_accepts_file(filter, "readme.md"));
    bc_hash_filter_destroy(fixture->memory_context, filter);
}

static void test_pattern_with_slash_matches_nothing_basename(void** state)
{
    struct fixture* fixture = *state;
    bc_hash_filter_t* filter = NULL;
    assert_true(bc_hash_filter_create(fixture->memory_context, NULL, "src/foo.c", &filter));
    assert_true(bc_hash_filter_accepts_file(filter, "foo.c"));
    assert_true(bc_hash_filter_accepts_file(filter, "src"));
    bc_hash_filter_destroy(fixture->memory_context, filter);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_null_filter_accepts_everything, setup, teardown),
        cmocka_unit_test_setup_teardown(test_empty_filter_accepts_everything, setup, teardown),
        cmocka_unit_test_setup_teardown(test_empty_strings_behave_like_null, setup, teardown),
        cmocka_unit_test_setup_teardown(test_single_exclude_file, setup, teardown),
        cmocka_unit_test_setup_teardown(test_multiple_excludes, setup, teardown),
        cmocka_unit_test_setup_teardown(test_include_gates_file, setup, teardown),
        cmocka_unit_test_setup_teardown(test_include_never_gates_directory, setup, teardown),
        cmocka_unit_test_setup_teardown(test_include_plus_exclude_intersection, setup, teardown),
        cmocka_unit_test_setup_teardown(test_multiple_includes_any_matches, setup, teardown),
        cmocka_unit_test_setup_teardown(test_pattern_with_slash_matches_nothing_basename, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
