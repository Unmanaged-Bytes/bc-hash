// SPDX-License-Identifier: MIT

#include "bc_hash_diff_internal.h"
#include "bc_runtime_error_collector.h"
#include "bc_hash_types_internal.h"
#include "bc_hash_verify_internal.h"

#include "bc_allocators_pool.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_core_sort.h"

#define BC_HASH_DIFF_EXIT_NO_DIFF 0
#define BC_HASH_DIFF_EXIT_DIFF_PRESENT 1
#define BC_HASH_DIFF_EXIT_ERROR 2
#define BC_HASH_DIFF_STDERR_BUFFER_BYTES ((size_t)512)
#define BC_HASH_DIFF_STDOUT_BUFFER_BYTES ((size_t)(64 * 1024))

static int bc_hash_diff_path_compare(const char* left, const char* right)
{
    size_t left_length = 0;
    size_t right_length = 0;
    (void)bc_core_length(left, '\0', &left_length);
    (void)bc_core_length(right, '\0', &right_length);
    size_t shared_length = left_length < right_length ? left_length : right_length;
    int comparison = 0;
    if (shared_length > 0) {
        (void)bc_core_compare(left, right, shared_length, &comparison);
    }
    if (comparison != 0) {
        return comparison;
    }
    if (left_length < right_length) {
        return -1;
    }
    if (left_length > right_length) {
        return 1;
    }
    return 0;
}

static bool bc_hash_diff_strings_equal(const char* left, const char* right)
{
    size_t left_length = 0;
    size_t right_length = 0;
    (void)bc_core_length(left, '\0', &left_length);
    (void)bc_core_length(right, '\0', &right_length);
    if (left_length != right_length) {
        return false;
    }
    bool equal = false;
    (void)bc_core_equal(left, right, left_length, &equal);
    return equal;
}

static const char* bc_hash_diff_algorithm_name(bc_hash_algorithm_t algorithm)
{
    switch (algorithm) {
    case BC_HASH_ALGORITHM_CRC32:
        return "crc32";
    case BC_HASH_ALGORITHM_XXH3:
        return "xxh3";
    case BC_HASH_ALGORITHM_XXH128:
        return "xxh128";
    case BC_HASH_ALGORITHM_SHA256:
    default:
        return "sha256";
    }
}

static bool bc_hash_diff_expectation_less_than(const void* left_pointer, const void* right_pointer, void* user_data)
{
    (void)user_data;
    const bc_hash_verify_expectation_t* left = (const bc_hash_verify_expectation_t*)left_pointer;
    const bc_hash_verify_expectation_t* right = (const bc_hash_verify_expectation_t*)right_pointer;
    return bc_hash_diff_path_compare(left->target_path, right->target_path) < 0;
}

static void bc_hash_diff_emit_stderr_quoted(const char* prefix, const char* label, const char* mid, const char* path, const char* suffix)
{
    char stderr_buffer[BC_HASH_DIFF_STDERR_BUFFER_BYTES];
    bc_core_writer_t stderr_writer;
    if (!bc_core_writer_init_standard_error(&stderr_writer, stderr_buffer, sizeof(stderr_buffer))) {
        return;
    }
    (void)bc_core_writer_write_cstring(&stderr_writer, prefix);
    (void)bc_core_writer_write_cstring(&stderr_writer, label);
    (void)bc_core_writer_write_cstring(&stderr_writer, mid);
    (void)bc_core_writer_write_cstring(&stderr_writer, path);
    (void)bc_core_writer_write_cstring(&stderr_writer, suffix);
    (void)bc_core_writer_destroy(&stderr_writer);
}

static bool bc_hash_diff_copy_vector_to_array(bc_allocators_context_t* memory_context, const bc_containers_vector_t* vector,
                                              bc_hash_verify_expectation_t** out_array, size_t* out_length)
{
    size_t length = bc_containers_vector_length(vector);
    if (length == 0) {
        *out_array = NULL;
        *out_length = 0;
        return true;
    }
    size_t bytes = length * sizeof(bc_hash_verify_expectation_t);
    bc_hash_verify_expectation_t* array = NULL;
    if (!bc_allocators_pool_allocate(memory_context, bytes, (void**)&array)) {
        return false;
    }
    for (size_t index = 0; index < length; index++) {
        if (!bc_containers_vector_get(vector, index, &array[index])) {
            bc_allocators_pool_free(memory_context, array);
            return false;
        }
    }
    *out_array = array;
    *out_length = length;
    return true;
}

static bool bc_hash_diff_parse_side(bc_allocators_context_t* memory_context, const char* path, const char* label,
                                    bc_hash_verify_expectation_t** out_array, size_t* out_length, bc_hash_algorithm_t* out_algorithm)
{
    bc_containers_vector_t* vector = NULL;
    if (!bc_containers_vector_create(memory_context, sizeof(bc_hash_verify_expectation_t), 128, (size_t)1 << 28, &vector)) {
        bc_hash_diff_emit_stderr_quoted("bc-hash: diff: failed to allocate for '", label, "", "", "'\n");
        return false;
    }

    bc_hash_verify_parse_status_t parse_status = bc_hash_verify_parse_digest_file(memory_context, path, vector, out_algorithm);
    if (parse_status == BC_HASH_VERIFY_PARSE_STATUS_IO_ERROR) {
        bc_hash_diff_emit_stderr_quoted("bc-hash: diff: cannot read ", label, " digest file '", path, "'\n");
        bc_containers_vector_destroy(memory_context, vector);
        return false;
    }
    if (parse_status == BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR) {
        bc_hash_diff_emit_stderr_quoted("bc-hash: diff: malformed ", label, " digest file '", path, "'\n");
        bc_containers_vector_destroy(memory_context, vector);
        return false;
    }

    if (!bc_hash_diff_copy_vector_to_array(memory_context, vector, out_array, out_length)) {
        bc_hash_diff_emit_stderr_quoted("bc-hash: diff: failed to flatten ", label, " digest entries", "", "\n");
        bc_containers_vector_destroy(memory_context, vector);
        return false;
    }

    bc_containers_vector_destroy(memory_context, vector);
    return true;
}

bool bc_hash_diff_run(bc_allocators_context_t* memory_context, const char* digest_path_a, const char* digest_path_b, int* out_exit_code)
{
    bc_hash_verify_expectation_t* entries_a = NULL;
    bc_hash_verify_expectation_t* entries_b = NULL;
    size_t length_a = 0;
    size_t length_b = 0;
    bc_hash_algorithm_t algorithm_a = BC_HASH_ALGORITHM_SHA256;
    bc_hash_algorithm_t algorithm_b = BC_HASH_ALGORITHM_SHA256;

    if (!bc_hash_diff_parse_side(memory_context, digest_path_a, "left", &entries_a, &length_a, &algorithm_a)) {
        *out_exit_code = BC_HASH_DIFF_EXIT_ERROR;
        return true;
    }
    if (!bc_hash_diff_parse_side(memory_context, digest_path_b, "right", &entries_b, &length_b, &algorithm_b)) {
        if (entries_a != NULL) {
            bc_allocators_pool_free(memory_context, entries_a);
        }
        *out_exit_code = BC_HASH_DIFF_EXIT_ERROR;
        return true;
    }

    if (algorithm_a != algorithm_b) {
        bc_hash_diff_emit_stderr_quoted("bc-hash: diff: algorithm mismatch (", bc_hash_diff_algorithm_name(algorithm_a), " vs ",
                                        bc_hash_diff_algorithm_name(algorithm_b), ")\n");
        if (entries_a != NULL) {
            bc_allocators_pool_free(memory_context, entries_a);
        }
        if (entries_b != NULL) {
            bc_allocators_pool_free(memory_context, entries_b);
        }
        *out_exit_code = BC_HASH_DIFF_EXIT_ERROR;
        return true;
    }

    if (length_a > 1 && entries_a != NULL) {
        bc_core_sort_with_compare(entries_a, length_a, sizeof(bc_hash_verify_expectation_t), bc_hash_diff_expectation_less_than, NULL);
    }
    if (length_b > 1 && entries_b != NULL) {
        bc_core_sort_with_compare(entries_b, length_b, sizeof(bc_hash_verify_expectation_t), bc_hash_diff_expectation_less_than, NULL);
    }

    size_t added = 0;
    size_t removed = 0;
    size_t modified = 0;
    size_t unchanged = 0;
    size_t cursor_a = 0;
    size_t cursor_b = 0;

    char stdout_buffer[BC_HASH_DIFF_STDOUT_BUFFER_BYTES];
    bc_core_writer_t stdout_writer;
    bool stdout_writer_ready = bc_core_writer_init_standard_output(&stdout_writer, stdout_buffer, sizeof(stdout_buffer));

    while (cursor_a < length_a && cursor_b < length_b) {
        const bc_hash_verify_expectation_t* left = &entries_a[cursor_a];
        const bc_hash_verify_expectation_t* right = &entries_b[cursor_b];
        int comparison = bc_hash_diff_path_compare(left->target_path, right->target_path);
        if (comparison < 0) {
            if (stdout_writer_ready) {
                (void)bc_core_writer_write_cstring(&stdout_writer, "REMOVED   ");
                (void)bc_core_writer_write_cstring(&stdout_writer, left->target_path);
                (void)bc_core_writer_write_char(&stdout_writer, '\n');
            }
            removed += 1;
            cursor_a += 1;
            continue;
        }
        if (comparison > 0) {
            if (stdout_writer_ready) {
                (void)bc_core_writer_write_cstring(&stdout_writer, "ADDED     ");
                (void)bc_core_writer_write_cstring(&stdout_writer, right->target_path);
                (void)bc_core_writer_write_char(&stdout_writer, '\n');
            }
            added += 1;
            cursor_b += 1;
            continue;
        }
        if (bc_hash_diff_strings_equal(left->expected_hex, right->expected_hex)) {
            unchanged += 1;
        } else {
            if (stdout_writer_ready) {
                (void)bc_core_writer_write_cstring(&stdout_writer, "MODIFIED  ");
                (void)bc_core_writer_write_cstring(&stdout_writer, left->target_path);
                (void)bc_core_writer_write_cstring(&stdout_writer, "  ");
                (void)bc_core_writer_write_cstring(&stdout_writer, left->expected_hex);
                (void)bc_core_writer_write_cstring(&stdout_writer, " -> ");
                (void)bc_core_writer_write_cstring(&stdout_writer, right->expected_hex);
                (void)bc_core_writer_write_char(&stdout_writer, '\n');
            }
            modified += 1;
        }
        cursor_a += 1;
        cursor_b += 1;
    }

    while (cursor_a < length_a) {
        if (stdout_writer_ready) {
            (void)bc_core_writer_write_cstring(&stdout_writer, "REMOVED   ");
            (void)bc_core_writer_write_cstring(&stdout_writer, entries_a[cursor_a].target_path);
            (void)bc_core_writer_write_char(&stdout_writer, '\n');
        }
        removed += 1;
        cursor_a += 1;
    }
    while (cursor_b < length_b) {
        if (stdout_writer_ready) {
            (void)bc_core_writer_write_cstring(&stdout_writer, "ADDED     ");
            (void)bc_core_writer_write_cstring(&stdout_writer, entries_b[cursor_b].target_path);
            (void)bc_core_writer_write_char(&stdout_writer, '\n');
        }
        added += 1;
        cursor_b += 1;
    }

    if (stdout_writer_ready) {
        (void)bc_core_writer_destroy(&stdout_writer);
    }

    char stderr_buffer[BC_HASH_DIFF_STDERR_BUFFER_BYTES];
    bc_core_writer_t stderr_writer;
    if (bc_core_writer_init_standard_error(&stderr_writer, stderr_buffer, sizeof(stderr_buffer))) {
        (void)bc_core_writer_write_cstring(&stderr_writer, "bc-hash: ");
        (void)bc_core_writer_write_unsigned_integer_64_decimal(&stderr_writer, (uint64_t)added);
        (void)bc_core_writer_write_cstring(&stderr_writer, " added, ");
        (void)bc_core_writer_write_unsigned_integer_64_decimal(&stderr_writer, (uint64_t)removed);
        (void)bc_core_writer_write_cstring(&stderr_writer, " removed, ");
        (void)bc_core_writer_write_unsigned_integer_64_decimal(&stderr_writer, (uint64_t)modified);
        (void)bc_core_writer_write_cstring(&stderr_writer, " modified, ");
        (void)bc_core_writer_write_unsigned_integer_64_decimal(&stderr_writer, (uint64_t)unchanged);
        (void)bc_core_writer_write_cstring(&stderr_writer, " unchanged\n");
        (void)bc_core_writer_destroy(&stderr_writer);
    }

    if (entries_a != NULL) {
        bc_allocators_pool_free(memory_context, entries_a);
    }
    if (entries_b != NULL) {
        bc_allocators_pool_free(memory_context, entries_b);
    }

    *out_exit_code = (added == 0 && removed == 0 && modified == 0) ? BC_HASH_DIFF_EXIT_NO_DIFF : BC_HASH_DIFF_EXIT_DIFF_PRESENT;
    return true;
}
