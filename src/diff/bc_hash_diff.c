// SPDX-License-Identifier: MIT

#include "bc_hash_diff_internal.h"
#include "bc_hash_error_internal.h"
#include "bc_hash_types_internal.h"
#include "bc_hash_verify_internal.h"

#include "bc_allocators_pool.h"
#include "bc_containers_vector.h"
#include "bc_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BC_HASH_DIFF_EXIT_NO_DIFF 0
#define BC_HASH_DIFF_EXIT_DIFF_PRESENT 1
#define BC_HASH_DIFF_EXIT_ERROR 2

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

static int bc_hash_diff_compare_expectations(const void* left_pointer, const void* right_pointer)
{
    const bc_hash_verify_expectation_t* left = (const bc_hash_verify_expectation_t*)left_pointer;
    const bc_hash_verify_expectation_t* right = (const bc_hash_verify_expectation_t*)right_pointer;
    return strcmp(left->target_path, right->target_path);
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
        fprintf(stderr, "bc-hash: diff: failed to allocate for '%s'\n", label);
        return false;
    }

    bc_hash_verify_parse_status_t parse_status = bc_hash_verify_parse_digest_file(memory_context, path, vector, out_algorithm);
    if (parse_status == BC_HASH_VERIFY_PARSE_STATUS_IO_ERROR) {
        fprintf(stderr, "bc-hash: diff: cannot read %s digest file '%s'\n", label, path);
        bc_containers_vector_destroy(memory_context, vector);
        return false;
    }
    if (parse_status == BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR) {
        fprintf(stderr, "bc-hash: diff: malformed %s digest file '%s'\n", label, path);
        bc_containers_vector_destroy(memory_context, vector);
        return false;
    }

    if (!bc_hash_diff_copy_vector_to_array(memory_context, vector, out_array, out_length)) {
        fprintf(stderr, "bc-hash: diff: failed to flatten %s digest entries\n", label);
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
        fprintf(stderr, "bc-hash: diff: algorithm mismatch (%s vs %s)\n", bc_hash_diff_algorithm_name(algorithm_a),
                bc_hash_diff_algorithm_name(algorithm_b));
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
        qsort(entries_a, length_a, sizeof(bc_hash_verify_expectation_t), bc_hash_diff_compare_expectations);
    }
    if (length_b > 1 && entries_b != NULL) {
        qsort(entries_b, length_b, sizeof(bc_hash_verify_expectation_t), bc_hash_diff_compare_expectations);
    }

    size_t added = 0;
    size_t removed = 0;
    size_t modified = 0;
    size_t unchanged = 0;
    size_t cursor_a = 0;
    size_t cursor_b = 0;

    while (cursor_a < length_a && cursor_b < length_b) {
        const bc_hash_verify_expectation_t* left = &entries_a[cursor_a];
        const bc_hash_verify_expectation_t* right = &entries_b[cursor_b];
        int comparison = strcmp(left->target_path, right->target_path);
        if (comparison < 0) {
            fprintf(stdout, "REMOVED   %s\n", left->target_path);
            removed += 1;
            cursor_a += 1;
            continue;
        }
        if (comparison > 0) {
            fprintf(stdout, "ADDED     %s\n", right->target_path);
            added += 1;
            cursor_b += 1;
            continue;
        }
        if (strcmp(left->expected_hex, right->expected_hex) == 0) {
            unchanged += 1;
        } else {
            fprintf(stdout, "MODIFIED  %s  %s -> %s\n", left->target_path, left->expected_hex, right->expected_hex);
            modified += 1;
        }
        cursor_a += 1;
        cursor_b += 1;
    }

    while (cursor_a < length_a) {
        fprintf(stdout, "REMOVED   %s\n", entries_a[cursor_a].target_path);
        removed += 1;
        cursor_a += 1;
    }
    while (cursor_b < length_b) {
        fprintf(stdout, "ADDED     %s\n", entries_b[cursor_b].target_path);
        added += 1;
        cursor_b += 1;
    }

    fflush(stdout);

    fprintf(stderr, "bc-hash: %zu added, %zu removed, %zu modified, %zu unchanged\n", added, removed, modified, unchanged);

    if (entries_a != NULL) {
        bc_allocators_pool_free(memory_context, entries_a);
    }
    if (entries_b != NULL) {
        bc_allocators_pool_free(memory_context, entries_b);
    }

    *out_exit_code = (added == 0 && removed == 0 && modified == 0) ? BC_HASH_DIFF_EXIT_NO_DIFF : BC_HASH_DIFF_EXIT_DIFF_PRESENT;
    return true;
}
