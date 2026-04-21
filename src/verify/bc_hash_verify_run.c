// SPDX-License-Identifier: MIT

#include "bc_hash_output_internal.h"
#include "bc_hash_verify_internal.h"
#include "bc_hash_worker_internal.h"

#include "bc_allocators_pool.h"
#include "bc_core.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BC_HASH_VERIFY_EXIT_CODE_OK 0
#define BC_HASH_VERIFY_EXIT_CODE_MISMATCH 1

static void bc_hash_verify_compute_result_hex(bc_hash_algorithm_t algorithm, const bc_hash_result_entry_t* result, char* out_hex_buffer)
{
    static const char bc_hash_verify_hex_alphabet[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    switch (algorithm) {
        case BC_HASH_ALGORITHM_CRC32: {
            uint32_t crc32_value = result->crc32_value;
            for (size_t index = 0; index < BC_HASH_CRC32_HEX_LENGTH; ++index) {
                size_t shift_bits = 28u - (index * 4u);
                uint32_t nibble = (crc32_value >> shift_bits) & 0xFu;
                out_hex_buffer[index] = bc_hash_verify_hex_alphabet[nibble];
            }
            out_hex_buffer[BC_HASH_CRC32_HEX_LENGTH] = '\0';
            return;
        }
        case BC_HASH_ALGORITHM_XXH3:
            bc_hash_output_encode_hex(result->xxh3_digest, BC_HASH_XXH3_DIGEST_SIZE, out_hex_buffer);
            return;
        case BC_HASH_ALGORITHM_XXH128:
            bc_hash_output_encode_hex(result->xxh128_digest, BC_HASH_XXH128_DIGEST_SIZE, out_hex_buffer);
            return;
        case BC_HASH_ALGORITHM_SHA256:
        default:
            bc_hash_output_encode_hex(result->sha256_digest, BC_CORE_SHA256_DIGEST_SIZE, out_hex_buffer);
            return;
    }
}

static bool bc_hash_verify_stat_target(const char* path, size_t* out_file_size, int* out_errno)
{
    struct stat stat_buffer;
    if (stat(path, &stat_buffer) != 0) {
        *out_errno = errno;
        return false;
    }
    if (!S_ISREG(stat_buffer.st_mode)) {
        *out_errno = EISDIR;
        return false;
    }
    *out_file_size = (size_t)stat_buffer.st_size;
    *out_errno = 0;
    return true;
}

bool bc_hash_verify_run(bc_allocators_context_t* memory_context, bc_concurrency_context_t* concurrency_context,
                        bc_concurrency_signal_handler_t* signal_handler, bc_hash_algorithm_t algorithm,
                        bc_containers_vector_t* expectations, bc_runtime_error_collector_t* errors, int* out_exit_code)
{
    size_t expectation_count = bc_containers_vector_length(expectations);
    if (expectation_count == 0) {
        *out_exit_code = BC_HASH_VERIFY_EXIT_CODE_MISMATCH;
        return true;
    }

    bc_containers_vector_t* entries = NULL;
    if (!bc_containers_vector_create(memory_context, sizeof(bc_hash_file_entry_t), 128, (size_t)1 << 28, &entries)) {
        return false;
    }

    size_t dispatched_count = 0;
    size_t missing_count = 0;
    for (size_t index = 0; index < expectation_count; index++) {
        bc_hash_verify_expectation_t expectation;
        if (!bc_containers_vector_get(expectations, index, &expectation)) {
            bc_containers_vector_destroy(memory_context, entries);
            return false;
        }
        size_t file_size = 0;
        int stat_errno = 0;
        if (!bc_hash_verify_stat_target(expectation.target_path, &file_size, &stat_errno)) {
            expectation.target_missing = true;
            expectation.stat_errno = stat_errno;
            expectation.dispatch_index = BC_HASH_VERIFY_SENTINEL_DISPATCH_INDEX;
            missing_count += 1;
        } else {
            bc_hash_file_entry_t entry = {
                .absolute_path = (char*)expectation.target_path,
                .absolute_path_length = expectation.target_path_length,
                .file_size = file_size,
            };
            if (!bc_containers_vector_push(memory_context, entries, &entry)) {
                bc_containers_vector_destroy(memory_context, entries);
                return false;
            }
            expectation.dispatch_index = dispatched_count;
            expectation.target_missing = false;
            dispatched_count += 1;
        }
        if (!bc_containers_vector_set(expectations, index, &expectation)) {
            bc_containers_vector_destroy(memory_context, entries);
            return false;
        }
    }

    bc_hash_result_entry_t* results = NULL;
    if (dispatched_count > 0) {
        size_t results_bytes = dispatched_count * sizeof(bc_hash_result_entry_t);
        if (!bc_allocators_pool_allocate(memory_context, results_bytes, (void**)&results)) {
            bc_containers_vector_destroy(memory_context, entries);
            return false;
        }
        bc_core_zero(results, results_bytes);

        size_t effective_worker_count = bc_concurrency_effective_worker_count(concurrency_context);
        bool dispatch_ok;
        if (effective_worker_count >= 2) {
            dispatch_ok = bc_hash_worker_dispatch_all(concurrency_context, algorithm, entries, results, errors, memory_context,
                                                     signal_handler);
        } else {
            dispatch_ok = bc_hash_worker_dispatch_sequential(algorithm, entries, results, errors, memory_context, signal_handler);
        }
        if (!dispatch_ok) {
            bc_allocators_pool_free(memory_context, results);
            bc_containers_vector_destroy(memory_context, entries);
            return false;
        }
    }

    size_t ok_count = 0;
    size_t failed_count = 0;
    char computed_hex_buffer[BC_HASH_MAX_HEX_LENGTH + 1];

    for (size_t index = 0; index < expectation_count; index++) {
        bc_hash_verify_expectation_t expectation;
        if (!bc_containers_vector_get(expectations, index, &expectation)) {
            continue;
        }

        if (expectation.target_missing) {
            fprintf(stdout, "%s: MISSING\n", expectation.target_path);
            continue;
        }

        const bc_hash_result_entry_t* result = &results[expectation.dispatch_index];
        if (!result->success) {
            fprintf(stdout, "%s: FAILED\n", expectation.target_path);
            failed_count += 1;
            continue;
        }

        bc_hash_verify_compute_result_hex(algorithm, result, computed_hex_buffer);
        if (strcmp(computed_hex_buffer, expectation.expected_hex) == 0) {
            fprintf(stdout, "%s: OK\n", expectation.target_path);
            ok_count += 1;
        } else {
            fprintf(stdout, "%s: FAILED\n", expectation.target_path);
            failed_count += 1;
        }
    }

    fflush(stdout);

    fprintf(stderr, "bc-hash: %zu/%zu verified, %zu failed, %zu missing\n", ok_count, expectation_count, failed_count, missing_count);

    if (results != NULL) {
        bc_allocators_pool_free(memory_context, results);
    }
    bc_containers_vector_destroy(memory_context, entries);

    *out_exit_code = (failed_count == 0 && missing_count == 0) ? BC_HASH_VERIFY_EXIT_CODE_OK : BC_HASH_VERIFY_EXIT_CODE_MISMATCH;
    return true;
}
