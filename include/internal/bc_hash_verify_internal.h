// SPDX-License-Identifier: MIT

#ifndef BC_HASH_VERIFY_INTERNAL_H
#define BC_HASH_VERIFY_INTERNAL_H

#include "bc_hash_error_internal.h"
#include "bc_hash_types_internal.h"

#include "bc_allocators.h"
#include "bc_concurrency.h"
#include "bc_concurrency_signal.h"
#include "bc_containers_vector.h"

#include <stdbool.h>
#include <stddef.h>

#define BC_HASH_VERIFY_SENTINEL_DISPATCH_INDEX ((size_t)-1)

typedef struct bc_hash_verify_expectation {
    const char* target_path;
    size_t target_path_length;
    char expected_hex[BC_HASH_MAX_HEX_LENGTH + 1];
    size_t expected_hex_length;
    size_t dispatch_index;
    bool target_missing;
    int stat_errno;
} bc_hash_verify_expectation_t;

typedef enum {
    BC_HASH_VERIFY_PARSE_STATUS_OK,
    BC_HASH_VERIFY_PARSE_STATUS_IO_ERROR,
    BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR,
} bc_hash_verify_parse_status_t;

bc_hash_verify_parse_status_t bc_hash_verify_parse_digest_file(bc_allocators_context_t* memory_context, const char* digest_file_path,
                                                               bc_containers_vector_t* out_expectations, bc_hash_algorithm_t* out_algorithm);

bool bc_hash_verify_run(bc_allocators_context_t* memory_context, bc_concurrency_context_t* concurrency_context,
                        bc_concurrency_signal_handler_t* signal_handler, bc_hash_algorithm_t algorithm,
                        bc_containers_vector_t* expectations, bc_hash_error_collector_t* errors, int* out_exit_code);

#endif /* BC_HASH_VERIFY_INTERNAL_H */
