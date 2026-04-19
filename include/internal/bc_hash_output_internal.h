// SPDX-License-Identifier: MIT

#ifndef BC_HASH_OUTPUT_INTERNAL_H
#define BC_HASH_OUTPUT_INTERNAL_H

#include "bc_hash_types_internal.h"

#include "bc_containers_vector.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct bc_hash_output_context {
    uint64_t started_at_unix_ms;
    uint64_t wall_ms;
    size_t worker_count;
    const char* dispatch_mode;
    const char* tool_version;
} bc_hash_output_context_t;

bool bc_hash_output_write(FILE* output_stream, bc_hash_output_format_t format, bc_hash_algorithm_t algorithm,
                          const bc_containers_vector_t* entries, const bc_hash_result_entry_t* results,
                          const bc_hash_output_context_t* context);

bool bc_hash_output_encode_hex(const uint8_t* digest, size_t digest_length, char* out_buffer);

#endif /* BC_HASH_OUTPUT_INTERNAL_H */
