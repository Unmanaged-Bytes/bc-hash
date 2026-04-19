// SPDX-License-Identifier: MIT

#ifndef BC_HASH_ERROR_INTERNAL_H
#define BC_HASH_ERROR_INTERNAL_H

#include "bc_allocators_context.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct bc_hash_error_collector bc_hash_error_collector_t;

bool bc_hash_error_collector_create(bc_allocators_context_t* memory_context, bc_hash_error_collector_t** out_collector);

void bc_hash_error_collector_destroy(bc_allocators_context_t* memory_context, bc_hash_error_collector_t* collector);

bool bc_hash_error_collector_record(bc_hash_error_collector_t* collector, bc_allocators_context_t* memory_context, const char* path,
                                    const char* stage, int errno_value);

bool bc_hash_error_collector_flush_to_stderr(const bc_hash_error_collector_t* collector);

size_t bc_hash_error_collector_count(const bc_hash_error_collector_t* collector);

#endif /* BC_HASH_ERROR_INTERNAL_H */
