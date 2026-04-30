// SPDX-License-Identifier: MIT

#ifndef BC_HASH_DISCOVERY_INTERNAL_H
#define BC_HASH_DISCOVERY_INTERNAL_H

#include "bc_runtime_error_collector.h"
#include "bc_hash_filter_internal.h"
#include "bc_hash_types_internal.h"

#include "bc_allocators_context.h"
#include "bc_concurrency.h"
#include "bc_runtime_signal.h"
#include "bc_containers_vector.h"

#include <stdbool.h>
#include <stddef.h>

bool bc_hash_discovery_glob_contains_metacharacter(const char* pattern, bool* out_contains);

bool bc_hash_discovery_expand(bc_allocators_context_t* memory_context, bc_containers_vector_t* entries,
                              bc_runtime_error_collector_t* errors, bc_runtime_signal_handler_t* signal_handler,
                              const bc_hash_filter_t* filter, const char* const* input_paths, size_t input_count);

bool bc_hash_discovery_expand_parallel(bc_allocators_context_t* memory_context, bc_concurrency_context_t* concurrency_context,
                                       bc_containers_vector_t* entries, bc_runtime_error_collector_t* errors,
                                       bc_runtime_signal_handler_t* signal_handler, const bc_hash_filter_t* filter,
                                       const char* const* input_paths, size_t input_count);

#endif /* BC_HASH_DISCOVERY_INTERNAL_H */
