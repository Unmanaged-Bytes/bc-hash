// SPDX-License-Identifier: MIT

#ifndef BC_HASH_WORKER_INTERNAL_H
#define BC_HASH_WORKER_INTERNAL_H

#include "bc_hash_error_internal.h"
#include "bc_hash_types_internal.h"

#include "bc_allocators_context.h"
#include "bc_concurrency.h"
#include "bc_concurrency_signal.h"
#include "bc_containers_vector.h"

#include <stdbool.h>

bool bc_hash_worker_dispatch_all(bc_concurrency_context_t* concurrency, bc_hash_algorithm_t algorithm,
                                 const bc_containers_vector_t* entries, bc_hash_result_entry_t* results, bc_hash_error_collector_t* errors,
                                 bc_allocators_context_t* main_memory_context, bc_concurrency_signal_handler_t* signal_handler);

bool bc_hash_worker_dispatch_sequential(bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                                        bc_hash_result_entry_t* results, bc_hash_error_collector_t* errors,
                                        bc_allocators_context_t* main_memory_context,
                                        const bc_concurrency_signal_handler_t* signal_handler);

#endif /* BC_HASH_WORKER_INTERNAL_H */
