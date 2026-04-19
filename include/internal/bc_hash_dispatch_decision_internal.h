// SPDX-License-Identifier: MIT

#ifndef BC_HASH_DISPATCH_DECISION_INTERNAL_H
#define BC_HASH_DISPATCH_DECISION_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#include "bc_hash_throughput_internal.h"

bool bc_hash_dispatch_decision_should_go_multithread(size_t file_count, size_t total_bytes,
                                                     const bc_hash_throughput_constants_t* throughput_constants,
                                                     size_t worker_count);

size_t bc_hash_dispatch_decision_optimal_worker_count(double single_thread_gigabytes_per_second,
                                                     double memory_bandwidth_gigabytes_per_second,
                                                     size_t physical_core_count);

#endif /* BC_HASH_DISPATCH_DECISION_INTERNAL_H */
