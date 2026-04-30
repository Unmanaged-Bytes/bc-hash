// SPDX-License-Identifier: MIT

#ifndef BC_HASH_THROUGHPUT_INTERNAL_H
#define BC_HASH_THROUGHPUT_INTERNAL_H

#include "bc_allocators_context.h"
#include "bc_concurrency.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct bc_hash_throughput_constants {
    double sha256_gigabytes_per_second;
    double crc32c_gigabytes_per_second;
    double memory_bandwidth_gigabytes_per_second;
    double parallel_startup_overhead_microseconds;
    double per_file_cost_warm_microseconds;
} bc_hash_throughput_constants_t;

bool bc_hash_throughput_measure(bc_concurrency_context_t* concurrency_context, bc_hash_throughput_constants_t* out_constants);

bool bc_hash_throughput_cache_read_host_signature(char* out_cpu_model, size_t cpu_model_capacity, char* out_microcode,
                                                  size_t microcode_capacity, char* out_kernel_version, size_t kernel_version_capacity);

bool bc_hash_throughput_cache_load(const char* absolute_cache_path, bc_hash_throughput_constants_t* out_constants);

bool bc_hash_throughput_cache_store(const char* absolute_cache_path, const bc_hash_throughput_constants_t* constants);

bool bc_hash_throughput_get_or_measure(bc_concurrency_context_t* concurrency_context, bc_hash_throughput_constants_t* out_constants);

#endif /* BC_HASH_THROUGHPUT_INTERNAL_H */
