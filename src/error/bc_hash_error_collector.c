// SPDX-License-Identifier: MIT

#include "bc_hash_error_internal.h"

#include "bc_allocators_pool.h"
#include "bc_containers_vector.h"
#include "bc_core.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BC_HASH_ERROR_INITIAL_CAPACITY 16
#define BC_HASH_ERROR_MAX_CAPACITY 65536

typedef struct bc_hash_error_record {
    char* path;
    const char* stage;
    int errno_value;
} bc_hash_error_record_t;

struct bc_hash_error_collector {
    bc_containers_vector_t* records;
};

bool bc_hash_error_collector_create(bc_allocators_context_t* memory_context, bc_hash_error_collector_t** out_collector)
{
    bc_hash_error_collector_t* collector = NULL;
    if (!bc_allocators_pool_allocate(memory_context, sizeof(bc_hash_error_collector_t), (void**)&collector)) {
        return false;
    }
    bc_core_zero(collector, sizeof(*collector));

    if (!bc_containers_vector_create(memory_context, sizeof(bc_hash_error_record_t), BC_HASH_ERROR_INITIAL_CAPACITY,
                                     BC_HASH_ERROR_MAX_CAPACITY, &collector->records)) {
        bc_allocators_pool_free(memory_context, collector);
        return false;
    }

    *out_collector = collector;
    return true;
}

void bc_hash_error_collector_destroy(bc_allocators_context_t* memory_context, bc_hash_error_collector_t* collector)
{
    size_t record_count = bc_containers_vector_length(collector->records);
    for (size_t index = 0; index < record_count; ++index) {
        bc_hash_error_record_t record;
        if (bc_containers_vector_get(collector->records, index, &record)) {
            bc_allocators_pool_free(memory_context, record.path);
        }
    }
    bc_containers_vector_destroy(memory_context, collector->records);
    bc_allocators_pool_free(memory_context, collector);
}

bool bc_hash_error_collector_record(bc_hash_error_collector_t* collector, bc_allocators_context_t* memory_context, const char* path,
                                    const char* stage, int errno_value)
{
    size_t path_length = strlen(path);
    char* path_copy = NULL;
    if (!bc_allocators_pool_allocate(memory_context, path_length + 1, (void**)&path_copy)) {
        return false;
    }
    bc_core_copy(path_copy, path, path_length);
    path_copy[path_length] = '\0';

    bc_hash_error_record_t record = {
        .path = path_copy,
        .stage = stage,
        .errno_value = errno_value,
    };

    if (!bc_containers_vector_push(memory_context, collector->records, &record)) {
        bc_allocators_pool_free(memory_context, path_copy);
        return false;
    }
    return true;
}

bool bc_hash_error_collector_flush_to_stderr(const bc_hash_error_collector_t* collector)
{
    size_t record_count = bc_containers_vector_length(collector->records);
    for (size_t index = 0; index < record_count; ++index) {
        bc_hash_error_record_t record;
        if (!bc_containers_vector_get(collector->records, index, &record)) {
            return false;
        }
        const char* reason = record.errno_value != 0 ? strerror(record.errno_value) : "error";
        fprintf(stderr, "bc-hash: %s: %s: %s\n", record.stage, record.path, reason);
    }
    return true;
}

size_t bc_hash_error_collector_count(const bc_hash_error_collector_t* collector)
{
    return bc_containers_vector_length(collector->records);
}
