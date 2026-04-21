// SPDX-License-Identifier: MIT

#include "bc_hash_reader_internal.h"
#include "bc_hash_worker_internal.h"

#include "bc_allocators_pool.h"
#include "bc_concurrency.h"
#include "bc_containers_vector.h"
#include "bc_core.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define XXH_INLINE_ALL
#include <xxhash.h>

#define BC_HASH_DISPATCH_BATCH_SIZE ((size_t)BC_HASH_READER_RING_SLOT_COUNT)

typedef struct bc_hash_dispatch_context {
    const bc_containers_vector_t* entries;
    bc_hash_result_entry_t* results;
    const size_t* processing_order;
    size_t entry_count;
    size_t batch_count;
    size_t ring_slot_index;
    bc_hash_algorithm_t algorithm;
    bc_concurrency_signal_handler_t* signal_handler;
} bc_hash_dispatch_context_t;

static bool bc_hash_dispatch_should_stop(const bc_concurrency_signal_handler_t* signal_handler)
{
    if (signal_handler == NULL) {
        return false;
    }
    bool should_stop = false;
    bc_concurrency_signal_handler_should_stop(signal_handler, &should_stop);
    return should_stop;
}

typedef struct bc_hash_sort_descriptor {
    size_t entry_index;
    size_t file_size;
} bc_hash_sort_descriptor_t;

typedef struct bc_hash_crc32_state {
    uint32_t running_crc;
    bool first_chunk;
} bc_hash_crc32_state_t;

typedef struct bc_hash_sha256_state {
    bc_core_sha256_context_t digest_context;
} bc_hash_sha256_state_t;

typedef struct bc_hash_xxh3_state {
    XXH3_state_t digest_context;
} bc_hash_xxh3_state_t;

typedef struct bc_hash_consumer_state {
    union {
        bc_hash_crc32_state_t crc32;
        bc_hash_sha256_state_t sha256;
        bc_hash_xxh3_state_t xxh3;
    } algo;
} bc_hash_consumer_state_t;

static int bc_hash_dispatch_compare_size_descending(const void* left_element, const void* right_element)
{
    const bc_hash_sort_descriptor_t* left = (const bc_hash_sort_descriptor_t*)left_element;
    const bc_hash_sort_descriptor_t* right = (const bc_hash_sort_descriptor_t*)right_element;
    if (left->file_size < right->file_size) {
        return 1;
    }
    if (left->file_size > right->file_size) {
        return -1;
    }
    return 0;
}

static bool bc_hash_dispatch_consumer_crc32(void* consumer_context, const void* chunk_data, size_t chunk_size)
{
    bc_hash_consumer_state_t* state = (bc_hash_consumer_state_t*)consumer_context;
    uint32_t chunk_crc = 0;
    if (state->algo.crc32.first_chunk) {
        if (!bc_core_crc32c(chunk_data, chunk_size, &chunk_crc)) {
            return false;
        }
        state->algo.crc32.first_chunk = false;
    } else {
        if (!bc_core_crc32c_update(state->algo.crc32.running_crc, chunk_data, chunk_size, &chunk_crc)) {
            return false;
        }
    }
    state->algo.crc32.running_crc = chunk_crc;
    return true;
}

static bool bc_hash_dispatch_consumer_sha256(void* consumer_context, const void* chunk_data, size_t chunk_size)
{
    bc_hash_consumer_state_t* state = (bc_hash_consumer_state_t*)consumer_context;
    return bc_core_sha256_update(&state->algo.sha256.digest_context, chunk_data, chunk_size);
}

static bool bc_hash_dispatch_consumer_xxh3(void* consumer_context, const void* chunk_data, size_t chunk_size)
{
    bc_hash_consumer_state_t* state = (bc_hash_consumer_state_t*)consumer_context;
    return XXH3_64bits_update(&state->algo.xxh3.digest_context, chunk_data, chunk_size) == XXH_OK;
}

static bool bc_hash_dispatch_consumer_xxh128(void* consumer_context, const void* chunk_data, size_t chunk_size)
{
    bc_hash_consumer_state_t* state = (bc_hash_consumer_state_t*)consumer_context;
    return XXH3_128bits_update(&state->algo.xxh3.digest_context, chunk_data, chunk_size) == XXH_OK;
}

static bc_hash_reader_consumer_fn_t bc_hash_dispatch_consumer_function_for(bc_hash_algorithm_t algorithm)
{
    switch (algorithm) {
        case BC_HASH_ALGORITHM_CRC32:
            return bc_hash_dispatch_consumer_crc32;
        case BC_HASH_ALGORITHM_XXH3:
            return bc_hash_dispatch_consumer_xxh3;
        case BC_HASH_ALGORITHM_XXH128:
            return bc_hash_dispatch_consumer_xxh128;
        case BC_HASH_ALGORITHM_SHA256:
        default:
            return bc_hash_dispatch_consumer_sha256;
    }
}

static void bc_hash_dispatch_consumer_begin(bc_hash_algorithm_t algorithm, bc_hash_consumer_state_t* state)
{
    switch (algorithm) {
        case BC_HASH_ALGORITHM_CRC32:
            state->algo.crc32.running_crc = 0;
            state->algo.crc32.first_chunk = true;
            return;
        case BC_HASH_ALGORITHM_XXH3:
            XXH3_64bits_reset(&state->algo.xxh3.digest_context);
            return;
        case BC_HASH_ALGORITHM_XXH128:
            XXH3_128bits_reset(&state->algo.xxh3.digest_context);
            return;
        case BC_HASH_ALGORITHM_SHA256:
        default:
            bc_core_sha256_init(&state->algo.sha256.digest_context);
            return;
    }
}

static bool bc_hash_dispatch_consumer_finalize(bc_hash_algorithm_t algorithm, bc_hash_consumer_state_t* state,
                                               bc_hash_result_entry_t* result)
{
    switch (algorithm) {
        case BC_HASH_ALGORITHM_CRC32:
            result->crc32_value = state->algo.crc32.running_crc;
            return true;
        case BC_HASH_ALGORITHM_XXH3: {
            XXH64_hash_t xxh3_hash = XXH3_64bits_digest(&state->algo.xxh3.digest_context);
            XXH64_canonicalFromHash((XXH64_canonical_t*)result->xxh3_digest, xxh3_hash);
            return true;
        }
        case BC_HASH_ALGORITHM_XXH128: {
            XXH128_hash_t xxh128_hash = XXH3_128bits_digest(&state->algo.xxh3.digest_context);
            XXH128_canonicalFromHash((XXH128_canonical_t*)result->xxh128_digest, xxh128_hash);
            return true;
        }
        case BC_HASH_ALGORITHM_SHA256:
        default:
            return bc_core_sha256_finalize(&state->algo.sha256.digest_context, result->sha256_digest);
    }
}

static void bc_hash_dispatch_batch_iteration(size_t iteration_index, void* argument)
{
    bc_hash_dispatch_context_t* context = (bc_hash_dispatch_context_t*)argument;
    if (bc_hash_dispatch_should_stop(context->signal_handler)) {
        return;
    }
    size_t batch_start = iteration_index * BC_HASH_DISPATCH_BATCH_SIZE;
    size_t remaining = context->entry_count - batch_start;
    size_t batch_size = remaining < BC_HASH_DISPATCH_BATCH_SIZE ? remaining : BC_HASH_DISPATCH_BATCH_SIZE;

    bc_hash_reader_batch_item_t batch_items[BC_HASH_DISPATCH_BATCH_SIZE];
    bc_hash_consumer_state_t consumer_states[BC_HASH_DISPATCH_BATCH_SIZE];
    size_t entry_indices[BC_HASH_DISPATCH_BATCH_SIZE];

    size_t prepared_count = 0;
    for (size_t offset = 0; offset < batch_size; ++offset) {
        size_t entry_index = context->processing_order[batch_start + offset];
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(context->entries, entry_index, &entry)) {
            context->results[entry_index].success = false;
            context->results[entry_index].errno_value = 0;
            continue;
        }
        bc_hash_dispatch_consumer_begin(context->algorithm, &consumer_states[prepared_count]);
        batch_items[prepared_count].absolute_path = entry.absolute_path;
        batch_items[prepared_count].file_size = entry.file_size;
        batch_items[prepared_count].consumer_context = &consumer_states[prepared_count];
        batch_items[prepared_count].success = false;
        batch_items[prepared_count].errno_value = 0;
        entry_indices[prepared_count] = entry_index;
        prepared_count += 1;
    }

    if (prepared_count == 0) {
        return;
    }

    bc_hash_reader_ring_t* ring = (bc_hash_reader_ring_t*)bc_concurrency_worker_slot(context->ring_slot_index);
    bc_hash_reader_consumer_fn_t consumer_function = bc_hash_dispatch_consumer_function_for(context->algorithm);

    bc_hash_reader_consume_batch(ring, batch_items, prepared_count, consumer_function);

    for (size_t index = 0; index < prepared_count; ++index) {
        size_t entry_index = entry_indices[index];
        bc_hash_result_entry_t* result = &context->results[entry_index];
        if (!batch_items[index].success) {
            result->success = false;
            result->errno_value = batch_items[index].errno_value;
            continue;
        }
        if (!bc_hash_dispatch_consumer_finalize(context->algorithm, &consumer_states[index], result)) {
            result->success = false;
            result->errno_value = EIO;
            continue;
        }
        result->success = true;
        result->errno_value = 0;
    }
}

static bool bc_hash_dispatch_build_processing_order(bc_allocators_context_t* main_memory_context, const bc_containers_vector_t* entries,
                                                    size_t worker_count, size_t** out_processing_order)
{
    size_t entry_count = bc_containers_vector_length(entries);
    size_t descriptors_bytes = entry_count * sizeof(bc_hash_sort_descriptor_t);
    size_t order_bytes = entry_count * sizeof(size_t);

    bc_hash_sort_descriptor_t* descriptors = NULL;
    if (!bc_allocators_pool_allocate(main_memory_context, descriptors_bytes, (void**)&descriptors)) {
        return false;
    }

    for (size_t index = 0; index < entry_count; ++index) {
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(entries, index, &entry)) {
            bc_allocators_pool_free(main_memory_context, descriptors);
            return false;
        }
        descriptors[index].entry_index = index;
        descriptors[index].file_size = entry.file_size;
    }

    qsort(descriptors, entry_count, sizeof(bc_hash_sort_descriptor_t), bc_hash_dispatch_compare_size_descending);

    size_t* processing_order = NULL;
    if (!bc_allocators_pool_allocate(main_memory_context, order_bytes, (void**)&processing_order)) {
        bc_allocators_pool_free(main_memory_context, descriptors);
        return false;
    }

    size_t bucket_count = worker_count > 0 ? worker_count : 1;
    size_t write_position = 0;
    for (size_t bucket_index = 0; bucket_index < bucket_count; ++bucket_index) {
        for (size_t descriptor_index = bucket_index; descriptor_index < entry_count; descriptor_index += bucket_count) {
            processing_order[write_position] = descriptors[descriptor_index].entry_index;
            write_position += 1;
        }
    }

    bc_allocators_pool_free(main_memory_context, descriptors);
    *out_processing_order = processing_order;
    return true;
}

static void bc_hash_dispatch_ring_init(void* data, size_t worker_index, void* arg)
{
    (void)worker_index;
    (void)arg;
    bc_hash_reader_ring_init((bc_hash_reader_ring_t*)data);
}

static void bc_hash_dispatch_ring_destroy(void* data, size_t worker_index, void* arg)
{
    (void)worker_index;
    (void)arg;
    bc_hash_reader_ring_destroy((bc_hash_reader_ring_t*)data);
}

bool bc_hash_worker_dispatch_all(bc_concurrency_context_t* concurrency, bc_hash_algorithm_t algorithm,
                                 const bc_containers_vector_t* entries, bc_hash_result_entry_t* results, bc_runtime_error_collector_t* errors,
                                 bc_allocators_context_t* main_memory_context, bc_concurrency_signal_handler_t* signal_handler)
{
    size_t entry_count = bc_containers_vector_length(entries);
    if (entry_count == 0) {
        return true;
    }

    size_t worker_count = bc_concurrency_effective_worker_count(concurrency);
    size_t* processing_order = NULL;
    if (!bc_hash_dispatch_build_processing_order(main_memory_context, entries, worker_count, &processing_order)) {
        return false;
    }

    bc_concurrency_slot_config_t slot_config = {
        .size = bc_hash_reader_ring_struct_size(),
        .init = bc_hash_dispatch_ring_init,
        .destroy = bc_hash_dispatch_ring_destroy,
        .arg = NULL,
    };
    size_t ring_slot_index = 0;
    if (!bc_concurrency_register_slot(concurrency, &slot_config, &ring_slot_index)) {
        bc_allocators_pool_free(main_memory_context, processing_order);
        return false;
    }

    size_t batch_count = (entry_count + BC_HASH_DISPATCH_BATCH_SIZE - 1) / BC_HASH_DISPATCH_BATCH_SIZE;

    bc_hash_dispatch_context_t context = {
        .entries = entries,
        .results = results,
        .processing_order = processing_order,
        .entry_count = entry_count,
        .batch_count = batch_count,
        .ring_slot_index = ring_slot_index,
        .algorithm = algorithm,
        .signal_handler = signal_handler,
    };

    bool dispatch_ok = bc_concurrency_for(concurrency, 0, batch_count, 1, bc_hash_dispatch_batch_iteration, &context);

    bc_allocators_pool_free(main_memory_context, processing_order);

    if (!dispatch_ok) {
        return false;
    }

    for (size_t index = 0; index < entry_count; ++index) {
        if (results[index].success) {
            continue;
        }
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(entries, index, &entry)) {
            continue;
        }
        bc_runtime_error_collector_append(errors, main_memory_context, entry.absolute_path, "hash", results[index].errno_value);
    }

    return true;
}

bool bc_hash_worker_dispatch_sequential(bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                                        bc_hash_result_entry_t* results, bc_runtime_error_collector_t* errors,
                                        bc_allocators_context_t* main_memory_context,
                                        const bc_concurrency_signal_handler_t* signal_handler)
{
    size_t entry_count = bc_containers_vector_length(entries);
    if (entry_count == 0) {
        return true;
    }

    bc_hash_reader_consumer_fn_t consumer_function = bc_hash_dispatch_consumer_function_for(algorithm);

    for (size_t entry_index = 0; entry_index < entry_count; ++entry_index) {
        if (bc_hash_dispatch_should_stop(signal_handler)) {
            break;
        }
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(entries, entry_index, &entry)) {
            results[entry_index].success = false;
            results[entry_index].errno_value = 0;
            continue;
        }

        bc_hash_consumer_state_t consumer_state;
        bc_hash_dispatch_consumer_begin(algorithm, &consumer_state);

        int consume_errno = 0;
        if (!bc_hash_reader_consume_file(entry.absolute_path, entry.file_size, &consumer_state, consumer_function, &consume_errno)) {
            results[entry_index].success = false;
            results[entry_index].errno_value = consume_errno;
            continue;
        }

        if (!bc_hash_dispatch_consumer_finalize(algorithm, &consumer_state, &results[entry_index])) {
            results[entry_index].success = false;
            results[entry_index].errno_value = EIO;
            continue;
        }
        results[entry_index].success = true;
        results[entry_index].errno_value = 0;
    }

    for (size_t entry_index = 0; entry_index < entry_count; ++entry_index) {
        if (results[entry_index].success) {
            continue;
        }
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(entries, entry_index, &entry)) {
            continue;
        }
        bc_runtime_error_collector_append(errors, main_memory_context, entry.absolute_path, "hash", results[entry_index].errno_value);
    }

    return true;
}
