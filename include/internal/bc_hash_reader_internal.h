// SPDX-License-Identifier: MIT

#ifndef BC_HASH_READER_INTERNAL_H
#define BC_HASH_READER_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

typedef bool (*bc_hash_reader_consumer_fn_t)(void* consumer_context, const void* chunk_data, size_t chunk_size);

bool bc_hash_reader_consume_file(const char* absolute_path, size_t file_size_hint, void* consumer_context,
                                 bc_hash_reader_consumer_fn_t consumer_function, int* out_errno_value);

typedef struct bc_hash_reader_batch_item {
    const char* absolute_path;
    size_t file_size;
    void* consumer_context;
    bool success;
    int errno_value;
} bc_hash_reader_batch_item_t;

typedef struct bc_hash_reader_ring bc_hash_reader_ring_t;

#define BC_HASH_READER_RING_SLOT_COUNT 32
#define BC_HASH_READER_RING_SLOT_BUFFER_BYTES ((size_t)(128 * 1024))

bool bc_hash_reader_ring_init(bc_hash_reader_ring_t* ring);
void bc_hash_reader_ring_destroy(bc_hash_reader_ring_t* ring);
size_t bc_hash_reader_ring_struct_size(void);

bool bc_hash_reader_consume_batch(bc_hash_reader_ring_t* ring, bc_hash_reader_batch_item_t* items, size_t item_count,
                                  bc_hash_reader_consumer_fn_t consumer_function);

#endif /* BC_HASH_READER_INTERNAL_H */
