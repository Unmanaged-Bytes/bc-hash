// SPDX-License-Identifier: MIT

#ifndef BC_HASH_FILTER_INTERNAL_H
#define BC_HASH_FILTER_INTERNAL_H

#include "bc_allocators.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct bc_hash_filter bc_hash_filter_t;

bool bc_hash_filter_create(bc_allocators_context_t* memory_context, const char* include_list, const char* exclude_list,
                           bc_hash_filter_t** out_filter);

void bc_hash_filter_destroy(bc_allocators_context_t* memory_context, bc_hash_filter_t* filter);

bool bc_hash_filter_accepts_file(const bc_hash_filter_t* filter, const char* basename);

bool bc_hash_filter_accepts_directory(const bc_hash_filter_t* filter, const char* basename);

#endif /* BC_HASH_FILTER_INTERNAL_H */
