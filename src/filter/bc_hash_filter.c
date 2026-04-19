// SPDX-License-Identifier: MIT

#include "bc_hash_filter_internal.h"

#include "bc_allocators_pool.h"
#include "bc_core.h"

#include <fnmatch.h>
#include <stddef.h>
#include <string.h>

struct bc_hash_filter {
    char** include_patterns;
    size_t include_count;
    char** exclude_patterns;
    size_t exclude_count;
    char* include_buffer;
    char* exclude_buffer;
};

static bool bc_hash_filter_count_and_split(bc_allocators_context_t* memory_context, const char* list, char** out_buffer, char*** out_patterns,
                                           size_t* out_count)
{
    if (list == NULL || list[0] == '\0') {
        *out_buffer = NULL;
        *out_patterns = NULL;
        *out_count = 0;
        return true;
    }

    size_t list_length = strlen(list);
    char* buffer = NULL;
    if (!bc_allocators_pool_allocate(memory_context, list_length + 1, (void**)&buffer)) {
        return false;
    }
    bc_core_copy(buffer, list, list_length);
    buffer[list_length] = '\0';

    size_t count = 1;
    for (size_t index = 0; index < list_length; index++) {
        if (buffer[index] == '\n') {
            count++;
        }
    }

    char** patterns = NULL;
    if (!bc_allocators_pool_allocate(memory_context, count * sizeof(char*), (void**)&patterns)) {
        bc_allocators_pool_free(memory_context, buffer);
        return false;
    }

    size_t write_index = 0;
    patterns[write_index++] = buffer;
    for (size_t index = 0; index < list_length; index++) {
        if (buffer[index] == '\n') {
            buffer[index] = '\0';
            if (write_index < count) {
                patterns[write_index++] = buffer + index + 1;
            }
        }
    }

    *out_buffer = buffer;
    *out_patterns = patterns;
    *out_count = count;
    return true;
}

bool bc_hash_filter_create(bc_allocators_context_t* memory_context, const char* include_list, const char* exclude_list,
                           bc_hash_filter_t** out_filter)
{
    bc_hash_filter_t* filter = NULL;
    if (!bc_allocators_pool_allocate(memory_context, sizeof(bc_hash_filter_t), (void**)&filter)) {
        return false;
    }
    bc_core_zero(filter, sizeof(*filter));

    if (!bc_hash_filter_count_and_split(memory_context, include_list, &filter->include_buffer, &filter->include_patterns,
                                        &filter->include_count)) {
        bc_allocators_pool_free(memory_context, filter);
        return false;
    }

    if (!bc_hash_filter_count_and_split(memory_context, exclude_list, &filter->exclude_buffer, &filter->exclude_patterns,
                                        &filter->exclude_count)) {
        if (filter->include_patterns != NULL) {
            bc_allocators_pool_free(memory_context, filter->include_patterns);
        }
        if (filter->include_buffer != NULL) {
            bc_allocators_pool_free(memory_context, filter->include_buffer);
        }
        bc_allocators_pool_free(memory_context, filter);
        return false;
    }

    *out_filter = filter;
    return true;
}

void bc_hash_filter_destroy(bc_allocators_context_t* memory_context, bc_hash_filter_t* filter)
{
    if (filter->exclude_patterns != NULL) {
        bc_allocators_pool_free(memory_context, filter->exclude_patterns);
    }
    if (filter->exclude_buffer != NULL) {
        bc_allocators_pool_free(memory_context, filter->exclude_buffer);
    }
    if (filter->include_patterns != NULL) {
        bc_allocators_pool_free(memory_context, filter->include_patterns);
    }
    if (filter->include_buffer != NULL) {
        bc_allocators_pool_free(memory_context, filter->include_buffer);
    }
    bc_allocators_pool_free(memory_context, filter);
}

static bool bc_hash_filter_basename_matches_any(char** patterns, size_t count, const char* basename)
{
    for (size_t index = 0; index < count; index++) {
        if (fnmatch(patterns[index], basename, 0) == 0) {
            return true;
        }
    }
    return false;
}

bool bc_hash_filter_accepts_file(const bc_hash_filter_t* filter, const char* basename)
{
    if (filter == NULL) {
        return true;
    }
    if (filter->exclude_count > 0 && bc_hash_filter_basename_matches_any(filter->exclude_patterns, filter->exclude_count, basename)) {
        return false;
    }
    if (filter->include_count > 0 && !bc_hash_filter_basename_matches_any(filter->include_patterns, filter->include_count, basename)) {
        return false;
    }
    return true;
}

bool bc_hash_filter_accepts_directory(const bc_hash_filter_t* filter, const char* basename)
{
    if (filter == NULL) {
        return true;
    }
    if (filter->exclude_count > 0 && bc_hash_filter_basename_matches_any(filter->exclude_patterns, filter->exclude_count, basename)) {
        return false;
    }
    return true;
}
