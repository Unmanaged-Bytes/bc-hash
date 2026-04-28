// SPDX-License-Identifier: MIT

#ifndef BC_HASH_STRINGS_INTERNAL_H
#define BC_HASH_STRINGS_INTERNAL_H

#include "bc_core.h"

#include <stdbool.h>
#include <stddef.h>

static inline size_t bc_hash_strings_length(const char* null_terminated_string)
{
    size_t length = 0;
    (void)bc_core_length(null_terminated_string, '\0', &length);
    return length;
}

static inline bool bc_hash_strings_equal(const char* left, const char* right)
{
    size_t left_length = bc_hash_strings_length(left);
    size_t right_length = bc_hash_strings_length(right);
    if (left_length != right_length) {
        return false;
    }
    bool result = false;
    (void)bc_core_equal(left, right, left_length, &result);
    return result;
}

static inline char* bc_hash_strings_find_last_byte(char* data, size_t data_length, char target)
{
    size_t offset = 0;
    if (!bc_core_find_last_byte(data, data_length, (unsigned char)target, &offset)) {
        return NULL;
    }
    return data + offset;
}

#endif /* BC_HASH_STRINGS_INTERNAL_H */
