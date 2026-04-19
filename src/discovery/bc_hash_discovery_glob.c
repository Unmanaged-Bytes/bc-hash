// SPDX-License-Identifier: MIT

#include "bc_hash_discovery_internal.h"

#include <stdbool.h>
#include <stddef.h>

bool bc_hash_discovery_glob_contains_metacharacter(const char* pattern, bool* out_contains)
{
    bool escaped = false;
    for (const char* cursor = pattern; *cursor != '\0'; ++cursor) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (*cursor == '\\') {
            escaped = true;
            continue;
        }
        if (*cursor == '*' || *cursor == '?' || *cursor == '[') {
            *out_contains = true;
            return true;
        }
    }
    *out_contains = false;
    return true;
}
