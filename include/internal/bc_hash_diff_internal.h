// SPDX-License-Identifier: MIT

#ifndef BC_HASH_DIFF_INTERNAL_H
#define BC_HASH_DIFF_INTERNAL_H

#include "bc_allocators.h"

#include <stdbool.h>

bool bc_hash_diff_run(bc_allocators_context_t* memory_context, const char* digest_path_a, const char* digest_path_b, int* out_exit_code);

#endif /* BC_HASH_DIFF_INTERNAL_H */
