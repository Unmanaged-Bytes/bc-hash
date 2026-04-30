// SPDX-License-Identifier: MIT

#ifndef BC_HASH_CLI_INTERNAL_H
#define BC_HASH_CLI_INTERNAL_H

#include "bc_hash_types_internal.h"

#include "bc_runtime.h"
#include "bc_runtime_cli.h"

#include <stdbool.h>

const bc_runtime_cli_program_spec_t* bc_hash_cli_program_spec(void);

bool bc_hash_cli_bind_options(const bc_runtime_config_store_t* store, const bc_runtime_cli_parsed_t* parsed,
                              bc_hash_cli_options_t* out_options);

bool bc_hash_cli_bind_global_threads(const bc_runtime_config_store_t* store, bc_hash_threads_mode_t* out_mode,
                                     size_t* out_explicit_worker_count);

#endif /* BC_HASH_CLI_INTERNAL_H */
