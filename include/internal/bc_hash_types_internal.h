// SPDX-License-Identifier: MIT

#ifndef BC_HASH_TYPES_INTERNAL_H
#define BC_HASH_TYPES_INTERNAL_H

#include "bc_core_hash.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BC_HASH_CRC32_HEX_LENGTH 8
#define BC_HASH_SHA256_HEX_LENGTH 64
#define BC_HASH_XXH3_DIGEST_SIZE 8
#define BC_HASH_XXH3_HEX_LENGTH 16
#define BC_HASH_XXH128_DIGEST_SIZE 16
#define BC_HASH_XXH128_HEX_LENGTH 32
#define BC_HASH_MAX_HEX_LENGTH BC_HASH_SHA256_HEX_LENGTH

typedef enum {
    BC_HASH_ALGORITHM_CRC32 = 0,
    BC_HASH_ALGORITHM_SHA256 = 1,
    BC_HASH_ALGORITHM_XXH3 = 3,
    BC_HASH_ALGORITHM_XXH128 = 4,
} bc_hash_algorithm_t;

typedef enum {
    BC_HASH_OUTPUT_FORMAT_SIMPLE = 0,
    BC_HASH_OUTPUT_FORMAT_JSON = 1,
    BC_HASH_OUTPUT_FORMAT_HRBL = 2,
} bc_hash_output_format_t;

typedef enum {
    BC_HASH_THREADS_MODE_AUTO = 0,
    BC_HASH_THREADS_MODE_MONO = 1,
    BC_HASH_THREADS_MODE_EXPLICIT = 2,
} bc_hash_threads_mode_t;

typedef enum {
    BC_HASH_OUTPUT_DESTINATION_AUTO = 0,
    BC_HASH_OUTPUT_DESTINATION_STDOUT = 1,
    BC_HASH_OUTPUT_DESTINATION_FILE = 2,
} bc_hash_output_destination_mode_t;

typedef enum {
    BC_HASH_OUTPUT_FORMAT_MODE_AUTO = 0,
    BC_HASH_OUTPUT_FORMAT_MODE_EXPLICIT = 1,
} bc_hash_output_format_mode_t;

typedef struct bc_hash_cli_options {
    bc_hash_algorithm_t algorithm;
    bc_hash_threads_mode_t threads_mode;
    size_t explicit_worker_count;
    bc_hash_output_destination_mode_t output_destination_mode;
    const char* output_destination_path;
    bc_hash_output_format_mode_t output_format_mode;
    bc_hash_output_format_t output_format;
    const char* include_list;
    const char* exclude_list;
    bool help_requested;
    int positional_argument_count;
    const char* const* positional_argument_values;
} bc_hash_cli_options_t;

typedef struct bc_hash_file_entry {
    char* absolute_path;
    size_t absolute_path_length;
    size_t file_size;
} bc_hash_file_entry_t;

typedef struct bc_hash_result_entry {
    bool success;
    int errno_value;
    uint32_t crc32_value;
    uint8_t sha256_digest[BC_CORE_SHA256_DIGEST_SIZE];
    uint8_t xxh3_digest[BC_HASH_XXH3_DIGEST_SIZE];
    uint8_t xxh128_digest[BC_HASH_XXH128_DIGEST_SIZE];
} bc_hash_result_entry_t;

#endif /* BC_HASH_TYPES_INTERNAL_H */
