// SPDX-License-Identifier: MIT

#include "bc_hash_output_internal.h"

#include "bc_allocators.h"
#include "bc_core.h"
#include "bc_hrbl.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define BC_HASH_OUTPUT_HRBL_SCHEMA_VERSION UINT64_C(1)
#define BC_HASH_OUTPUT_HRBL_TOOL_NAME "bc-hash"

#ifndef BC_HASH_VERSION_STRING
#define BC_HASH_VERSION_STRING "0.0.0-unversioned"
#endif

static const char* bc_hash_output_hrbl_algorithm_name(bc_hash_algorithm_t algorithm)
{
    switch (algorithm) {
        case BC_HASH_ALGORITHM_CRC32:
            return "crc32";
        case BC_HASH_ALGORITHM_XXH3:
            return "xxh3";
        case BC_HASH_ALGORITHM_XXH128:
            return "xxh128";
        case BC_HASH_ALGORITHM_SHA256:
        default:
            return "sha256";
    }
}

static size_t bc_hash_output_hrbl_cstr_length(const char* value)
{
    size_t length = 0;
    (void)bc_core_length(value, 0u, &length);
    return length;
}

static bool bc_hash_output_hrbl_set_string(bc_hrbl_writer_t* writer, const char* key, const char* value)
{
    size_t key_length = bc_hash_output_hrbl_cstr_length(key);
    size_t value_length = bc_hash_output_hrbl_cstr_length(value);
    return bc_hrbl_writer_set_string(writer, key, key_length, value, value_length);
}

static bool bc_hash_output_hrbl_set_uint64(bc_hrbl_writer_t* writer, const char* key, uint64_t value)
{
    size_t key_length = bc_hash_output_hrbl_cstr_length(key);
    return bc_hrbl_writer_set_uint64(writer, key, key_length, value);
}

static bool bc_hash_output_hrbl_set_bool(bc_hrbl_writer_t* writer, const char* key, bool value)
{
    size_t key_length = bc_hash_output_hrbl_cstr_length(key);
    return bc_hrbl_writer_set_bool(writer, key, key_length, value);
}

static bool bc_hash_output_hrbl_set_int64(bc_hrbl_writer_t* writer, const char* key, int64_t value)
{
    size_t key_length = bc_hash_output_hrbl_cstr_length(key);
    return bc_hrbl_writer_set_int64(writer, key, key_length, value);
}

static void bc_hash_output_hrbl_digest_hex(bc_hash_algorithm_t algorithm,
                                           const bc_hash_result_entry_t* result,
                                           char* out_buffer,
                                           size_t* out_length)
{
    switch (algorithm) {
        case BC_HASH_ALGORITHM_CRC32: {
            static const char hex_alphabet[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
            uint32_t crc32_value = result->crc32_value;
            for (size_t index = 0; index < BC_HASH_CRC32_HEX_LENGTH; ++index) {
                size_t shift_bits = 28u - (index * 4u);
                uint32_t nibble = (crc32_value >> shift_bits) & 0xFu;
                out_buffer[index] = hex_alphabet[nibble];
            }
            out_buffer[BC_HASH_CRC32_HEX_LENGTH] = '\0';
            *out_length = BC_HASH_CRC32_HEX_LENGTH;
            return;
        }
        case BC_HASH_ALGORITHM_XXH3:
            bc_hash_output_encode_hex(result->xxh3_digest, BC_HASH_XXH3_DIGEST_SIZE, out_buffer);
            *out_length = BC_HASH_XXH3_HEX_LENGTH;
            return;
        case BC_HASH_ALGORITHM_XXH128:
            bc_hash_output_encode_hex(result->xxh128_digest, BC_HASH_XXH128_DIGEST_SIZE, out_buffer);
            *out_length = BC_HASH_XXH128_HEX_LENGTH;
            return;
        case BC_HASH_ALGORITHM_SHA256:
        default:
            bc_hash_output_encode_hex(result->sha256_digest, BC_CORE_SHA256_DIGEST_SIZE, out_buffer);
            *out_length = BC_HASH_SHA256_HEX_LENGTH;
            return;
    }
}

static bool bc_hash_output_hrbl_write_file_block(bc_hrbl_writer_t* writer,
                                                 bc_hash_algorithm_t algorithm,
                                                 const bc_hash_file_entry_t* entry,
                                                 const bc_hash_result_entry_t* result)
{
    if (!bc_hrbl_writer_begin_block(writer, entry->absolute_path, entry->absolute_path_length)) {
        return false;
    }
    if (result->success) {
        if (!bc_hash_output_hrbl_set_bool(writer, "ok", true)) {
            return false;
        }
        char digest_buffer[BC_HASH_MAX_HEX_LENGTH + 1];
        size_t digest_length = 0;
        bc_hash_output_hrbl_digest_hex(algorithm, result, digest_buffer, &digest_length);
        size_t digest_key_length = bc_hash_output_hrbl_cstr_length("digest_hex");
        if (!bc_hrbl_writer_set_string(writer, "digest_hex", digest_key_length, digest_buffer, digest_length)) {
            return false;
        }
        if (!bc_hash_output_hrbl_set_uint64(writer, "size_bytes", (uint64_t)entry->file_size)) {
            return false;
        }
    } else {
        if (!bc_hash_output_hrbl_set_bool(writer, "ok", false)) {
            return false;
        }
        if (!bc_hash_output_hrbl_set_int64(writer, "errno", (int64_t)result->errno_value)) {
            return false;
        }
        char message_buffer[128];
        const char* message_pointer = strerror_r(result->errno_value, message_buffer, sizeof(message_buffer));
        const char* message_string = message_pointer != NULL ? message_pointer : "unknown error";
        if (!bc_hash_output_hrbl_set_string(writer, "error_message", message_string)) {
            return false;
        }
    }
    return bc_hrbl_writer_end_block(writer);
}

bool bc_hash_output_write_hrbl(bc_core_writer_t* output_writer, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                               const bc_hash_result_entry_t* results, const bc_hash_output_context_t* context);

bool bc_hash_output_write_hrbl(bc_core_writer_t* output_writer, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                               const bc_hash_result_entry_t* results, const bc_hash_output_context_t* context)
{
    bc_allocators_context_config_t allocator_config;
    bc_core_zero(&allocator_config, sizeof(allocator_config));
    bc_allocators_context_t* memory_context = NULL;
    if (!bc_allocators_context_create(&allocator_config, &memory_context)) {
        fputs("bc-hash: hrbl output: allocator init failed\n", stderr);
        return false;
    }

    bc_hrbl_writer_t* writer = NULL;
    if (!bc_hrbl_writer_create(memory_context, &writer)) {
        fputs("bc-hash: hrbl output: writer create failed\n", stderr);
        bc_allocators_context_destroy(memory_context);
        return false;
    }

    bool success = false;
    void* buffer = NULL;
    size_t buffer_size = 0;

    size_t entry_count = bc_containers_vector_length(entries);
    size_t files_ok = 0;
    size_t files_error = 0;
    uint64_t bytes_total = 0;
    for (size_t index = 0; index < entry_count; ++index) {
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(entries, index, &entry)) {
            continue;
        }
        if (results[index].success) {
            files_ok += 1;
            bytes_total += (uint64_t)entry.file_size;
        } else {
            files_error += 1;
        }
    }

    const char* tool_version = (context != NULL && context->tool_version != NULL) ? context->tool_version : BC_HASH_VERSION_STRING;
    uint64_t started_at_unix_ms = context != NULL ? context->started_at_unix_ms : 0;
    uint64_t wall_ms = context != NULL ? context->wall_ms : 0;
    uint64_t worker_count = context != NULL ? (uint64_t)context->worker_count : 0;
    const char* dispatch_mode = (context != NULL && context->dispatch_mode != NULL) ? context->dispatch_mode : "unknown";

    if (!bc_hrbl_writer_begin_block(writer, "bc_hash", bc_hash_output_hrbl_cstr_length("bc_hash"))) {
        goto cleanup;
    }
    if (!bc_hash_output_hrbl_set_string(writer, "tool", BC_HASH_OUTPUT_HRBL_TOOL_NAME)) goto cleanup;
    if (!bc_hash_output_hrbl_set_string(writer, "tool_version", tool_version)) goto cleanup;
    if (!bc_hash_output_hrbl_set_uint64(writer, "schema_version", BC_HASH_OUTPUT_HRBL_SCHEMA_VERSION)) goto cleanup;
    if (!bc_hash_output_hrbl_set_string(writer, "algorithm", bc_hash_output_hrbl_algorithm_name(algorithm))) goto cleanup;
    if (!bc_hash_output_hrbl_set_uint64(writer, "started_at_unix_ms", started_at_unix_ms)) goto cleanup;
    if (!bc_hash_output_hrbl_set_uint64(writer, "wall_ms", wall_ms)) goto cleanup;
    if (!bc_hash_output_hrbl_set_uint64(writer, "worker_count", worker_count)) goto cleanup;
    if (!bc_hash_output_hrbl_set_string(writer, "dispatch_mode", dispatch_mode)) goto cleanup;
    if (!bc_hash_output_hrbl_set_uint64(writer, "files_total", (uint64_t)entry_count)) goto cleanup;
    if (!bc_hash_output_hrbl_set_uint64(writer, "files_ok", (uint64_t)files_ok)) goto cleanup;
    if (!bc_hash_output_hrbl_set_uint64(writer, "files_error", (uint64_t)files_error)) goto cleanup;
    if (!bc_hash_output_hrbl_set_uint64(writer, "bytes_total", bytes_total)) goto cleanup;

    if (!bc_hrbl_writer_begin_block(writer, "files", bc_hash_output_hrbl_cstr_length("files"))) goto cleanup;
    for (size_t index = 0; index < entry_count; ++index) {
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(entries, index, &entry)) {
            continue;
        }
        if (!bc_hash_output_hrbl_write_file_block(writer, algorithm, &entry, &results[index])) {
            goto cleanup;
        }
    }
    if (!bc_hrbl_writer_end_block(writer)) goto cleanup;

    if (!bc_hrbl_writer_end_block(writer)) goto cleanup;

    if (!bc_hrbl_writer_finalize_to_buffer(writer, &buffer, &buffer_size)) {
        fputs("bc-hash: hrbl output: finalize failed\n", stderr);
        goto cleanup;
    }

    if (!bc_core_writer_write_bytes(output_writer, buffer, buffer_size)) {
        fputs("bc-hash: hrbl output: writer failed\n", stderr);
        goto cleanup;
    }
    success = true;

cleanup:
    if (buffer != NULL) {
        bc_hrbl_free_buffer(memory_context, buffer);
    }
    bc_hrbl_writer_destroy(writer);
    bc_allocators_context_destroy(memory_context);
    return success;
}
