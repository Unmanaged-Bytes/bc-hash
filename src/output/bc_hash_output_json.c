// SPDX-License-Identifier: MIT

#include "bc_hash_output_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BC_HASH_OUTPUT_JSON_SCHEMA_VERSION 1
#define BC_HASH_OUTPUT_JSON_TOOL_NAME "bc-hash"
#define BC_HASH_OUTPUT_JSON_DEFAULT_VERSION "1.1.0"

static void bc_hash_output_json_write_escaped_string(FILE* output_stream, const char* input_string)
{
    fputc('"', output_stream);
    const unsigned char* cursor = (const unsigned char*)input_string;
    while (*cursor != 0) {
        unsigned char byte_value = *cursor;
        switch (byte_value) {
            case '"':
                fputs("\\\"", output_stream);
                break;
            case '\\':
                fputs("\\\\", output_stream);
                break;
            case '\b':
                fputs("\\b", output_stream);
                break;
            case '\f':
                fputs("\\f", output_stream);
                break;
            case '\n':
                fputs("\\n", output_stream);
                break;
            case '\r':
                fputs("\\r", output_stream);
                break;
            case '\t':
                fputs("\\t", output_stream);
                break;
            default:
                if (byte_value < 0x20u) {
                    fprintf(output_stream, "\\u%04x", (unsigned int)byte_value);
                } else {
                    fputc((int)byte_value, output_stream);
                }
                break;
        }
        cursor += 1;
    }
    fputc('"', output_stream);
}

static const char* bc_hash_output_json_algorithm_name(bc_hash_algorithm_t algorithm)
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

static void bc_hash_output_json_format_timestamp(uint64_t unix_ms, char* out_buffer, size_t buffer_size)
{
    time_t seconds = (time_t)(unix_ms / 1000u);
    struct tm tm_utc;
    if (gmtime_r(&seconds, &tm_utc) == NULL) {
        snprintf(out_buffer, buffer_size, "1970-01-01T00:00:00Z");
        return;
    }
    strftime(out_buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

static void bc_hash_output_json_write_hex_crc32(FILE* output_stream, uint32_t crc32_value)
{
    static const char hex_alphabet[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    char hex_buffer[BC_HASH_CRC32_HEX_LENGTH + 1];
    for (size_t index = 0; index < BC_HASH_CRC32_HEX_LENGTH; ++index) {
        size_t shift_bits = 28u - (index * 4u);
        uint32_t nibble = (crc32_value >> shift_bits) & 0xFu;
        hex_buffer[index] = hex_alphabet[nibble];
    }
    hex_buffer[BC_HASH_CRC32_HEX_LENGTH] = '\0';
    fputc('"', output_stream);
    fputs(hex_buffer, output_stream);
    fputc('"', output_stream);
}

static void bc_hash_output_json_write_hex_bytes(FILE* output_stream, const uint8_t* digest, size_t digest_length)
{
    char hex_buffer[(BC_HASH_MAX_HEX_LENGTH) + 1];
    bc_hash_output_encode_hex(digest, digest_length, hex_buffer);
    fputc('"', output_stream);
    fputs(hex_buffer, output_stream);
    fputc('"', output_stream);
}

static void bc_hash_output_json_write_header(FILE* output_stream, bc_hash_algorithm_t algorithm, const bc_hash_output_context_t* context)
{
    char timestamp_buffer[32];
    uint64_t started_at_unix_ms = context != NULL ? context->started_at_unix_ms : 0;
    bc_hash_output_json_format_timestamp(started_at_unix_ms, timestamp_buffer, sizeof(timestamp_buffer));

    const char* tool_version = (context != NULL && context->tool_version != NULL) ? context->tool_version : BC_HASH_OUTPUT_JSON_DEFAULT_VERSION;

    fputs("{\"type\":\"header\",\"tool\":\"", output_stream);
    fputs(BC_HASH_OUTPUT_JSON_TOOL_NAME, output_stream);
    fputs("\",\"version\":", output_stream);
    bc_hash_output_json_write_escaped_string(output_stream, tool_version);
    fprintf(output_stream, ",\"schema_version\":%d", BC_HASH_OUTPUT_JSON_SCHEMA_VERSION);
    fputs(",\"algorithm\":\"", output_stream);
    fputs(bc_hash_output_json_algorithm_name(algorithm), output_stream);
    fputs("\",\"started_at\":\"", output_stream);
    fputs(timestamp_buffer, output_stream);
    fputs("\"}\n", output_stream);
}

static void bc_hash_output_json_write_entry_success(FILE* output_stream, bc_hash_algorithm_t algorithm, const bc_hash_file_entry_t* entry,
                                                    const bc_hash_result_entry_t* result)
{
    fputs("{\"type\":\"entry\",\"path\":", output_stream);
    bc_hash_output_json_write_escaped_string(output_stream, entry->absolute_path);
    fputs(",\"digest\":", output_stream);
    switch (algorithm) {
        case BC_HASH_ALGORITHM_CRC32:
            bc_hash_output_json_write_hex_crc32(output_stream, result->crc32_value);
            break;
        case BC_HASH_ALGORITHM_XXH3:
            bc_hash_output_json_write_hex_bytes(output_stream, result->xxh3_digest, BC_HASH_XXH3_DIGEST_SIZE);
            break;
        case BC_HASH_ALGORITHM_XXH128:
            bc_hash_output_json_write_hex_bytes(output_stream, result->xxh128_digest, BC_HASH_XXH128_DIGEST_SIZE);
            break;
        case BC_HASH_ALGORITHM_SHA256:
        default:
            bc_hash_output_json_write_hex_bytes(output_stream, result->sha256_digest, BC_CORE_SHA256_DIGEST_SIZE);
            break;
    }
    fprintf(output_stream, ",\"size_bytes\":%zu,\"ok\":true}\n", entry->file_size);
}

static void bc_hash_output_json_write_entry_error(FILE* output_stream, const bc_hash_file_entry_t* entry,
                                                  const bc_hash_result_entry_t* result)
{
    char message_buffer[128];
    int errno_value = result->errno_value;
    const char* message_pointer = strerror_r(errno_value, message_buffer, sizeof(message_buffer));
    const char* message_string = message_pointer != NULL ? message_pointer : "unknown error";

    fputs("{\"type\":\"entry\",\"path\":", output_stream);
    bc_hash_output_json_write_escaped_string(output_stream, entry->absolute_path);
    fputs(",\"ok\":false,\"error\":{\"errno\":", output_stream);
    fprintf(output_stream, "%d", errno_value);
    fputs(",\"message\":", output_stream);
    bc_hash_output_json_write_escaped_string(output_stream, message_string);
    fputs("}}\n", output_stream);
}

static void bc_hash_output_json_write_summary(FILE* output_stream, const bc_containers_vector_t* entries,
                                              const bc_hash_result_entry_t* results, const bc_hash_output_context_t* context)
{
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

    uint64_t wall_ms = context != NULL ? context->wall_ms : 0;
    size_t worker_count = context != NULL ? context->worker_count : 0;
    const char* dispatch_mode = (context != NULL && context->dispatch_mode != NULL) ? context->dispatch_mode : "unknown";

    fprintf(output_stream,
            "{\"type\":\"summary\",\"files_total\":%zu,\"files_ok\":%zu,\"files_error\":%zu,\"bytes_total\":%" PRIu64
            ",\"wall_ms\":%" PRIu64 ",\"workers\":%zu,\"mode\":",
            entry_count, files_ok, files_error, bytes_total, wall_ms, worker_count);
    bc_hash_output_json_write_escaped_string(output_stream, dispatch_mode);
    fputs("}\n", output_stream);
}

bool bc_hash_output_write_json(FILE* output_stream, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                               const bc_hash_result_entry_t* results, const bc_hash_output_context_t* context);

bool bc_hash_output_write_json(FILE* output_stream, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                               const bc_hash_result_entry_t* results, const bc_hash_output_context_t* context)
{
    bc_hash_output_json_write_header(output_stream, algorithm, context);

    size_t entry_count = bc_containers_vector_length(entries);
    for (size_t index = 0; index < entry_count; ++index) {
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(entries, index, &entry)) {
            continue;
        }
        if (results[index].success) {
            bc_hash_output_json_write_entry_success(output_stream, algorithm, &entry, &results[index]);
        } else {
            bc_hash_output_json_write_entry_error(output_stream, &entry, &results[index]);
        }
    }

    bc_hash_output_json_write_summary(output_stream, entries, results, context);
    return true;
}
