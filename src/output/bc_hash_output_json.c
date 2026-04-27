// SPDX-License-Identifier: MIT

#include "bc_hash_output_internal.h"

#include "bc_core.h"

#include <string.h>
#include <time.h>

#define BC_HASH_OUTPUT_JSON_SCHEMA_VERSION 1
#define BC_HASH_OUTPUT_JSON_TOOL_NAME "bc-hash"
#define BC_HASH_OUTPUT_JSON_DEFAULT_VERSION "1.1.0"

static bool bc_hash_output_json_write_escaped_string(bc_core_writer_t* writer, const char* input_string)
{
    if (!bc_core_writer_write_char(writer, '"')) {
        return false;
    }
    const unsigned char* cursor = (const unsigned char*)input_string;
    while (*cursor != 0) {
        unsigned char byte_value = *cursor;
        bool ok = true;
        switch (byte_value) {
            case '"':
                ok = BC_CORE_WRITER_PUTS(writer, "\\\"");
                break;
            case '\\':
                ok = BC_CORE_WRITER_PUTS(writer, "\\\\");
                break;
            case '\b':
                ok = BC_CORE_WRITER_PUTS(writer, "\\b");
                break;
            case '\f':
                ok = BC_CORE_WRITER_PUTS(writer, "\\f");
                break;
            case '\n':
                ok = BC_CORE_WRITER_PUTS(writer, "\\n");
                break;
            case '\r':
                ok = BC_CORE_WRITER_PUTS(writer, "\\r");
                break;
            case '\t':
                ok = BC_CORE_WRITER_PUTS(writer, "\\t");
                break;
            default:
                if (byte_value < 0x20u) {
                    ok = BC_CORE_WRITER_PUTS(writer, "\\u")
                         && bc_core_writer_write_unsigned_integer_64_hexadecimal_padded(writer, (uint64_t)byte_value, 4U);
                } else {
                    ok = bc_core_writer_write_char(writer, (char)byte_value);
                }
                break;
        }
        if (!ok) {
            return false;
        }
        cursor += 1;
    }
    return bc_core_writer_write_char(writer, '"');
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

static void bc_hash_output_json_format_timestamp(uint64_t unix_ms, char* out_buffer, size_t buffer_size, size_t* out_length)
{
    time_t seconds = (time_t)(unix_ms / 1000u);
    struct tm tm_utc;
    if (gmtime_r(&seconds, &tm_utc) == NULL) {
        static const char fallback[] = "1970-01-01T00:00:00Z";
        size_t fallback_length = sizeof(fallback) - 1U;
        if (fallback_length < buffer_size) {
            bc_core_copy(out_buffer, fallback, fallback_length);
            out_buffer[fallback_length] = '\0';
            *out_length = fallback_length;
            return;
        }
        *out_length = 0;
        return;
    }
    size_t formatted = strftime(out_buffer, buffer_size, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    *out_length = formatted;
}

static bool bc_hash_output_json_write_string_literal(bc_core_writer_t* writer, const char* literal)
{
    size_t length = 0;
    if (!bc_core_length(literal, 0, &length)) {
        return false;
    }
    return bc_core_writer_write_bytes(writer, literal, length);
}

static bool bc_hash_output_json_write_hex_crc32(bc_core_writer_t* writer, uint32_t crc32_value)
{
    if (!bc_core_writer_write_char(writer, '"')) {
        return false;
    }
    if (!bc_core_writer_write_unsigned_integer_64_hexadecimal_padded(writer, (uint64_t)crc32_value, BC_HASH_CRC32_HEX_LENGTH)) {
        return false;
    }
    return bc_core_writer_write_char(writer, '"');
}

static bool bc_hash_output_json_write_hex_bytes(bc_core_writer_t* writer, const uint8_t* digest, size_t digest_length)
{
    char hex_buffer[(BC_HASH_MAX_HEX_LENGTH) + 1];
    bc_hash_output_encode_hex(digest, digest_length, hex_buffer);
    if (!bc_core_writer_write_char(writer, '"')) {
        return false;
    }
    if (!bc_core_writer_write_bytes(writer, hex_buffer, digest_length * 2U)) {
        return false;
    }
    return bc_core_writer_write_char(writer, '"');
}

static bool bc_hash_output_json_write_header(bc_core_writer_t* writer, bc_hash_algorithm_t algorithm, const bc_hash_output_context_t* context)
{
    char timestamp_buffer[32];
    size_t timestamp_length = 0;
    uint64_t started_at_unix_ms = context != NULL ? context->started_at_unix_ms : 0;
    bc_hash_output_json_format_timestamp(started_at_unix_ms, timestamp_buffer, sizeof(timestamp_buffer), &timestamp_length);

    const char* tool_version = (context != NULL && context->tool_version != NULL) ? context->tool_version : BC_HASH_OUTPUT_JSON_DEFAULT_VERSION;

    if (!BC_CORE_WRITER_PUTS(writer, "{\"type\":\"header\",\"tool\":\"" BC_HASH_OUTPUT_JSON_TOOL_NAME "\",\"version\":")) {
        return false;
    }
    if (!bc_hash_output_json_write_escaped_string(writer, tool_version)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"schema_version\":")) {
        return false;
    }
    if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, (uint64_t)BC_HASH_OUTPUT_JSON_SCHEMA_VERSION)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"algorithm\":\"")) {
        return false;
    }
    if (!bc_hash_output_json_write_string_literal(writer, bc_hash_output_json_algorithm_name(algorithm))) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, "\",\"started_at\":\"")) {
        return false;
    }
    if (!bc_core_writer_write_bytes(writer, timestamp_buffer, timestamp_length)) {
        return false;
    }
    return BC_CORE_WRITER_PUTS(writer, "\"}\n");
}

static bool bc_hash_output_json_write_entry_success(bc_core_writer_t* writer, bc_hash_algorithm_t algorithm,
                                                    const bc_hash_file_entry_t* entry,
                                                    const bc_hash_result_entry_t* result)
{
    if (!BC_CORE_WRITER_PUTS(writer, "{\"type\":\"entry\",\"path\":")) {
        return false;
    }
    if (!bc_hash_output_json_write_escaped_string(writer, entry->absolute_path)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"digest\":")) {
        return false;
    }
    bool ok = true;
    switch (algorithm) {
        case BC_HASH_ALGORITHM_CRC32:
            ok = bc_hash_output_json_write_hex_crc32(writer, result->crc32_value);
            break;
        case BC_HASH_ALGORITHM_XXH3:
            ok = bc_hash_output_json_write_hex_bytes(writer, result->xxh3_digest, BC_HASH_XXH3_DIGEST_SIZE);
            break;
        case BC_HASH_ALGORITHM_XXH128:
            ok = bc_hash_output_json_write_hex_bytes(writer, result->xxh128_digest, BC_HASH_XXH128_DIGEST_SIZE);
            break;
        case BC_HASH_ALGORITHM_SHA256:
        default:
            ok = bc_hash_output_json_write_hex_bytes(writer, result->sha256_digest, BC_CORE_SHA256_DIGEST_SIZE);
            break;
    }
    if (!ok) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"size_bytes\":")) {
        return false;
    }
    if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, (uint64_t)entry->file_size)) {
        return false;
    }
    return BC_CORE_WRITER_PUTS(writer, ",\"ok\":true}\n");
}

static bool bc_hash_output_json_write_entry_error(bc_core_writer_t* writer, const bc_hash_file_entry_t* entry,
                                                  const bc_hash_result_entry_t* result)
{
    char message_buffer[128];
    int errno_value = result->errno_value;
    const char* message_pointer = strerror_r(errno_value, message_buffer, sizeof(message_buffer));
    const char* message_string = message_pointer != NULL ? message_pointer : "unknown error";

    if (!BC_CORE_WRITER_PUTS(writer, "{\"type\":\"entry\",\"path\":")) {
        return false;
    }
    if (!bc_hash_output_json_write_escaped_string(writer, entry->absolute_path)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"ok\":false,\"error\":{\"errno\":")) {
        return false;
    }
    if (!bc_core_writer_write_signed_integer_64(writer, (int64_t)errno_value)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"message\":")) {
        return false;
    }
    if (!bc_hash_output_json_write_escaped_string(writer, message_string)) {
        return false;
    }
    return BC_CORE_WRITER_PUTS(writer, "}}\n");
}

static bool bc_hash_output_json_write_summary(bc_core_writer_t* writer, const bc_containers_vector_t* entries,
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

    if (!BC_CORE_WRITER_PUTS(writer, "{\"type\":\"summary\",\"files_total\":")) {
        return false;
    }
    if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, (uint64_t)entry_count)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"files_ok\":")) {
        return false;
    }
    if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, (uint64_t)files_ok)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"files_error\":")) {
        return false;
    }
    if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, (uint64_t)files_error)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"bytes_total\":")) {
        return false;
    }
    if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, bytes_total)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"wall_ms\":")) {
        return false;
    }
    if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, wall_ms)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"workers\":")) {
        return false;
    }
    if (!bc_core_writer_write_unsigned_integer_64_decimal(writer, (uint64_t)worker_count)) {
        return false;
    }
    if (!BC_CORE_WRITER_PUTS(writer, ",\"mode\":")) {
        return false;
    }
    if (!bc_hash_output_json_write_escaped_string(writer, dispatch_mode)) {
        return false;
    }
    return BC_CORE_WRITER_PUTS(writer, "}\n");
}

bool bc_hash_output_write_json(bc_core_writer_t* writer, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                               const bc_hash_result_entry_t* results, const bc_hash_output_context_t* context);

bool bc_hash_output_write_json(bc_core_writer_t* writer, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                               const bc_hash_result_entry_t* results, const bc_hash_output_context_t* context)
{
    if (!bc_hash_output_json_write_header(writer, algorithm, context)) {
        return false;
    }

    size_t entry_count = bc_containers_vector_length(entries);
    for (size_t index = 0; index < entry_count; ++index) {
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(entries, index, &entry)) {
            continue;
        }
        if (results[index].success) {
            if (!bc_hash_output_json_write_entry_success(writer, algorithm, &entry, &results[index])) {
                return false;
            }
        } else {
            if (!bc_hash_output_json_write_entry_error(writer, &entry, &results[index])) {
                return false;
            }
        }
    }

    return bc_hash_output_json_write_summary(writer, entries, results, context);
}
