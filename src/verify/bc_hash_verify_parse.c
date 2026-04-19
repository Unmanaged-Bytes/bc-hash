// SPDX-License-Identifier: MIT

#include "bc_hash_verify_internal.h"

#include "bc_allocators_pool.h"
#include "bc_core.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BC_HASH_VERIFY_PARSE_LINE_BUFFER 65536

static bool bc_hash_verify_is_hex_character(char character)
{
    if (character >= '0' && character <= '9') {
        return true;
    }
    if (character >= 'a' && character <= 'f') {
        return true;
    }
    if (character >= 'A' && character <= 'F') {
        return true;
    }
    return false;
}

static bool bc_hash_verify_algorithm_from_hex_length(size_t hex_length, bc_hash_algorithm_t* out_algorithm)
{
    switch (hex_length) {
        case BC_HASH_CRC32_HEX_LENGTH:
            *out_algorithm = BC_HASH_ALGORITHM_CRC32;
            return true;
        case BC_HASH_XXH3_HEX_LENGTH:
            *out_algorithm = BC_HASH_ALGORITHM_XXH3;
            return true;
        case BC_HASH_XXH128_HEX_LENGTH:
            *out_algorithm = BC_HASH_ALGORITHM_XXH128;
            return true;
        case BC_HASH_SHA256_HEX_LENGTH:
            *out_algorithm = BC_HASH_ALGORITHM_SHA256;
            return true;
        default:
            return false;
    }
}

static bool bc_hash_verify_algorithm_from_name(const char* name, size_t name_length, bc_hash_algorithm_t* out_algorithm)
{
    if (name_length == 5 && strncmp(name, "crc32", 5) == 0) {
        *out_algorithm = BC_HASH_ALGORITHM_CRC32;
        return true;
    }
    if (name_length == 6 && strncmp(name, "sha256", 6) == 0) {
        *out_algorithm = BC_HASH_ALGORITHM_SHA256;
        return true;
    }
    if (name_length == 4 && strncmp(name, "xxh3", 4) == 0) {
        *out_algorithm = BC_HASH_ALGORITHM_XXH3;
        return true;
    }
    if (name_length == 6 && strncmp(name, "xxh128", 6) == 0) {
        *out_algorithm = BC_HASH_ALGORITHM_XXH128;
        return true;
    }
    return false;
}

static bool bc_hash_verify_intern_path(bc_allocators_context_t* memory_context, const char* path, size_t path_length, const char** out_interned)
{
    char* buffer = NULL;
    if (!bc_allocators_pool_allocate(memory_context, path_length + 1, (void**)&buffer)) {
        return false;
    }
    bc_core_copy(buffer, path, path_length);
    buffer[path_length] = '\0';
    *out_interned = buffer;
    return true;
}

static bool bc_hash_verify_push_expectation(bc_allocators_context_t* memory_context, bc_containers_vector_t* expectations, const char* path,
                                            size_t path_length, const char* hex, size_t hex_length)
{
    if (hex_length > BC_HASH_MAX_HEX_LENGTH) {
        return false;
    }
    const char* interned_path = NULL;
    if (!bc_hash_verify_intern_path(memory_context, path, path_length, &interned_path)) {
        return false;
    }
    bc_hash_verify_expectation_t expectation;
    bc_core_zero(&expectation, sizeof(expectation));
    expectation.target_path = interned_path;
    expectation.target_path_length = path_length;
    for (size_t index = 0; index < hex_length; index++) {
        char character = hex[index];
        if (character >= 'A' && character <= 'F') {
            character = (char)(character | 0x20);
        }
        expectation.expected_hex[index] = character;
    }
    expectation.expected_hex[hex_length] = '\0';
    expectation.expected_hex_length = hex_length;
    expectation.dispatch_index = BC_HASH_VERIFY_SENTINEL_DISPATCH_INDEX;
    expectation.target_missing = false;
    expectation.stat_errno = 0;
    if (!bc_containers_vector_push(memory_context, expectations, &expectation)) {
        return false;
    }
    return true;
}

static bool bc_hash_verify_parse_simple_line(bc_allocators_context_t* memory_context, bc_containers_vector_t* expectations, const char* line,
                                             size_t line_length, size_t* inout_hex_length)
{
    size_t cursor = 0;
    while (cursor < line_length && (line[cursor] == ' ' || line[cursor] == '\t')) {
        cursor++;
    }
    if (cursor == line_length) {
        return true;
    }
    if (line[cursor] == '#') {
        return true;
    }

    size_t hex_start = cursor;
    while (cursor < line_length && bc_hash_verify_is_hex_character(line[cursor])) {
        cursor++;
    }
    size_t hex_length = cursor - hex_start;
    if (hex_length == 0) {
        return false;
    }

    if (cursor + 1 >= line_length) {
        return false;
    }
    if (line[cursor] != ' ') {
        return false;
    }
    cursor++;
    if (line[cursor] != ' ' && line[cursor] != '*') {
        return false;
    }
    cursor++;

    size_t path_start = cursor;
    size_t path_length = line_length - path_start;
    if (path_length == 0) {
        return false;
    }

    if (*inout_hex_length == 0) {
        *inout_hex_length = hex_length;
    } else if (*inout_hex_length != hex_length) {
        return false;
    }

    return bc_hash_verify_push_expectation(memory_context, expectations, line + path_start, path_length, line + hex_start, hex_length);
}

static bool bc_hash_verify_find_json_string(const char* line, size_t line_length, const char* key, size_t* out_value_start,
                                            size_t* out_value_length)
{
    size_t key_length = strlen(key);
    if (key_length + 4 > line_length) {
        return false;
    }

    for (size_t index = 0; index + key_length + 3 < line_length; index++) {
        if (line[index] != '"') {
            continue;
        }
        if (strncmp(line + index + 1, key, key_length) != 0) {
            continue;
        }
        size_t after_key = index + 1 + key_length;
        if (after_key >= line_length || line[after_key] != '"') {
            continue;
        }
        size_t colon_position = after_key + 1;
        while (colon_position < line_length && (line[colon_position] == ' ' || line[colon_position] == '\t')) {
            colon_position++;
        }
        if (colon_position >= line_length || line[colon_position] != ':') {
            continue;
        }
        size_t quote_position = colon_position + 1;
        while (quote_position < line_length && (line[quote_position] == ' ' || line[quote_position] == '\t')) {
            quote_position++;
        }
        if (quote_position >= line_length || line[quote_position] != '"') {
            continue;
        }
        size_t value_start = quote_position + 1;
        size_t scan = value_start;
        while (scan < line_length) {
            if (line[scan] == '\\') {
                if (scan + 1 >= line_length) {
                    return false;
                }
                scan += 2;
                continue;
            }
            if (line[scan] == '"') {
                *out_value_start = value_start;
                *out_value_length = scan - value_start;
                return true;
            }
            scan++;
        }
        return false;
    }
    return false;
}

static bool bc_hash_verify_unescape_json_string(const char* input, size_t input_length, char* output, size_t output_capacity, size_t* out_output_length)
{
    size_t output_index = 0;
    for (size_t index = 0; index < input_length; index++) {
        if (output_index >= output_capacity) {
            return false;
        }
        char character = input[index];
        if (character != '\\') {
            output[output_index++] = character;
            continue;
        }
        if (index + 1 >= input_length) {
            return false;
        }
        char next = input[index + 1];
        switch (next) {
            case '"':
            case '\\':
            case '/':
                output[output_index++] = next;
                break;
            case 'b':
                output[output_index++] = '\b';
                break;
            case 'f':
                output[output_index++] = '\f';
                break;
            case 'n':
                output[output_index++] = '\n';
                break;
            case 'r':
                output[output_index++] = '\r';
                break;
            case 't':
                output[output_index++] = '\t';
                break;
            case 'u': {
                if (index + 5 >= input_length) {
                    return false;
                }
                unsigned int code_point = 0;
                for (size_t digit = 0; digit < 4; digit++) {
                    char hex_character = input[index + 2 + digit];
                    unsigned int value;
                    if (hex_character >= '0' && hex_character <= '9') {
                        value = (unsigned int)(hex_character - '0');
                    } else if (hex_character >= 'a' && hex_character <= 'f') {
                        value = (unsigned int)(hex_character - 'a' + 10);
                    } else if (hex_character >= 'A' && hex_character <= 'F') {
                        value = (unsigned int)(hex_character - 'A' + 10);
                    } else {
                        return false;
                    }
                    code_point = (code_point << 4) | value;
                }
                if (code_point < 0x80) {
                    output[output_index++] = (char)code_point;
                } else if (code_point < 0x800) {
                    if (output_index + 2 > output_capacity) {
                        return false;
                    }
                    output[output_index++] = (char)(0xC0 | (code_point >> 6));
                    output[output_index++] = (char)(0x80 | (code_point & 0x3F));
                } else {
                    if (output_index + 3 > output_capacity) {
                        return false;
                    }
                    output[output_index++] = (char)(0xE0 | (code_point >> 12));
                    output[output_index++] = (char)(0x80 | ((code_point >> 6) & 0x3F));
                    output[output_index++] = (char)(0x80 | (code_point & 0x3F));
                }
                index += 4;
                break;
            }
            default:
                return false;
        }
        index += 1;
    }
    *out_output_length = output_index;
    return true;
}

static bool bc_hash_verify_json_contains_literal(const char* line, size_t line_length, const char* key, const char* expected_value)
{
    size_t value_start = 0;
    size_t value_length = 0;
    if (!bc_hash_verify_find_json_string(line, line_length, key, &value_start, &value_length)) {
        return false;
    }
    size_t expected_length = strlen(expected_value);
    if (expected_length != value_length) {
        return false;
    }
    return strncmp(line + value_start, expected_value, expected_length) == 0;
}

static bool bc_hash_verify_parse_ndjson_line(bc_allocators_context_t* memory_context, bc_containers_vector_t* expectations, const char* line,
                                             size_t line_length, bc_hash_algorithm_t* inout_algorithm, bool* inout_algorithm_set,
                                             size_t* inout_hex_length)
{
    size_t cursor = 0;
    while (cursor < line_length && (line[cursor] == ' ' || line[cursor] == '\t')) {
        cursor++;
    }
    if (cursor == line_length) {
        return true;
    }
    if (line[cursor] != '{') {
        return false;
    }

    if (bc_hash_verify_json_contains_literal(line, line_length, "type", "header")) {
        size_t value_start = 0;
        size_t value_length = 0;
        if (!bc_hash_verify_find_json_string(line, line_length, "algorithm", &value_start, &value_length)) {
            return false;
        }
        if (!bc_hash_verify_algorithm_from_name(line + value_start, value_length, inout_algorithm)) {
            return false;
        }
        *inout_algorithm_set = true;
        return true;
    }

    if (bc_hash_verify_json_contains_literal(line, line_length, "type", "entry")) {
        size_t path_start = 0;
        size_t path_length = 0;
        if (!bc_hash_verify_find_json_string(line, line_length, "path", &path_start, &path_length)) {
            return false;
        }
        size_t digest_start = 0;
        size_t digest_length = 0;
        if (!bc_hash_verify_find_json_string(line, line_length, "digest", &digest_start, &digest_length)) {
            return true;
        }
        if (digest_length > BC_HASH_MAX_HEX_LENGTH) {
            return false;
        }
        if (*inout_hex_length == 0) {
            *inout_hex_length = digest_length;
        } else if (*inout_hex_length != digest_length) {
            return false;
        }
        char path_buffer[BC_HASH_VERIFY_PARSE_LINE_BUFFER];
        size_t decoded_length = 0;
        if (!bc_hash_verify_unescape_json_string(line + path_start, path_length, path_buffer, sizeof(path_buffer), &decoded_length)) {
            return false;
        }
        return bc_hash_verify_push_expectation(memory_context, expectations, path_buffer, decoded_length, line + digest_start, digest_length);
    }

    return true;
}

static bool bc_hash_verify_read_file_fully(bc_allocators_context_t* memory_context, const char* file_path, char** out_buffer, size_t* out_size)
{
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        return false;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return false;
    }
    long size_long = ftell(file);
    if (size_long < 0) {
        fclose(file);
        return false;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return false;
    }
    size_t file_size = (size_t)size_long;
    char* buffer = NULL;
    if (!bc_allocators_pool_allocate(memory_context, file_size + 1, (void**)&buffer)) {
        fclose(file);
        return false;
    }
    size_t read_total = 0;
    while (read_total < file_size) {
        size_t read_now = fread(buffer + read_total, 1, file_size - read_total, file);
        if (read_now == 0) {
            bc_allocators_pool_free(memory_context, buffer);
            fclose(file);
            return false;
        }
        read_total += read_now;
    }
    buffer[file_size] = '\0';
    fclose(file);
    *out_buffer = buffer;
    *out_size = file_size;
    return true;
}

static bool bc_hash_verify_line_is_whitespace(const char* line, size_t line_length)
{
    for (size_t index = 0; index < line_length; index++) {
        if (line[index] != ' ' && line[index] != '\t') {
            return false;
        }
    }
    return true;
}

bc_hash_verify_parse_status_t bc_hash_verify_parse_digest_file(bc_allocators_context_t* memory_context, const char* digest_file_path,
                                                               bc_containers_vector_t* expectations, bc_hash_algorithm_t* out_algorithm)
{
    char* file_buffer = NULL;
    size_t file_size = 0;
    if (!bc_hash_verify_read_file_fully(memory_context, digest_file_path, &file_buffer, &file_size)) {
        return BC_HASH_VERIFY_PARSE_STATUS_IO_ERROR;
    }

    bool is_ndjson = false;
    {
        size_t cursor = 0;
        while (cursor < file_size) {
            size_t line_start = cursor;
            while (cursor < file_size && file_buffer[cursor] != '\n') {
                cursor++;
            }
            size_t line_length = cursor - line_start;
            if (cursor < file_size) {
                cursor++;
            }
            if (line_length == 0 || bc_hash_verify_line_is_whitespace(file_buffer + line_start, line_length)) {
                continue;
            }
            size_t probe = 0;
            while (probe < line_length && (file_buffer[line_start + probe] == ' ' || file_buffer[line_start + probe] == '\t')) {
                probe++;
            }
            if (probe < line_length && file_buffer[line_start + probe] == '{') {
                is_ndjson = true;
            }
            break;
        }
    }

    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    bool algorithm_set = false;
    size_t hex_length = 0;
    size_t cursor = 0;
    size_t entries_before = bc_containers_vector_length(expectations);

    while (cursor < file_size) {
        size_t line_start = cursor;
        while (cursor < file_size && file_buffer[cursor] != '\n') {
            cursor++;
        }
        size_t line_length = cursor - line_start;
        if (cursor < file_size) {
            cursor++;
        }
        if (line_length > 0 && file_buffer[line_start + line_length - 1] == '\r') {
            line_length -= 1;
        }
        if (line_length == 0 || bc_hash_verify_line_is_whitespace(file_buffer + line_start, line_length)) {
            continue;
        }

        if (is_ndjson) {
            if (!bc_hash_verify_parse_ndjson_line(memory_context, expectations, file_buffer + line_start, line_length, &algorithm,
                                                  &algorithm_set, &hex_length)) {
                bc_allocators_pool_free(memory_context, file_buffer);
                return BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR;
            }
        } else {
            if (!bc_hash_verify_parse_simple_line(memory_context, expectations, file_buffer + line_start, line_length, &hex_length)) {
                bc_allocators_pool_free(memory_context, file_buffer);
                return BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR;
            }
        }
    }

    bc_allocators_pool_free(memory_context, file_buffer);

    size_t entries_added = bc_containers_vector_length(expectations) - entries_before;
    if (entries_added == 0) {
        return BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR;
    }

    if (is_ndjson) {
        if (!algorithm_set) {
            if (!bc_hash_verify_algorithm_from_hex_length(hex_length, &algorithm)) {
                return BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR;
            }
        }
    } else {
        if (!bc_hash_verify_algorithm_from_hex_length(hex_length, &algorithm)) {
            return BC_HASH_VERIFY_PARSE_STATUS_FORMAT_ERROR;
        }
    }

    *out_algorithm = algorithm;
    return BC_HASH_VERIFY_PARSE_STATUS_OK;
}
