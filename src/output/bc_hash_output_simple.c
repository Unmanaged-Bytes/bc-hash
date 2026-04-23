// SPDX-License-Identifier: MIT

#include "bc_hash_output_internal.h"

#include "bc_core.h"

static const char bc_hash_output_hex_alphabet[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

bool bc_hash_output_encode_hex(const uint8_t* digest, size_t digest_length, char* out_buffer)
{
    for (size_t index = 0; index < digest_length; ++index) {
        uint8_t byte_value = digest[index];
        out_buffer[(index * 2) + 0] = bc_hash_output_hex_alphabet[(byte_value >> 4) & 0x0Fu];
        out_buffer[(index * 2) + 1] = bc_hash_output_hex_alphabet[byte_value & 0x0Fu];
    }
    out_buffer[digest_length * 2] = '\0';
    return true;
}

static void bc_hash_output_write_hex_crc32(uint32_t crc32_value, char* out_buffer)
{
    for (size_t index = 0; index < BC_HASH_CRC32_HEX_LENGTH; ++index) {
        size_t shift_bits = 28u - (index * 4u);
        uint32_t nibble = (crc32_value >> shift_bits) & 0xFu;
        out_buffer[index] = bc_hash_output_hex_alphabet[nibble];
    }
    out_buffer[BC_HASH_CRC32_HEX_LENGTH] = '\0';
}

bool bc_hash_output_write_simple(bc_core_writer_t* writer, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                                 const bc_hash_result_entry_t* results);

bool bc_hash_output_write_json(bc_core_writer_t* writer, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                               const bc_hash_result_entry_t* results, const bc_hash_output_context_t* context);

bool bc_hash_output_write_hrbl(bc_core_writer_t* writer, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                               const bc_hash_result_entry_t* results, const bc_hash_output_context_t* context);

bool bc_hash_output_write(bc_core_writer_t* writer, bc_hash_output_format_t format, bc_hash_algorithm_t algorithm,
                          const bc_containers_vector_t* entries, const bc_hash_result_entry_t* results,
                          const bc_hash_output_context_t* context)
{
    if (format == BC_HASH_OUTPUT_FORMAT_JSON) {
        return bc_hash_output_write_json(writer, algorithm, entries, results, context);
    }
    if (format == BC_HASH_OUTPUT_FORMAT_HRBL) {
        return bc_hash_output_write_hrbl(writer, algorithm, entries, results, context);
    }
    return bc_hash_output_write_simple(writer, algorithm, entries, results);
}

bool bc_hash_output_write_simple(bc_core_writer_t* writer, bc_hash_algorithm_t algorithm, const bc_containers_vector_t* entries,
                                 const bc_hash_result_entry_t* results)
{
    size_t entry_count = bc_containers_vector_length(entries);
    char hex_buffer[BC_HASH_MAX_HEX_LENGTH + 1];

    for (size_t index = 0; index < entry_count; ++index) {
        if (!results[index].success) {
            continue;
        }
        bc_hash_file_entry_t entry;
        if (!bc_containers_vector_get(entries, index, &entry)) {
            continue;
        }
        size_t hex_length = 0;
        switch (algorithm) {
            case BC_HASH_ALGORITHM_CRC32:
                bc_hash_output_write_hex_crc32(results[index].crc32_value, hex_buffer);
                hex_length = BC_HASH_CRC32_HEX_LENGTH;
                break;
            case BC_HASH_ALGORITHM_XXH3:
                bc_hash_output_encode_hex(results[index].xxh3_digest, BC_HASH_XXH3_DIGEST_SIZE, hex_buffer);
                hex_length = BC_HASH_XXH3_HEX_LENGTH;
                break;
            case BC_HASH_ALGORITHM_XXH128:
                bc_hash_output_encode_hex(results[index].xxh128_digest, BC_HASH_XXH128_DIGEST_SIZE, hex_buffer);
                hex_length = BC_HASH_XXH128_HEX_LENGTH;
                break;
            case BC_HASH_ALGORITHM_SHA256:
            default:
                bc_hash_output_encode_hex(results[index].sha256_digest, BC_CORE_SHA256_DIGEST_SIZE, hex_buffer);
                hex_length = BC_HASH_SHA256_HEX_LENGTH;
                break;
        }
        if (!bc_core_writer_write_bytes(writer, hex_buffer, hex_length)) {
            return false;
        }
        if (!BC_CORE_WRITER_PUTS(writer, "  ")) {
            return false;
        }
        if (!bc_core_writer_write_bytes(writer, entry.absolute_path, entry.absolute_path_length)) {
            return false;
        }
        if (!bc_core_writer_write_char(writer, '\n')) {
            return false;
        }
    }
    return true;
}
