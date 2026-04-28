// SPDX-License-Identifier: MIT

#include "bc_hash_strings_internal.h"
#include "bc_hash_throughput_internal.h"

#include "bc_core.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#define BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY ((size_t)256)
#define BC_HASH_THROUGHPUT_CACHE_LINE_CAPACITY ((size_t)512)
#define BC_HASH_THROUGHPUT_CACHE_READER_BUFFER_BYTES ((size_t)4096)
#define BC_HASH_THROUGHPUT_CACHE_WRITER_BUFFER_BYTES ((size_t)1024)

static bool bc_hash_throughput_cache_copy_value_into(char* destination, size_t destination_capacity, const char* source)
{
    size_t source_length = bc_hash_strings_length(source);
    if (destination_capacity == 0) {
        return false;
    }
    size_t copy_length = source_length < destination_capacity - 1 ? source_length : destination_capacity - 1;
    if (copy_length > 0) {
        bc_core_copy(destination, source, copy_length);
    }
    destination[copy_length] = '\0';
    return true;
}

static bool bc_hash_throughput_cache_read_cpuinfo_field(const char* field_name, char* out_value, size_t value_capacity)
{
    int file_descriptor = open("/proc/cpuinfo", O_RDONLY | O_CLOEXEC);
    if (file_descriptor < 0) {
        return false;
    }
    char reader_buffer[BC_HASH_THROUGHPUT_CACHE_READER_BUFFER_BYTES];
    bc_core_reader_t reader;
    if (!bc_core_reader_init(&reader, file_descriptor, reader_buffer, sizeof(reader_buffer))) {
        close(file_descriptor);
        return false;
    }
    size_t field_name_length = bc_hash_strings_length(field_name);
    bool found = false;
    const char* line_data = NULL;
    size_t line_length = 0;
    while (bc_core_reader_read_line(&reader, &line_data, &line_length)) {
        if (line_length < field_name_length) {
            continue;
        }
        bool field_matches = false;
        (void)bc_core_starts_with(line_data, line_length, field_name, field_name_length, &field_matches);
        if (!field_matches) {
            continue;
        }
        size_t cursor = field_name_length;
        while (cursor < line_length && (line_data[cursor] == ' ' || line_data[cursor] == '\t')) {
            cursor += 1;
        }
        if (cursor >= line_length || line_data[cursor] != ':') {
            continue;
        }
        cursor += 1;
        while (cursor < line_length && (line_data[cursor] == ' ' || line_data[cursor] == '\t')) {
            cursor += 1;
        }
        size_t copied = 0;
        while (cursor < line_length && copied + 1 < value_capacity) {
            out_value[copied] = line_data[cursor];
            cursor += 1;
            copied += 1;
        }
        if (value_capacity > 0) {
            out_value[copied] = '\0';
        }
        found = true;
        break;
    }
    (void)bc_core_reader_destroy(&reader);
    close(file_descriptor);
    return found;
}

bool bc_hash_throughput_cache_read_host_signature(char* out_cpu_model, size_t cpu_model_capacity, char* out_microcode,
                                                  size_t microcode_capacity, char* out_kernel_version, size_t kernel_version_capacity)
{
    if (!bc_hash_throughput_cache_read_cpuinfo_field("model name", out_cpu_model, cpu_model_capacity)) {
        return false;
    }
    if (!bc_hash_throughput_cache_read_cpuinfo_field("microcode", out_microcode, microcode_capacity)) {
        out_microcode[0] = '\0';
    }
    struct utsname uname_info;
    if (uname(&uname_info) != 0) {
        return false;
    }
    size_t copied = 0;
    while (uname_info.release[copied] != '\0' && copied + 1 < kernel_version_capacity) {
        out_kernel_version[copied] = uname_info.release[copied];
        copied += 1;
    }
    out_kernel_version[copied] = '\0';
    return true;
}

static bool bc_hash_throughput_cache_parse_double(const char* value_text, double* out_value)
{
    char* end_pointer = NULL;
    double parsed = strtod(value_text, &end_pointer);
    if (end_pointer == value_text) {
        return false;
    }
    *out_value = parsed;
    return true;
}

bool bc_hash_throughput_cache_load(const char* absolute_cache_path, bc_hash_throughput_constants_t* out_constants)
{
    int file_descriptor = open(absolute_cache_path, O_RDONLY | O_CLOEXEC);
    if (file_descriptor < 0) {
        return false;
    }
    char reader_buffer[BC_HASH_THROUGHPUT_CACHE_READER_BUFFER_BYTES];
    bc_core_reader_t reader;
    if (!bc_core_reader_init(&reader, file_descriptor, reader_buffer, sizeof(reader_buffer))) {
        close(file_descriptor);
        return false;
    }

    char cached_cpu_model[BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY] = {0};
    char cached_microcode[BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY] = {0};
    char cached_kernel_version[BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY] = {0};
    bool sha256_ok = false;
    bool crc32c_ok = false;
    bool memory_bandwidth_ok = false;
    bool parallel_startup_ok = false;
    bool per_file_cost_ok = false;

    const char* line_data = NULL;
    size_t line_length = 0;
    char value_terminated[BC_HASH_THROUGHPUT_CACHE_LINE_CAPACITY];

    while (bc_core_reader_read_line(&reader, &line_data, &line_length)) {
        size_t separator_offset = 0;
        if (!bc_core_find_byte(line_data, line_length, (unsigned char)'=', &separator_offset)) {
            continue;
        }
        size_t value_start = separator_offset + 1;
        size_t value_length = line_length > value_start ? line_length - value_start : 0;
        if (value_length + 1 > sizeof(value_terminated)) {
            value_length = sizeof(value_terminated) - 1;
        }
        if (value_length > 0) {
            bc_core_copy(value_terminated, line_data + value_start, value_length);
        }
        value_terminated[value_length] = '\0';

        bool key_equal = false;
        (void)bc_core_equal(line_data, "cpu_model", separator_offset == 9 ? 9u : separator_offset, &key_equal);
        if (separator_offset == 9 && key_equal) {
            (void)bc_hash_throughput_cache_copy_value_into(cached_cpu_model, sizeof(cached_cpu_model), value_terminated);
            continue;
        }
        key_equal = false;
        if (separator_offset == 9) {
            (void)bc_core_equal(line_data, "microcode", 9u, &key_equal);
            if (key_equal) {
                (void)bc_hash_throughput_cache_copy_value_into(cached_microcode, sizeof(cached_microcode), value_terminated);
                continue;
            }
        }
        if (separator_offset == 14) {
            key_equal = false;
            (void)bc_core_equal(line_data, "kernel_version", 14u, &key_equal);
            if (key_equal) {
                (void)bc_hash_throughput_cache_copy_value_into(cached_kernel_version, sizeof(cached_kernel_version), value_terminated);
                continue;
            }
        }
        if (separator_offset == 11) {
            key_equal = false;
            (void)bc_core_equal(line_data, "sha256_gbps", 11u, &key_equal);
            if (key_equal) {
                sha256_ok = bc_hash_throughput_cache_parse_double(value_terminated, &out_constants->sha256_gigabytes_per_second);
                continue;
            }
            key_equal = false;
            (void)bc_core_equal(line_data, "crc32c_gbps", 11u, &key_equal);
            if (key_equal) {
                crc32c_ok = bc_hash_throughput_cache_parse_double(value_terminated, &out_constants->crc32c_gigabytes_per_second);
                continue;
            }
            key_equal = false;
            (void)bc_core_equal(line_data, "mem_bw_gbps", 11u, &key_equal);
            if (key_equal) {
                memory_bandwidth_ok =
                    bc_hash_throughput_cache_parse_double(value_terminated, &out_constants->memory_bandwidth_gigabytes_per_second);
                continue;
            }
        }
        if (separator_offset == 19) {
            key_equal = false;
            (void)bc_core_equal(line_data, "parallel_startup_us", 19u, &key_equal);
            if (key_equal) {
                parallel_startup_ok =
                    bc_hash_throughput_cache_parse_double(value_terminated, &out_constants->parallel_startup_overhead_microseconds);
                continue;
            }
        }
        if (separator_offset == 16) {
            key_equal = false;
            (void)bc_core_equal(line_data, "per_file_cost_us", 16u, &key_equal);
            if (key_equal) {
                per_file_cost_ok = bc_hash_throughput_cache_parse_double(value_terminated, &out_constants->per_file_cost_warm_microseconds);
                continue;
            }
        }
    }
    (void)bc_core_reader_destroy(&reader);
    close(file_descriptor);

    if (!sha256_ok || !crc32c_ok || !memory_bandwidth_ok || !parallel_startup_ok || !per_file_cost_ok) {
        return false;
    }

    char current_cpu_model[BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY];
    char current_microcode[BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY];
    char current_kernel_version[BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY];
    if (!bc_hash_throughput_cache_read_host_signature(current_cpu_model, sizeof(current_cpu_model), current_microcode,
                                                      sizeof(current_microcode), current_kernel_version, sizeof(current_kernel_version))) {
        return false;
    }
    if (!bc_hash_strings_equal(cached_cpu_model, current_cpu_model)) {
        return false;
    }
    if (!bc_hash_strings_equal(cached_microcode, current_microcode)) {
        return false;
    }
    if (!bc_hash_strings_equal(cached_kernel_version, current_kernel_version)) {
        return false;
    }
    return true;
}

static bool bc_hash_throughput_cache_ensure_parent_directory(const char* absolute_cache_path)
{
    char directory_path[BC_HASH_THROUGHPUT_CACHE_LINE_CAPACITY];
    size_t source_length = bc_hash_strings_length(absolute_cache_path);
    if (source_length + 1 > sizeof(directory_path)) {
        return false;
    }
    if (source_length > 0) {
        bc_core_copy(directory_path, absolute_cache_path, source_length);
    }
    directory_path[source_length] = '\0';
    char* last_slash = bc_hash_strings_find_last_byte(directory_path, source_length, '/');
    if (last_slash == NULL || last_slash == directory_path) {
        return true;
    }
    *last_slash = '\0';
    if (mkdir(directory_path, 0755) == 0) {
        return true;
    }
    if (errno == EEXIST) {
        return true;
    }
    return false;
}

bool bc_hash_throughput_cache_store(const char* absolute_cache_path, const bc_hash_throughput_constants_t* constants)
{
    if (!bc_hash_throughput_cache_ensure_parent_directory(absolute_cache_path)) {
        return false;
    }
    char cpu_model[BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY];
    char microcode[BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY];
    char kernel_version[BC_HASH_THROUGHPUT_CACHE_SIGNATURE_CAPACITY];
    if (!bc_hash_throughput_cache_read_host_signature(cpu_model, sizeof(cpu_model), microcode, sizeof(microcode), kernel_version,
                                                      sizeof(kernel_version))) {
        return false;
    }
    int file_descriptor = open(absolute_cache_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (file_descriptor < 0) {
        return false;
    }
    char writer_buffer[BC_HASH_THROUGHPUT_CACHE_WRITER_BUFFER_BYTES];
    bc_core_writer_t writer;
    if (!bc_core_writer_init(&writer, file_descriptor, writer_buffer, sizeof(writer_buffer))) {
        close(file_descriptor);
        return false;
    }
    (void)bc_core_writer_write_cstring(&writer, "cpu_model=");
    (void)bc_core_writer_write_cstring(&writer, cpu_model);
    (void)bc_core_writer_write_cstring(&writer, "\nmicrocode=");
    (void)bc_core_writer_write_cstring(&writer, microcode);
    (void)bc_core_writer_write_cstring(&writer, "\nkernel_version=");
    (void)bc_core_writer_write_cstring(&writer, kernel_version);
    (void)bc_core_writer_write_cstring(&writer, "\nsha256_gbps=");
    (void)bc_core_writer_write_double(&writer, constants->sha256_gigabytes_per_second, 6);
    (void)bc_core_writer_write_cstring(&writer, "\ncrc32c_gbps=");
    (void)bc_core_writer_write_double(&writer, constants->crc32c_gigabytes_per_second, 6);
    (void)bc_core_writer_write_cstring(&writer, "\nmem_bw_gbps=");
    (void)bc_core_writer_write_double(&writer, constants->memory_bandwidth_gigabytes_per_second, 6);
    (void)bc_core_writer_write_cstring(&writer, "\nparallel_startup_us=");
    (void)bc_core_writer_write_double(&writer, constants->parallel_startup_overhead_microseconds, 6);
    (void)bc_core_writer_write_cstring(&writer, "\nper_file_cost_us=");
    (void)bc_core_writer_write_double(&writer, constants->per_file_cost_warm_microseconds, 6);
    (void)bc_core_writer_write_char(&writer, '\n');
    bool error_occurred = bc_core_writer_has_error(&writer);
    (void)bc_core_writer_destroy(&writer);
    int close_status = close(file_descriptor);
    return !error_occurred && close_status == 0;
}

static bool bc_hash_throughput_cache_default_path(char* out_path, size_t path_capacity)
{
    if (path_capacity == 0) {
        return false;
    }
    const char* xdg_cache_home = getenv("XDG_CACHE_HOME");
    bc_core_writer_t path_writer;
    if (xdg_cache_home != NULL && xdg_cache_home[0] != '\0') {
        if (!bc_core_writer_init_buffer_only(&path_writer, out_path, path_capacity - 1)) {
            return false;
        }
        (void)bc_core_writer_write_cstring(&path_writer, xdg_cache_home);
        (void)bc_core_writer_write_cstring(&path_writer, "/bc-hash/throughput.txt");
    } else {
        const char* home = getenv("HOME");
        if (home == NULL || home[0] == '\0') {
            return false;
        }
        if (!bc_core_writer_init_buffer_only(&path_writer, out_path, path_capacity - 1)) {
            return false;
        }
        (void)bc_core_writer_write_cstring(&path_writer, home);
        (void)bc_core_writer_write_cstring(&path_writer, "/.cache/bc-hash/throughput.txt");
    }
    bool error_occurred = bc_core_writer_has_error(&path_writer);
    const char* path_data = NULL;
    size_t path_length = 0;
    (void)bc_core_writer_buffer_data(&path_writer, &path_data, &path_length);
    out_path[path_length] = '\0';
    (void)bc_core_writer_destroy(&path_writer);
    return !error_occurred && path_length > 0;
}

bool bc_hash_throughput_get_or_measure(bc_concurrency_context_t* concurrency_context, bc_hash_throughput_constants_t* out_constants)
{
    char cache_path[BC_HASH_THROUGHPUT_CACHE_LINE_CAPACITY];
    bool have_cache_path = bc_hash_throughput_cache_default_path(cache_path, sizeof(cache_path));

    if (have_cache_path && bc_hash_throughput_cache_load(cache_path, out_constants)) {
        return true;
    }
    if (!bc_hash_throughput_measure(concurrency_context, out_constants)) {
        return false;
    }
    if (have_cache_path) {
        (void)bc_hash_throughput_cache_store(cache_path, out_constants);
    }
    return true;
}
