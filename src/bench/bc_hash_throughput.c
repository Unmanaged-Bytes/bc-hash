// SPDX-License-Identifier: MIT

#include "bc_hash_throughput_internal.h"

#include "bc_concurrency.h"
#include "bc_core.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BC_HASH_THROUGHPUT_BUFFER_BYTES ((size_t)(64 * 1024 * 1024))
#define BC_HASH_THROUGHPUT_BUFFER_ALIGNMENT ((size_t)4096)
#define BC_HASH_THROUGHPUT_HASH_ITERATION_COUNT ((size_t)5)
#define BC_HASH_THROUGHPUT_MEMORY_ITERATION_COUNT ((size_t)5)
#define BC_HASH_THROUGHPUT_STARTUP_ITERATION_COUNT ((size_t)32)
#define BC_HASH_THROUGHPUT_PER_FILE_ITERATION_COUNT ((size_t)256)
#define BC_HASH_THROUGHPUT_PER_FILE_PROBE_SIZE ((size_t)100)

static double bc_hash_throughput_monotonic_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static bool bc_hash_throughput_double_less_than(const void* left, const void* right, void* user_data)
{
    (void)user_data;
    double left_value = *(const double*)left;
    double right_value = *(const double*)right;
    return left_value < right_value;
}

static double bc_hash_throughput_median_seconds(double* samples, size_t sample_count)
{
    bc_core_sort_with_compare(samples, sample_count, sizeof(double), bc_hash_throughput_double_less_than, NULL);
    return samples[sample_count / 2];
}

static bool bc_hash_throughput_allocate_buffer(uint8_t** out_buffer)
{
    void* raw = NULL;
    if (posix_memalign(&raw, BC_HASH_THROUGHPUT_BUFFER_ALIGNMENT, BC_HASH_THROUGHPUT_BUFFER_BYTES) != 0) {
        return false;
    }
    uint8_t* buffer = (uint8_t*)raw;
    for (size_t offset = 0; offset < BC_HASH_THROUGHPUT_BUFFER_BYTES; ++offset) {
        buffer[offset] = (uint8_t)(offset & 0xFFU);
    }
    *out_buffer = buffer;
    return true;
}

static volatile uint64_t bc_hash_throughput_benchmark_sink;

static double bc_hash_throughput_measure_sha256(const uint8_t* buffer)
{
    uint8_t digest[BC_CORE_SHA256_DIGEST_SIZE];
    bc_core_sha256(buffer, BC_HASH_THROUGHPUT_BUFFER_BYTES, digest);
    bc_hash_throughput_benchmark_sink += digest[0];

    double samples[BC_HASH_THROUGHPUT_HASH_ITERATION_COUNT];
    for (size_t iteration_index = 0; iteration_index < BC_HASH_THROUGHPUT_HASH_ITERATION_COUNT; ++iteration_index) {
        double start_seconds = bc_hash_throughput_monotonic_seconds();
        bc_core_sha256(buffer, BC_HASH_THROUGHPUT_BUFFER_BYTES, digest);
        double end_seconds = bc_hash_throughput_monotonic_seconds();
        samples[iteration_index] = end_seconds - start_seconds;
        bc_hash_throughput_benchmark_sink += digest[0];
    }
    double median_seconds = bc_hash_throughput_median_seconds(samples, BC_HASH_THROUGHPUT_HASH_ITERATION_COUNT);
    double bytes_per_second = (double)BC_HASH_THROUGHPUT_BUFFER_BYTES / median_seconds;
    return bytes_per_second / 1e9;
}

static double bc_hash_throughput_measure_crc32c(const uint8_t* buffer)
{
    uint32_t digest = 0;
    bc_core_crc32c(buffer, BC_HASH_THROUGHPUT_BUFFER_BYTES, &digest);
    bc_hash_throughput_benchmark_sink += digest;

    double samples[BC_HASH_THROUGHPUT_HASH_ITERATION_COUNT];
    for (size_t iteration_index = 0; iteration_index < BC_HASH_THROUGHPUT_HASH_ITERATION_COUNT; ++iteration_index) {
        double start_seconds = bc_hash_throughput_monotonic_seconds();
        bc_core_crc32c(buffer, BC_HASH_THROUGHPUT_BUFFER_BYTES, &digest);
        double end_seconds = bc_hash_throughput_monotonic_seconds();
        samples[iteration_index] = end_seconds - start_seconds;
        bc_hash_throughput_benchmark_sink += digest;
    }
    double median_seconds = bc_hash_throughput_median_seconds(samples, BC_HASH_THROUGHPUT_HASH_ITERATION_COUNT);
    double bytes_per_second = (double)BC_HASH_THROUGHPUT_BUFFER_BYTES / median_seconds;
    return bytes_per_second / 1e9;
}

static double bc_hash_throughput_measure_memory_bandwidth_with_copy_fn(uint8_t* buffer,
                                                                       void (*copy_function)(void* destination, const void* source, size_t length))
{
    size_t half_size = BC_HASH_THROUGHPUT_BUFFER_BYTES / 2;
    uint8_t* source_region = buffer;
    uint8_t* destination_region = buffer + half_size;

    copy_function(destination_region, source_region, half_size);
    bc_hash_throughput_benchmark_sink += destination_region[0];

    double samples[BC_HASH_THROUGHPUT_MEMORY_ITERATION_COUNT];
    for (size_t iteration_index = 0; iteration_index < BC_HASH_THROUGHPUT_MEMORY_ITERATION_COUNT; ++iteration_index) {
        double start_seconds = bc_hash_throughput_monotonic_seconds();
        copy_function(destination_region, source_region, half_size);
        double end_seconds = bc_hash_throughput_monotonic_seconds();
        samples[iteration_index] = end_seconds - start_seconds;
        bc_hash_throughput_benchmark_sink += destination_region[0];
    }
    double median_seconds = bc_hash_throughput_median_seconds(samples, BC_HASH_THROUGHPUT_MEMORY_ITERATION_COUNT);
    double bytes_per_second = (double)half_size * 2.0 / median_seconds;
    return bytes_per_second / 1e9;
}

static void bc_hash_throughput_libc_memcpy_adapter(void* destination, const void* source, size_t length)
{
    memcpy(destination, source, length);
}

static void bc_hash_throughput_bc_core_copy_adapter(void* destination, const void* source, size_t length)
{
    (void)bc_core_copy(destination, source, length);
}

static double bc_hash_throughput_measure_memory_bandwidth(uint8_t* buffer)
{
    double memcpy_gbps = bc_hash_throughput_measure_memory_bandwidth_with_copy_fn(buffer, bc_hash_throughput_libc_memcpy_adapter);
    double bc_core_copy_gbps = bc_hash_throughput_measure_memory_bandwidth_with_copy_fn(buffer, bc_hash_throughput_bc_core_copy_adapter);
    return memcpy_gbps > bc_core_copy_gbps ? memcpy_gbps : bc_core_copy_gbps;
}

static void bc_hash_throughput_noop_task(void* task_argument)
{
    (void)task_argument;
}

static double bc_hash_throughput_measure_parallel_startup_overhead(bc_concurrency_context_t* concurrency_context)
{
    size_t effective_worker_count = bc_concurrency_effective_worker_count(concurrency_context);
    if (effective_worker_count < 2) {
        return 0.0;
    }
    size_t task_count = effective_worker_count;

    double cold_start_seconds = bc_hash_throughput_monotonic_seconds();
    for (size_t task_index = 0; task_index < task_count; ++task_index) {
        bc_concurrency_submit(concurrency_context, bc_hash_throughput_noop_task, NULL);
    }
    bc_concurrency_dispatch_and_wait(concurrency_context);
    double cold_end_seconds = bc_hash_throughput_monotonic_seconds();
    double cold_first_dispatch_microseconds = (cold_end_seconds - cold_start_seconds) * 1e6;

    double warm_start_seconds = bc_hash_throughput_monotonic_seconds();
    for (size_t iteration_index = 0; iteration_index < BC_HASH_THROUGHPUT_STARTUP_ITERATION_COUNT; ++iteration_index) {
        for (size_t task_index = 0; task_index < task_count; ++task_index) {
            bc_concurrency_submit(concurrency_context, bc_hash_throughput_noop_task, NULL);
        }
        bc_concurrency_dispatch_and_wait(concurrency_context);
    }
    double warm_end_seconds = bc_hash_throughput_monotonic_seconds();
    double warm_per_iteration_microseconds = ((warm_end_seconds - warm_start_seconds) / (double)BC_HASH_THROUGHPUT_STARTUP_ITERATION_COUNT) * 1e6;

    return cold_first_dispatch_microseconds > warm_per_iteration_microseconds ? cold_first_dispatch_microseconds
                                                                              : warm_per_iteration_microseconds;
}

static double bc_hash_throughput_measure_per_file_cost_warm(void)
{
    char absolute_path[] = "/tmp/bc_hash_throughput_probe_XXXXXX";
    int probe_fd = mkstemp(absolute_path);
    if (probe_fd < 0) {
        return 0.0;
    }
    char probe_payload[BC_HASH_THROUGHPUT_PER_FILE_PROBE_SIZE];
    for (size_t offset = 0; offset < BC_HASH_THROUGHPUT_PER_FILE_PROBE_SIZE; ++offset) {
        probe_payload[offset] = (char)(offset & 0xFFU);
    }
    ssize_t written = write(probe_fd, probe_payload, BC_HASH_THROUGHPUT_PER_FILE_PROBE_SIZE);
    close(probe_fd);
    if (written < 0 || (size_t)written != BC_HASH_THROUGHPUT_PER_FILE_PROBE_SIZE) {
        unlink(absolute_path);
        return 0.0;
    }

    uint8_t read_buffer[BC_HASH_THROUGHPUT_PER_FILE_PROBE_SIZE];
    int warmup_fd = open(absolute_path, O_RDONLY);
    if (warmup_fd >= 0) {
        ssize_t warmup_bytes_read = read(warmup_fd, read_buffer, BC_HASH_THROUGHPUT_PER_FILE_PROBE_SIZE);
        (void)warmup_bytes_read;
        close(warmup_fd);
    }

    double start_seconds = bc_hash_throughput_monotonic_seconds();
    for (size_t iteration_index = 0; iteration_index < BC_HASH_THROUGHPUT_PER_FILE_ITERATION_COUNT; ++iteration_index) {
        int iteration_fd = open(absolute_path, O_RDONLY);
        if (iteration_fd < 0) {
            continue;
        }
        ssize_t bytes_read = read(iteration_fd, read_buffer, BC_HASH_THROUGHPUT_PER_FILE_PROBE_SIZE);
        close(iteration_fd);
        if (bytes_read > 0) {
            uint8_t digest[BC_CORE_SHA256_DIGEST_SIZE];
            bc_core_sha256(read_buffer, (size_t)bytes_read, digest);
        }
    }
    double end_seconds = bc_hash_throughput_monotonic_seconds();
    double total_seconds = end_seconds - start_seconds;

    unlink(absolute_path);

    double per_iteration_seconds = total_seconds / (double)BC_HASH_THROUGHPUT_PER_FILE_ITERATION_COUNT;
    return per_iteration_seconds * 1e6;
}

bool bc_hash_throughput_measure(bc_concurrency_context_t* concurrency_context,
                                bc_hash_throughput_constants_t* out_constants)
{
    uint8_t* buffer = NULL;
    if (!bc_hash_throughput_allocate_buffer(&buffer)) {
        return false;
    }

    out_constants->sha256_gigabytes_per_second = bc_hash_throughput_measure_sha256(buffer);
    out_constants->crc32c_gigabytes_per_second = bc_hash_throughput_measure_crc32c(buffer);
    out_constants->memory_bandwidth_gigabytes_per_second = bc_hash_throughput_measure_memory_bandwidth(buffer);

    free(buffer);

    out_constants->parallel_startup_overhead_microseconds = bc_hash_throughput_measure_parallel_startup_overhead(concurrency_context);
    out_constants->per_file_cost_warm_microseconds = bc_hash_throughput_measure_per_file_cost_warm();

    return true;
}
