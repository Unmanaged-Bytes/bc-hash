// SPDX-License-Identifier: MIT

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include <cmocka.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "bc_hash_reader_internal.h"

typedef struct consumer_state {
    size_t bytes_received;
} consumer_state_t;

static bool record_consumer(void* context, const void* chunk_data, size_t chunk_size)
{
    consumer_state_t* state = (consumer_state_t*)context;
    (void)chunk_data;
    state->bytes_received += chunk_size;
    return true;
}

static int write_file_with_bytes(const char* absolute_path, size_t byte_count)
{
    int file_descriptor = open(absolute_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (file_descriptor < 0) {
        return -1;
    }
    char chunk[4096];
    memset(chunk, 'A', sizeof(chunk));
    size_t remaining = byte_count;
    while (remaining > 0) {
        size_t to_write = remaining > sizeof(chunk) ? sizeof(chunk) : remaining;
        ssize_t written = write(file_descriptor, chunk, to_write);
        if (written <= 0) {
            close(file_descriptor);
            return -1;
        }
        remaining -= (size_t)written;
    }
    close(file_descriptor);
    return 0;
}

static void test_uring_batch_rejects_file_that_grew_between_stat_and_read(void** state)
{
    (void)state;

    char root[256];
    snprintf(root, sizeof(root), "/tmp/bc_hash_ring_growth_%d_%ld", (int)getpid(), (long)time(NULL));
    assert_int_equal(mkdir(root, 0755), 0);

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/victim.bin", root);

    const size_t stale_size = 1024U;
    const size_t actual_size = 4096U;
    assert_int_equal(write_file_with_bytes(file_path, actual_size), 0);

    size_t ring_size = bc_hash_reader_ring_struct_size();
    bc_hash_reader_ring_t* ring = (bc_hash_reader_ring_t*)malloc(ring_size);
    assert_non_null(ring);
    assert_true(bc_hash_reader_ring_init(ring));

    consumer_state_t consumer = {0};
    bc_hash_reader_batch_item_t item = {0};
    item.absolute_path = file_path;
    item.file_size = stale_size;
    item.consumer_context = &consumer;

    assert_true(bc_hash_reader_consume_batch(ring, &item, 1U, record_consumer));
    assert_false(item.success);

    bc_hash_reader_ring_destroy(ring);
    free(ring);

    unlink(file_path);
    rmdir(root);
}

static void test_uring_batch_accepts_file_whose_size_matches(void** state)
{
    (void)state;

    char root[256];
    snprintf(root, sizeof(root), "/tmp/bc_hash_ring_growth_ok_%d_%ld", (int)getpid(), (long)time(NULL));
    assert_int_equal(mkdir(root, 0755), 0);

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/stable.bin", root);

    const size_t actual_size = 4096U;
    assert_int_equal(write_file_with_bytes(file_path, actual_size), 0);

    size_t ring_size = bc_hash_reader_ring_struct_size();
    bc_hash_reader_ring_t* ring = (bc_hash_reader_ring_t*)malloc(ring_size);
    assert_non_null(ring);
    assert_true(bc_hash_reader_ring_init(ring));

    consumer_state_t consumer = {0};
    bc_hash_reader_batch_item_t item = {0};
    item.absolute_path = file_path;
    item.file_size = actual_size;
    item.consumer_context = &consumer;

    assert_true(bc_hash_reader_consume_batch(ring, &item, 1U, record_consumer));
    assert_true(item.success);
    assert_int_equal(consumer.bytes_received, actual_size);

    bc_hash_reader_ring_destroy(ring);
    free(ring);

    unlink(file_path);
    rmdir(root);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_uring_batch_rejects_file_that_grew_between_stat_and_read),
        cmocka_unit_test(test_uring_batch_accepts_file_whose_size_matches),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
