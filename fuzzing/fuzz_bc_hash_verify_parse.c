// SPDX-License-Identifier: MIT

#include "bc_allocators.h"
#include "bc_containers_vector.h"
#include "bc_core_parse.h"
#include "bc_hash_types_internal.h"
#include "bc_hash_verify_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    char path[] = "/tmp/bc_hash_fuzz_digest_XXXXXX";
    const int fd = mkstemp(path);
    if (fd < 0) {
        return 0;
    }
    const ssize_t written = write(fd, data, size);
    (void)written;
    close(fd);

    bc_allocators_context_t* memory_context = NULL;
    if (!bc_allocators_context_create(NULL, &memory_context)) {
        unlink(path);
        return 0;
    }

    bc_containers_vector_t* expectations = NULL;
    if (!bc_containers_vector_create(memory_context, sizeof(bc_hash_verify_expectation_t), 16, 1u << 20, &expectations)) {
        bc_allocators_context_destroy(memory_context);
        unlink(path);
        return 0;
    }

    bc_hash_algorithm_t algorithm = BC_HASH_ALGORITHM_SHA256;
    (void)bc_hash_verify_parse_digest_file(memory_context, path, expectations, &algorithm);

    bc_containers_vector_destroy(memory_context, expectations);
    bc_allocators_context_destroy(memory_context);
    unlink(path);
    return 0;
}

#ifndef BC_FUZZ_LIBFUZZER
int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <iterations> [seed]\n", argv[0]);
        return 2;
    }
    uint64_t iterations = 0;
    size_t consumed = 0;
    if (!bc_core_parse_unsigned_integer_64_decimal(argv[1], strlen(argv[1]), &iterations, &consumed) || consumed != strlen(argv[1])) {
        fprintf(stderr, "invalid iterations: %s\n", argv[1]);
        return 2;
    }
    uint64_t seed = 0;
    if (argc >= 3) {
        if (!bc_core_parse_unsigned_integer_64_decimal(argv[2], strlen(argv[2]), &seed, &consumed) || consumed != strlen(argv[2])) {
            fprintf(stderr, "invalid seed: %s\n", argv[2]);
            return 2;
        }
    }
    srand((unsigned int)seed);

    uint8_t buffer[8192];
    for (uint64_t i = 0; i < iterations; i++) {
        const size_t length = (size_t)(rand() % (int)sizeof(buffer));
        for (size_t j = 0; j < length; j++) {
            buffer[j] = (uint8_t)(rand() & 0xFF);
        }
        LLVMFuzzerTestOneInput(buffer, length);
    }
    return 0;
}
#endif
