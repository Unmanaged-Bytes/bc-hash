// SPDX-License-Identifier: MIT

#ifndef BC_HASH_DIRENT_INTERNAL_H
#define BC_HASH_DIRENT_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define BC_HASH_DIRENT_BUFFER_SIZE ((size_t)8192)

typedef struct bc_hash_dirent_reader {
    int dir_fd;
    int last_errno;
    ssize_t buffer_used;
    size_t cursor;
    char buffer[BC_HASH_DIRENT_BUFFER_SIZE];
} bc_hash_dirent_reader_t;

typedef struct bc_hash_dirent_entry {
    const char* name;
    size_t name_length;
    unsigned char d_type;
} bc_hash_dirent_entry_t;

void bc_hash_dirent_reader_init(bc_hash_dirent_reader_t* reader, int dir_fd);

bool bc_hash_dirent_reader_next(bc_hash_dirent_reader_t* reader, bc_hash_dirent_entry_t* out_entry, bool* out_has_entry);

#endif /* BC_HASH_DIRENT_INTERNAL_H */
