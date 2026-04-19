// SPDX-License-Identifier: MIT

#include "bc_hash_reader_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#define BC_HASH_READER_STREAM_BUFFER_SIZE ((size_t)(128 * 1024))
#define BC_HASH_READER_FADVISE_THRESHOLD BC_HASH_READER_STREAM_BUFFER_SIZE

static bool bc_hash_reader_open_read_only(const char* absolute_path, int* out_file_descriptor, int* out_errno_value)
{
    int flags_with_noatime = O_RDONLY | O_CLOEXEC | O_NOATIME;
    int file_descriptor = open(absolute_path, flags_with_noatime);
    if (file_descriptor < 0 && errno == EPERM) {
        int flags_without_noatime = O_RDONLY | O_CLOEXEC;
        file_descriptor = open(absolute_path, flags_without_noatime);
    }
    if (file_descriptor < 0) {
        *out_errno_value = errno;
        return false;
    }
    *out_file_descriptor = file_descriptor;
    return true;
}

bool bc_hash_reader_consume_file(const char* absolute_path, size_t file_size_hint, void* consumer_context,
                                 bc_hash_reader_consumer_fn_t consumer_function, int* out_errno_value)
{
    *out_errno_value = 0;

    int file_descriptor = -1;
    if (!bc_hash_reader_open_read_only(absolute_path, &file_descriptor, out_errno_value)) {
        return false;
    }

    if (file_size_hint > BC_HASH_READER_FADVISE_THRESHOLD) {
        posix_fadvise(file_descriptor, (off_t)0, (off_t)0, POSIX_FADV_SEQUENTIAL);
    }

    unsigned char stream_buffer[BC_HASH_READER_STREAM_BUFFER_SIZE] __attribute__((aligned(64)));

    while (true) {
        ssize_t bytes_read = read(file_descriptor, stream_buffer, sizeof(stream_buffer));
        if (bytes_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            *out_errno_value = errno;
            close(file_descriptor);
            return false;
        }
        if (bytes_read == 0) {
            close(file_descriptor);
            return true;
        }
        if (!consumer_function(consumer_context, stream_buffer, (size_t)bytes_read)) {
            *out_errno_value = EIO;
            close(file_descriptor);
            return false;
        }
        if ((size_t)bytes_read < sizeof(stream_buffer)) {
            close(file_descriptor);
            return true;
        }
    }
}
