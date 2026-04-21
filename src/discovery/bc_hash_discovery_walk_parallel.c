// SPDX-License-Identifier: MIT

#include "bc_io_dirent_reader.h"
#include "bc_hash_discovery_internal.h"
#include "bc_hash_strings_internal.h"

#include "bc_allocators_pool.h"
#include "bc_concurrency.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_io_file.h"
#include "bc_io_file_open.h"
#include "bc_io_file_path.h"
#include "bc_io_mmap.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BC_HASH_WALK_PARALLEL_QUEUE_CAPACITY ((size_t)16384)
#define BC_HASH_WALK_PARALLEL_INITIAL_VECTOR_CAPACITY ((size_t)1024)
#define BC_HASH_WALK_PARALLEL_MAX_VECTOR_CAPACITY ((size_t)1U << 28)
#define BC_HASH_WALK_PARALLEL_TERMINATION_SPIN_PAUSES ((int)64)

typedef struct bc_hash_walk_parallel_queue_entry {
    char absolute_path[BC_IO_MAX_PATH_LENGTH];
    size_t absolute_path_length;
} bc_hash_walk_parallel_queue_entry_t;

typedef struct bc_hash_walk_parallel_worker_slot {
    bc_containers_vector_t* file_entries;
    bc_runtime_error_collector_t* errors;
    char cache_line_padding[BC_CACHE_LINE_SIZE - 2 * sizeof(void*)];
} bc_hash_walk_parallel_worker_slot_t;

typedef struct bc_hash_walk_parallel_shared {
    bc_concurrency_queue_t* directory_queue;
    size_t worker_slot_index;
    _Atomic int outstanding_directory_count;
    bc_allocators_context_t* main_memory_context;
    bc_concurrency_signal_handler_t* signal_handler;
    const bc_hash_filter_t* filter;
} bc_hash_walk_parallel_shared_t;

static bool bc_hash_walk_parallel_should_stop(const bc_hash_walk_parallel_shared_t* shared)
{
    if (shared->signal_handler == NULL) {
        return false;
    }
    bool should_stop = false;
    bc_concurrency_signal_handler_should_stop(shared->signal_handler, &should_stop);
    return should_stop;
}

static bool bc_hash_walk_parallel_ensure_worker_slot(const bc_hash_walk_parallel_shared_t* shared, bc_allocators_context_t* worker_memory,
                                                    bc_hash_walk_parallel_worker_slot_t** out_slot)
{
    bc_hash_walk_parallel_worker_slot_t* slot = (bc_hash_walk_parallel_worker_slot_t*)bc_concurrency_worker_slot(shared->worker_slot_index);
    if (slot == NULL) {
        return false;
    }
    if (slot->file_entries == NULL) {
        if (!bc_containers_vector_create(worker_memory, sizeof(bc_hash_file_entry_t), BC_HASH_WALK_PARALLEL_INITIAL_VECTOR_CAPACITY,
                                         BC_HASH_WALK_PARALLEL_MAX_VECTOR_CAPACITY, &slot->file_entries)) {
            return false;
        }
    }
    if (slot->errors == NULL) {
        if (!bc_runtime_error_collector_create(worker_memory, &slot->errors)) {
            return false;
        }
    }
    *out_slot = slot;
    return true;
}

static bool bc_hash_walk_parallel_append_file_entry(bc_allocators_context_t* worker_memory, bc_containers_vector_t* worker_vector,
                                                   const char* absolute_path, size_t absolute_path_length, size_t file_size)
{
    if (file_size == 0) {
        return true;
    }
    char* path_copy = NULL;
    if (!bc_allocators_pool_allocate(worker_memory, absolute_path_length + 1, (void**)&path_copy)) {
        return false;
    }
    bc_core_copy(path_copy, absolute_path, absolute_path_length);
    path_copy[absolute_path_length] = '\0';

    bc_hash_file_entry_t entry = {
        .absolute_path = path_copy,
        .absolute_path_length = absolute_path_length,
        .file_size = file_size,
    };
    if (!bc_containers_vector_push(worker_memory, worker_vector, &entry)) {
        bc_allocators_pool_free(worker_memory, path_copy);
        return false;
    }
    return true;
}

static void bc_hash_walk_parallel_process_directory(bc_hash_walk_parallel_shared_t* shared, bc_allocators_context_t* worker_memory,
                                                    bc_hash_walk_parallel_worker_slot_t* worker_slot, const char* directory_path,
                                                    size_t directory_path_length)
{
    int directory_file_descriptor = open(directory_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_file_descriptor < 0) {
        bc_runtime_error_collector_append(worker_slot->errors, worker_memory, directory_path, "open", errno);
        return;
    }

    bc_io_dirent_reader_t dirent_reader;
    bc_io_dirent_reader_init(&dirent_reader, directory_file_descriptor);

    for (;;) {
        bc_io_dirent_entry_t current_entry;
        bool has_entry = false;
        if (!bc_io_dirent_reader_next(&dirent_reader, &current_entry, &has_entry)) {
            bc_runtime_error_collector_append(worker_slot->errors, worker_memory, directory_path, "getdents64", dirent_reader.last_errno);
            break;
        }
        if (!has_entry) {
            break;
        }
        if (current_entry.name[0] == '.') {
            continue;
        }

        const char* entry_name = current_entry.name;
        size_t entry_name_length = current_entry.name_length;
        char child_path_buffer[BC_IO_MAX_PATH_LENGTH];
        size_t child_path_length = 0;
        if (!bc_io_file_path_join(child_path_buffer, sizeof(child_path_buffer), directory_path, directory_path_length, entry_name,
                                  entry_name_length, &child_path_length)) {
            bc_runtime_error_collector_append(worker_slot->errors, worker_memory, directory_path, "path-too-long", ENAMETOOLONG);
            continue;
        }

        bc_io_file_entry_type_t entry_type = BC_IO_ENTRY_TYPE_OTHER;
        size_t resolved_file_size = 0;
        bool size_already_known = false;
        if (current_entry.d_type != DT_UNKNOWN) {
            bc_io_file_dtype_to_entry_type(current_entry.d_type, &entry_type);
        } else {
            dev_t device_value = 0;
            ino_t inode_value = 0;
            time_t modification_time_value = 0;
            if (!bc_io_file_stat_if_unknown(directory_file_descriptor, entry_name, &entry_type, &device_value, &inode_value,
                                            &resolved_file_size, &modification_time_value)) {
                bc_runtime_error_collector_append(worker_slot->errors, worker_memory, child_path_buffer, "stat", errno);
                continue;
            }
            size_already_known = true;
        }

        switch (entry_type) {
        case BC_IO_ENTRY_TYPE_FILE: {
            if (!bc_hash_filter_accepts_file(shared->filter, entry_name)) {
                break;
            }
            if (!size_already_known) {
                struct stat file_stat_buffer;
                if (fstatat(directory_file_descriptor, entry_name, &file_stat_buffer, AT_SYMLINK_NOFOLLOW) != 0) {
                    bc_runtime_error_collector_append(worker_slot->errors, worker_memory, child_path_buffer, "stat", errno);
                    continue;
                }
                resolved_file_size = (size_t)file_stat_buffer.st_size;
            }
            if (!bc_hash_walk_parallel_append_file_entry(worker_memory, worker_slot->file_entries, child_path_buffer, child_path_length,
                                                        resolved_file_size)) {
                bc_runtime_error_collector_append(worker_slot->errors, worker_memory, child_path_buffer, "enqueue", ENOMEM);
            }
            break;
        }
        case BC_IO_ENTRY_TYPE_DIRECTORY: {
            if (!bc_hash_filter_accepts_directory(shared->filter, entry_name)) {
                break;
            }
            bc_hash_walk_parallel_queue_entry_t sub_entry;
            bc_core_zero(&sub_entry, sizeof(sub_entry));
            bc_core_copy(sub_entry.absolute_path, child_path_buffer, child_path_length);
            sub_entry.absolute_path_length = child_path_length;
            sub_entry.absolute_path[child_path_length] = '\0';

            atomic_fetch_add_explicit(&shared->outstanding_directory_count, 1, memory_order_relaxed);
            if (!bc_concurrency_queue_push(shared->directory_queue, &sub_entry)) {
                atomic_fetch_sub_explicit(&shared->outstanding_directory_count, 1, memory_order_relaxed);
                bc_hash_walk_parallel_process_directory(shared, worker_memory, worker_slot, sub_entry.absolute_path,
                                                        sub_entry.absolute_path_length);
            }
            break;
        }
        case BC_IO_ENTRY_TYPE_SYMLINK:
        case BC_IO_ENTRY_TYPE_OTHER:
        default:
            break;
        }
    }

    close(directory_file_descriptor);
}

static void bc_hash_walk_parallel_worker_task(void* task_argument)
{
    bc_hash_walk_parallel_shared_t* shared = (bc_hash_walk_parallel_shared_t*)task_argument;
    bc_allocators_context_t* worker_memory = bc_concurrency_worker_memory();
    if (worker_memory == NULL) {
        worker_memory = shared->main_memory_context;
    }
    bc_hash_walk_parallel_worker_slot_t* worker_slot = NULL;
    if (!bc_hash_walk_parallel_ensure_worker_slot(shared, worker_memory, &worker_slot)) {
        return;
    }

    for (;;) {
        if (bc_hash_walk_parallel_should_stop(shared)) {
            return;
        }
        bc_hash_walk_parallel_queue_entry_t entry;
        if (bc_concurrency_queue_pop(shared->directory_queue, &entry)) {
            bc_hash_walk_parallel_process_directory(shared, worker_memory, worker_slot, entry.absolute_path, entry.absolute_path_length);
            atomic_fetch_sub_explicit(&shared->outstanding_directory_count, 1, memory_order_release);
            continue;
        }
        int outstanding = atomic_load_explicit(&shared->outstanding_directory_count, memory_order_acquire);
        if (outstanding == 0) {
            return;
        }
        for (int spin = 0; spin < BC_HASH_WALK_PARALLEL_TERMINATION_SPIN_PAUSES; ++spin) {
        }
    }
}

typedef struct bc_hash_walk_parallel_merge_argument {
    bc_containers_vector_t* destination_entries;
    bc_allocators_context_t* destination_memory_context;
    bool ok;
} bc_hash_walk_parallel_merge_argument_t;

/* cppcheck-suppress constParameterCallback; signature fixed by bc_concurrency_foreach_slot */
static void bc_hash_walk_parallel_merge_worker_slot(void* slot_data, size_t worker_index, void* arg)
{
    (void)worker_index;
    const bc_hash_walk_parallel_worker_slot_t* slot = (const bc_hash_walk_parallel_worker_slot_t*)slot_data;
    bc_hash_walk_parallel_merge_argument_t* merge_argument = (bc_hash_walk_parallel_merge_argument_t*)arg;
    if (!merge_argument->ok) {
        return;
    }
    if (slot->file_entries != NULL) {
        size_t count = bc_containers_vector_length(slot->file_entries);
        for (size_t entry_index = 0; entry_index < count; ++entry_index) {
            bc_hash_file_entry_t entry;
            if (!bc_containers_vector_get(slot->file_entries, entry_index, &entry)) {
                merge_argument->ok = false;
                return;
            }
            if (!bc_containers_vector_push(merge_argument->destination_memory_context, merge_argument->destination_entries, &entry)) {
                merge_argument->ok = false;
                return;
            }
        }
    }
    if (slot->errors != NULL) {
        bc_runtime_error_collector_flush_to_stderr(slot->errors, "bc-hash");
    }
}

static bool bc_hash_walk_parallel_append_root_file(bc_allocators_context_t* memory_context, bc_containers_vector_t* destination_entries,
                                                   bc_runtime_error_collector_t* errors, const char* input_path, size_t file_size)
{
    if (file_size == 0) {
        return true;
    }
    size_t input_path_length = bc_hash_strings_length(input_path);
    char* path_copy = NULL;
    if (!bc_allocators_pool_allocate(memory_context, input_path_length + 1, (void**)&path_copy)) {
        bc_runtime_error_collector_append(errors, memory_context, input_path, "allocate", ENOMEM);
        return false;
    }
    bc_core_copy(path_copy, input_path, input_path_length);
    path_copy[input_path_length] = '\0';

    bc_hash_file_entry_t entry = {
        .absolute_path = path_copy,
        .absolute_path_length = input_path_length,
        .file_size = file_size,
    };
    if (!bc_containers_vector_push(memory_context, destination_entries, &entry)) {
        bc_allocators_pool_free(memory_context, path_copy);
        bc_runtime_error_collector_append(errors, memory_context, input_path, "enqueue", ENOMEM);
        return false;
    }
    return true;
}

static bool bc_hash_walk_parallel_push_root_directory(bc_hash_walk_parallel_shared_t* shared, bc_runtime_error_collector_t* errors,
                                                     const char* input_path)
{
    size_t input_path_length = bc_hash_strings_length(input_path);
    while (input_path_length > 1 && input_path[input_path_length - 1] == '/') {
        input_path_length -= 1;
    }
    if (input_path_length >= BC_IO_MAX_PATH_LENGTH) {
        bc_runtime_error_collector_append(errors, shared->main_memory_context, input_path, "path-too-long", ENAMETOOLONG);
        return false;
    }

    bc_hash_walk_parallel_queue_entry_t queue_entry;
    bc_core_zero(&queue_entry, sizeof(queue_entry));
    bc_core_copy(queue_entry.absolute_path, input_path, input_path_length);
    queue_entry.absolute_path_length = input_path_length;
    queue_entry.absolute_path[input_path_length] = '\0';

    atomic_fetch_add_explicit(&shared->outstanding_directory_count, 1, memory_order_relaxed);
    if (!bc_concurrency_queue_push(shared->directory_queue, &queue_entry)) {
        atomic_fetch_sub_explicit(&shared->outstanding_directory_count, 1, memory_order_relaxed);
        bc_runtime_error_collector_append(errors, shared->main_memory_context, input_path, "enqueue", ENOSPC);
        return false;
    }
    return true;
}

static void bc_hash_walk_parallel_process_input_path(bc_hash_walk_parallel_shared_t* shared, bc_containers_vector_t* destination_entries,
                                                     bc_runtime_error_collector_t* errors, const char* input_path)
{
    struct stat input_stat_buffer;
    if (fstatat(AT_FDCWD, input_path, &input_stat_buffer, AT_SYMLINK_NOFOLLOW) != 0) {
        bc_runtime_error_collector_append(errors, shared->main_memory_context, input_path, "stat", errno);
        return;
    }
    if (S_ISREG(input_stat_buffer.st_mode)) {
        bc_hash_walk_parallel_append_root_file(shared->main_memory_context, destination_entries, errors, input_path,
                                               (size_t)input_stat_buffer.st_size);
    } else if (S_ISDIR(input_stat_buffer.st_mode)) {
        bc_hash_walk_parallel_push_root_directory(shared, errors, input_path);
    } else if (S_ISLNK(input_stat_buffer.st_mode)) {
        bc_runtime_error_collector_append(errors, shared->main_memory_context, input_path, "skip-symlink", ELOOP);
    } else {
        bc_runtime_error_collector_append(errors, shared->main_memory_context, input_path, "skip-other", EINVAL);
    }
}

static void bc_hash_walk_parallel_expand_glob(bc_hash_walk_parallel_shared_t* shared, bc_containers_vector_t* destination_entries,
                                              bc_runtime_error_collector_t* errors, const char* pattern)
{
    glob_t glob_buffer;
    int glob_flags = GLOB_NOSORT | GLOB_NOCHECK | GLOB_NOMAGIC;
    int glob_result = glob(pattern, glob_flags, NULL, &glob_buffer);
    if (glob_result != 0) {
        bc_runtime_error_collector_append(errors, shared->main_memory_context, pattern, "glob", EINVAL);
        globfree(&glob_buffer);
        return;
    }
    for (size_t index = 0; index < glob_buffer.gl_pathc; ++index) {
        bc_hash_walk_parallel_process_input_path(shared, destination_entries, errors, glob_buffer.gl_pathv[index]);
    }
    globfree(&glob_buffer);
}

bool bc_hash_discovery_expand_parallel(bc_allocators_context_t* memory_context, bc_concurrency_context_t* concurrency_context,
                                       bc_containers_vector_t* entries, bc_runtime_error_collector_t* errors,
                                       bc_concurrency_signal_handler_t* signal_handler, const bc_hash_filter_t* filter,
                                       const char* const* input_paths, size_t input_count)
{
    bc_hash_walk_parallel_shared_t shared;
    bc_core_zero(&shared, sizeof(shared));
    shared.main_memory_context = memory_context;
    shared.signal_handler = signal_handler;
    shared.filter = filter;
    atomic_store_explicit(&shared.outstanding_directory_count, 0, memory_order_relaxed);

    if (!bc_concurrency_queue_create(memory_context, sizeof(bc_hash_walk_parallel_queue_entry_t), BC_HASH_WALK_PARALLEL_QUEUE_CAPACITY,
                                     &shared.directory_queue)) {
        return false;
    }

    bc_concurrency_slot_config_t slot_config = {
        .size = sizeof(bc_hash_walk_parallel_worker_slot_t),
        .init = NULL,
        .destroy = NULL,
        .arg = NULL,
    };
    if (!bc_concurrency_register_slot(concurrency_context, &slot_config, &shared.worker_slot_index)) {
        bc_concurrency_queue_destroy(shared.directory_queue);
        return false;
    }

    for (size_t input_index = 0; input_index < input_count; ++input_index) {
        const char* input_path = input_paths[input_index];
        bool contains_metacharacter = false;
        bc_hash_discovery_glob_contains_metacharacter(input_path, &contains_metacharacter);
        if (contains_metacharacter) {
            bc_hash_walk_parallel_expand_glob(&shared, entries, errors, input_path);
        } else {
            bc_hash_walk_parallel_process_input_path(&shared, entries, errors, input_path);
        }
    }

    size_t effective_worker_count = bc_concurrency_effective_worker_count(concurrency_context);
    for (size_t worker_index = 0; worker_index < effective_worker_count; ++worker_index) {
        bc_concurrency_submit(concurrency_context, bc_hash_walk_parallel_worker_task, &shared);
    }
    bc_concurrency_dispatch_and_wait(concurrency_context);

    bc_hash_walk_parallel_merge_argument_t merge_argument = {
        .destination_entries = entries,
        .destination_memory_context = memory_context,
        .ok = true,
    };
    bc_concurrency_foreach_slot(concurrency_context, shared.worker_slot_index, bc_hash_walk_parallel_merge_worker_slot, &merge_argument);

    bc_concurrency_queue_destroy(shared.directory_queue);

    return merge_argument.ok;
}
