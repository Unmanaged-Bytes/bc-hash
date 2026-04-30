// SPDX-License-Identifier: MIT

#include "bc_hash_discovery_internal.h"
#include "bc_hash_strings_internal.h"

#include "bc_allocators_pool.h"
#include "bc_concurrency.h"
#include "bc_containers_vector.h"
#include "bc_core.h"
#include "bc_io_file.h"
#include "bc_io_walk.h"
#include "bc_runtime_error_collector.h"
#include "bc_runtime_signal.h"

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BC_HASH_WALK_INITIAL_VECTOR_CAPACITY ((size_t)1024)
#define BC_HASH_WALK_MAX_VECTOR_CAPACITY ((size_t)1U << 28)

typedef struct bc_hash_walk_worker_slot {
    bc_containers_vector_t* file_entries;
    bc_runtime_error_collector_t* errors;
    BC_PAD_TO_CACHE_LINE(2 * sizeof(void*));
} bc_hash_walk_worker_slot_t;

typedef struct bc_hash_walk_context {
    size_t worker_slot_index;
    bc_allocators_context_t* main_memory_context;
    const bc_hash_filter_t* filter;
} bc_hash_walk_context_t;

/* cppcheck-suppress constParameterCallback; signature fixed by bc_io_walk_should_stop_fn */
static bool bc_hash_walk_should_stop_check(void* user_data)
{
    const bc_runtime_signal_handler_t* handler = (const bc_runtime_signal_handler_t*)user_data;
    if (handler == NULL) {
        return false;
    }
    bool should_stop = false;
    bc_runtime_signal_handler_should_stop(handler, &should_stop);
    return should_stop;
}

static const char* bc_hash_walk_basename(const char* path, size_t path_length)
{
    if (path_length == 0) {
        return path;
    }
    for (size_t index = path_length; index > 0; --index) {
        if (path[index - 1] == '/') {
            return path + index;
        }
    }
    return path;
}

static bool bc_hash_walk_ensure_slot(const bc_hash_walk_context_t* context, bc_allocators_context_t* worker_memory,
                                     bc_hash_walk_worker_slot_t** out_slot)
{
    bc_hash_walk_worker_slot_t* slot = (bc_hash_walk_worker_slot_t*)bc_concurrency_worker_slot(context->worker_slot_index);
    if (slot == NULL) {
        return false;
    }
    if (slot->file_entries == NULL) {
        if (!bc_containers_vector_create(worker_memory, sizeof(bc_hash_file_entry_t), BC_HASH_WALK_INITIAL_VECTOR_CAPACITY,
                                         BC_HASH_WALK_MAX_VECTOR_CAPACITY, &slot->file_entries)) {
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

/* cppcheck-suppress constParameterCallback; signature fixed by bc_io_walk_filter_fn */
static bool bc_hash_walk_filter(const bc_io_walk_entry_t* entry, void* user_data)
{
    const bc_hash_walk_context_t* context = (const bc_hash_walk_context_t*)user_data;
    const char* basename = bc_hash_walk_basename(entry->absolute_path, entry->absolute_path_length);
    if (entry->kind == BC_IO_WALK_ENTRY_FILE) {
        return bc_hash_filter_accepts_file(context->filter, basename);
    }
    if (entry->kind == BC_IO_WALK_ENTRY_DIRECTORY) {
        return bc_hash_filter_accepts_directory(context->filter, basename);
    }
    return false;
}

/* cppcheck-suppress constParameterCallback; signature fixed by bc_io_walk_visit_fn */
static bool bc_hash_walk_visit(const bc_io_walk_entry_t* entry, void* user_data)
{
    if (entry->kind != BC_IO_WALK_ENTRY_FILE) {
        return true;
    }
    if (entry->file_size == 0) {
        return true;
    }

    const bc_hash_walk_context_t* context = (const bc_hash_walk_context_t*)user_data;
    bc_allocators_context_t* worker_memory = bc_concurrency_worker_memory();
    if (worker_memory == NULL) {
        worker_memory = context->main_memory_context;
    }

    bc_hash_walk_worker_slot_t* slot = NULL;
    if (!bc_hash_walk_ensure_slot(context, worker_memory, &slot)) {
        return false;
    }

    char* path_copy = NULL;
    if (!bc_allocators_pool_allocate(worker_memory, entry->absolute_path_length + 1, (void**)&path_copy)) {
        return false;
    }
    bc_core_copy(path_copy, entry->absolute_path, entry->absolute_path_length);
    path_copy[entry->absolute_path_length] = '\0';

    bc_hash_file_entry_t file_entry = {
        .absolute_path = path_copy,
        .absolute_path_length = entry->absolute_path_length,
        .file_size = entry->file_size,
    };
    if (!bc_containers_vector_push(worker_memory, slot->file_entries, &file_entry)) {
        bc_allocators_pool_free(worker_memory, path_copy);
        return false;
    }
    return true;
}

/* cppcheck-suppress constParameterCallback; signature fixed by bc_io_walk_error_fn */
static void bc_hash_walk_on_error(const char* path, const char* stage, int errno_value, void* user_data)
{
    const bc_hash_walk_context_t* context = (const bc_hash_walk_context_t*)user_data;
    bc_allocators_context_t* worker_memory = bc_concurrency_worker_memory();
    if (worker_memory == NULL) {
        worker_memory = context->main_memory_context;
    }
    bc_hash_walk_worker_slot_t* slot = NULL;
    if (!bc_hash_walk_ensure_slot(context, worker_memory, &slot)) {
        return;
    }
    (void)bc_runtime_error_collector_append(slot->errors, worker_memory, path, stage, errno_value);
}

typedef struct bc_hash_walk_merge_argument {
    bc_containers_vector_t* destination_entries;
    bc_allocators_context_t* destination_memory_context;
    bool ok;
} bc_hash_walk_merge_argument_t;

/* cppcheck-suppress constParameterCallback; signature fixed by bc_concurrency_foreach_slot */
static void bc_hash_walk_merge_worker_slot(void* slot_data, size_t worker_index, void* arg)
{
    (void)worker_index;
    const bc_hash_walk_worker_slot_t* slot = (const bc_hash_walk_worker_slot_t*)slot_data;
    bc_hash_walk_merge_argument_t* merge_argument = (bc_hash_walk_merge_argument_t*)arg;
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

static bool bc_hash_walk_append_root_file(bc_allocators_context_t* memory_context, bc_containers_vector_t* destination_entries,
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

static void bc_hash_walk_run_on_directory(bc_hash_walk_context_t* context, bc_allocators_context_t* memory_context,
                                          bc_concurrency_context_t* concurrency_context, bc_runtime_error_collector_t* errors,
                                          bc_runtime_signal_handler_t* signal_handler, const char* input_path)
{
    size_t input_path_length = bc_hash_strings_length(input_path);
    while (input_path_length > 1 && input_path[input_path_length - 1] == '/') {
        input_path_length -= 1;
    }
    if (input_path_length >= BC_IO_MAX_PATH_LENGTH) {
        bc_runtime_error_collector_append(errors, memory_context, input_path, "path-too-long", ENAMETOOLONG);
        return;
    }

    bc_io_walk_config_t config = {
        .root = input_path,
        .root_length = input_path_length,
        .main_memory_context = memory_context,
        .concurrency_context = concurrency_context,
        .should_stop_check = bc_hash_walk_should_stop_check,
        .should_stop_user_data = signal_handler,
        .queue_capacity = 0,
        .filter = bc_hash_walk_filter,
        .filter_user_data = context,
        .visit = bc_hash_walk_visit,
        .visit_user_data = context,
        .on_error = bc_hash_walk_on_error,
        .error_user_data = context,
    };
    bc_io_walk_stats_t stats;
    (void)bc_io_walk_parallel(&config, &stats);
}

static void bc_hash_walk_process_input_path(bc_hash_walk_context_t* context, bc_allocators_context_t* memory_context,
                                            bc_concurrency_context_t* concurrency_context, bc_containers_vector_t* destination_entries,
                                            bc_runtime_error_collector_t* errors, bc_runtime_signal_handler_t* signal_handler,
                                            const char* input_path)
{
    struct stat input_stat_buffer;
    if (fstatat(AT_FDCWD, input_path, &input_stat_buffer, AT_SYMLINK_NOFOLLOW) != 0) {
        bc_runtime_error_collector_append(errors, memory_context, input_path, "stat", errno);
        return;
    }
    if (S_ISREG(input_stat_buffer.st_mode)) {
        bc_hash_walk_append_root_file(memory_context, destination_entries, errors, input_path, (size_t)input_stat_buffer.st_size);
    } else if (S_ISDIR(input_stat_buffer.st_mode)) {
        bc_hash_walk_run_on_directory(context, memory_context, concurrency_context, errors, signal_handler, input_path);
    } else if (S_ISLNK(input_stat_buffer.st_mode)) {
        bc_runtime_error_collector_append(errors, memory_context, input_path, "skip-symlink", ELOOP);
    } else {
        bc_runtime_error_collector_append(errors, memory_context, input_path, "skip-other", EINVAL);
    }
}

static void bc_hash_walk_expand_glob(bc_hash_walk_context_t* context, bc_allocators_context_t* memory_context,
                                     bc_concurrency_context_t* concurrency_context, bc_containers_vector_t* destination_entries,
                                     bc_runtime_error_collector_t* errors, bc_runtime_signal_handler_t* signal_handler,
                                     const char* pattern)
{
    glob_t glob_buffer;
    int glob_flags = GLOB_NOSORT | GLOB_NOCHECK | GLOB_NOMAGIC;
    int glob_result = glob(pattern, glob_flags, NULL, &glob_buffer);
    if (glob_result != 0) {
        bc_runtime_error_collector_append(errors, memory_context, pattern, "glob", EINVAL);
        globfree(&glob_buffer);
        return;
    }
    for (size_t index = 0; index < glob_buffer.gl_pathc; ++index) {
        bc_hash_walk_process_input_path(context, memory_context, concurrency_context, destination_entries, errors, signal_handler,
                                        glob_buffer.gl_pathv[index]);
    }
    globfree(&glob_buffer);
}

bool bc_hash_discovery_expand_parallel(bc_allocators_context_t* memory_context, bc_concurrency_context_t* concurrency_context,
                                       bc_containers_vector_t* entries, bc_runtime_error_collector_t* errors,
                                       bc_runtime_signal_handler_t* signal_handler, const bc_hash_filter_t* filter,
                                       const char* const* input_paths, size_t input_count)
{
    bc_hash_walk_context_t context = {
        .worker_slot_index = 0,
        .main_memory_context = memory_context,
        .filter = filter,
    };

    bc_concurrency_slot_config_t slot_config = {
        .size = sizeof(bc_hash_walk_worker_slot_t),
        .init = NULL,
        .destroy = NULL,
        .arg = NULL,
    };
    if (!bc_concurrency_register_slot(concurrency_context, &slot_config, &context.worker_slot_index)) {
        return false;
    }

    for (size_t input_index = 0; input_index < input_count; ++input_index) {
        const char* input_path = input_paths[input_index];
        bool contains_metacharacter = false;
        bc_hash_discovery_glob_contains_metacharacter(input_path, &contains_metacharacter);
        if (contains_metacharacter) {
            bc_hash_walk_expand_glob(&context, memory_context, concurrency_context, entries, errors, signal_handler, input_path);
        } else {
            bc_hash_walk_process_input_path(&context, memory_context, concurrency_context, entries, errors, signal_handler, input_path);
        }
    }

    bc_hash_walk_merge_argument_t merge_argument = {
        .destination_entries = entries,
        .destination_memory_context = memory_context,
        .ok = true,
    };
    bc_concurrency_foreach_slot(concurrency_context, context.worker_slot_index, bc_hash_walk_merge_worker_slot, &merge_argument);

    return merge_argument.ok;
}
