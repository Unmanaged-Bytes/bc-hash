// SPDX-License-Identifier: MIT

#include "bc_hash_discovery_internal.h"

#include "bc_allocators_pool.h"
#include "bc_core.h"
#include "bc_io_file.h"
#include "bc_io_file_inode.h"
#include "bc_io_file_open.h"
#include "bc_io_file_path.h"
#include "bc_io_mmap.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BC_HASH_WALK_PATH_BUFFER_SIZE BC_IO_MAX_PATH_LENGTH

typedef struct bc_hash_walk_state {
    bc_allocators_context_t* memory_context;
    bc_containers_vector_t* entries;
    bc_hash_error_collector_t* errors;
    bc_io_file_inode_set_t* visited_directories;
    bc_concurrency_signal_handler_t* signal_handler;
    const bc_hash_filter_t* filter;
} bc_hash_walk_state_t;

static bool bc_hash_walk_should_stop(const bc_hash_walk_state_t* state)
{
    if (state->signal_handler == NULL) {
        return false;
    }
    bool should_stop = false;
    bc_concurrency_signal_handler_should_stop(state->signal_handler, &should_stop);
    return should_stop;
}

static bool bc_hash_walk_append_entry(bc_hash_walk_state_t* state, const char* absolute_path, size_t absolute_path_length, size_t file_size)
{
    if (file_size == 0) {
        return true;
    }
    char* path_copy = NULL;
    if (!bc_allocators_pool_allocate(state->memory_context, absolute_path_length + 1, (void**)&path_copy)) {
        bc_hash_error_collector_record(state->errors, state->memory_context, absolute_path, "allocate", ENOMEM);
        return false;
    }
    bc_core_copy(path_copy, absolute_path, absolute_path_length);
    path_copy[absolute_path_length] = '\0';

    bc_hash_file_entry_t entry = {
        .absolute_path = path_copy,
        .absolute_path_length = absolute_path_length,
        .file_size = file_size,
    };

    if (!bc_containers_vector_push(state->memory_context, state->entries, &entry)) {
        bc_allocators_pool_free(state->memory_context, path_copy);
        bc_hash_error_collector_record(state->errors, state->memory_context, absolute_path, "enqueue", ENOMEM);
        return false;
    }
    return true;
}

static bool bc_hash_walk_directory(bc_hash_walk_state_t* state, int directory_file_descriptor, const char* directory_path,
                                   size_t directory_path_length);

static bool bc_hash_walk_descend_child(bc_hash_walk_state_t* state, int parent_directory_file_descriptor, const char* child_name,
                                       const char* child_absolute_path, size_t child_absolute_path_length)
{
    struct stat child_stat_buffer;
    if (fstatat(parent_directory_file_descriptor, child_name, &child_stat_buffer, AT_SYMLINK_NOFOLLOW) != 0) {
        bc_hash_error_collector_record(state->errors, state->memory_context, child_absolute_path, "stat", errno);
        return false;
    }

    bool was_already_present = false;
    if (!bc_io_file_inode_set_insert(state->visited_directories, child_stat_buffer.st_dev, child_stat_buffer.st_ino,
                                     &was_already_present)) {
        bc_hash_error_collector_record(state->errors, state->memory_context, child_absolute_path, "dedup", ENOMEM);
        return false;
    }
    if (was_already_present) {
        return true;
    }

    int child_file_descriptor = openat(parent_directory_file_descriptor, child_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child_file_descriptor < 0) {
        bc_hash_error_collector_record(state->errors, state->memory_context, child_absolute_path, "open", errno);
        return false;
    }

    bool descend_ok = bc_hash_walk_directory(state, child_file_descriptor, child_absolute_path, child_absolute_path_length);
    close(child_file_descriptor);
    return descend_ok;
}

static bool bc_hash_walk_handle_entry(bc_hash_walk_state_t* state, int directory_file_descriptor, const struct dirent* directory_entry,
                                      const char* directory_path, size_t directory_path_length)
{
    const char* entry_name = directory_entry->d_name;
    if (entry_name[0] == '.') {
        return true;
    }

    char child_path_buffer[BC_HASH_WALK_PATH_BUFFER_SIZE];
    size_t entry_name_length = strlen(entry_name);
    size_t child_path_length = 0;
    if (!bc_io_file_path_join(child_path_buffer, sizeof(child_path_buffer), directory_path, directory_path_length, entry_name,
                              entry_name_length, &child_path_length)) {
        bc_hash_error_collector_record(state->errors, state->memory_context, directory_path, "path-too-long", ENAMETOOLONG);
        return false;
    }

    bc_io_file_entry_type_t entry_type = BC_IO_ENTRY_TYPE_OTHER;
    size_t resolved_file_size = 0;
    bool size_already_known = false;
    if (directory_entry->d_type != DT_UNKNOWN) {
        bc_io_file_dtype_to_entry_type(directory_entry->d_type, &entry_type);
    } else {
        dev_t device_value = 0;
        ino_t inode_value = 0;
        time_t modification_time_value = 0;
        if (!bc_io_file_stat_if_unknown(directory_file_descriptor, entry_name, &entry_type, &device_value, &inode_value,
                                        &resolved_file_size, &modification_time_value)) {
            bc_hash_error_collector_record(state->errors, state->memory_context, child_path_buffer, "stat", errno);
            return true;
        }
        size_already_known = true;
    }

    switch (entry_type) {
    case BC_IO_ENTRY_TYPE_FILE: {
        if (!bc_hash_filter_accepts_file(state->filter, entry_name)) {
            return true;
        }
        if (!size_already_known) {
            struct stat file_stat_buffer;
            if (fstatat(directory_file_descriptor, entry_name, &file_stat_buffer, AT_SYMLINK_NOFOLLOW) != 0) {
                bc_hash_error_collector_record(state->errors, state->memory_context, child_path_buffer, "stat", errno);
                return true;
            }
            resolved_file_size = (size_t)file_stat_buffer.st_size;
        }
        bc_hash_walk_append_entry(state, child_path_buffer, child_path_length, resolved_file_size);
        return true;
    }
    case BC_IO_ENTRY_TYPE_DIRECTORY:
        if (!bc_hash_filter_accepts_directory(state->filter, entry_name)) {
            return true;
        }
        bc_hash_walk_descend_child(state, directory_file_descriptor, entry_name, child_path_buffer, child_path_length);
        return true;
    case BC_IO_ENTRY_TYPE_SYMLINK:
    case BC_IO_ENTRY_TYPE_OTHER:
    default:
        return true;
    }
}

static bool bc_hash_walk_directory(bc_hash_walk_state_t* state, int directory_file_descriptor, const char* directory_path,
                                   size_t directory_path_length)
{
    int duplicated_file_descriptor = dup(directory_file_descriptor);
    if (duplicated_file_descriptor < 0) {
        bc_hash_error_collector_record(state->errors, state->memory_context, directory_path, "dup", errno);
        return false;
    }
    DIR* directory_stream = fdopendir(duplicated_file_descriptor);
    if (directory_stream == NULL) {
        close(duplicated_file_descriptor);
        bc_hash_error_collector_record(state->errors, state->memory_context, directory_path, "fdopendir", errno);
        return false;
    }

    const struct dirent* directory_entry = NULL;
    errno = 0;
    while ((directory_entry = readdir(directory_stream)) != NULL) {
        if (bc_hash_walk_should_stop(state)) {
            break;
        }
        if (directory_entry->d_name[0] == '.' &&
            (directory_entry->d_name[1] == '\0' || (directory_entry->d_name[1] == '.' && directory_entry->d_name[2] == '\0'))) {
            errno = 0;
            continue;
        }
        bc_hash_walk_handle_entry(state, directory_file_descriptor, directory_entry, directory_path, directory_path_length);
        errno = 0;
    }

    if (errno != 0) {
        bc_hash_error_collector_record(state->errors, state->memory_context, directory_path, "readdir", errno);
    }

    closedir(directory_stream);
    return true;
}

static bool bc_hash_walk_process_input_path(bc_hash_walk_state_t* state, const char* input_path)
{
    struct stat input_stat_buffer;
    if (fstatat(AT_FDCWD, input_path, &input_stat_buffer, AT_SYMLINK_NOFOLLOW) != 0) {
        bc_hash_error_collector_record(state->errors, state->memory_context, input_path, "stat", errno);
        return false;
    }

    if (S_ISLNK(input_stat_buffer.st_mode)) {
        bc_hash_error_collector_record(state->errors, state->memory_context, input_path, "skip-symlink", ELOOP);
        return false;
    }

    if (S_ISREG(input_stat_buffer.st_mode)) {
        return bc_hash_walk_append_entry(state, input_path, strlen(input_path), (size_t)input_stat_buffer.st_size);
    }

    if (S_ISDIR(input_stat_buffer.st_mode)) {
        bool was_already_present = false;
        if (!bc_io_file_inode_set_insert(state->visited_directories, input_stat_buffer.st_dev, input_stat_buffer.st_ino,
                                         &was_already_present)) {
            bc_hash_error_collector_record(state->errors, state->memory_context, input_path, "dedup", ENOMEM);
            return false;
        }
        if (was_already_present) {
            return true;
        }

        int directory_file_descriptor = open(input_path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory_file_descriptor < 0) {
            bc_hash_error_collector_record(state->errors, state->memory_context, input_path, "open", errno);
            return false;
        }

        size_t input_path_length = strlen(input_path);
        while (input_path_length > 1 && input_path[input_path_length - 1] == '/') {
            input_path_length -= 1;
        }

        bool descend_ok = bc_hash_walk_directory(state, directory_file_descriptor, input_path, input_path_length);
        close(directory_file_descriptor);
        return descend_ok;
    }

    bc_hash_error_collector_record(state->errors, state->memory_context, input_path, "skip-other", EINVAL);
    return false;
}

static bool bc_hash_walk_expand_glob(bc_hash_walk_state_t* state, const char* pattern)
{
    glob_t glob_buffer;
    int glob_flags = GLOB_NOSORT | GLOB_NOCHECK | GLOB_NOMAGIC;
    int glob_result = glob(pattern, glob_flags, NULL, &glob_buffer);
    if (glob_result != 0) {
        bc_hash_error_collector_record(state->errors, state->memory_context, pattern, "glob", EINVAL);
        globfree(&glob_buffer);
        return false;
    }

    bool any_match = false;
    for (size_t index = 0; index < glob_buffer.gl_pathc; ++index) {
        const char* matched_path = glob_buffer.gl_pathv[index];
        if (strcmp(matched_path, pattern) == 0) {
            bool pattern_has_metacharacter = false;
            bc_hash_discovery_glob_contains_metacharacter(pattern, &pattern_has_metacharacter);
            if (pattern_has_metacharacter && glob_buffer.gl_pathc == 1) {
                bc_hash_error_collector_record(state->errors, state->memory_context, pattern, "glob-no-match", ENOENT);
                break;
            }
        }
        bc_hash_walk_process_input_path(state, matched_path);
        any_match = true;
    }

    globfree(&glob_buffer);
    return any_match;
}

bool bc_hash_discovery_expand(bc_allocators_context_t* memory_context, bc_containers_vector_t* entries, bc_hash_error_collector_t* errors,
                              bc_concurrency_signal_handler_t* signal_handler, const bc_hash_filter_t* filter, const char* const* input_paths,
                              size_t input_count)
{
    bc_hash_walk_state_t walk_state = {
        .memory_context = memory_context,
        .entries = entries,
        .errors = errors,
        .visited_directories = NULL,
        .signal_handler = signal_handler,
        .filter = filter,
    };

    if (!bc_io_file_inode_set_create(memory_context, 256, &walk_state.visited_directories)) {
        return false;
    }

    for (size_t index = 0; index < input_count; ++index) {
        if (bc_hash_walk_should_stop(&walk_state)) {
            break;
        }
        const char* input_path = input_paths[index];
        bool contains_metacharacter = false;
        bc_hash_discovery_glob_contains_metacharacter(input_path, &contains_metacharacter);
        if (contains_metacharacter) {
            bc_hash_walk_expand_glob(&walk_state, input_path);
        } else {
            bc_hash_walk_process_input_path(&walk_state, input_path);
        }
    }

    bc_io_file_inode_set_destroy(walk_state.visited_directories);
    return true;
}
