#include "kprocess.h"

#include <stdlib.h>
#include <string.h>

static void free_environment(KProcess *process)
{
    if (process->environment == NULL) {
        return;
    }
    for (size_t i = 0; i < process->environment_count; ++i) {
        free(process->environment[i]);
    }
    free(process->environment);
    process->environment = NULL;
    process->environment_count = 0;
}

void kprocess_init(KProcess *process)
{
    if (process == NULL) {
        return;
    }
    process->environment = NULL;
    process->environment_count = 0;
}

void kprocess_destroy(KProcess *process)
{
    if (process == NULL) {
        return;
    }
    free_environment(process);
}

void kprocess_clear_environment(KProcess *process)
{
    if (process == NULL) {
        return;
    }
    free_environment(process);
}

void kprocess_set_env(KProcess *process, const char *name, const char *value, bool overwrite)
{
    if (process == NULL || name == NULL || value == NULL) {
        return;
    }

    size_t name_length = strlen(name);
    size_t entry_length = name_length + 1 + strlen(value);
    char *entry = (char *)malloc(entry_length + 1);
    if (entry == NULL) {
        return;
    }
    memcpy(entry, name, name_length);
    entry[name_length] = '=';
    strcpy(entry + name_length + 1, value);

    for (size_t i = 0; i < process->environment_count; ++i) {
        if (strncmp(process->environment[i], name, name_length) == 0 && process->environment[i][name_length] == '=') {
            if (overwrite) {
                free(process->environment[i]);
                process->environment[i] = entry;
            } else {
                free(entry);
            }
            return;
        }
    }

    char **new_env = (char **)realloc(process->environment, sizeof(char *) * (process->environment_count + 1));
    if (new_env == NULL) {
        free(entry);
        return;
    }
    process->environment = new_env;
    process->environment[process->environment_count] = entry;
    process->environment_count++;
}

void kprocess_unset_env(KProcess *process, const char *name)
{
    if (process == NULL || name == NULL || process->environment_count == 0) {
        return;
    }

    size_t name_length = strlen(name);
    for (size_t i = 0; i < process->environment_count; ++i) {
        if (strncmp(process->environment[i], name, name_length) == 0 && process->environment[i][name_length] == '=') {
            free(process->environment[i]);
            for (size_t j = i + 1; j < process->environment_count; ++j) {
                process->environment[j - 1] = process->environment[j];
            }
            process->environment_count--;
            if (process->environment_count == 0) {
                free(process->environment);
                process->environment = NULL;
            } else {
                char **new_env = (char **)realloc(process->environment, sizeof(char *) * process->environment_count);
                if (new_env != NULL) {
                    process->environment = new_env;
                }
            }
            return;
        }
    }
}
