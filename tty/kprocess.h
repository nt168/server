#ifndef KPROCESS_H
#define KPROCESS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char **environment;
    size_t environment_count;
} KProcess;

void kprocess_init(KProcess *process);
void kprocess_destroy(KProcess *process);
void kprocess_clear_environment(KProcess *process);
void kprocess_set_env(KProcess *process, const char *name, const char *value, bool overwrite);
void kprocess_unset_env(KProcess *process, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* KPROCESS_H */
