#ifndef SHELLCOMMAND_H
#define SHELLCOMMAND_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

char *shell_command_expand(const char *text);
char **shell_command_split(const char *command, size_t *count);
void shell_command_free_list(char **items, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* SHELLCOMMAND_H */
