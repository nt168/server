#ifndef TOOLS_H
#define TOOLS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

const char *tools_get_kb_layout_dir(void);
void tools_add_custom_color_scheme_dir(const char *directory);
char **tools_get_color_scheme_dirs(size_t *count);
void tools_free_color_scheme_dirs(char **dirs, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* TOOLS_H */
