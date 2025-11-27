#include "tools.h"

#include <stdlib.h>
#include <string.h>

const char *tools_get_kb_layout_dir(void)
{
    (void)0;
    return NULL;
}

void tools_add_custom_color_scheme_dir(const char *directory)
{
    (void)directory;
}

char **tools_get_color_scheme_dirs(size_t *count)
{
    if (count != NULL) {
        *count = 0;
    }
    return NULL;
}

void tools_free_color_scheme_dirs(char **dirs, size_t count)
{
    (void)count;
    if (dirs == NULL) {
        return;
    }
    free(dirs);
}
