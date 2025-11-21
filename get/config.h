#ifndef GET_CONFIG_H
#define GET_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

struct get_config {
    char tmp_dir[256];
    char channel_dir[256];
    char fifo_read[512];
    char fifo_write[512];
};

bool load_get_config(const char *path, struct get_config *out);

#endif // GET_CONFIG_H
