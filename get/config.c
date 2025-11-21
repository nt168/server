#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void trim(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r' || isspace((unsigned char)str[len - 1]))) {
        str[--len] = '\0';
    }
    size_t start = 0;
    while (str[start] && isspace((unsigned char)str[start])) {
        start++;
    }
    if (start > 0) {
        memmove(str, str + start, strlen(str + start) + 1);
    }
}

static void build_fifo_path(const char *tmp_dir, const char *channel_dir, char *buf, size_t buf_len, const char *suffix) {
    snprintf(buf, buf_len, "%s/%s/%s", tmp_dir, channel_dir, suffix);
}

static void set_defaults(struct get_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->tmp_dir, sizeof(cfg->tmp_dir), "%s", "/tmp/phy");
    snprintf(cfg->channel_dir, sizeof(cfg->channel_dir), "%s", "channel");
    build_fifo_path(cfg->tmp_dir, cfg->channel_dir, cfg->fifo_read, sizeof(cfg->fifo_read), "Read");
    build_fifo_path(cfg->tmp_dir, cfg->channel_dir, cfg->fifo_write, sizeof(cfg->fifo_write), "Write");
}

bool load_get_config(const char *path, struct get_config *out) {
    FILE *fp = fopen(path, "r");
    struct get_config tmp;

    set_defaults(&tmp);

    if (!fp) {
        // fallback to defaults when config cannot be opened
        *out = tmp;
        return false;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        trim(line);
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        char *eq = strchr(line, '=');
        if (!eq) {
            continue;
        }
        *eq = '\0';
        char *key = line;
        char *value = eq + 1;
        trim(key);
        trim(value);

        if (strcmp(key, "TmpDir") == 0) {
            snprintf(tmp.tmp_dir, sizeof(tmp.tmp_dir), "%s", value);
        } else if (strcmp(key, "MessChannelDir") == 0) {
            snprintf(tmp.channel_dir, sizeof(tmp.channel_dir), "%s", value);
        }
    }
    fclose(fp);

    build_fifo_path(tmp.tmp_dir, tmp.channel_dir, tmp.fifo_read, sizeof(tmp.fifo_read), "Read");
    build_fifo_path(tmp.tmp_dir, tmp.channel_dir, tmp.fifo_write, sizeof(tmp.fifo_write), "Write");

    *out = tmp;
    return true;
}
