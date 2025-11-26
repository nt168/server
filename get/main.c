#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "channel_client.h"
#include "protocol.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s [--config path] 1 1 <addr> <user> <password> [--timeout sec]\n", prog);
    fprintf(stderr, "       %s [--config path] history --receiver <addr> --type <det_type> [--timeout sec]\n", prog);
}

static bool parse_history_args(int argc, char **argv, int start_idx, char **receiver, char **type_name, int *timeout_sec) {
    *receiver = NULL;
    *type_name = NULL;
    *timeout_sec = 3;

    for (int i = start_idx; i < argc; i++) {
        if (strcmp(argv[i], "history") == 0) {
            continue;
        } else if (strcmp(argv[i], "--receiver") == 0 && i + 1 < argc) {
            *receiver = argv[++i];
        } else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
            *type_name = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            *timeout_sec = atoi(argv[++i]);
        } else {
            return false;
        }
    }
    return *receiver && *type_name;
}

static bool try_parse_mesdet(const char *name, mesdet *out) {
    size_t count = sizeof(_mde_str_tbl) / sizeof(*_mde_str_tbl);
    for (size_t i = 0; i < count; ++i) {
        const char *entry = _mde_str_tbl[i];
        if (!entry) {
            continue;
        }
        if (strcmp(entry, name) == 0) {
            *out = (mesdet)i;
            return true;
        }
    }
    return false;
}

int main(int argc, char **argv) {
    char *config_path = "/opt/phytune/server/conf/server.cnf";
    int timeout_sec = 3;

    int idx = 1;
    if (idx + 1 < argc && strcmp(argv[idx], "--config") == 0) {
        config_path = argv[idx + 1];
        idx += 2;
    }

    if (idx >= argc) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[idx], "history") == 0) {
        char *receiver = NULL;
        char *type_name = NULL;
        if (!parse_history_args(argc, argv, idx, &receiver, &type_name, &timeout_sec)) {
            usage(argv[0]);
            return 1;
        }

        mesdet detect_type = ENV;
        if (!try_parse_mesdet(type_name, &detect_type)) {
            fprintf(stderr, "Unknown detect type: %s\n", type_name);
            return 1;
        }

        struct get_config cfg;
        if (!load_get_config(config_path, &cfg)) {
            fprintf(stderr, "Using default configuration because %s could not be read.\n", config_path);
        }

        if (!send_mix_history(&cfg, receiver, detect_type, timeout_sec)) {
            return 1;
        }
        return 0;
    }

    if (idx + 4 >= argc) {
        usage(argv[0]);
        return 1;
    }

    int main_type_arg = atoi(argv[idx++]);
    int sub_type_arg = atoi(argv[idx++]);
    const char *addr = argv[idx++];
    const char *user = argv[idx++];
    const char *password = argv[idx++];

    if (idx + 1 < argc && strcmp(argv[idx], "--timeout") == 0) {
        timeout_sec = atoi(argv[idx + 1]);
    }

    if (!(main_type_arg == CTRLAGT || main_type_arg == 1)) {
        fprintf(stderr, "Unsupported main message type (expected CTRLAGT): %d\n", main_type_arg);
        return 1;
    }
    if (sub_type_arg != INSERT) {
        fprintf(stderr, "Unsupported control subtype (expected INSERT): %d\n", sub_type_arg);
        return 1;
    }

    struct get_config cfg;
    if (!load_get_config(config_path, &cfg)) {
        fprintf(stderr, "Using default configuration because %s could not be read.\n", config_path);
    }

    switch (main_type_arg)
    {
        case STATUS:
             if (!send_ctrl(&cfg, STATUS, sub_type_arg, addr, user, password, timeout_sec)) {
                return 1;
            }
        break;

        case DETECT:
        /* code */
        break; 

        case MESS:
        /* code */
        break;
           
        case CTRLAGT:
            if (!send_ctrl(&cfg, CTRLAGT, sub_type_arg, addr, user, password, timeout_sec)) {
                return 1;
            }
        break;
           
        case EXECUT:
        /* code */
        break;
           
        case OPTIM:
        /* code */
        break;
           
        case HISTORY:
        /* code */
        break;
           
        case MIX:
        /* code */
        break;
           
        case HEARTBEAT:
        /* code */
        break;

        default:
            break;
    }

    if (!send_ctrlagt_insert(&cfg, addr, user, password, timeout_sec)) {
        return 1;
    }

    return 0;
}
