#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol.h"

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --read <fifo> --write <fifo> --expect-type <mesdet-name>\n", prog);
}

static bool parse_args(int argc, char **argv, const char **read_fifo, const char **write_fifo, mesdet *expected_type) {
    *read_fifo = NULL;
    *write_fifo = NULL;
    *expected_type = ENV;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--read") == 0 && i + 1 < argc) {
            *read_fifo = argv[++i];
        } else if (strcmp(argv[i], "--write") == 0 && i + 1 < argc) {
            *write_fifo = argv[++i];
        } else if (strcmp(argv[i], "--expect-type") == 0 && i + 1 < argc) {
            const char *name = argv[++i];
            size_t count = sizeof(_mde_str_tbl) / sizeof(*_mde_str_tbl);
            for (size_t idx = 0; idx < count; ++idx) {
                if (_mde_str_tbl[idx] && strcmp(_mde_str_tbl[idx], name) == 0) {
                    *expected_type = (mesdet)idx;
                    break;
                }
            }
        }
    }
    return *read_fifo && *write_fifo;
}

int main(int argc, char **argv) {
    const char *fifo_read = NULL;
    const char *fifo_write = NULL;
    mesdet expected = ENV;
    if (!parse_args(argc, argv, &fifo_read, &fifo_write, &expected)) {
        usage(argv[0]);
        return 1;
    }

    int rfd = open(fifo_read, O_RDONLY);
    if (rfd < 0) {
        perror("fake_server open read fifo");
        return 1;
    }

    unsigned char buf[sizeof(struct transfer) > sizeof(ntsp) ? sizeof(struct transfer) : sizeof(ntsp)];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read(rfd, buf, sizeof(buf));
    close(rfd);
    if (n < 0) {
        perror("fake_server read");
        return 1;
    }

    bool is_mix = strncmp((const char *)buf, m_nspdes, m_nspl) == 0;
    int wfd = open(fifo_write, O_WRONLY);
    if (wfd < 0) {
        perror("fake_server open write fifo");
        return 1;
    }

    if (is_mix) {
        ntsp *req = (ntsp *)buf;
        if (req->mdt.mde.mty != MIX || req->mdt.mde.sty != MIXALL) {
            fprintf(stderr, "Unexpected request header\n");
            close(wfd);
            return 1;
        }
        if (req->mdt.mde.gty != (ucha)expected) {
            fprintf(stderr, "Unexpected detect type: %u\n", req->mdt.mde.gty);
            close(wfd);
            return 1;
        }

        struct transfer resp;
        memset(&resp, 0, sizeof(resp));
        resp.mma.matp = MIX;
        resp.mma.mmi = MIXALL;
        resp.td.affi = req->mdt.mde.gty;
        snprintf(resp.td.mes, sizeof(resp.td.mes), "%s history ok", MDE2STR(resp.td.affi));

        if (write(wfd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
            perror("fake_server write");
            close(wfd);
            return 1;
        }
    } else {
        struct transfer *req = (struct transfer *)buf;
        if (req->mma.matp != CTRLAGT || req->mma.mct != INSERT) {
            fprintf(stderr, "Unexpected transfer payload\n");
            close(wfd);
            return 1;
        }

        char *add = NULL, *usr = NULL, *pwd = NULL;
        char mes_copy[sizeof(req->td.mes)];
        strncpy(mes_copy, req->td.mes, sizeof(mes_copy) - 1);
        mes_copy[sizeof(mes_copy) - 1] = '\0';

        char *saveptr = NULL;
        add = strtok_r(mes_copy, ";", &saveptr);
        usr = strtok_r(NULL, ";", &saveptr);
        pwd = strtok_r(NULL, ";", &saveptr);

        if (!add || !usr || !pwd) {
            fprintf(stderr, "Malformed control request\n");
            close(wfd);
            return 1;
        }

        struct transfer resp;
        memset(&resp, 0, sizeof(resp));
        resp.mma.matp = MESS;
        resp.mma.mme = COMM;
        snprintf(resp.td.mes, sizeof(resp.td.mes), "insert ok: %s %s %s", add, usr, pwd);

        if (write(wfd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
            perror("fake_server write");
            close(wfd);
            return 1;
        }
    }

    close(wfd);
    return 0;
}
