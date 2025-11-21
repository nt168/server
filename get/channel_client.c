#define _POSIX_C_SOURCE 200809L

#include "channel_client.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>
#include <unistd.h>

#include "protocol.h"

static void fill_timestamp(char *buf, size_t len) {
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(buf, len, "%Y%m%d%H%M%S", &tm_info);
}

static bool write_full(int fd, const void *data, size_t len) {
    const unsigned char *p = data;
    size_t written = 0;
    while (written < len) {
        ssize_t rc = write(fd, p + written, len - written);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        written += (size_t)rc;
    }
    return true;
}

static bool read_full_with_timeout(int fd, void *data, size_t len, int timeout_sec) {
    unsigned char *p = data;
    size_t read_bytes = 0;
    while (read_bytes < len) {
        fd_set set;
        FD_ZERO(&set);
        FD_SET(fd, &set);
        struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
        int sel = select(fd + 1, &set, NULL, NULL, timeout_sec > 0 ? &tv : NULL);
        if (sel == 0) {
            return false; // timeout
        }
        if (sel < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        ssize_t rc = read(fd, p + read_bytes, len - read_bytes);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (rc == 0) {
            return false;
        }
        read_bytes += (size_t)rc;
    }
    return true;
}

static void build_mix_request(ntsp *out, const char *receiver, mesdet detect_type) {
    memset(out, 0, sizeof(*out));
    snprintf(out->des, sizeof(out->des), "%s", m_nspdes);
    out->mdt.mde.mty = MIX;
    out->mdt.mde.sty = MIXALL;
    out->mdt.mde.gty = (ucha)detect_type;
    out->mdt.ide = (uint64_t)time(NULL);
    snprintf(out->mdt.sdr, sizeof(out->mdt.sdr), "%s", "get");
    snprintf(out->mdt.rcr, sizeof(out->mdt.rcr), "%s", receiver);
    fill_timestamp(out->mdt.tim, sizeof(out->mdt.tim));
    out->dln = 0;
}

static void build_ctrlagt_insert(struct transfer *out, const char *addr, const char *user, const char *password) {
    memset(out, 0, sizeof(*out));
    out->mma.matp = CTRLAGT;
    out->mma.mct = INSERT;

    snprintf(out->td.sender, sizeof(out->td.sender), "%s", "get");
    snprintf(out->td.mes, sizeof(out->td.mes), "%s;%s;%s", addr, user, password);
}

static void print_transfer(const struct transfer *tran) {
    printf("Message family: %d\n", tran->mma.matp);
    switch (tran->mma.matp) {
        case MIX:
            printf("Response type: %s (%d)\n", MDE2STR(tran->td.affi), tran->td.affi);
            break;
        case MESS:
            printf("Response message type: %d\n", tran->mma.mme);
            break;
        default:
            printf("Response subtype: %d\n", tran->mma.mmi);
            break;
    }
    printf("Response message: %s\n", tran->td.mes);
}

bool send_mix_history(const struct get_config *cfg, const char *receiver, mesdet detect_type, int timeout_sec) {
    ntsp request;
    build_mix_request(&request, receiver, detect_type);

    int write_fd = open(cfg->fifo_read, O_WRONLY);
    if (write_fd < 0) {
        perror("open fifo_read for write");
        return false;
    }

    size_t request_size = sizeof(request);
    bool ok = write_full(write_fd, &request, request_size);
    close(write_fd);
    if (!ok) {
        fprintf(stderr, "Failed to send request to server\n");
        return false;
    }

    int read_fd = open(cfg->fifo_write, O_RDONLY);
    if (read_fd < 0) {
        perror("open fifo_write for read");
        return false;
    }

    struct transfer resp;
    memset(&resp, 0, sizeof(resp));
    ok = read_full_with_timeout(read_fd, &resp, sizeof(resp), timeout_sec);
    close(read_fd);
    if (!ok) {
        fprintf(stderr, "Failed to read response from server\n");
        return false;
    }

    print_transfer(&resp);
    return true;
}

bool send_ctrlagt_insert(const struct get_config *cfg, const char *addr, const char *user, const char *password, int timeout_sec) {
    struct transfer request;
    build_ctrlagt_insert(&request, addr, user, password);

    int write_fd = open(cfg->fifo_read, O_WRONLY);
    if (write_fd < 0) {
        perror("open fifo_read for write");
        return false;
    }

    bool ok = write_full(write_fd, &request, sizeof(request));
    close(write_fd);
    if (!ok) {
        fprintf(stderr, "Failed to send request to server\n");
        return false;
    }

    int read_fd = open(cfg->fifo_write, O_RDONLY);
    if (read_fd < 0) {
        perror("open fifo_write for read");
        return false;
    }

    struct transfer resp;
    memset(&resp, 0, sizeof(resp));
    ok = read_full_with_timeout(read_fd, &resp, sizeof(resp), timeout_sec);
    close(read_fd);
    if (!ok) {
        fprintf(stderr, "Failed to read response from server\n");
        return false;
    }

    print_transfer(&resp);
    return true;
}
