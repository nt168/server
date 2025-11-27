#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "protocol.h"

#define DEFAULT_CONFIG "conf/phy_server.cnf"
#define DEFAULT_TMPDIR "/tmp/phy"
#define DEFAULT_CHANNEL "channel"

static char fifo_read_path[256];
static char fifo_write_path[256];
static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig)
{
    (void)sig;
    keep_running = 0;
}

static void parse_config_paths(const char *cfg_path)
{
    FILE *fp = fopen(cfg_path, "r");
    char tmpdir[128] = {0};
    char channel[128] = {0};

    if (fp == NULL) {
        fprintf(stderr, "open config %s failed, use defaults: %s\n", cfg_path, strerror(errno));
        strncpy(tmpdir, DEFAULT_TMPDIR, sizeof(tmpdir) - 1);
        strncpy(channel, DEFAULT_CHANNEL, sizeof(channel) - 1);
    } else {
        char line[256];
        while (fgets(line, sizeof(line), fp) != NULL) {
            if (strncmp(line, "TmpDir=", 7) == 0) {
                strncpy(tmpdir, line + 7, sizeof(tmpdir) - 1);
                tmpdir[strcspn(tmpdir, "\r\n")] = '\0';
            } else if (strncmp(line, "MessChannelDir=", 15) == 0) {
                strncpy(channel, line + 15, sizeof(channel) - 1);
                channel[strcspn(channel, "\r\n")] = '\0';
            }
        }
        fclose(fp);

        if (tmpdir[0] == '\0') {
            strncpy(tmpdir, DEFAULT_TMPDIR, sizeof(tmpdir) - 1);
        }
        if (channel[0] == '\0') {
            strncpy(channel, DEFAULT_CHANNEL, sizeof(channel) - 1);
        }
    }

    snprintf(fifo_read_path, sizeof(fifo_read_path), "%s/%s/Read", tmpdir, channel);
    snprintf(fifo_write_path, sizeof(fifo_write_path), "%s/%s/Write", tmpdir, channel);
}

static void ensure_fifo(const char *path)
{
    if (access(path, F_OK) != 0) {
        if (mkfifo(path, 0666) != 0 && errno != EEXIST) {
            fprintf(stderr, "mkfifo %s failed: %s\n", path, strerror(errno));
        }
    }
}

static void *monitor_responses(void *arg)
{
    (void)arg;
    int fd = -1;
    fd_set readset;

    ensure_fifo(fifo_write_path);

    while (keep_running) {
        if (fd < 0) {
            fd = open(fifo_write_path, O_RDONLY);
            if (fd < 0) {
                fprintf(stderr, "open %s for read failed: %s\n", fifo_write_path, strerror(errno));
                sleep(1);
                continue;
            }
        }

        FD_ZERO(&readset);
        FD_SET(fd, &readset);
        if (select(fd + 1, &readset, NULL, NULL, NULL) <= 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "select on %s failed: %s\n", fifo_write_path, strerror(errno));
            break;
        }

        if (!FD_ISSET(fd, &readset)) {
            continue;
        }

        struct transfer resp;
        ssize_t nread = read(fd, &resp, sizeof(resp));
        if (nread == (ssize_t)sizeof(resp)) {
            printf("[server] type=%d, subtype=%d, msg=%s\n", resp.mma.matp, resp.mma.mde, resp.td.mes);
            fflush(stdout);
        } else if (nread == 0) {
            close(fd);
            fd = -1;
        } else if (nread < 0) {
            if (errno != EINTR) {
                fprintf(stderr, "read from %s failed: %s\n", fifo_write_path, strerror(errno));
                close(fd);
                fd = -1;
                sleep(1);
            }
        }
    }

    if (fd >= 0) {
        close(fd);
    }
    return NULL;
}

static bool send_message_to_server(const struct transfer *tran)
{
    ensure_fifo(fifo_read_path);
    int fd = open(fifo_read_path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "open %s for write failed: %s\n", fifo_read_path, strerror(errno));
        return false;
    }

    ssize_t wlen = write(fd, tran, sizeof(*tran));
    close(fd);
    if (wlen != (ssize_t)sizeof(*tran)) {
        fprintf(stderr, "write to %s incomplete: %zd/%zu\n", fifo_read_path, wlen, sizeof(*tran));
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    const char *cfg_path = (argc > 1) ? argv[1] : DEFAULT_CONFIG;
    parse_config_paths(cfg_path);

    signal(SIGINT, handle_sigint);

    pthread_t tid;
    if (pthread_create(&tid, NULL, monitor_responses, NULL) != 0) {
        fprintf(stderr, "failed to start response monitor thread: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    printf("fifo read path: %s\n", fifo_read_path);
    printf("fifo write path: %s\n", fifo_write_path);
    printf("Enter: <type> <subtype> <message>. Type 'quit' to exit.\n");

    char line[1024];
    while (keep_running && fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, "quit") == 0) {
            break;
        }

        char *type_str = strtok(line, " ");
        char *subtype_str = strtok(NULL, " ");
        char *payload = strtok(NULL, "");

        if (!type_str || !subtype_str || !payload) {
            printf("Invalid input. Expected: <type> <subtype> <message>\n");
            continue;
        }

        struct transfer tran;
        memset(&tran, 0, sizeof(tran));
        tran.mma.matp = (mestype)atoi(type_str);
        tran.mma.mde = (mesdet)atoi(subtype_str);
        strncpy(tran.td.mes, payload, sizeof(tran.td.mes) - 1);

        if (!send_message_to_server(&tran)) {
            fprintf(stderr, "failed to send message to server\n");
        }
    }

    keep_running = 0;
    pthread_kill(tid, SIGINT);
    pthread_join(tid, NULL);
    return 0;
}
