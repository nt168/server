#include "ae.h"
#include "anet.h"
#include "zmalloc.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEMO_BACKLOG 511
#define DEMO_BUFFER 4096

#ifndef UNUSED
#define UNUSED(V) ((void)(V))
#endif

typedef struct DemoClient {
    int fd;
    char buffer[DEMO_BUFFER];
    size_t read_len;
    struct DemoServer *server;
} DemoClient;

typedef struct DemoServer {
    aeEventLoop *el;
    int listen_fd;
    int should_stop;
} DemoServer;

static DemoServer *globalServer = NULL;

static void closeClient(DemoServer *server, DemoClient *client) {
    if (client->fd != -1) {
        aeDeleteFileEvent(server->el, client->fd, AE_READABLE);
        close(client->fd);
        client->fd = -1;
    }
    zfree(client);
}

static void clientReadHandler(struct aeEventLoop *el, int fd, void *privdata, int mask) {
    UNUSED(el);
    UNUSED(mask);
    DemoClient *client = privdata;
    DemoServer *server = client->server;

    ssize_t nread = read(fd, client->buffer, sizeof(client->buffer));
    if (nread <= 0) {
        closeClient(server, client);
        return;
    }

    ssize_t nwritten = 0;
    while (nwritten < nread) {
        ssize_t n = write(fd, client->buffer + nwritten, nread - nwritten);
        if (n <= 0) {
            if (errno == EINTR) continue;
            closeClient(server, client);
            return;
        }
        nwritten += n;
    }
}

static void acceptHandler(struct aeEventLoop *el, int fd, void *privdata, int mask) {
    UNUSED(mask);
    DemoServer *server = privdata;
    char cip[INET6_ADDRSTRLEN];
    int cport;

    int cfd = anetTcpAccept(NULL, fd, cip, sizeof(cip), &cport);
    if (cfd == ANET_ERR) return;
    anetNonBlock(NULL, cfd);

    DemoClient *client = zmalloc(sizeof(*client));
    client->fd = cfd;
    client->read_len = 0;
    client->server = server;

    if (aeCreateFileEvent(server->el, cfd, AE_READABLE, clientReadHandler, client) == AE_ERR) {
        closeClient(server, client);
        return;
    }
}

static void beforeSleep(struct aeEventLoop *eventLoop) {
    UNUSED(eventLoop);
    if (globalServer && globalServer->should_stop) aeStop(globalServer->el);
}

static void signalHandler(int sig) {
    UNUSED(sig);
    if (globalServer) globalServer->should_stop = 1;
}

int main(int argc, char **argv) {
    int port = 0;
    if (argc > 1) port = atoi(argv[1]);
    if (port == 0) port = 56379;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, signalHandler);

    DemoServer server = {0};
    server.el = aeCreateEventLoop(1024);
    if (!server.el) {
        fprintf(stderr, "Failed to create event loop\n");
        exit(1);
    }
    globalServer = &server;

    char err[ANET_ERR_LEN];
    server.listen_fd = anetTcpServer(err, port, NULL, DEMO_BACKLOG);
    if (server.listen_fd == ANET_ERR) {
        fprintf(stderr, "Failed to listen: %s\n", err);
        exit(1);
    }
    anetNonBlock(NULL, server.listen_fd);

    if (aeCreateFileEvent(server.el, server.listen_fd, AE_READABLE, acceptHandler, &server) == AE_ERR) {
        fprintf(stderr, "Failed to create accept event\n");
        exit(1);
    }

    aeSetBeforeSleepProc(server.el, beforeSleep);

    aeMain(server.el);

    aeDeleteEventLoop(server.el);
    close(server.listen_fd);
    return 0;
}
