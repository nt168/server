#define _GNU_SOURCE
#define _XOPEN_SOURCE 600
#include "kpty.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#ifdef HAVE_POSIX_OPENPT
#include <fcntl.h>
#endif
#ifdef HAVE_OPENPTY
#include <pty.h>
#endif

static int open_master(void)
{
#ifdef HAVE_POSIX_OPENPT
    int fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (fd >= 0) {
        if (grantpt(fd) < 0) {
            close(fd);
            return -1;
        }
        if (unlockpt(fd) < 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
#else
    int master_fd = -1;
    int slave_fd = -1;
    if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL) == 0) {
        if (slave_fd >= 0) {
            close(slave_fd);
        }
        return master_fd;
    }
    return -1;
#endif
}

static int open_slave(int master_fd)
{
#ifdef HAVE_PTSNAME
    char *name = ptsname(master_fd);
    if (name == NULL) {
        return -1;
    }
    return open(name, O_RDWR | O_NOCTTY);
#else
    (void)master_fd;
    errno = ENOSYS;
    return -1;
#endif
}

void kpty_init(KPty *pty)
{
    if (pty == NULL) {
        return;
    }
    pty->master_fd = -1;
    pty->slave_fd = -1;
}

void kpty_destroy(KPty *pty)
{
    if (pty == NULL) {
        return;
    }
    kpty_close(pty);
}

int kpty_open(KPty *pty)
{
    if (pty == NULL) {
        errno = EINVAL;
        return -1;
    }
    int master_fd = open_master();
    if (master_fd < 0) {
        return -1;
    }
    int slave_fd = open_slave(master_fd);
    if (slave_fd < 0) {
        close(master_fd);
        return -1;
    }
    pty->master_fd = master_fd;
    pty->slave_fd = slave_fd;
    return 0;
}

int kpty_open_with_fd(KPty *pty, int master_fd)
{
    if (pty == NULL || master_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    int slave_fd = open_slave(master_fd);
    if (slave_fd < 0) {
        return -1;
    }
    pty->master_fd = master_fd;
    pty->slave_fd = slave_fd;
    return 0;
}

void kpty_close(KPty *pty)
{
    if (pty == NULL) {
        return;
    }
    if (pty->master_fd >= 0) {
        close(pty->master_fd);
        pty->master_fd = -1;
    }
    if (pty->slave_fd >= 0) {
        close(pty->slave_fd);
        pty->slave_fd = -1;
    }
}

int kpty_master_fd(const KPty *pty)
{
    return pty != NULL ? pty->master_fd : -1;
}

int kpty_slave_fd(const KPty *pty)
{
    return pty != NULL ? pty->slave_fd : -1;
}

int kpty_set_winsize(KPty *pty, int rows, int cols)
{
    if (pty == NULL || pty->master_fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_row = (unsigned short)rows;
    ws.ws_col = (unsigned short)cols;
    return ioctl(pty->master_fd, TIOCSWINSZ, &ws);
}

int kpty_tcgetattr(KPty *pty, struct termios *tio)
{
    if (pty == NULL || pty->slave_fd < 0 || tio == NULL) {
        errno = EINVAL;
        return -1;
    }
    return tcgetattr(pty->slave_fd, tio);
}

int kpty_tcsetattr(KPty *pty, const struct termios *tio)
{
    if (pty == NULL || pty->slave_fd < 0 || tio == NULL) {
        errno = EINVAL;
        return -1;
    }
    return tcsetattr(pty->slave_fd, TCSANOW, tio);
}
