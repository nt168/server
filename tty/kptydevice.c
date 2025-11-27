#include "kptydevice.h"

#include <unistd.h>

void kptydevice_init(KPtyDevice *device)
{
    if (device == NULL) {
        return;
    }
    kpty_init(&device->pty);
}

int kptydevice_open(KPtyDevice *device)
{
    if (device == NULL) {
        return -1;
    }
    return kpty_open(&device->pty);
}

int kptydevice_open_with_fd(KPtyDevice *device, int master_fd)
{
    if (device == NULL) {
        return -1;
    }
    return kpty_open_with_fd(&device->pty, master_fd);
}

void kptydevice_close(KPtyDevice *device)
{
    if (device == NULL) {
        return;
    }
    kpty_close(&device->pty);
}

ssize_t kptydevice_read(KPtyDevice *device, char *buffer, size_t length)
{
    if (device == NULL) {
        return -1;
    }
    int master_fd = kpty_master_fd(&device->pty);
    if (master_fd < 0) {
        return -1;
    }
    return read(master_fd, buffer, length);
}

ssize_t kptydevice_write(KPtyDevice *device, const char *buffer, size_t length)
{
    if (device == NULL) {
        return -1;
    }
    int master_fd = kpty_master_fd(&device->pty);
    if (master_fd < 0) {
        return -1;
    }
    return write(master_fd, buffer, length);
}

int kptydevice_master_fd(const KPtyDevice *device)
{
    if (device == NULL) {
        return -1;
    }
    return kpty_master_fd(&device->pty);
}

int kptydevice_slave_fd(const KPtyDevice *device)
{
    if (device == NULL) {
        return -1;
    }
    return kpty_slave_fd(&device->pty);
}

int kptydevice_set_winsize(KPtyDevice *device, int rows, int cols)
{
    if (device == NULL) {
        return -1;
    }
    return kpty_set_winsize(&device->pty, rows, cols);
}

int kptydevice_tcgetattr(KPtyDevice *device, struct termios *tio)
{
    if (device == NULL) {
        return -1;
    }
    return kpty_tcgetattr(&device->pty, tio);
}

int kptydevice_tcsetattr(KPtyDevice *device, const struct termios *tio)
{
    if (device == NULL) {
        return -1;
    }
    return kpty_tcsetattr(&device->pty, tio);
}
