#ifndef KPTYDEVICE_H
#define KPTYDEVICE_H

#include <stddef.h>
#include <sys/types.h>
#include <termios.h>

#include "kpty.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    KPty pty;
} KPtyDevice;

void kptydevice_init(KPtyDevice *device);
int kptydevice_open(KPtyDevice *device);
int kptydevice_open_with_fd(KPtyDevice *device, int master_fd);
void kptydevice_close(KPtyDevice *device);
ssize_t kptydevice_read(KPtyDevice *device, char *buffer, size_t length);
ssize_t kptydevice_write(KPtyDevice *device, const char *buffer, size_t length);
int kptydevice_master_fd(const KPtyDevice *device);
int kptydevice_slave_fd(const KPtyDevice *device);
int kptydevice_set_winsize(KPtyDevice *device, int rows, int cols);
int kptydevice_tcgetattr(KPtyDevice *device, struct termios *tio);
int kptydevice_tcsetattr(KPtyDevice *device, const struct termios *tio);

#ifdef __cplusplus
}
#endif

#endif /* KPTYDEVICE_H */
