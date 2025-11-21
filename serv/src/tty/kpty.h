#ifndef KPTY_H
#define KPTY_H

#include <stdbool.h>
#include <sys/types.h>
#include <termios.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int master_fd;
    int slave_fd;
} KPty;

void kpty_init(KPty *pty);
void kpty_destroy(KPty *pty);
int kpty_open(KPty *pty);
int kpty_open_with_fd(KPty *pty, int master_fd);
void kpty_close(KPty *pty);
int kpty_master_fd(const KPty *pty);
int kpty_slave_fd(const KPty *pty);
int kpty_set_winsize(KPty *pty, int rows, int cols);
int kpty_tcgetattr(KPty *pty, struct termios *tio);
int kpty_tcsetattr(KPty *pty, const struct termios *tio);

#ifdef __cplusplus
}
#endif

#endif /* KPTY_H */
