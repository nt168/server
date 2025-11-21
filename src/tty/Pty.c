#define _GNU_SOURCE
#define _XOPEN_SOURCE 600
#include "Pty.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
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
    char *name = NULL;
#ifdef HAVE_PTSNAME
    name = ptsname(master_fd);
#else
    (void)master_fd;
#endif
    if (name == NULL) {
        return -1;
    }
    int fd = open(name, O_RDWR | O_NOCTTY);
    return fd;
}

void pty_init(Pty *pty)
{
    if (pty == NULL) {
        return;
    }
    pty->master_fd = -1;
    pty->slave_fd = -1;
    pty->child_pid = -1;
    pty->window_columns = 0;
    pty->window_lines = 0;
    pty->erase_char = 0;
    pty->xon_xoff = true;
    pty->utf8_mode = true;
}

void pty_destroy(Pty *pty)
{
    if (pty == NULL) {
        return;
    }
    pty_close(pty);
}

static void configure_termios(Pty *pty)
{
    if (pty == NULL || pty->slave_fd < 0) {
        return;
    }
    struct termios tio;
    if (tcgetattr(pty->slave_fd, &tio) != 0) {
        return;
    }
    if (pty->xon_xoff) {
        tio.c_iflag |= (IXON | IXOFF);
    } else {
        tio.c_iflag &= ~(IXON | IXOFF);
    }
#ifdef IUTF8
    if (pty->utf8_mode) {
        tio.c_iflag |= IUTF8;
    } else {
        tio.c_iflag &= ~IUTF8;
    }
#endif
    if (pty->erase_char != 0) {
        tio.c_cc[VERASE] = pty->erase_char;
    }
    tcsetattr(pty->slave_fd, TCSANOW, &tio);
}

int pty_start(Pty *pty,
              const char *program,
              char *const *arguments,
              size_t argument_count,
              char *const *environment,
              size_t environment_count,
              const char *working_directory,
              unsigned long window_id,
              bool add_to_utmp)
{
    (void)window_id;
    (void)add_to_utmp;

    if (pty == NULL || program == NULL || argument_count == 0) {
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

    pty->slave_fd = slave_fd;
    configure_termios(pty);

    pid_t child = fork();
    if (child < 0) {
        close(master_fd);
        close(slave_fd);
        return -1;
    }

    if (child == 0) {
        // Child process
        setsid();
#ifdef TIOCSCTTY
        ioctl(slave_fd, TIOCSCTTY, 0);
#endif
        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);
        if (slave_fd > STDERR_FILENO) {
            close(slave_fd);
        }
        close(master_fd);

        if (working_directory != NULL && working_directory[0] != '\0') {
            chdir(working_directory);
        }

        if (environment != NULL && environment_count > 0) {
            size_t count = environment_count;
            char **envp = calloc(count + 1, sizeof(char *));
            if (envp != NULL) {
                for (size_t i = 0; i < count; ++i) {
                    envp[i] = environment[i];
                }
                execve(program, arguments, envp);
                free(envp);
            }
        }

        execvp(program, arguments);
        _exit(EXIT_FAILURE);
    }

    close(slave_fd);
    pty->master_fd = master_fd;
    pty->slave_fd = open_slave(master_fd);
    if (pty->slave_fd < 0) {
        pty->slave_fd = -1;
    }
    pty->child_pid = child;

    struct winsize ws;
    memset(&ws, 0, sizeof(ws));
    ws.ws_col = (unsigned short)pty->window_columns;
    ws.ws_row = (unsigned short)pty->window_lines;
    if (ws.ws_col > 0 && ws.ws_row > 0) {
        ioctl(master_fd, TIOCSWINSZ, &ws);
    }
    configure_termios(pty);
    return 0;
}

void pty_set_window_size(Pty *pty, int lines, int columns)
{
    if (pty == NULL) {
        return;
    }
    pty->window_lines = lines;
    pty->window_columns = columns;
    if (pty->master_fd >= 0) {
        struct winsize ws;
        memset(&ws, 0, sizeof(ws));
        ws.ws_row = (unsigned short)lines;
        ws.ws_col = (unsigned short)columns;
        ioctl(pty->master_fd, TIOCSWINSZ, &ws);
    }
}

void pty_set_flow_control_enabled(Pty *pty, bool enable)
{
    if (pty == NULL) {
        return;
    }
    pty->xon_xoff = enable;
    configure_termios(pty);
}

bool pty_flow_control_enabled(Pty *pty)
{
    if (pty == NULL) {
        return false;
    }
    if (pty->slave_fd >= 0) {
        struct termios tio;
        if (tcgetattr(pty->slave_fd, &tio) == 0) {
            return (tio.c_iflag & IXON) != 0 && (tio.c_iflag & IXOFF) != 0;
        }
    }
    return pty->xon_xoff;
}

void pty_set_utf8_mode(Pty *pty, bool enable)
{
    if (pty == NULL) {
        return;
    }
    pty->utf8_mode = enable;
    configure_termios(pty);
}

void pty_set_erase(Pty *pty, char erase)
{
    if (pty == NULL) {
        return;
    }
    pty->erase_char = erase;
    configure_termios(pty);
}

char pty_erase(Pty *pty)
{
    if (pty == NULL) {
        return '\0';
    }
    if (pty->slave_fd >= 0) {
        struct termios tio;
        if (tcgetattr(pty->slave_fd, &tio) == 0) {
            return tio.c_cc[VERASE];
        }
    }
    return pty->erase_char;
}

void pty_set_writeable(Pty *pty, bool writeable)
{
    if (pty == NULL || pty->slave_fd < 0) {
        return;
    }
    struct stat st;
    if (fstat(pty->slave_fd, &st) != 0) {
        return;
    }
    mode_t mode = st.st_mode;
    if (writeable) {
        mode |= S_IWGRP;
    } else {
        mode &= ~(S_IWGRP | S_IWOTH);
    }
    fchmod(pty->slave_fd, mode);
}

int pty_foreground_process_group(Pty *pty)
{
    if (pty == NULL || pty->master_fd < 0) {
        return 0;
    }
    return (int)tcgetpgrp(pty->master_fd);
}

void pty_close(Pty *pty)
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

ssize_t pty_send_data(Pty *pty, const char *data, size_t length)
{
    if (pty == NULL || pty->master_fd < 0 || data == NULL || length == 0) {
        return 0;
    }
    return write(pty->master_fd, data, length);
}

ssize_t pty_read(Pty *pty, char *buffer, size_t length)
{
    if (pty == NULL || pty->master_fd < 0 || buffer == NULL || length == 0) {
        return -1;
    }
    return read(pty->master_fd, buffer, length);
}

int pty_master_fd(const Pty *pty)
{
    if (pty == NULL) {
        return -1;
    }
    return pty->master_fd;
}

pid_t pty_child_pid(const Pty *pty)
{
    if (pty == NULL) {
        return -1;
    }
    return pty->child_pid;
}

int pty_wait_for_child(Pty *pty, int *status, int options)
{
    if (pty == NULL || pty->child_pid <= 0) {
        errno = ECHILD;
        return -1;
    }
    pid_t result = waitpid(pty->child_pid, status, options);
    if (result > 0 && (options & WNOHANG) == 0) {
        pty->child_pid = -1;
    } else if (result > 0 && (options & WNOHANG) != 0) {
        if (status == NULL || WIFEXITED(*status) || WIFSIGNALED(*status)) {
            pty->child_pid = -1;
        }
    }
    return result;
}
