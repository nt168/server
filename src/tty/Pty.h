#ifndef PTY_H
#define PTY_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Pty Pty;

typedef struct PtyEnvironment {
    char **items;
    size_t count;
} PtyEnvironment;

struct Pty {
    int master_fd;
    int slave_fd;
    pid_t child_pid;
    int window_columns;
    int window_lines;
    char erase_char;
    bool xon_xoff;
    bool utf8_mode;
};

void pty_init(Pty *pty);
void pty_destroy(Pty *pty);
int pty_start(Pty *pty,
              const char *program,
              char *const *arguments,
              size_t argument_count,
              char *const *environment,
              size_t environment_count,
              const char *working_directory,
              unsigned long window_id,
              bool add_to_utmp);
void pty_set_window_size(Pty *pty, int lines, int columns);
void pty_set_flow_control_enabled(Pty *pty, bool enable);
bool pty_flow_control_enabled(Pty *pty);
void pty_set_utf8_mode(Pty *pty, bool enable);
void pty_set_erase(Pty *pty, char erase);
char pty_erase(Pty *pty);
void pty_set_writeable(Pty *pty, bool writeable);
int pty_foreground_process_group(Pty *pty);
void pty_close(Pty *pty);
ssize_t pty_send_data(Pty *pty, const char *data, size_t length);
ssize_t pty_read(Pty *pty, char *buffer, size_t length);
int pty_master_fd(const Pty *pty);
pid_t pty_child_pid(const Pty *pty);
int pty_wait_for_child(Pty *pty, int *status, int options);

#ifdef __cplusplus
}
#endif

#endif /* PTY_H */
