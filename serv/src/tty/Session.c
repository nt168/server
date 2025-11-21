#include "Session.h"
#include "ShellCommand.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_last_session_id = 0;

static char *duplicate_string(const char *text)
{
    if (text == NULL) {
        return NULL;
    }
    size_t length = strlen(text);
    char *copy = (char *)malloc(length + 1);
    if (copy != NULL) {
        memcpy(copy, text, length + 1);
    }
    return copy;
}

static void free_string_array(char **items, size_t count)
{
    if (items == NULL) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free(items[i]);
    }
    free(items);
}

static char **duplicate_string_array(char *const *items, size_t count)
{
    if (items == NULL || count == 0) {
        return NULL;
    }
    char **copy = (char **)calloc(count, sizeof(char *));
    if (copy == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < count; ++i) {
        copy[i] = duplicate_string(items[i]);
        if (copy[i] == NULL) {
            free_string_array(copy, i);
            return NULL;
        }
    }
    return copy;
}

static void ensure_environment_defaults(Session *session)
{
    if (session == NULL) {
        return;
    }
    bool has_term = false;
    for (size_t i = 0; i < session->environment_count; ++i) {
        if (strncmp(session->environment[i], "TERM=", 5) == 0) {
            has_term = true;
            break;
        }
    }
    if (!has_term) {
        size_t new_count = session->environment_count + 1;
        char **env = (char **)realloc(session->environment, sizeof(char *) * new_count);
        if (env == NULL) {
            return;
        }
        session->environment = env;
        session->environment[session->environment_count] = duplicate_string("TERM=xterm-256color");
        if (session->environment[session->environment_count] == NULL) {
            return;
        }
        session->environment_count = new_count;
    }
}

void session_init(Session *session)
{
    if (session == NULL) {
        return;
    }
    memset(session, 0, sizeof(*session));
    pty_init(&session->pty);
    session->flow_control = true;
    session->auto_close = true;
    session->silence_seconds = 10;
    session->reported_columns = 0;
    session->reported_rows = 0;
    session->session_id = ++g_last_session_id;
}

void session_destroy(Session *session)
{
    if (session == NULL) {
        return;
    }
    session_close(session);
    free(session->program);
    session->program = NULL;
    free_string_array(session->arguments, session->argument_count);
    session->arguments = NULL;
    session->argument_count = 0;
    free_string_array(session->environment, session->environment_count);
    session->environment = NULL;
    session->environment_count = 0;
    free(session->initial_working_dir);
    session->initial_working_dir = NULL;
    pty_destroy(&session->pty);
}

int session_session_id(const Session *session)
{
    return session != NULL ? session->session_id : 0;
}

pid_t session_process_id(const Session *session)
{
    if (session == NULL) {
        return -1;
    }
    return pty_child_pid(&session->pty);
}

void session_set_program(Session *session, const char *program)
{
    if (session == NULL) {
        return;
    }
    free(session->program);
    session->program = shell_command_expand(program);
}

void session_set_arguments(Session *session, char *const *arguments, size_t count)
{
    if (session == NULL) {
        return;
    }
    free_string_array(session->arguments, session->argument_count);
    session->arguments = NULL;
    session->argument_count = 0;
    if (arguments == NULL || count == 0) {
        return;
    }
    session->arguments = duplicate_string_array(arguments, count);
    if (session->arguments != NULL) {
        session->argument_count = count;
        for (size_t i = 0; i < count; ++i) {
            char *expanded = shell_command_expand(session->arguments[i]);
            if (expanded != session->arguments[i]) {
                free(session->arguments[i]);
                session->arguments[i] = expanded;
            }
        }
    }
}

void session_set_initial_working_directory(Session *session, const char *directory)
{
    if (session == NULL) {
        return;
    }
    free(session->initial_working_dir);
    session->initial_working_dir = shell_command_expand(directory);
}

void session_set_environment(Session *session, char *const *environment, size_t count)
{
    if (session == NULL) {
        return;
    }
    free_string_array(session->environment, session->environment_count);
    session->environment = NULL;
    session->environment_count = 0;
    if (environment == NULL || count == 0) {
        return;
    }
    session->environment = duplicate_string_array(environment, count);
    if (session->environment != NULL) {
        session->environment_count = count;
    }
}

const char *session_program(const Session *session)
{
    return session != NULL ? session->program : NULL;
}

char **session_arguments(const Session *session, size_t *count)
{
    if (count != NULL) {
        *count = session != NULL ? session->argument_count : 0;
    }
    return session != NULL ? session->arguments : NULL;
}

const char *session_initial_working_directory(const Session *session)
{
    return session != NULL ? session->initial_working_dir : NULL;
}

char **session_environment(const Session *session, size_t *count)
{
    if (count != NULL) {
        *count = session != NULL ? session->environment_count : 0;
    }
    return session != NULL ? session->environment : NULL;
}

void session_set_add_to_utmp(Session *session, bool enabled)
{
    if (session != NULL) {
        session->add_to_utmp = enabled;
    }
}

bool session_add_to_utmp(const Session *session)
{
    return session != NULL && session->add_to_utmp;
}

void session_set_flow_control_enabled(Session *session, bool enabled)
{
    if (session == NULL) {
        return;
    }
    session->flow_control = enabled;
    pty_set_flow_control_enabled(&session->pty, enabled);
}

bool session_flow_control_enabled(Session *session)
{
    if (session == NULL) {
        return false;
    }
    return pty_flow_control_enabled(&session->pty);
}

void session_set_auto_close(Session *session, bool enabled)
{
    if (session != NULL) {
        session->auto_close = enabled;
    }
}

bool session_auto_close(const Session *session)
{
    return session != NULL && session->auto_close;
}

void session_set_size(Session *session, int columns, int rows)
{
    if (session == NULL) {
        return;
    }
    if (columns <= 0 || rows <= 0) {
        return;
    }
    if (session->reported_columns == columns && session->reported_rows == rows) {
        return;
    }
    session->reported_columns = columns;
    session->reported_rows = rows;
    pty_set_window_size(&session->pty, rows, columns);
}

void session_set_callbacks(Session *session, const SessionCallbacks *callbacks)
{
    if (session == NULL) {
        return;
    }
    if (callbacks != NULL) {
        session->callbacks = *callbacks;
    } else {
        memset(&session->callbacks, 0, sizeof(session->callbacks));
    }
}

static char **build_argument_vector(const Session *session, size_t *count)
{
    if (session == NULL || session->program == NULL) {
        return NULL;
    }
    size_t argc = session->argument_count + 1;
    char **argv = (char **)calloc(argc + 1, sizeof(char *));
    if (argv == NULL) {
        return NULL;
    }
    argv[0] = duplicate_string(session->program);
    if (argv[0] == NULL) {
        free(argv);
        return NULL;
    }
    for (size_t i = 0; i < session->argument_count; ++i) {
        argv[i + 1] = duplicate_string(session->arguments[i]);
        if (argv[i + 1] == NULL) {
            free_string_array(argv, i + 1);
            return NULL;
        }
    }
    if (count != NULL) {
        *count = argc;
    }
    return argv;
}

bool session_is_running(const Session *session)
{
    if (session == NULL) {
        return false;
    }
    pid_t pid = pty_child_pid(&session->pty);
    if (pid <= 0) {
        return false;
    }
    if (waitpid(pid, NULL, WNOHANG) == pid) {
        return false;
    }
    return true;
}

static const char *resolve_program(const Session *session)
{
    if (session == NULL || session->program == NULL || session->program[0] == '\0') {
        const char *shell = getenv("SHELL");
        return shell != NULL ? shell : "/bin/sh";
    }
    if (session->program[0] == '/') {
        return session->program;
    }
    return session->program;
}

int session_run(Session *session)
{
    if (session == NULL) {
        return -1;
    }

    ensure_environment_defaults(session);

    size_t argc = 0;
    char **argv = build_argument_vector(session, &argc);
    if (argv == NULL) {
        return -1;
    }

    const char *program = resolve_program(session);

    const char *working_dir = session->initial_working_dir;
    if (working_dir == NULL || working_dir[0] == '\0') {
        working_dir = getenv("PWD");
    }

    pty_set_flow_control_enabled(&session->pty, session->flow_control);

    int result = pty_start(&session->pty,
                           program,
                           argv,
                           argc,
                           session->environment,
                           session->environment_count,
                           working_dir,
                           0,
                           session->add_to_utmp);

    free_string_array(argv, argc);

    if (result == 0) {
        pty_set_writeable(&session->pty, false);
    }

    return result;
}

void session_close(Session *session)
{
    if (session == NULL) {
        return;
    }
    pid_t pid = pty_child_pid(&session->pty);
    if (pid > 0) {
        kill(pid, SIGKILL);
        int status = 0;
        pty_wait_for_child(&session->pty, &status, 0);
    }
    pty_close(&session->pty);
}

void session_send_text(Session *session, const char *text)
{
    if (session == NULL || text == NULL) {
        return;
    }
    session_send_bytes(session, text, strlen(text));
}

void session_send_bytes(Session *session, const char *bytes, size_t length)
{
    if (session == NULL || bytes == NULL || length == 0) {
        return;
    }
    pty_send_data(&session->pty, bytes, length);
}

int session_poll(Session *session, int timeout_ms)
{
    if (session == NULL) {
        return -1;
    }

    int master_fd = pty_master_fd(&session->pty);
    if (master_fd < 0) {
        return -1;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(master_fd, &read_fds);

    struct timeval tv;
    struct timeval *tv_ptr = NULL;
    if (timeout_ms >= 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        tv_ptr = &tv;
    }

    int ready = select(master_fd + 1, &read_fds, NULL, NULL, tv_ptr);
    if (ready < 0 && errno == EINTR) {
        return 0;
    }
    if (ready > 0 && FD_ISSET(master_fd, &read_fds)) {
        char buffer[4096];
        ssize_t bytes_read = pty_read(&session->pty, buffer, sizeof(buffer));
        if (bytes_read > 0 && session->callbacks.data != NULL) {
            session->callbacks.data(buffer, (size_t)bytes_read, session->callbacks.data_user_data);
        }
    }

    int status = 0;
    pid_t pid = pty_wait_for_child(&session->pty, &status, WNOHANG);
    if (pid > 0) {
        if (session->callbacks.finished != NULL) {
            int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            session->callbacks.finished(exit_code, session->callbacks.finished_user_data);
        }
        if (session->auto_close) {
            session_close(session);
        }
        return 1;
    }

    return ready;
}
