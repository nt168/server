#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#include "Session.h"
#include "nssh.h"

static volatile sig_atomic_t g_resize_requested = 0;

static void apply_terminal_size(Session *session)
{
    if (session == NULL) {
        return;
    }

    struct winsize window_size;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &window_size) == 0 && window_size.ws_col > 0 && window_size.ws_row > 0) {
        session_set_size(session, window_size.ws_col, window_size.ws_row);
    } else {
        session_set_size(session, 80, 24);
    }
}

static void handle_window_resize(int signal_number)
{
    (void)signal_number;
    g_resize_requested = 1;
}

static void handle_session_data(const char *data, size_t length, void *user_data)
{
    (void)user_data;
    if (data == NULL || length == 0) {
        return;
    }
    ssize_t written = write(STDOUT_FILENO, data, length);
    (void)written;
}

static void handle_session_finished(int exit_code, void *user_data)
{
    int *status = (int *)user_data;
    if (status != NULL) {
        *status = exit_code;
    }
}

static int copy_environment(Session *session)
{
    extern char **environ;
    size_t count = 0;
    while (environ[count] != NULL) {
        count++;
    }
    session_set_environment(session, environ, count);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && (strcmp(argv[1], "-ssh") == 0 || strcmp(argv[1], "ssh") == 0)) {
        return nssh_main(argc, argv);
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        fprintf(stderr, "       %s -ssh <host> <user> <password> [-t] [command ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    Session session;
    session_init(&session);

    session_set_program(&session, argv[1]);
    if (argc > 2) {
        session_set_arguments(&session, &argv[2], (size_t)(argc - 2));
    }
    copy_environment(&session);

    struct SessionCallbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    int exit_status = 0;
    callbacks.data = handle_session_data;
    callbacks.finished = handle_session_finished;
    callbacks.data_user_data = NULL;
    callbacks.finished_user_data = &exit_status;
    session_set_callbacks(&session, &callbacks);

    signal(SIGWINCH, handle_window_resize);
    apply_terminal_size(&session);

    if (session_run(&session) != 0) {
        fprintf(stderr, "Failed to start program: %s\n", argv[1]);
        session_destroy(&session);
        return EXIT_FAILURE;
    }

    session_set_flow_control_enabled(&session, true);

    while (session_is_running(&session)) {
        if (g_resize_requested) {
            g_resize_requested = 0;
            apply_terminal_size(&session);
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000; // 100 ms

        int ready = select(STDIN_FILENO + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (ready > 0 && FD_ISSET(STDIN_FILENO, &read_fds)) {
            char buffer[4096];
            ssize_t bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (bytes_read > 0) {
                session_send_bytes(&session, buffer, (size_t)bytes_read);
            } else if (bytes_read == 0) {
                // End of input
                FD_CLR(STDIN_FILENO, &read_fds);
            }
        }

        session_poll(&session, 0);
    }

    session_poll(&session, 0);

    session_destroy(&session);

    return exit_status;
}
