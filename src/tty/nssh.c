#include "nssh.h"

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "Session.h"

#define NSS_BUFFER_CAPACITY 4096

typedef struct NsshContext {
    Session *session;
    const char *host;
    const char *password;
    bool host_prompt_handled;
    bool password_prompt_handled;
    bool host_mismatch_detected;
    int password_attempts;
    char buffer[NSS_BUFFER_CAPACITY];
    size_t buffer_length;
} NsshContext;

static volatile sig_atomic_t g_resize_requested = 0;

static void nssh_apply_terminal_size(Session *session)
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

static void nssh_handle_window_resize(int signal_number)
{
    (void)signal_number;
    g_resize_requested = 1;
}

static void nssh_copy_environment(Session *session)
{
    extern char **environ;
    size_t count = 0;
    while (environ[count] != NULL) {
        count++;
    }
    session_set_environment(session, environ, count);
}

static void nssh_context_init(NsshContext *context, Session *session, const char *host, const char *password)
{
    memset(context, 0, sizeof(*context));
    context->session = session;
    context->host = host;
    context->password = password;
}

static void nssh_buffer_reset(NsshContext *context)
{
    context->buffer_length = 0;
    context->buffer[0] = '\0';
}

static void nssh_buffer_append(NsshContext *context, const char *data, size_t length)
{
    if (length == 0) {
        return;
    }

    if (length >= NSS_BUFFER_CAPACITY) {
        size_t offset = length - (NSS_BUFFER_CAPACITY - 1);
        memcpy(context->buffer, data + offset, NSS_BUFFER_CAPACITY - 1);
        context->buffer[NSS_BUFFER_CAPACITY - 1] = '\0';
        context->buffer_length = NSS_BUFFER_CAPACITY - 1;
        return;
    }

    if (context->buffer_length + length >= NSS_BUFFER_CAPACITY) {
        size_t overflow = context->buffer_length + length - (NSS_BUFFER_CAPACITY - 1);
        if (overflow > context->buffer_length) {
            overflow = context->buffer_length;
        }
        memmove(context->buffer, context->buffer + overflow, context->buffer_length - overflow);
        context->buffer_length -= overflow;
    }

    memcpy(context->buffer + context->buffer_length, data, length);
    context->buffer_length += length;
    context->buffer[context->buffer_length] = '\0';
}

static bool nssh_buffer_contains(const NsshContext *context, const char *needle)
{
    if (needle == NULL || needle[0] == '\0') {
        return false;
    }
    if (context->buffer_length == 0) {
        return false;
    }
    return strstr(context->buffer, needle) != NULL;
}

static bool nssh_buffer_contains_ci(const NsshContext *context, const char *needle)
{
    if (needle == NULL || needle[0] == '\0') {
        return false;
    }
    if (context->buffer_length == 0) {
        return false;
    }
    return strcasestr(context->buffer, needle) != NULL;
}

static void nssh_send_text(Session *session, const char *text)
{
    if (session == NULL || text == NULL) {
        return;
    }
    session_send_bytes(session, text, strlen(text));
}

static void nssh_send_password(NsshContext *context)
{
    if (context->session == NULL || context->password == NULL) {
        return;
    }
    nssh_send_text(context->session, context->password);
    session_send_bytes(context->session, "\n", 1);
    context->password_attempts++;
    context->password_prompt_handled = true;
}

static void nssh_handle_session_data(const char *data, size_t length, void *user_data)
{
    NsshContext *context = (NsshContext *)user_data;
    if (context == NULL || data == NULL || length == 0) {
        return;
    }

    ssize_t written = write(STDOUT_FILENO, data, length);
    (void)written;

    nssh_buffer_append(context, data, length);

    if (!context->host_mismatch_detected) {
        if (nssh_buffer_contains(context, "REMOTE HOST IDENTIFICATION HAS CHANGED") ||
            (nssh_buffer_contains(context, "Offending") && nssh_buffer_contains(context, "known_hosts")) ||
            nssh_buffer_contains(context, "Host key verification failed")) {
            context->host_mismatch_detected = true;
            if (context->session != NULL) {
                session_close(context->session);
            }
            return;
        }
    }

    if (!context->host_prompt_handled &&
        nssh_buffer_contains(context, "Are you sure you want to continue connecting")) {
        nssh_send_text(context->session, "yes\n");
        context->host_prompt_handled = true;
        context->password_prompt_handled = false;
        nssh_buffer_reset(context);
        return;
    }

    if (nssh_buffer_contains_ci(context, "permission denied")) {
        context->password_prompt_handled = false;
    }

    if (!context->password_prompt_handled &&
        (nssh_buffer_contains_ci(context, "password:") || nssh_buffer_contains_ci(context, "passphrase"))) {
        nssh_send_password(context);
        nssh_buffer_reset(context);
        return;
    }
}

static void nssh_handle_session_finished(int exit_code, void *user_data)
{
    int *status = (int *)user_data;
    if (status != NULL) {
        *status = exit_code;
    }
}

static int nssh_remove_known_host(const char *host)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execlp("ssh-keygen", "ssh-keygen", "-R", host, (char *)NULL);
        perror("execlp");
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        fprintf(stderr, "Removed old known_hosts entry for %s\n", host);
        return 0;
    }

    fprintf(stderr, "Failed to remove known_hosts entry for %s (status=%d)\n", host, status);
    return -1;
}

static char *nssh_build_user_host(const char *user, const char *host)
{
    size_t user_length = strlen(user);
    size_t host_length = strlen(host);
    size_t total_length = user_length + 1 + host_length + 1;
    char *result = (char *)malloc(total_length);
    if (result == NULL) {
        return NULL;
    }
    snprintf(result, total_length, "%s@%s", user, host);
    return result;
}

static int nssh_collect_remote_arguments(int argc, char **argv, size_t start_index, char ***out_arguments)
{
    size_t count = 0;
    for (size_t i = start_index; i < (size_t)argc; ++i) {
        if (strcmp(argv[i], "-t") == 0) {
            continue;
        }
        count++;
    }

    if (count == 0) {
        *out_arguments = NULL;
        return 0;
    }

    char **arguments = (char **)calloc(count, sizeof(char *));
    if (arguments == NULL) {
        return -1;
    }

    size_t index = 0;
    for (size_t i = start_index; i < (size_t)argc; ++i) {
        if (strcmp(argv[i], "-t") == 0) {
            continue;
        }
        arguments[index++] = argv[i];
    }

    *out_arguments = arguments;
    return (int)count;
}

int nssh_main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "Usage: %s -ssh <host> <user> <password> [-t] [command ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *mode = argv[1];
    if (strcmp(mode, "-ssh") != 0 && strcmp(mode, "ssh") != 0) {
        fprintf(stderr, "Usage: %s -ssh <host> <user> <password> [-t] [command ...]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *host = argv[2];
    const char *user = argv[3];
    const char *password = argv[4];

    char **remote_arguments = NULL;
    int remote_argument_count = nssh_collect_remote_arguments(argc, argv, 5, &remote_arguments);
    if (remote_argument_count < 0) {
        fprintf(stderr, "Failed to allocate memory for remote arguments\n");
        return EXIT_FAILURE;
    }

    bool attempted_removal = false;
    int exit_status = EXIT_FAILURE;
    int attempt = 0;

    while (attempt < 2) {
        attempt++;
        exit_status = EXIT_FAILURE;

        Session session;
        session_init(&session);

        char *user_host = nssh_build_user_host(user, host);
        if (user_host == NULL) {
            fprintf(stderr, "Failed to allocate memory for ssh target\n");
            session_destroy(&session);
            free(remote_arguments);
            return EXIT_FAILURE;
        }

        size_t ssh_argument_count = 2 + (remote_argument_count > 0 ? (size_t)remote_argument_count : 0);
        char **ssh_arguments = (char **)calloc(ssh_argument_count, sizeof(char *));
        if (ssh_arguments == NULL) {
            fprintf(stderr, "Failed to allocate memory for ssh arguments\n");
            free(user_host);
            session_destroy(&session);
            free(remote_arguments);
            return EXIT_FAILURE;
        }

        ssh_arguments[0] = "-tt";
        ssh_arguments[1] = user_host;
        for (int i = 0; i < remote_argument_count; ++i) {
            ssh_arguments[2 + i] = remote_arguments[i];
        }

        session_set_program(&session, "ssh");
        session_set_arguments(&session, ssh_arguments, ssh_argument_count);
        nssh_copy_environment(&session);

        NsshContext context;
        nssh_context_init(&context, &session, host, password);

        struct SessionCallbacks callbacks;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.data = nssh_handle_session_data;
        callbacks.finished = nssh_handle_session_finished;
        callbacks.data_user_data = &context;
        callbacks.finished_user_data = &exit_status;
        session_set_callbacks(&session, &callbacks);

        signal(SIGWINCH, nssh_handle_window_resize);
        nssh_apply_terminal_size(&session);

        if (session_run(&session) != 0) {
            fprintf(stderr, "Failed to start ssh session for %s@%s\n", user, host);
            session_destroy(&session);
            free(user_host);
            free(ssh_arguments);
            break;
        }

        session_set_flow_control_enabled(&session, true);

        while (session_is_running(&session)) {
            if (g_resize_requested) {
                g_resize_requested = 0;
                nssh_apply_terminal_size(&session);
            }

            fd_set read_fds;
            FD_ZERO(&read_fds);
            FD_SET(STDIN_FILENO, &read_fds);

            struct timeval timeout;
            timeout.tv_sec = 0;
            timeout.tv_usec = 100000;

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
                }
            }

            session_poll(&session, 0);
        }

        session_poll(&session, 0);

        session_destroy(&session);
        free(user_host);
        free(ssh_arguments);

        if (context.host_mismatch_detected && !attempted_removal) {
            if (nssh_remove_known_host(host) == 0) {
                attempted_removal = true;
                continue;
            }
        }

        break;
    }

    free(remote_arguments);

    return exit_status;
}
