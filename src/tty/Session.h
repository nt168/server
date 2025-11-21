#ifndef SESSION_H
#define SESSION_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "Pty.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Session Session;

typedef void (*SessionDataCallback)(const char *data, size_t length, void *user_data);
typedef void (*SessionFinishedCallback)(int exit_code, void *user_data);

typedef struct SessionCallbacks {
    SessionDataCallback data;
    SessionFinishedCallback finished;
    void *data_user_data;
    void *finished_user_data;
} SessionCallbacks;

struct Session {
    Pty pty;
    char *program;
    char **arguments;
    size_t argument_count;
    char **environment;
    size_t environment_count;
    char *initial_working_dir;

    bool add_to_utmp;
    bool flow_control;
    bool auto_close;
    bool monitor_activity;
    bool monitor_silence;
    bool notified_activity;
    int silence_seconds;

    int reported_columns;
    int reported_rows;

    int session_id;

    SessionCallbacks callbacks;
};

void session_init(Session *session);
void session_destroy(Session *session);

int session_session_id(const Session *session);
pid_t session_process_id(const Session *session);

void session_set_program(Session *session, const char *program);
void session_set_arguments(Session *session, char *const *arguments, size_t count);
void session_set_initial_working_directory(Session *session, const char *directory);
void session_set_environment(Session *session, char *const *environment, size_t count);

const char *session_program(const Session *session);
char **session_arguments(const Session *session, size_t *count);
const char *session_initial_working_directory(const Session *session);
char **session_environment(const Session *session, size_t *count);

void session_set_add_to_utmp(Session *session, bool enabled);
bool session_add_to_utmp(const Session *session);
void session_set_flow_control_enabled(Session *session, bool enabled);
bool session_flow_control_enabled(Session *session);
void session_set_auto_close(Session *session, bool enabled);
bool session_auto_close(const Session *session);

void session_set_size(Session *session, int columns, int rows);
void session_set_callbacks(Session *session, const SessionCallbacks *callbacks);

bool session_is_running(const Session *session);
int session_run(Session *session);
void session_close(Session *session);

void session_send_text(Session *session, const char *text);
void session_send_bytes(Session *session, const char *bytes, size_t length);

int session_poll(Session *session, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* SESSION_H */
