#if 0
#include <libssh/libssh.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define BUFFER_SIZE 256

typedef struct {
    ssh_channel channel;
    const char *password;
} thread_data_t;

volatile int password_prompted = 0;

void *write_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    ssh_channel channel = data->channel;
    int rc = 0;
    rc = ssh_channel_write(channel, "su\n", strlen("su\n"));
    // 等待读线程检测到密码提示
    while (!password_prompted) {
        sleep(1); // 100ms
    }

    password_prompted = 0;
    rc = ssh_channel_write(channel, "echo 0 > /proc/sys/kernel/kptr_restrict\n", strlen("echo 0 > /proc/sys/kernel/kptr_restrict\n"));
    while (!password_prompted) {
        sleep(1); // 100ms
    }

    password_prompted = 0;
    rc = ssh_channel_write(channel, "echo -1 > /proc/sys/kernel/perf_event_paranoid\n", strlen("echo -1 > /proc/sys/kernel/perf_event_paranoid\n"));
    while (!password_prompted) {
		sleep(1); // 100ms
	}
    rc = ssh_channel_write(channel, "exit\n", strlen("exit\n"));

    return NULL;
}

void *read_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    ssh_channel channel = data->channel;
    char buffer[BUFFER_SIZE] = {0};
    unsigned int nbytes;

    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[nbytes] = '\0'; // 确保缓冲区以 NULL 结尾
        printf("%s", buffer);

        // 检测到密码提示
        if (strstr(buffer, "Password:") != NULL || strstr(buffer, "password:") != NULL || strstr(buffer, "密码") != NULL) {
        	ssh_channel_write(channel, "phytools@123\n", 14);
            password_prompted = 1;
            continue;
        }

        if (strstr(buffer, "echo 0 > /proc/sys/kernel/kptr_restrict") != NULL) {
            password_prompted = 1;
            continue;
        }

        if (strstr(buffer, "echo -1 > /proc/sys/kernel/perf_event_paranoid") != NULL) {
            password_prompted = 1;
            continue;
        }

        if (strstr(buffer, "exit") != NULL) {
        	return NULL;
        }
        memset(buffer, 0, BUFFER_SIZE);

    }

    return NULL;
}

int execute_with_threads(ssh_session session, const char *password) {
    ssh_channel channel;
    int rc;
    pthread_t writer, reader;
    thread_data_t data;

    channel = ssh_channel_new(session);
    if (channel == NULL) return SSH_ERROR;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_pty(channel);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    rc = ssh_channel_request_shell(channel);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return rc;
    }

    data.channel = channel;
    data.password = password;

    // 创建读写线程
    pthread_create(&reader, NULL, read_thread, &data);
    pthread_create(&writer, NULL, write_thread, &data);

    // 等待线程结束
    pthread_join(writer, NULL);
    pthread_join(reader, NULL);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}

#if 0
int main() {
    ssh_session session;
    int rc;

    session = ssh_new();
    if (session == NULL) exit(-1);

    ssh_options_set(session, SSH_OPTIONS_HOST, "10.31.94.36");
    ssh_options_set(session, SSH_OPTIONS_USER, "test");

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(session));
        ssh_free(session);
        exit(-1);
    }

    rc = ssh_userauth_password(session, NULL, "phytools@123");
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    }

    rc = execute_with_threads(session, "phytools@123\n");
    if (rc != SSH_OK) {
        fprintf(stderr, "Error executing with threads: %d\n", rc);
    }

    ssh_disconnect(session);
    ssh_free(session);
    return rc;
}
#endif
#endif

#if 0
#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void execute_remote_command(ssh_session session, const char *command) {
    ssh_channel channel;
    int rc;
    char buffer[256];
    int nbytes;
    char *end_of_command = "command finished";  // 假设这个是结束标志
    size_t end_len = strlen(end_of_command);

    channel = ssh_channel_new(session);
    if (channel == NULL) return;

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        return;
    }

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return;
    }

    // 循环读取数据
    while (1) {
    	memset(buffer, 0, 256);
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes < 0) {
            // 读取错误
            break;
        } else if (nbytes == 0) {
            // 检查频道是否关闭
            if (ssh_channel_is_eof(channel)) {
                break;
            }
        }

        // 处理读取到的数据
        buffer[nbytes] = '\0';
        printf("%s", buffer);
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}

int main() {
    ssh_session session;
    int rc;

    session = ssh_new();
    if (session == NULL) exit(-1);

    ssh_options_set(session, SSH_OPTIONS_HOST, "10.31.94.36");
    ssh_options_set(session, SSH_OPTIONS_USER, "test");

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(session));
        ssh_free(session);
        exit(-1);
    }

    rc = ssh_userauth_password(session, NULL, "phytools@123");
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    }

    execute_remote_command(session, "ls -l /home/test");
    execute_remote_command(session, "/home/test/a.out");

    ssh_disconnect(session);
    ssh_free(session);

    return 0;
}
#endif

#if 0
#include <libssh/libssh.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int execute_command(ssh_channel channel, const char *command) {
    int rc;
    char buffer[256];
    int nbytes;

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        return rc;
    }

    // 循环读取数据，直到命令执行完毕
    while (1) {
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        if (nbytes < 0) {
            // 读取错误
            break;
        } else if (nbytes > 0) {
            // 处理读取到的数据
            fwrite(buffer, 1, nbytes, stdout);
        }

        // 检查频道是否关闭或达到EOF
        if (ssh_channel_is_eof(channel)) {
            break;
        }
    }

    // 检查命令的退出状态
    rc = ssh_channel_get_exit_status(channel);

    return rc;
}

void execute_commands(ssh_channel channel) {
    const char *commands[] = {
//        "echo 0 > /proc/sys/kernel/kptr_restrict",
//        "echo -1 > /proc/sys/kernel/perf_event_paranoid"
    		"/home/test/a.out",
			"/home/test/a.out"
    };

    for (int i = 0; i < 2; i++) {
        int rc = execute_command(channel, commands[i]);
        if (rc != 0) {
            printf("Command \"%s\" failed with exit status %d\n", commands[i], rc);
            break;
        } else {
            printf("Command \"%s\" executed successfully\n", commands[i]);
        }
    }
}

int main() {
    ssh_session session;
    ssh_channel channel;
    int rc;

    session = ssh_new();
    if (session == NULL) exit(-1);

    ssh_options_set(session, SSH_OPTIONS_HOST, "10.31.94.36");
    ssh_options_set(session, SSH_OPTIONS_USER, "test");

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Error connecting to localhost: %s\n", ssh_get_error(session));
        ssh_free(session);
        exit(-1);
    }

    rc = ssh_userauth_password(session, NULL, "phytools@123");
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Error authenticating with password: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        exit(-1);
    }

    execute_commands(channel);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    return 0;
}
#endif
