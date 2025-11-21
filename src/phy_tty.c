#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <pty.h>
#include <stdio.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include "phy_tty.h"
#include "log.h"
#include "messtype.h"
#include <pthread.h>
#include "channel.h"

extern void send_envmonitor(mestype matp, messta smtp, int affi, const char* mes);

extern int envRTReady[4];
extern char* envRTRes;
extern pthread_mutex_t envRTLock;
extern pthread_cond_t envRTCond;

extern char *CONFIG_PAWD;
extern char *CONFIG_SERVICE_ADDR;

#define BUFFER_SIZE 256
#define RESULT_SIZE 1638400*10


//忽略SIGCHILD信号
void ignoresigchld()
{
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags= SA_RESTART;
	if(sigaction(SIGCHLD, &sa, NULL) == -1){
		perror("sigaction");
		exit(1);
	}
}

void handlesigchld(int sig)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}

// SIGCHLD 信号的处理函数
void handle_child(int sig)
{
// 循环回收所有终止的子进程
    while (1) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);

        if (pid <= 0) {
            // 没有更多终止的子进程需要回收
            break;
        }

        if (WIFEXITED(status)) {
        	printf("handle_child: 子进程 %d 正常退出，状态码 %d\n", pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
        	printf("handle_child: 子进程 %d 被信号 %d 终止\n", pid, WTERMSIG(status));
        }
    }
}

// SIGINT 信号的处理函数
void signal_handle(int sig)
{
    if (sig == SIGINT) {
        printf("收到 SIGINT 信号，正在优雅退出子进程...\n");
        // 执行必要的清理操作
        exit(EXIT_SUCCESS);
    }
}

//全局数组来存储 PID
#define MAX_CHILDREN 1024
pid_t child_pids[MAX_CHILDREN];
int pid_count = 0;

//	fp = fopen(chlpidfil, "a+");
//	len = fprintf(fp, "pid:[%d]\n", pid);


//// 将子进程 PID 存储到数组中
//int write_pid(pid_t pid) {
//    if (pid_count >= MAX_CHILDREN) {
//        fprintf(stderr, "PID 存储已满\n");
//        return -1;
//    }
//    child_pids[pid_count++] = pid;
//    return 0; // 成功
//}

void append_result(char** results, const char* buffer) {
    if (*results == NULL) {
        *results = malloc(RESULT_SIZE);
        (*results)[0] = '\0';
    }
    strncat(*results, buffer, RESULT_SIZE - strlen(*results) - 1);
}

void construct_cutlines(char* full_cmd, size_t size, const char* add, const char* usr, const char* cmd, int flg) {
    char cmd_copy[1024];
    strncpy(cmd_copy, cmd, sizeof(cmd_copy));
    cmd_copy[sizeof(cmd_copy) - 1] = '\0';

    char* token = strtok(cmd_copy, ";");
    char final_cmd[2048] = "";

    int segment_count = 1;
    while (token != NULL) {
        char line[512] = "";
        switch (flg) {
            case 0: // 普通用户执行
                snprintf(line, sizeof(line), "echo \"<<<This is a beautiful segmentation line%d>>>\"; echo \"Running: %s\"; %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", segment_count, token, token, segment_count);
                break;
            case 1: // 使用 sudo 执行
                snprintf(line, sizeof(line), "echo \"<<<This is a beautiful segmentation line%d>>>\"; echo \"Running: sudo %s\"; sudo %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", segment_count, token, token, segment_count);
                break;
            case 2: // 使用 su 执行
                snprintf(line, sizeof(line), "echo \"<<<This is a beautiful segmentation line%d>>>\"; echo \"Running: su -c \\\"%s\\\" root\"; su -c \"%s\" root; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", segment_count, token, token, segment_count);
                break;
            case 4: // 本地执行
                snprintf(line, sizeof(line), "echo \"<<<This is a beautiful segmentation line%d>>>\"; echo \"Running: %s\"; %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", segment_count, token, token, segment_count);
                break;
            case 5: // 本地 sudo 执行
                snprintf(line, sizeof(line), "echo \"<<<This is a beautiful segmentation line%d>>>\"; echo \"Running: sudo %s\"; sudo %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", segment_count, token, token, segment_count);
                break;
            case 6: // 本地 su 执行
                snprintf(line, sizeof(line), "echo \"<<<This is a beautiful segmentation line%d>>>\"; echo \"Running: su -c \\\"%s\\\" root\"; su -c \"%s\" root; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", segment_count, token, token, segment_count);
                break;
            default:
                fprintf(stderr, "Invalid flag\n");
                return;
        }
        strncat(final_cmd, line, sizeof(final_cmd) - strlen(final_cmd) - 1);
        token = strtok(NULL, ";");
        segment_count++;
    }

    // Add final segmentation line after all commands
    snprintf(final_cmd + strlen(final_cmd), sizeof(final_cmd) - strlen(final_cmd), "echo \"<<<This is a beautiful segmentation line%d>>>\"; ", segment_count);

    if (flg == 0 || flg == 1 || flg == 2) {
        snprintf(full_cmd, size, "ssh -t %s@%s '%s'", usr, add, final_cmd);
    } else {
        snprintf(full_cmd, size, "%s", final_cmd);
    }
}

void construct_cmd(char* full_cmd, size_t size, const char* add, const char* usr, const char* cmd, int flg) {
    char cmd_copy[1024];
    strncpy(cmd_copy, cmd, sizeof(cmd_copy));
    cmd_copy[sizeof(cmd_copy) - 1] = '\0';

    char* token = strtok(cmd_copy, ";");
    char final_cmd[2048] = "";

    int segment_count = 1;
    while (token != NULL) {
    	char line[1024] = "";
        switch (flg) {
            case 0: // 普通用户执行
                snprintf(line, sizeof(line), "echo \"Running: %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 1: // 使用 sudo 执行
                snprintf(line, sizeof(line), "echo \"Running: sudo %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; sudo %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 2: // 使用 su 执行
                snprintf(line, sizeof(line), "echo \"Running: su -c \\\"%s\\\" root\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; su -c \"%s\" root; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 4: // 本地执行
                snprintf(line, sizeof(line), "echo \"Running: %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 5: // 本地 sudo 执行
                snprintf(line, sizeof(line), "echo \"Running: sudo %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; sudo %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 6: // 本地 su 执行
                snprintf(line, sizeof(line), "echo \"Running: su -c \\\"%s\\\" root\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; su -c \"%s\" root; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            default:
                fprintf(stderr, "Invalid flag\n");
                return;
        }
        strncat(final_cmd, line, sizeof(final_cmd) - strlen(final_cmd) - 1);
        token = strtok(NULL, ";");
        segment_count++;
    }

    if (flg == 0 || flg == 1 || flg == 2) {
        snprintf(full_cmd, size, "ssh -t %s@%s '%s'", usr, add, final_cmd);
    } else {
        snprintf(full_cmd, size, "%s", final_cmd);
    }
}

void cst_cmd(char* full_cmd, size_t size, const char* add, const char* usr, const char* cmd, int flg) {
    char cmd_copy[1024];
    strncpy(cmd_copy, cmd, sizeof(cmd_copy));
    cmd_copy[sizeof(cmd_copy) - 1] = '\0';

    char* token = strtok(cmd_copy, ";");
    char final_cmd[2048] = "";

    int segment_count = 1;
    while (token != NULL) {
    	char line[1024] = "";
        switch (flg) {
            case 0: // 普通用户执行
                snprintf(line, sizeof(line), "echo \"Running: %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 1: // 使用 sudo 执行
                snprintf(line, sizeof(line), "echo \"Running: sudo %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; sudo %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 2: // 使用 su 执行
                snprintf(line, sizeof(line), "echo \"Running: su -c \\\"%s\\\" root\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; su -c \"%s\" root; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 4: // 本地执行
                snprintf(line, sizeof(line), "echo \"Running: %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 5: // 本地 sudo 执行
                snprintf(line, sizeof(line), "echo \"Running: sudo %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; sudo %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 6: // 本地 su 执行
                snprintf(line, sizeof(line), "echo \"Running: su -c \\\"%s\\\" root\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; su -c \"%s\" root; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            default:
                fprintf(stderr, "Invalid flag\n");
                return;
        }
        strncat(final_cmd, line, sizeof(final_cmd) - strlen(final_cmd) - 1);
        token = strtok(NULL, ";");
        segment_count++;
    }

    if (flg == 0 || flg == 1 || flg == 2) {
        snprintf(full_cmd, size, "ssh -t %s@%s '%s'", usr, add, final_cmd);
    } else {
        snprintf(full_cmd, size, "%s", final_cmd);
    }
}

/*
flg
	0 用普通用户执行
	1 用sudo 去执行
	2 用su 去执行
	4 本地执行(不用ssh)
	5 本地sudo 执行(普通用户密码 不用管普通用户是否加入了 suders)
	6 本地su 执行(超级用户密码)
*/
int forkpty_cutlines(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec)
{
    int master_fd = -1;
    pid_t pid;
    fd_set read_fds;
    char buffer[BUFFER_SIZE];
    int status;
    char full_cmd[2048];
    struct timeval timeout, *timeout_ptr = NULL;
    int ret = 0;

    construct_cmd(full_cmd, sizeof(full_cmd), add, usr, cmd, flg);

    struct sigaction sa;
    sa.sa_handler = handle_child;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        return -1;
    }

    if (timeout_sec > 0) {
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;
        timeout_ptr = &timeout;
    }

    pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (pid == -1) {
        perror("forkpty");
        return -1;
    }

    if (pid == 0) {
        struct sigaction sa_child;
        sa_child.sa_handler = signal_handle;
        sigemptyset(&sa_child.sa_mask);
        sa_child.sa_flags = SA_RESTART;
        if (sigaction(SIGINT, &sa_child, NULL) == -1) {
            perror("sigaction in child");
            exit(EXIT_FAILURE);
        }

        execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        if (master_fd == -1) {
            fprintf(stderr, "Invalid master_fd\n");
            ret = -1;
            goto cleanup;
        }

        if (write_pid(pid) != 0) {
            ret = -1;
            goto cleanup;
        }

        time_t start_time = time(NULL);
        while (1) {
            FD_ZERO(&read_fds);
            FD_SET(master_fd, &read_fds);

            int select_ret = select(master_fd + 1, &read_fds, NULL, NULL, timeout_ptr);
            if (select_ret == -1) {
                if (errno == EINTR) {
                    continue;
                }
                perror("select");
                ret = -1;
                goto cleanup;
            } else if (select_ret == 0) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                ret = -1;
                goto cleanup;
            }

            if (FD_ISSET(master_fd, &read_fds)) {
                memset(buffer, 0, sizeof(buffer));
                int bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
                if (bytes_read > 0) {
                    buffer[bytes_read] = '\0';
                    if (!strstr(buffer, "password:") && !strstr(buffer, "Password:") && !strstr(buffer, "密码")) {
                        append_result(results, buffer);
                    }

                    if (strstr(buffer, "password:") || strstr(buffer, "Password:") || strstr(buffer, "密码")) {
                        if (strstr(buffer, add)) {
                            write(master_fd, pwd, strlen(pwd));
                            write(master_fd, "\n", 1);
                            continue;
                        }
//                        if (strstr(buffer, CONFIG_SERVICE_ADDR)) {
//                            write(master_fd, CONFIG_PAWD, strlen(CONFIG_PAWD));
//                            write(master_fd, "\n", 1);
//                            continue;
//                        }
                        if (flg == 0 || flg == 1 || flg == 4 || flg == 5) {
                            write(master_fd, pwd, strlen(pwd));
                            write(master_fd, "\n", 1);
                        } else if (flg == 2 || flg == 6) {
                            write(master_fd, spwd, strlen(spwd));
                            write(master_fd, "\n", 1);
                        }
                    } else if (strstr(buffer, "yes")) {
                        write(master_fd, "yes", 3);
                        write(master_fd, "\n", 1);
                        continue;
                    } else if (strstr(buffer, "[y/N]")) {
                        write(master_fd, "y", 1);
                        write(master_fd, "\n", 1);
                        continue;
                    } else if (strstr(buffer, "[Y/n]")) {
                        write(master_fd, "Y", 1);
                        write(master_fd, "\n", 1);
                        continue;
                    }
                } else if (bytes_read == 0) {
                    break;
                } else {
                    if (errno == EINTR) {
                        continue;
                    }
//                    perror("read");
                    ret = -1;
                    goto cleanup;
                }
            }

            if (timeout_sec > 0 && difftime(time(NULL), start_time) >= timeout_sec) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                ret = -1;
                goto cleanup;
            }
        }

    cleanup:
        if (master_fd != -1) {
            close(master_fd);
            master_fd = -1;
        }

        if (waitpid(pid, &status, 0) == -1) {
//            perror("waitpid");
            ret = -1;
        } else {
            if (WIFEXITED(status)) {
                printf("Child exited with status %d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("Child killed by signal %d\n", WTERMSIG(status));
            }
        }
    }
    return ret;
}

int forkpty_envcheck(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec)
{
	int master_fd = -1;
	pid_t pid;
	fd_set read_fds;
	char buffer[BUFFER_SIZE];
	int status;
	char full_cmd[2048];
	struct timeval timeout, *timeout_ptr = NULL;
	int ret = 0;

	construct_cmd(full_cmd, sizeof(full_cmd), add, usr, cmd, flg);

	struct sigaction sa;
	sa.sa_handler = handle_child;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

	if (timeout_sec > 0) {
		timeout.tv_sec = timeout_sec;
		timeout.tv_usec = 0;
		timeout_ptr = &timeout;
	}

	pid = forkpty(&master_fd, NULL, NULL, NULL);
	if (pid == -1) {
		perror("forkpty");
		return -1;
	}

	if (pid == 0) {
		struct sigaction sa_child;
		sa_child.sa_handler = signal_handle;
		sigemptyset(&sa_child.sa_mask);
		sa_child.sa_flags = SA_RESTART;
		if (sigaction(SIGINT, &sa_child, NULL) == -1) {
			perror("sigaction in child");
			exit(EXIT_FAILURE);
		}

		execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
		perror("execlp");
		exit(EXIT_FAILURE);
	} else {
		if (master_fd == -1) {
			fprintf(stderr, "Invalid master_fd\n");
			ret = -1;
			goto cleanup;
		}

		if (write_pid(pid) != 0) {
			ret = -1;
			goto cleanup;
		}

		time_t start_time = time(NULL);
		while (1) {
			FD_ZERO(&read_fds);
			FD_SET(master_fd, &read_fds);

			int select_ret = select(master_fd + 1, &read_fds, NULL, NULL, timeout_ptr);
			if (select_ret == -1) {
				if (errno == EINTR) {
					continue;
				}
				perror("select");
				ret = -1;
				goto cleanup;
			} else if (select_ret == 0) {
				printf("Command timed out\n");
				kill(pid, SIGKILL);
				ret = -1;
				goto cleanup;
			}

			if (FD_ISSET(master_fd, &read_fds)) {
				memset(buffer, 0, sizeof(buffer));
				int bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
				if (bytes_read > 0) {
					buffer[bytes_read] = '\0';
					if (!strstr(buffer, "password:") && !strstr(buffer, "Password:") && !strstr(buffer, "密码")) {
						append_result(results, buffer);
					}

					if (strstr(buffer, "password:") || strstr(buffer, "Password:") || strstr(buffer, "密码")) {
						if (strstr(buffer, add)) {
							write(master_fd, pwd, strlen(pwd));
							write(master_fd, "\n", 1);
							continue;
						}
						if (strstr(buffer, CONFIG_SERVICE_ADDR)) {
							write(master_fd, CONFIG_PAWD, strlen(CONFIG_PAWD));
							write(master_fd, "\n", 1);
							continue;
						}
						if (flg == 0 || flg == 1 || flg == 4 || flg == 5) {
							write(master_fd, pwd, strlen(pwd));
							write(master_fd, "\n", 1);
						} else if (flg == 2 || flg == 6) {
							write(master_fd, spwd, strlen(spwd));
							write(master_fd, "\n", 1);
						}
					} else if (strstr(buffer, "[y/N]")) {
						write(master_fd, "y", 1);
						write(master_fd, "\n", 1);
						continue;
					} else if (strstr(buffer, "[Y/n]")) {
						write(master_fd, "Y", 1);
						write(master_fd, "\n", 1);
						continue;
					}
				} else if (bytes_read == 0) {
					break;
				} else {
					if (errno == EINTR) {
						continue;
					}
					perror("read");
					ret = -1;
					goto cleanup;
				}
			}

			if (timeout_sec > 0 && difftime(time(NULL), start_time) >= timeout_sec) {
				printf("Command timed out\n");
				kill(pid, SIGKILL);
				ret = -1;
				goto cleanup;
			}
		}

	cleanup:
		if (master_fd != -1) {
			close(master_fd);
			master_fd = -1;
		}

		if (waitpid(pid, &status, 0) == -1) {
			perror("waitpid");
			ret = -1;
		} else {
			if (WIFEXITED(status)) {
				printf("Child exited with status %d\n", WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				printf("Child killed by signal %d\n", WTERMSIG(status));
			}
		}
	}
return ret;
}

int forkpty_envmonitor(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec, const char* date)
{
    int master_fd;
    pid_t pid;
    fd_set read_fds;
    char buffer[12800];
    int status;
    char full_cmd[2048];
    struct timeval timeout, *timeout_ptr = NULL;
    char* tmpresults = NULL;

    pid_t forkpid;

	char rst_filename[256] = {0};
	memset(rst_filename, 0, 256);
	phy_snprintf(rst_filename, 256, "/opt/phytune/server/results/%s/envrt_%s_res", add, date);

	char static_rst_filename[256] = {0};
	memset(static_rst_filename, 0, 256);
	phy_snprintf(static_rst_filename, 256, "/opt/phytune/server/results/%s/envsta_%s_res", add, date);

	char static_table_filename[256] = {0};
	memset(static_table_filename, 0, 256);
	phy_snprintf(static_table_filename, 256, "/opt/phytune/server/results/%s/envrt_sta_table_%s_res", add, date);

	char mes[1024] = {0};
	memset(mes, 0, 1024);
	phy_snprintf(mes, 1024, "%s;%s;%s", rst_filename, static_rst_filename, static_table_filename);


//    struct transfer tran;
    // 构造命令字符串
	pthread_mutex_lock(&envRTLock);
    construct_cmd(full_cmd, sizeof(full_cmd), add, usr, cmd, flg);

    // 捕捉 SIGCHLD 信号

    signal(SIGCHLD, handle_child);
    //pthread_mutex_unlock(&envRTLock);
    if (timeout_sec > 0) {
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;
        timeout_ptr = &timeout;
    }
    //pthread_mutex_lock(&envRTLock);
    pid = forkpty(&master_fd, NULL, NULL, NULL);
    pthread_mutex_unlock(&envRTLock);
    //log调试
//	FILE* dbgfp = NULL;
//	dbgfp = fopen("/tmp/log.res", "a");
//	fprintf(dbgfp, "after forkpty;%s;%s\n", date, cmd);
//	fclose(dbgfp);

    if (pid == -1) {
        perror("forkpty");
        return -1;
    }

    if (pid == 0) {
    	pthread_mutex_lock(&envRTLock);
    	// 捕捉 SIGCHLD 信号
    	signal(SIGINT, signal_handle);
        // 子进程，执行命令
        execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
        pthread_mutex_unlock(&envRTLock);
    } else {
    	pthread_mutex_lock(&envRTLock);
    	int pidrst = write_pid(pid);
    	pthread_mutex_unlock(&envRTLock);
        if(pidrst!=0){

            //log调试
//        	FILE* dbgfp = NULL;
//        	dbgfp = fopen("/tmp/log.res", "a");
//        	fprintf(dbgfp, "================write pid error ================;%s;%s\n", date, cmd);
//        	fclose(dbgfp);
        	return -1;
        }//加锁？？？不是
        //pthread_mutex_unlock(&envRTLock);
//    	struct sigaction sa;
//    	sa.sa_handler = handlesigchld;
//    	sigemptyset(&sa.sa_mask);
//    	sa.sa_flags = SA_RESTART;
//    	if(sigaction(SIGCHLD, &sa, NULL) == -1){
//    		perror("sigaction");
//    		return 1;
//    	}
        //fcntl(master_fd, F_SETFL, O_NONBLOCK);
        // 父进程，读取子进程输出
        time_t start_time = time(NULL);
        while (1) {
        	//pthread_mutex_lock(&envRTLock);
            FD_ZERO(&read_fds);//这里导致子线程(mpstat)闪退？？？
            FD_SET(master_fd, &read_fds);

            int ret = select(master_fd + 1, &read_fds, NULL, NULL, timeout_ptr);
            //pthread_mutex_unlock(&envRTLock);
            //log调试
//        	FILE* dbgfp = NULL;
//        	dbgfp = fopen("/tmp/log.res", "a");
//        	fprintf(dbgfp, "after thread select;%s;%s\n", date, cmd);
//        	fclose(dbgfp);

            if (ret == -1) {
                //log调试
//            	FILE* dbgfp = NULL;
//            	dbgfp = fopen("/tmp/log.res", "a");
//            	fprintf(dbgfp, "select error;%s;%s\n", date, cmd);
//            	fclose(dbgfp);
                perror("select");
                return -1;
            } else if (ret == 0) {
                //log调试
//            	FILE* dbgfp = NULL;
//            	dbgfp = fopen("/tmp/log.res", "a");
//            	fprintf(dbgfp, "select time out;%s;%s\n", date, cmd);
//            	fclose(dbgfp);
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                break;
            }

            //waitpid校验
        	int forkpidstatus;
        	int rststatus = waitpid(pid, &forkpidstatus, WNOHANG);
        	if(rststatus == -1){
        		//伪终端登录失败
        		if(envRTReady[3] != 1){
        			send_envmonitor(DETECT, FINISH, ENVRT, "sshfalse");
        			envRTReady[3] = 1;
        		}

        		envRTReady[2] = 1;
        		pthread_cond_broadcast(&envRTCond);
                perror("read");
                close(master_fd);
                return -1;
        	}

            if (FD_ISSET(master_fd, &read_fds)) {
                memset(buffer, 0, sizeof(buffer)); // 初始化缓冲区
                int bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
                if (bytes_read > 0) {
                    // 确保缓冲区以空字符结尾
                    buffer[bytes_read] = '\0';
                    if(strstr(cmd, "mpstat")){
                    	//mpstatThread
                        if(buffer[0] == '\r' && buffer[1] == '\n' && buffer[19] == 'C' && buffer[20] == 'P' && buffer[21] == 'U'){//需要有字符串大段开头的校验字符
                        	pthread_mutex_lock(&envRTLock);
                        	append_result(&envRTRes, tmpresults);
                        	envRTReady[0] = 1;
                        	if(envRTReady[1] == 1){
                        		pthread_cond_signal(&envRTCond);
                        	}else{
                        		pthread_cond_wait(&envRTCond, &envRTLock);
                        		if(envRTReady[2] == 1){
                        			pthread_mutex_unlock(&envRTLock);
                        			phy_free(envRTRes);
                        			phy_free(tmpresults);
                                    close(master_fd);
                                    return -1;
                        		}
    							FILE* fp = NULL;
    							fp = fopen(rst_filename, "w");
    							fprintf(fp, "%s", envRTRes);
    							fclose(fp);
    							send_envmonitor(DETECT, FINISH, ENVRT, mes);
    							phy_free(envRTRes);
    							envRTReady[0] = 0;
    							envRTReady[1] = 0;
                        	}
                        	pthread_mutex_unlock(&envRTLock);

    						phy_free(tmpresults);
                        }
                    }else if(strstr(cmd, "env_monitor")){
                    	if(buffer[0] == '&'){
							//pthread_mutex_lock(&envRTLock);
							FILE* tableFP = NULL;
							tableFP = fopen(static_rst_filename, "w");
							fprintf(tableFP, "%s", tmpresults);
							fclose(tableFP);
							//pthread_mutex_unlock(&envRTLock);
							phy_free(tmpresults);
                    	}
                    }else{
                    	//sarThread
                    	//if(buffer[0] == 'L' && buffer[1] == 'i' && buffer[2] == 'n' && buffer[3] == 'u' && buffer[4] == 'x'){//需要有字符串大段开头的校验字符
                    	if(buffer[0] == '\r' && buffer[1] == '\n' && buffer[19] == 'p' && buffer[20] == 's' && buffer[21] == 'w'){
                    		pthread_mutex_lock(&envRTLock);
                    		append_result(&envRTRes, tmpresults);
                        	envRTReady[1] = 1;
                        	if(envRTReady[0] == 1){
                        		pthread_cond_signal(&envRTCond);
                        	}else{
                        		pthread_cond_wait(&envRTCond, &envRTLock);
                        		if(envRTReady[2] == 1){
                        			pthread_mutex_unlock(&envRTLock);
                        			phy_free(envRTRes);
                        			phy_free(tmpresults);
                                    close(master_fd);
                                    return -1;
                        		}
    							FILE* fp = NULL;
    							fp = fopen(rst_filename, "w");
    							fprintf(fp, "%s", envRTRes);
    							fclose(fp);
    							send_envmonitor(DETECT, FINISH, ENVRT, mes);
    							phy_free(envRTRes);
    							envRTReady[0] = 0;
    							envRTReady[1] = 0;
                        	}
                        	pthread_mutex_unlock(&envRTLock);
                        	phy_free(tmpresults);
                    	}
                    }

                    append_result(&tmpresults, buffer);

                    // 检查是否需要输入密码
                    pthread_mutex_lock(&envRTLock);
                    if (strstr(buffer, "password:") != NULL || strstr(buffer, "Password:") != NULL || strstr(buffer, "密码") != NULL) {
                    	if(strstr(buffer, add)){
                    		write(master_fd, pwd, strlen(pwd));
                    		write(master_fd, "\n", 1);
                    		pthread_mutex_unlock(&envRTLock);
                    		continue;
                    	}
                    	if(strstr(buffer, CONFIG_SERVICE_ADDR)){
                    		write(master_fd, CONFIG_PAWD, strlen(CONFIG_PAWD));
                    		write(master_fd, "\n", 1);
                    		pthread_mutex_unlock(&envRTLock);
                    		continue;
                    	}
                        if (flg == 0 || flg == 1 || flg == 4 || flg == 5) {
                            write(master_fd, pwd, strlen(pwd));
                            write(master_fd, "\n", 1);
                        } else if (flg == 2 || flg == 6) {
                            write(master_fd, spwd, strlen(spwd));
                            write(master_fd, "\n", 1);
                        }
					}else if(strstr(buffer,"yes")){
						write(master_fd, "yes", 3);
						write(master_fd, "\n", 1);
						pthread_mutex_unlock(&envRTLock);
						continue;
					}
                    pthread_mutex_unlock(&envRTLock);

                } else if (bytes_read == 0) {
                  	FILE* fp = NULL;
					fp = fopen("/tmp/env.res", "w");
					fprintf(fp, "byte == 0");
					fclose(fp);
                    // EOF, 子进程已经退出
					close(master_fd);
                    break;
                } else {
                	//after kill forkpty interface
                	int forkpidstatus;
                	forkpid = waitpid(pid, &forkpidstatus, WNOHANG);
                	if(forkpid == 0){
                		//forkpty正常输出时偶然也会进来
                		//正在运行
                		continue;
                	}else if(forkpid > 0){//forkpty已死
                		envRTReady[2] = 1;
                		pthread_cond_broadcast(&envRTCond);
                        perror("read");
                        close(master_fd);
                        return -1;
                		//已退出
                	}else{

                		//调用失败
                		envRTReady[2] = 1;
                		pthread_cond_broadcast(&envRTCond);
                        perror("read");
                        close(master_fd);
                        return -1;
                	}

                }
            }

            // 检查超时
            if (timeout_sec > 0 && difftime(time(NULL), start_time) >= timeout_sec) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                break;
            }
        }

        // 等待子进程退出
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child killed by signal %d\n", WTERMSIG(status));
        }
    }
    close(master_fd);
    return 0;
}

int forkpty_runpid(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec)
{
    int master_fd;
    pid_t pid;
    fd_set read_fds;
    char buffer[BUFFER_SIZE];
    int status;
    char full_cmd[2048];
    struct timeval timeout, *timeout_ptr = NULL;
    construct_cmd(full_cmd, sizeof(full_cmd), add, usr, cmd, flg);

    // 捕捉 SIGCHLD 信号
	signal(SIGCHLD, handle_child);

	if (timeout_sec > 0) {
		timeout.tv_sec = timeout_sec;
		timeout.tv_usec = 0;
		timeout_ptr = &timeout;
	}

	pid = forkpty(&master_fd, NULL, NULL, NULL);
	if (pid == -1) {
		perror("forkpty");
		return -1;
	}

	if (pid == 0) {
		// 捕捉 SIGCHLD 信号
		signal(SIGINT, signal_handle);
		// 子进程，执行命令
		execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
		perror("execlp");
		exit(EXIT_FAILURE);
	} else {
		if(0 != write_pid(pid)){
			return -1;
		}
//    	struct sigaction sa;
//    	sa.sa_handler = handlesigchld;
//    	sigemptyset(&sa.sa_mask);
//    	sa.sa_flags = SA_RESTART;
//    	if(sigaction(SIGCHLD, &sa, NULL) == -1){
//    		perror("sigaction");
//    		return 1;
//    	}

		// 父进程，读取子进程输出
		time_t start_time = time(NULL);
		while (1) {
			FD_ZERO(&read_fds);
			FD_SET(master_fd, &read_fds);

			int ret = select(master_fd + 1, &read_fds, NULL, NULL, timeout_ptr);
			if (ret == -1) {
				perror("select");
				return -1;
			} else if (ret == 0) {
				printf("Command timed out\n");
				kill(pid, SIGKILL);
				break;
			}

			if (FD_ISSET(master_fd, &read_fds)) {
				memset(buffer, 0, sizeof(buffer)); // 初始化缓冲区
				int bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
				if (bytes_read > 0) {
					// 确保缓冲区以空字符结尾
					buffer[bytes_read] = '\0';
					if((strstr(buffer, "password:") == NULL && strstr(buffer, "Password:") == NULL && strstr(buffer, "密码") == NULL)){
						//append_result(results, buffer);
					}

//                  memset(&tran, 0, sizeof(struct transfer));
//					snprintf(tran.td.mes, 1280, "%s", "");
//					tran.mma.matp = MESS;
//					tran.mma.mde = COMM;
//					tran.td.affi = 0;
//                  write_message_to_controller((char*)(&tran), sizeof(struct transfer));

					// 检查是否需要输入密码
					if (strstr(buffer, "password:") != NULL || strstr(buffer, "Password:") != NULL || strstr(buffer, "密码") != NULL) {
						if(strstr(buffer, add)){
							write(master_fd, pwd, strlen(pwd));
							write(master_fd, "\n", 1);
							continue;
						}
						if(strstr(buffer, CONFIG_SERVICE_ADDR)){
							write(master_fd, CONFIG_PAWD, strlen(CONFIG_PAWD));
							write(master_fd, "\n", 1);
							continue;
						}
						if (flg == 0 || flg == 1 || flg == 4 || flg == 5) {
							write(master_fd, pwd, strlen(pwd));
							write(master_fd, "\n", 1);
						} else if (flg == 2 || flg == 6) {
							write(master_fd, spwd, strlen(spwd));
							write(master_fd, "\n", 1);
						}
						}else if(strstr(buffer,"yes")){
							write(master_fd, "yes", 3);
							write(master_fd, "\n", 1);
						continue;
					}
				} else if (bytes_read == 0) {
					// EOF, 子进程已经退出
					break;
				} else {
					perror("read");
					return -1;
				}
			}

			// 检查超时
			if (timeout_sec > 0 && difftime(time(NULL), start_time) >= timeout_sec) {
				printf("Command timed out\n");
				kill(pid, SIGKILL);
				break;
			}
		}

		// 等待子进程退出
		waitpid(pid, &status, 0);
		if (WIFEXITED(status)) {
			printf("Child exited with status %d\n", WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			printf("Child killed by signal %d\n", WTERMSIG(status));
		}
	}

	close(master_fd);
	return 0;
}

void construct_command_stderr(char* full_cmd, size_t size, const char* add, const char* usr, const char* cmd, int flg)
{
    char cmd_copy[1024];
    strncpy(cmd_copy, cmd, sizeof(cmd_copy));
    cmd_copy[sizeof(cmd_copy) - 1] = '\0';

    char* token = strtok(cmd_copy, ";");
    char final_cmd[2048] = "";
    int segment_count = 1;

    while (token != NULL) {
        char line[512] = "";
        switch (flg) {
            case 0: // 普通用户执行
                snprintf(line, sizeof(line), "echo \"Running: %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; { stdbuf -oL -eL %s 2>&1 1>&3 | sed 's/^/stderr: /'; } 3>&1 | sed 's/^/stdout: /'; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 1: // 使用 sudo 执行
                snprintf(line, sizeof(line), "echo \"Running: sudo %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; { stdbuf -oL -eL sudo %s 2>&1 1>&3 | sed 's/^/stderr: /'; } 3>&1 | sed 's/^/stdout: /'; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 2: // 使用 su 执行
                snprintf(line, sizeof(line), "echo \"Running: su -c \\\"%s\\\" root\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; { stdbuf -oL -eL su -c \"%s\" root 2>&1 1>&3 | sed 's/^/stderr: /'; } 3>&1 | sed 's/^/stdout: /'; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 4: // 本地执行
                snprintf(line, sizeof(line), "echo \"Running: %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; { stdbuf -oL -eL %s 2>&1 1>&3 | sed 's/^/stderr: /'; } 3>&1 | sed 's/^/stdout: /'; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 5: // 本地 sudo 执行
                snprintf(line, sizeof(line), "echo \"Running: sudo %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; { stdbuf -oL -eL sudo %s 2>&1 1>&3 | sed 's/^/stderr: /'; } 3>&1 | sed 's/^/stdout: /'; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 6: // 本地 su 执行
                snprintf(line, sizeof(line), "echo \"Running: su -c \\\"%s\\\" root\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; { stdbuf -oL -eL su -c \"%s\" root 2>&1 1>&3 | sed 's/^/stderr: /'; } 3>&1 | sed 's/^/stdout: /'; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            default:
                fprintf(stderr, "Invalid flag\n");
                return;
        }
        strncat(final_cmd, line, sizeof(final_cmd) - strlen(final_cmd) - 1);
        token = strtok(NULL, ";");
        segment_count++;
    }

    if (flg == 0 || flg == 1 || flg == 2) {
        snprintf(full_cmd, size, "ssh -t %s@%s '%s'", usr, add, final_cmd);
    } else {
        snprintf(full_cmd, size, "%s", final_cmd);
    }
}

int my_forkpty_ex(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec)
{
    int master_fd;
    pid_t pid;
    fd_set read_fds;
    char buffer[BUFFER_SIZE];
    int status;
    char full_cmd[2048];
    struct timeval timeout, *timeout_ptr = NULL;

    // 构造命令字符串
//    construct_command(full_cmd, sizeof(full_cmd), add, usr, cmd, flg);
    construct_command_stderr(full_cmd, sizeof(full_cmd), add, usr, cmd, flg);
    // 捕捉 SIGCHLD 信号
    signal(SIGCHLD, handle_child);

    if (timeout_sec > 0) {
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;
        timeout_ptr = &timeout;
    }

    pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (pid == -1) {
        perror("forkpty");
        return -1;
    }

    if (pid == 0) {
        // 子进程，执行命令
        execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        // 父进程，读取子进程输出
        time_t start_time = time(NULL);
        while (1) {
            FD_ZERO(&read_fds);
            FD_SET(master_fd, &read_fds);

            int ret = select(master_fd + 1, &read_fds, NULL, NULL, timeout_ptr);
            if (ret == -1) {
                perror("select");
                return -1;
            } else if (ret == 0) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                break;
            }

            if (FD_ISSET(master_fd, &read_fds)) {
                memset(buffer, 0, sizeof(buffer)); // 初始化缓冲区
                int bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
                if (bytes_read > 0) {
                    // 确保缓冲区以空字符结尾
                    buffer[bytes_read] = '\0';
                    append_result(results, buffer);
                    printf("%s", buffer);
                    fflush(stdout);

                    // 检查是否需要输入密码
                    if (strstr(buffer, "password:") != NULL || strstr(buffer, "Password:") != NULL || strstr(buffer, "密码") != NULL) {
                        if (flg == 0 || flg == 1 || flg == 4) {
                            write(master_fd, pwd, strlen(pwd));
                            write(master_fd, "\n", 1);
                        } else if (flg == 2 || flg == 6) {
                            write(master_fd, spwd, strlen(spwd));
                            write(master_fd, "\n", 1);
                        }
                    }
                } else if (bytes_read == 0) {
                    // EOF, 子进程已经退出
                    break;
                } else {
                    perror("read");
                    return -1;
                }
            }

            // 检查超时
            if (timeout_sec > 0 && difftime(time(NULL), start_time) >= timeout_sec) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                break;
            }
        }

        // 等待子进程退出
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child killed by signal %d\n", WTERMSIG(status));
        }
    }

    close(master_fd);
    return 0;
}

int phy_forkpty_realtime(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec)
{
    int master_fd;
    pid_t pid;
    fd_set read_fds;
    char buffer[BUFFER_SIZE];
    int status;
    char full_cmd[512];
    struct timeval timeout, *timeout_ptr = NULL;

    // 构造命令字符串
    //construct_cmd(full_cmd, sizeof(full_cmd), add, usr, cmd, flg);
    construct_command_stderr(full_cmd, sizeof(full_cmd), add, usr, cmd, flg);

    // 捕捉 SIGCHLD 信号
    signal(SIGCHLD, handle_child);

    if (timeout_sec > 0) {
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;
        timeout_ptr = &timeout;
    }

    pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (pid == -1) {
		phy_log(LOG_LEVEL_ERR, "%s", "phy_forkpty_realtime: forkpty err!");
//        perror("forkpty");
        return -1;
    }

    if (pid == 0) {
        // 子进程，执行命令
        execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        // 父进程，读取子进程输出
        time_t start_time = time(NULL);
        while (1) {
            FD_ZERO(&read_fds);
            FD_SET(master_fd, &read_fds);

            int ret = select(master_fd + 1, &read_fds, NULL, NULL, timeout_ptr);
            if (ret == -1) {
//                perror("select");
            	phy_log(LOG_LEVEL_ERR, "%s", "phy_forkpty_realtime: select err!");
                return -1;
            } else if (ret == 0) {
                phy_log(LOG_LEVEL_ERR, "%s", "phy_forkpty_realtime: Command timed out!");
                kill(pid, SIGKILL);
                break;
            }

            if (FD_ISSET(master_fd, &read_fds)) {
                memset(buffer, 0, sizeof(buffer)); // 初始化缓冲区
                int bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
                if (bytes_read > 0) {
                    // 确保缓冲区以空字符结尾
                    buffer[bytes_read] = '\0';
                    append_result(results, buffer);
                    printf("%s", buffer);
                    fflush(stdout);

                    // 检查是否需要输入密码
                    if (strstr(buffer, "password:") != NULL || strstr(buffer, "Password:") != NULL || strstr(buffer, "密码") != NULL) {
                    	if(strstr(buffer, add)){
                    		write(master_fd, pwd, strlen(pwd));
                    		write(master_fd, "\n", 1);
                    		continue;
                    	}
                        if (flg == 0 || flg == 1 || flg == 4) {
                            write(master_fd, pwd, strlen(pwd));
                            write(master_fd, "\n", 1);
                        } else if (flg == 2 || flg == 6) {
                            write(master_fd, spwd, strlen(spwd));
                            write(master_fd, "\n", 1);
                        }
                    }
                } else if (bytes_read == 0) {
                    // EOF, 子进程已经退出
                    break;
                } else {
                	phy_log(LOG_LEVEL_ERR, "%s", "phy_forkpty_realtime: read err!");
//                    perror("read");
                    return -1;
                }
            }

            // 检查超时
            if (timeout_sec > 0 && difftime(time(NULL), start_time) >= timeout_sec) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                break;
            }
        }

        // 等待子进程退出
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
        	phy_log(LOG_LEVEL_ERR, "phy_forkpty_realtime: Child exited with status %d.", WEXITSTATUS(status));
//            printf("Child exited with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
        	phy_log(LOG_LEVEL_ERR, "phy_forkpty_realtime: Child killed by signal %d\n", WTERMSIG(status));
//            printf("Child killed by signal %d\n", WTERMSIG(status));
        }
    }
    close(master_fd);
    return 0;
}



int tty_execute(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec)
{
    int stdout_pipe[2], stderr_pipe[2];
    pid_t pid;
    fd_set read_fds;
    char buffer[BUFFER_SIZE];
    int status;
    struct timeval timeout;

    // 构造命令字符串
    char full_cmd[2048];
    construct_cmd(full_cmd, sizeof(full_cmd), add, usr, cmd, flg);

    // 捕捉 SIGCHLD 信号
    signal(SIGCHLD, handle_child);

    // 创建管道
    if (pipe(stdout_pipe) == -1 || pipe(stderr_pipe) == -1) {
        perror("pipe");
        return -1;
    }

    pid = fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // 子进程
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        // 执行命令
        execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
    	 time_t start_time = time(NULL);
        // 父进程
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        while (1) {
            FD_ZERO(&read_fds);
            FD_SET(stdout_pipe[0], &read_fds);
            FD_SET(stderr_pipe[0], &read_fds);

            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            int ret = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);
            if (ret == -1) {
                perror("select");
                return -1;
            } else if (ret == 0) {
                // 超时，没有数据可读
                continue;
            }

            if (FD_ISSET(stdout_pipe[0], &read_fds)) {
                memset(buffer, 0, sizeof(buffer));
                int bytes_read = read(stdout_pipe[0], buffer, sizeof(buffer) - 1);
                if (bytes_read > 0) {
                    buffer[bytes_read] = '\0';
                    // 确保每行都带有前缀
                    char* line = strtok(buffer, "\n");
                    while (line != NULL) {
                        printf("STDOUT: %s\n", line);
                        append_result(results, line);
                        append_result(results, "\n");
                        line = strtok(NULL, "\n");
                    }
                    fflush(stdout);
                    // 检查是否需要输入密码
                    if (strstr(buffer, "password:") != NULL || strstr(buffer, "Password:") != NULL || strstr(buffer, "密码") != NULL) {
                    	if(strstr(buffer, add)){
                    		write(stdout_pipe[0], pwd, strlen(pwd));
                    		write(stdout_pipe[0], "\n", 1);
                    		continue;
                    	}
                        if (flg == 0 || flg == 1 || flg == 4) {
                            write(stdout_pipe[0], pwd, strlen(pwd));
                            write(stdout_pipe[0], "\n", 1);
                        } else if (flg == 2 || flg == 6) {
                            write(stdout_pipe[0], spwd, strlen(spwd));
                            write(stdout_pipe[0], "\n", 1);
                        }
                    }

                } else if (bytes_read == 0) {
                    break;
                } else {
                    perror("read stdout");
                    return -1;
                }
            }

            if (FD_ISSET(stderr_pipe[0], &read_fds)) {
                memset(buffer, 0, sizeof(buffer));
                int bytes_read = read(stderr_pipe[0], buffer, sizeof(buffer) - 1);
                if (bytes_read > 0) {
                    buffer[bytes_read] = '\0';
                    // 确保每行都带有前缀
                    char* line = strtok(buffer, "\n");
                    while (line != NULL) {
                        printf("STDERR: %s\n", line);
                        append_result(results, line);
                        append_result(results, "\n");
                        line = strtok(NULL, "\n");
                    }
                    fflush(stdout);
                } else if (bytes_read == 0) {
                    break;
                } else {
                    perror("read stderr");
                    return -1;
                }
            }

            // 检查超时
            if (timeout_sec > 0 && difftime(time(NULL), start_time) >= timeout_sec) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                break;
            }
        }

        // 等待子进程退出
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child killed by signal %d\n", WTERMSIG(status));
        }
    }

    close(stdout_pipe[0]);
    close(stderr_pipe[0]);

    return 0;
}

char* parse_results(const char* results, const char* start_marker, const char* end_marker)
{
    const char* start = strstr(results, start_marker);
    if (start == NULL) {
        return NULL; // Start marker not found
    }

    start += strlen(start_marker); // Move past the start marker

    const char* end = strstr(start, end_marker);
    if (end == NULL) {
        return NULL; // End marker not found
    }

    size_t result_size = end - start;
    char* extracted_data = (char*)malloc(result_size + 1);
    if (extracted_data == NULL) {
        perror("malloc");
        return NULL;
    }

    strncpy(extracted_data, start, result_size);
    extracted_data[result_size] = '\0'; // Null-terminate the string

    return extracted_data;
}

////////////////////////////
void construct_cmd_local(char* full_cmd, size_t size, const char* cmd, int flg)
{
    char cmd_copy[1024];
    strncpy(cmd_copy, cmd, sizeof(cmd_copy));
    cmd_copy[sizeof(cmd_copy) - 1] = '\0';

    char* token = strtok(cmd_copy, ";");
    char final_cmd[2048] = "";

    int segment_count = 1;
    while (token != NULL) {
    	char line[1024] = "";
        switch (flg) {
            case 0: // 普通用户执行
                snprintf(line, sizeof(line), "echo \"Running: %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 1: // 使用 sudo 执行
                snprintf(line, sizeof(line), "echo \"Running: sudo %s\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; sudo %s; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            case 2: // 使用 su 执行
                snprintf(line, sizeof(line), "echo \"Running: su -c \\\"%s\\\" root\"; echo \"<<<This is a beautiful segmentation line%d>>>\"; su -c \"%s\" root; echo \"<<<This is a beautiful segmentation line%d>>>\"; ", token, segment_count, token, segment_count);
                break;
            default:
                fprintf(stderr, "Invalid flag\n");
                return;
        }
        strncat(final_cmd, line, sizeof(final_cmd) - strlen(final_cmd) - 1);
        token = strtok(NULL, ";");
        segment_count++;
    }
    snprintf(full_cmd, size, "%s", final_cmd);
}

int forkpty_local(const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec)
{
    int master_fd = -1;
    pid_t pid;
    fd_set read_fds;
    char buffer[BUFFER_SIZE];
    int status;
    char full_cmd[2048];
    struct timeval timeout, *timeout_ptr = NULL;
    int ret = 0;

    construct_cmd_local(full_cmd, sizeof(full_cmd), cmd, flg);

    struct sigaction sa;
    sa.sa_handler = handle_child;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        return -1;
    }

    if (timeout_sec > 0) {
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;
        timeout_ptr = &timeout;
    }

    pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (pid == -1) {
        perror("forkpty");
        return -1;
    }

    if (pid == 0) {
        struct sigaction sa_child;
        sa_child.sa_handler = signal_handle;
        sigemptyset(&sa_child.sa_mask);
        sa_child.sa_flags = SA_RESTART;
        if (sigaction(SIGINT, &sa_child, NULL) == -1) {
            perror("sigaction in child");
            exit(EXIT_FAILURE);
        }

        execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        if (master_fd == -1) {
            fprintf(stderr, "Invalid master_fd\n");
            ret = -1;
            goto cleanup;
        }

        if (write_pid(pid) != 0) {
            ret = -1;
            goto cleanup;
        }

        time_t start_time = time(NULL);
        while (1) {
            FD_ZERO(&read_fds);
            FD_SET(master_fd, &read_fds);

            int select_ret = select(master_fd + 1, &read_fds, NULL, NULL, timeout_ptr);
            if (select_ret == -1) {
                if (errno == EINTR) {
                    continue;
                }
                perror("select");
                ret = -1;
                goto cleanup;
            } else if (select_ret == 0) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                ret = -1;
                goto cleanup;
            }

            if (FD_ISSET(master_fd, &read_fds)) {
                memset(buffer, 0, sizeof(buffer));
                int bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
                if (bytes_read > 0) {
                    buffer[bytes_read] = '\0';
                    if (!strstr(buffer, "password:") && !strstr(buffer, "Password:") && !strstr(buffer, "密码")) {
                        append_result(results, buffer);
                    }

                    if (strstr(buffer, "password:") || strstr(buffer, "Password:") || strstr(buffer, "密码")) {
                        if ( flg == 0 || flg == 1 ) {
                            write(master_fd, pwd, strlen(pwd));
                            write(master_fd, "\n", 1);
                        } else if ( flg == 2 ) {
                            write(master_fd, spwd, strlen(spwd));
                            write(master_fd, "\n", 1);
                        }
                    } else if (strstr(buffer, "yes")) {
                        write(master_fd, "yes", 3);
                        write(master_fd, "\n", 1);
                        continue;
                    } else if (strstr(buffer, "[y/N]")) {
                        write(master_fd, "y", 1);
                        write(master_fd, "\n", 1);
                        continue;
                    } else if (strstr(buffer, "[Y/n]")) {
                        write(master_fd, "Y", 1);
                        write(master_fd, "\n", 1);
                        continue;
                    }
                } else if (bytes_read == 0) {
                    break;
                } else {
                    if (errno == EINTR) {
                        continue;
                    }
                    perror("read");
                    ret = -1;
                    goto cleanup;
                }
            }

            if (timeout_sec > 0 && difftime(time(NULL), start_time) >= timeout_sec) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                ret = -1;
                goto cleanup;
            }
        }

    cleanup:
        if (master_fd != -1) {
            close(master_fd);
            master_fd = -1;
        }

        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            ret = -1;
        } else {
            if (WIFEXITED(status)) {
                printf("Child exited with status %d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("Child killed by signal %d\n", WTERMSIG(status));
            }
        }
    }
    return ret;
}

int forkpty_envcheck_local(const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec)
{
    int master_fd = -1;
    pid_t pid;
    fd_set read_fds;
    char buffer[BUFFER_SIZE];
    int status;
    char full_cmd[2048];
    struct timeval timeout, *timeout_ptr = NULL;
    int ret = 0;

    construct_cmd_local(full_cmd, sizeof(full_cmd), cmd, flg);

    struct sigaction sa;
    sa.sa_handler = handle_child;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        return -1;
    }

    if (timeout_sec > 0) {
        timeout.tv_sec = timeout_sec;
        timeout.tv_usec = 0;
        timeout_ptr = &timeout;
    }

    pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (pid == -1) {
        perror("forkpty");
        return -1;
    }

    if (pid == 0) {
        struct sigaction sa_child;
        sa_child.sa_handler = signal_handle;
        sigemptyset(&sa_child.sa_mask);
        sa_child.sa_flags = SA_RESTART;
        if (sigaction(SIGINT, &sa_child, NULL) == -1) {
            perror("sigaction in child");
            exit(EXIT_FAILURE);
        }

        execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        if (master_fd == -1) {
            fprintf(stderr, "Invalid master_fd\n");
            ret = -1;
            goto cleanup;
        }

        if (write_pid(pid) != 0) {
            ret = -1;
            goto cleanup;
        }

        time_t start_time = time(NULL);
        while (1) {
            FD_ZERO(&read_fds);
            FD_SET(master_fd, &read_fds);

            int select_ret = select(master_fd + 1, &read_fds, NULL, NULL, timeout_ptr);
            if (select_ret == -1) {
                if (errno == EINTR) {
                    continue;
                }
                perror("select");
                ret = -1;
                goto cleanup;
            } else if (select_ret == 0) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                ret = -1;
                goto cleanup;
            }

            if (FD_ISSET(master_fd, &read_fds)) {
                memset(buffer, 0, sizeof(buffer));
                int bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
                if (bytes_read > 0) {
                    buffer[bytes_read] = '\0';
                    if (!strstr(buffer, "password:") && !strstr(buffer, "Password:") && !strstr(buffer, "密码")) {
                        append_result(results, buffer);
                    }

                    if (strstr(buffer, "password:") || strstr(buffer, "Password:") || strstr(buffer, "密码")) {

                        if (strstr(buffer, CONFIG_SERVICE_ADDR)) {
                            write(master_fd, CONFIG_PAWD, strlen(CONFIG_PAWD));
                            write(master_fd, "\n", 1);
                            continue;
                        }
                        if ( flg == 0 || flg == 1 ) {
                            write(master_fd, pwd, strlen(pwd));
                            write(master_fd, "\n", 1);
                        } else if ( flg == 2 ) {
                            write(master_fd, spwd, strlen(spwd));
                            write(master_fd, "\n", 1);
                        }
                    } else if (strstr(buffer, "[y/N]")) {
                        write(master_fd, "y", 1);
                        write(master_fd, "\n", 1);
                        continue;
                    } else if (strstr(buffer, "[Y/n]")) {
                        write(master_fd, "Y", 1);
                        write(master_fd, "\n", 1);
                        continue;
                    }
                } else if (bytes_read == 0) {
                    break;
                } else {
                    if (errno == EINTR) {
                        continue;
                    }
                    perror("read");
                    ret = -1;
                    goto cleanup;
                }
            }

            if (timeout_sec > 0 && difftime(time(NULL), start_time) >= timeout_sec) {
                printf("Command timed out\n");
                kill(pid, SIGKILL);
                ret = -1;
                goto cleanup;
            }
        }

    cleanup:
        if (master_fd != -1) {
            close(master_fd);
            master_fd = -1;
        }

        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            ret = -1;
        } else {
            if (WIFEXITED(status)) {
                printf("Child exited with status %d\n", WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                printf("Child killed by signal %d\n", WTERMSIG(status));
            }
        }
    }
    return ret;
}


#define BUF_SIZE 1024

void handle_output(int fd, const char *output_type) {
    char buf[BUF_SIZE];
    int nread;
    while ((nread = read(fd, buf, BUF_SIZE)) > 0) {
        write(STDOUT_FILENO, buf, nread);  // 实时输出到标准输出
    }
}

int openPTY(int pty[2])
{

  if((pty[0] = open("/dev/ptmx", O_RDWR)) == -1) {
    perror("open /dev/ptmx ");
    return 1;
  }
  if(grantpt(pty[0]) == -1) {
    perror("grantpt ");
    return 1;
  }

  if(unlockpt(pty[0]) == -1) {
    perror("unlockpt ");
    return 1;
  }

  char* slave = NULL;
  slave = ptsname(pty[0]);
  if(!slave) {
    perror("pstname ");
    return 1;
  }

  if((pty[1] = open(slave, O_RDWR)) == -1) {
    perror("open slave tty ");
    return 1;
  }
  return 0;
}

static int exit_on_sigchld;
#define RECV_BUFF_LEN 1024
static int exit_on_sigchld;
void readChildStatus(int signal, siginfo_t* info, void* uap)
{
  if(info->si_signo == SIGCHLD && (info->si_code == CLD_EXITED || info->si_code == CLD_KILLED || info->si_code == CLD_DUMPED))
  {
    int status;
    waitpid(info->si_pid, &status, WNOHANG);
    if(exit_on_sigchld) exit(0);
  }
}

int nt_tty(const char* usr, const char* upw, const char* rpw, const char* cmd, char** res, int flg, int sec)
{
	int master_fd = -1;
	pid_t pid;
	fd_set read_fds;
	char buffer[BUFFER_SIZE];
	int status;
	char full_cmd[2048];
	struct timeval timeout, *timeout_ptr = NULL;
	int ret = 0;

	construct_cmd_local(full_cmd, sizeof(full_cmd), cmd, flg);

	struct sigaction sa;
	sa.sa_handler = handle_child;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

	if (sec > 0) {
		timeout.tv_sec = sec;
		timeout.tv_usec = 0;
		timeout_ptr = &timeout;
	}

	pid = forkpty(&master_fd, NULL, NULL, NULL);
	if (pid == -1) {
		perror("forkpty");
		return -1;
	}

	if (pid == 0) {
		struct sigaction sa_child;
		sa_child.sa_handler = signal_handle;
		sigemptyset(&sa_child.sa_mask);
		sa_child.sa_flags = SA_RESTART;
		if (sigaction(SIGINT, &sa_child, NULL) == -1) {
			perror("sigaction in child");
			exit(EXIT_FAILURE);
		}

		execlp("/bin/bash", "bash", "-c", full_cmd, (char *)NULL);
		perror("execlp");
		exit(EXIT_FAILURE);
	} else {
		if (master_fd == -1) {
			fprintf(stderr, "Invalid master_fd\n");
			ret = -1;
			goto cleanup;
		}

		if (write_pid(pid) != 0) {
			ret = -1;
			goto cleanup;
		}

		time_t start_time = time(NULL);
		while (1) {
			FD_ZERO(&read_fds);
			FD_SET(master_fd, &read_fds);

			int select_ret = select(master_fd + 1, &read_fds, NULL, NULL, timeout_ptr);
			if (select_ret == -1) {
				if (errno == EINTR) {
					continue;
				}
				perror("select");
				ret = -1;
				goto cleanup;
			} else if (select_ret == 0) {
				printf("Command timed out\n");
				kill(pid, SIGKILL);
				ret = -1;
				goto cleanup;
			}

			if (FD_ISSET(master_fd, &read_fds)) {
				memset(buffer, 0, sizeof(buffer));
				int bytes_read = read(master_fd, buffer, sizeof(buffer) - 1);
				if (bytes_read > 0) {
					buffer[bytes_read] = '\0';
					if (!strstr(buffer, "password:") && !strstr(buffer, "Password:") && !strstr(buffer, "密码")) {
						append_result(res, buffer);
					}

					if (strstr(buffer, "password:") || strstr(buffer, "Password:") || strstr(buffer, "密码")) {
						if (flg == 0 || flg == 1) {
							write(master_fd, upw, strlen(upw));
							write(master_fd, "\n", 1);
						} else if (flg == 2) {
							write(master_fd, rpw, strlen(rpw));
							write(master_fd, "\n", 1);
						}
					} else if (strstr(buffer, "yes")) {
						write(master_fd, "yes", 3);
						write(master_fd, "\n", 1);
						continue;
					} else if (strstr(buffer, "[y/N]")) {
						write(master_fd, "y", 1);
						write(master_fd, "\n", 1);
						continue;
					} else if (strstr(buffer, "[Y/n]")) {
						write(master_fd, "Y", 1);
						write(master_fd, "\n", 1);
						continue;
					}
				} else if (bytes_read == 0) {
					break;
				} else {
					if (errno == EINTR) {
						continue;
					}
//					perror("read");
					ret = -1;
					goto cleanup;
				}
			}

			if (sec > 0 && difftime(time(NULL), start_time) >= sec) {
				printf("Command timed out\n");
				kill(pid, SIGKILL);
				ret = -1;
				goto cleanup;
			}
		}

	cleanup:
		if (master_fd != -1) {
			close(master_fd);
			master_fd = -1;
		}

		if (waitpid(pid, &status, 0) == -1) {
//			perror("waitpid");
			ret = -1;
		} else {
			if (WIFEXITED(status)) {
				printf("Child exited with status %d\n", WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				printf("Child killed by signal %d\n", WTERMSIG(status));
			}
		}
	}
	return ret;
}

bool tty_rcp(const char* add, const char* usr, const char* pwd, const char* ori, const char* dst)
{
	char* res = null;
	char cmd[256] = {0};
	memset(cmd, 0, 256);

	phy_snprintf(cmd, 256, "scp -rp %s %s@%s:%s/", ori, usr, add, m_tmpdir);
	if(-1 == forkpty_cutlines(add, usr, pwd, null, cmd, 4, &res, -1) ){
		return false;
	}
	phy_free(res);
	return true;
}

bool rmt_exe(const char* add, const char* usr, const char* pwd, const char* kpw, const char* ori, const char* tmd, char** res, int mod, int tot, bool rfl)
{
	char cmd[256] = {0};
	char* nam = null;
	char* tre = null;

	if (null == add || null == usr || null == pwd || null == ori || null == tmd){
		return false;
	}

	nam = basename((char*)ori);
	if (null == nam){
		return false;
	}

	memset(cmd, 0, sizeof(cmd));
	phy_snprintf(cmd, sizeof(cmd), "scp -rp %s %s@%s:%s/", ori, usr, add, tmd);
//	if( -1 == forkpty_cutlines(add, usr, pwd, null, cmd, 4, &tre, -1) ){
//		return false;
//	}
	forkpty_cutlines(add, usr, pwd, null, cmd, 4, &tre, -1);
	phy_free(tre);
	usleep(300000);

	memset(cmd, 0, sizeof(cmd));
	phy_snprintf(cmd, sizeof(cmd), "%s/%s", tmd, nam);
	forkpty_cutlines(add, usr, pwd, kpw, cmd, mod, &tre, tot);

	if( rfl == true ){
		*res = parse_results(tre, m_seglin, m_seglin);
		if (*res == NULL) {
			return false;
		}
	}
	phy_free(tre);
	return true;
}
