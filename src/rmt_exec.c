#include <libssh/libssh.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <stdio.h>
#include <regex.h>
#include <pthread.h>
#include "rmt_exec.h"
#include "channel.h"
#include "log.h"

extern int forkpty_cutlines(const char* add, const char* usr, const char* pwd, const char* spwd, const char* cmd, int flg, char** results, int timeout_sec);

#define NMLEN 64
typedef struct mnrst{
	ssh_channel channel;
	char nmpip[NMLEN];
}mnrst;

void* ipt_mnr(void* arg)
{
	mnrst* nst = null;
	nst = (mnrst*)arg;
	ssh_channel chl = nst->channel;
//	memset(nst->nmpip, 0, NMLEN);
//	snprintf(nst->nmpip, NMLEN, "%s", nst->nmpip):;

#define BUF_SIZE 1024
	size_t     n;
	fd_set     rdset;
	int	fd;
	int ret;
	char       buf[BUF_SIZE*2];

	if (access(nst->nmpip, F_OK)){
		phy_log(LOG_LEVEL_WARNING, "ipt_mnr:  Fifo file \"%s\" not exist and will create it now.\n", nst->nmpip);
		mkfifo(nst->nmpip, 06666);
	}

	phy_log(LOG_LEVEL_TRACE, "ipt_mnr:  Start open '%s'...", nst->nmpip);

	if ( (fd = open(nst->nmpip, O_RDONLY | O_NONBLOCK)) < 0){
		phy_log(LOG_LEVEL_ERR, "exec_ctl:  Open fifo[%s] for read error: %s.", nst->nmpip, strerror(errno));
		return null;
	}

	while(1){
		FD_ZERO(&rdset);
		FD_SET(fd, &rdset);
		ret = select(fd + 1, &rdset, NULL, NULL, NULL);
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				phy_log(LOG_LEVEL_WARNING, "exec_ctl: Select get error: %s\n", strerror(errno));
				break;
			}
		}else if (ret == 0){
			phy_log(LOG_LEVEL_TRACE, "exec_ctl:  %s\n", "Select get timeout.");
		}else{
			if (FD_ISSET(fd, &rdset))
			{
				memset(buf, 0, BUF_SIZE);
				n  = read(fd, buf,sizeof(buf) - 1);
				if (n < 0)
				{
					if(errno == EINTR){
						continue;
					}else{
						phy_log(LOG_LEVEL_WARNING, "exec_ctl: Read form fifo get error: %s\n", strerror(errno));
						break;
					}
				}else if (0 == n){
					phy_log(LOG_LEVEL_TRACE, "exec_ctl: Another side of fifo get closed and program will exit now.");
					continue;
				}else{
					printf("cmd: %s\n", buf);
//					write_file("/tmp/cdd", buf);
					ssh_channel_write(chl, buf, strlen(buf));
					ssh_channel_write(chl, "\n", 1);
				}
			}
		}
	}
	return null;
}


void remove_ansi_control(char *str) {
    regex_t regex;
    regcomp(&regex, "\x1B\\[[0-9;]*[A-Za-z]", REG_EXTENDED);

    char result[strlen(str) + 1];
    result[0] = '\0';

    regmatch_t match;
    while (regexec(&regex, str, 1, &match, 0) == 0) {
        strncat(result, str, match.rm_so);
        str += match.rm_eo;
    }
    strcat(result, str);

    strcpy(str, result);
    regfree(&regex);
}

void sch_hdl(int sig){
    // 处理SIGCHLD信号，避免产生僵尸进程
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

void sig_hdl(int sig)
{
    pid_t pid = getpid();  // 获取当前进程的PID
    switch(sig){
        case SIGINT:
            printf("子进程 %d 收到 SIGINT 信号，程序被中断\n", pid);
//            writes_file("/tmp/xxxs", "SIGINIxxxxxx", 12);
            break;
        case SIGTERM:
            printf("子进程 %d 收到 SIGTERM 信号，程序终止\n", pid);
//            writes_file("/tmp/xxxs", "SIGTERMxxxxxx", 12);
            break;
        case SIGKILL:
            printf("子进程 %d 被 SIGKILL 信号杀死\n", pid);
//            writes_file("/tmp/xxxs", "SIGKILLxxxxxx", 12);
            break;
        default:
            printf("子进程 %d 收到未知信号 %d\n", pid, sig);
            break;
    }
    exit(0);  // 收到信号后退出程序
}

#if 0
void sig_fun(int sig, siginfo_t *si, void *unused) {
    // 获取传递的信号数据
    sig_dt *data = (signal_data_t *)si->si_value.sival_ptr;

    if (data) {
        // 修改传递的数据
        printf("Signal received, modifying value in signal handler...\n");
        data->value = 100;  // 修改共享的数据
        flag = 1;  // 设置标志
    }
}
#endif

//#define ME_DBUG
void rmt_exec(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmd, const char* ipt, const char* opt, int rfl, int pid)
{
#define RDLEN 256
#ifdef ME_DBUG
    pid_t child_pid = fork();
    if (child_pid == 0) {
#endif
    	ssh_session session;
    	ssh_channel channel;
    	int rc;

    	char* rms = (char*)malloc(strlen(cmd) + 2);
    	snprintf(rms, strlen(cmd) + 2, "%s\n", cmd);

    	signal(SIGINT, sig_hdl);   // 注册信号处理函数
    	signal(SIGTERM, sig_hdl);  // 注册信号处理函数

        session = ssh_new();
        if (session == null) {
            fprintf(stderr, "Failed to create SSH session.");
            exit(1);
        }

        ssh_options_set(session, SSH_OPTIONS_HOST, add);
        ssh_options_set(session, SSH_OPTIONS_USER, usr);

        rc = ssh_connect(session);
        if (rc != SSH_OK) {
            fprintf(stderr, "Error connecting to %s: %s", add, ssh_get_error(session));
            ssh_free(session);
            exit(1);
        }

        rc = ssh_userauth_password(session, null, upw);
        if (rc != SSH_AUTH_SUCCESS) {
            fprintf(stderr, "Authentication failed: %s", ssh_get_error(session));
            ssh_disconnect(session);
            ssh_free(session);
            exit(1);
        }

    	channel = ssh_channel_new(session);
		if(channel == NULL){
			return;
		}

		rc = ssh_channel_open_session(channel);
		if(rc != SSH_OK){
			ssh_channel_free(channel);
			return;
		}

    	rc = ssh_channel_request_pty(channel);
    	if (rc != SSH_OK) {
    		ssh_channel_close(channel);
    		ssh_channel_free(channel);
    		return;
    	}

    	char buffer[RDLEN];
    	int nbytes = 0;

    	char command[1024];
		if (rfl == 1) {
			snprintf(command, sizeof(command), "echo '%s' | sudo -S %s", rpw, cmd);
		} else if (rfl == 2) {
			snprintf(command, sizeof(command), "su -c '%s'", cmd);
		} else {
			snprintf(command, sizeof(command), "%s\n", cmd);
		}

    	rc = ssh_channel_request_exec(channel, command);
    	if (rc != SSH_OK) {
    		ssh_channel_close(channel);
    		ssh_channel_free(channel);
    		return;
    	}

    	int opt_fd = open(opt, O_WRONLY|O_NONBLOCK);
		if (opt_fd < 0) {
			fprintf(stderr, "Failed to open output named pipe.");
			ssh_channel_close(channel);
			ssh_channel_free(channel);
			ssh_disconnect(session);
			ssh_free(session);
			exit(1);
		}

    	while(1){
			memset(buffer, 0 ,RDLEN);
			nbytes = ssh_channel_read(channel, buffer, RDLEN, 0);
			if(nbytes > 0) {
				if (strstr(buffer, "password:") != NULL || strstr(buffer, "Password:") != NULL || strstr(buffer, "输入密码") != NULL){
					if(rfl == 2){
						ssh_channel_write(channel, rpw, strlen(rpw));
						ssh_channel_write(channel, "\n", 1);
					}else if(rfl == 0){
						ssh_channel_write(channel, upw, strlen(rpw));
						ssh_channel_write(channel, "\n", 1);
					}
					break;
				}
				if (strstr(buffer, "exit")){
					goto rtu;
				}
				un_remove_str(buffer, rms);
				write(opt_fd, buffer, strlen(buffer));
			}else if(nbytes == 0){
rtu:
				kill(pid, SIGKILL);
				ssh_channel_send_eof(channel);
				ssh_channel_close(channel);
				ssh_channel_free(channel);
				ssh_disconnect(session);
				ssh_free(session);
				phy_free(rms);
				exit(0);
			}
		}
#ifdef ME_DBUG
    } else if (child_pid > 0) {
    	return;
    } else {
#endif
        fprintf(stderr, "Failed to fork process.");
#ifdef ME_DBUG
    }
#endif

}

void exec_ctl(const char* fds, int cfl, const char* cmd, int *cpid)
{
    pid_t pid = fork();
	if (pid == 0) {
#define BUF_SIZE 1024
		size_t     n;
		fd_set     rdset;
		int	fd;
		int ret;
		char       buf[BUF_SIZE*2];

    	signal(SIGINT, sig_hdl);   // 注册信号处理函数
    	signal(SIGTERM, sig_hdl);  // 注册信号处理函数

		if (access(fds, F_OK))
		{
			mkfifo(fds, 06666);
		}

	//  signal(SIGPIPE, signal_pipe);  ///注册信号函数

		if (access(fds, F_OK))
		{
			phy_log(LOG_LEVEL_WARNING, "exec_ctl:  Fifo file \"%s\" not exist and will create it now.\n", fds);
			mkfifo(fds, 06666);
		}

		phy_log(LOG_LEVEL_TRACE, "exec_ctl:  Start open '%s'...", fds);
		if(cfl == 1){
			if ( (fd = open(fds, O_WRONLY)) < 0)
			{
				phy_log(LOG_LEVEL_ERR, "exec_ctl:  Open fifo[%s] for write error: %s.", fds, strerror(errno));
				return;

			}
		}else if(cfl == 0){
			if ( (fd = open(fds, O_RDONLY)) < 0)
			{
				phy_log(LOG_LEVEL_ERR, "exec_ctl:  Open fifo[%s] for read error: %s.", fds, strerror(errno));
				return;
			}
		}

		while(1)
		{
			FD_ZERO(&rdset);
			FD_SET(fd, &rdset);
			ret = select(fd + 1, &rdset, NULL, NULL, NULL);
			if (ret == -1) {
				if (errno == EINTR) {
					continue;
				} else {
					phy_log(LOG_LEVEL_WARNING, "exec_ctl: Select get error: %s\n", strerror(errno));
					break;
				}
			}else if (ret == 0){
				phy_log(LOG_LEVEL_TRACE, "exec_ctl:  %s\n", "Select get timeout.");
			}else{
				if (FD_ISSET(fd, &rdset))
				{
					memset(buf, 0, BUF_SIZE);
					n  = read(fd, buf,sizeof(buf) - 1);
					if (n < 0)
					{
						if(errno == EINTR){
							continue;
						}else{
							phy_log(LOG_LEVEL_WARNING, "exec_ctl: Read form fifo get error: %s\n", strerror(errno));
							break;
						}
					}else if (0 == n){
						phy_log(LOG_LEVEL_TRACE, "exec_ctl: Another side of fifo get closed and program will exit now.");
						continue;
					}else{
						printf("%s", buf);
						writes_file("/tmp/abc", buf, n);
					}
				}
			}
		}
    }else if (pid > 0) {
    	*cpid = pid;
    	return;
    }
}

bool exec_cmd(const char* ipt, const char* cmd, size_t len)
{
	sleep(5);
    int wfd = 0;
    size_t wln = 0;
    if ((wfd = open(ipt, O_WRONLY | O_NONBLOCK)) < 0) {
        return false;
    }
    wln = write(wfd, cmd, len);
    close(wfd);
    if(wln != len){
        return false;
    }
    return true;
}

//#define RMT_OPT
void rmt_exec_gtx(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmd, const char* cpulist, int rfl)
{
	pid_t* rthreads = NULL;
	pid_t* othreads = NULL;

	int i = 0;
	rmt_args_t* rarg;
	char** arr;
	char** stmp;
	rarg = (rmt_args_t*)malloc(sizeof(rmt_args_t));
	snprintf(rarg->add, SSTR, "%s", add);
	snprintf(rarg->usr, SSTR, "%s", usr);
	snprintf(rarg->upw, SSTR, "%s", upw);
	snprintf(rarg->rpw, SSTR, "%s", rpw);
	snprintf(rarg->cmd, LSTR, "%s", cmd);
	rarg->rfl = rfl;

	phy_strarr_init(&arr);
	str_to_arr(cpulist, ",", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		i++;
	}

	delete_file("/tmp/rmt_dir");
	phy_mkdir("/tmp/rmt_dir");
#ifdef RMT_OPT
	rthreads = (pid_t*)phy_calloc(rthreads, i, sizeof(pid_t));
#endif
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pid_t));

	i = 0;
	for (stmp = arr; NULL != *stmp; stmp++){

		rarg->ncp = atoi(*stmp);
		snprintf(rarg->ipt, MSTR, "/tmp/rmt_dir/rmt_ipt_%d", rarg->ncp);
		snprintf(rarg->opt, MSTR, "/tmp/rmt_dir/rmt_opt_%d", rarg->ncp);
		snprintf(rarg->ofl, MSTR, "/tmp/rmt_dir/rmt_ofl_%d", rarg->ncp);
//rmt_opt
#ifdef RMT_OPT
		othreads[i] = rmt_thread_start(rmt_opt, (void*)rarg);
#endif
//rmt_thread
		rmt_thread_args_t	thread_args;
		thread_args.server_num = i + 1;
		thread_args.args = NULL;
		thread_args.args = rarg;
		rthreads[i] = rmt_thread_start(rmt_run, &thread_args);
		i++;
//		break;
	}
}

int	rmt_fork()
{
	fflush(stdout);
	fflush(stderr);
	return fork();
}

int	loc_child_fork()
{
	pid_t		pid;
	sigset_t	mask, orig_mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &orig_mask);
	pid = rmt_fork();
	sigprocmask(SIG_SETMASK, &orig_mask, NULL);
	if (0 == pid){
		signal(SIGCHLD, SIG_DFL);
	}
	return pid;
}

int	rmt_child_fork()
{
	pid_t		pid;
	sigset_t	mask, orig_mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &orig_mask);
	pid = rmt_fork();
	sigprocmask(SIG_SETMASK, &orig_mask, NULL);
	if (0 == pid){
		signal(SIGCHLD, SIG_DFL);
	}
	return pid;
}

RMT_THREAD_HANDLE	rmt_thread_start(RMT_THREAD_ENTRY_POINTER(handler), void* thread_args)//rmt_thread_args_t *thread_args)
{
	RMT_THREAD_HANDLE	thread = RMT_THREAD_HANDLE_NULL;

#ifdef THREAD_PROCESS
	if (0 == (thread = rmt_child_fork()))
	{
		phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: rmt_child_fork().");
		(*handler)(thread_args);
		rmt_thread_exit(EXIT_SUCCESS);
	}
	else if (-1 == thread)
	{
		phy_error("failed to fork: %s", phy_strerror(errno));
		thread = (RMT_THREAD_HANDLE)RMT_THREAD_ERROR;
		phy_log(LOG_LEVEL_ERR, "rmt_thread_start: phy_strerror().");
	}
#else
	pthread_create(&thread, NULL, handler, thread_args);
#endif
//	phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: child pid: %d.", thread);
	return thread;
}

LOC_THREAD_HANDLE	loc_thread_start(LOC_THREAD_ENTRY_POINTER(handler), void* thread_args)//rmt_thread_args_t *thread_args)
{
	LOC_THREAD_HANDLE	thread = LOC_THREAD_HANDLE_NULL;

#ifdef THREAD_PROCESS
	if (0 == (thread = loc_child_fork()))
	{
		phy_log(LOG_LEVEL_TRACE, "loc_thread_start: loc_child_fork().");
		(*handler)(thread_args);
		loc_thread_exit(EXIT_SUCCESS);
	}
	else if (-1 == thread)
	{
		phy_error("failed to fork: %s", phy_strerror(errno));
		thread = (LOC_THREAD_HANDLE)LOC_THREAD_ERROR;
		phy_log(LOG_LEVEL_ERR, "loc_thread_start: phy_strerror().");
	}
#else
	pthread_create(&thread, NULL, handler, thread_args);
#endif
//	phy_log(LOG_LEVEL_TRACE, "loc_thread_start: child pid: %d.", thread);
	return thread;
}

void mk_fifo(const char* ffnm)
{
	if (access(ffnm, F_OK))
	{
		phy_log(LOG_LEVEL_WARNING, "mk_fifo:  Fifo file \"%s\" not exist and will create it now.\n", ffnm);
		mkfifo(ffnm, 06666);
	}
}

LOC_THREAD_ENTRY(loc_run, args)
{
#define BUFFER_SIZE 1024
    loc_thread_args_t* ar = (loc_thread_args_t*)args;
    phy_setproctitle("LocRun_%d, Pid:%d", ar->server_num, (int)getpid());
    loc_args_t *a = NULL;
    a = (loc_args_t *)(ar->args);

    char *rms = (char*)malloc(strlen(a->cmd) + 2);
    snprintf(rms, strlen(a->cmd) + 2, "%s\n", a->cmd);

	int master_fd = -1;
	pid_t pid;
	fd_set read_fds;
	char buffer[BUFFER_SIZE];
	int status;
	char full_cmd[2048];
	struct timeval timeout, *timeout_ptr = NULL;
	int ret = 0;

	construct_cmd_local(full_cmd, sizeof(full_cmd), a->cmd, a->rfl);

	struct sigaction sa;
	sa.sa_handler = handle_child;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

	if (a->tot > 0) {
		timeout.tv_sec = a->tot;
		timeout.tv_usec = 0;
		timeout_ptr = &timeout;
	}

	phy_log(LOG_LEVEL_TRACE, "rmt_run:  open opt_fd %s\n", a->opt);
	int opt_fd = open(a->opt, O_WRONLY | O_NONBLOCK);
	if (opt_fd < 0) {
		phy_log(LOG_LEVEL_ERR, "loc_run:  Failed to open output named pipe %s\n", a->opt);
		exit(1);
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
						write(opt_fd, buffer, bytes_read);
					}

					if (strstr(buffer, "password:") || strstr(buffer, "Password:") || strstr(buffer, "密码")) {
						if (a->rfl == 0 || a->rfl == 1) {
							write(master_fd, a->upw, strlen(a->upw));
							write(master_fd, "\n", 1);
						} else if (a->rfl == 2) {
							write(master_fd, a->rpw, strlen(a->rpw));
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

			if (a->tot > 0 && difftime(time(NULL), start_time) >= a->tot) {
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

RMT_THREAD_ENTRY(rmt_run, args)
{
	rmt_thread_args_t* ar = NULL;
	ar = (rmt_thread_args_t*)args;
	phy_setproctitle("RmtRun_%d, Pid:%d", ar->server_num, (int)getpid());
	rmt_args_t *a = NULL;
	a = (rmt_args_t *)(ar->args);
#define RMT_RDLEN 1024
    	ssh_session session;
    	ssh_channel channel;
    	int rc;

    	char* rms = (char*)malloc(strlen(a->cmd) + 2);
    	snprintf(rms, strlen(a->cmd) + 2, "%s\n", a->cmd);

    	signal(SIGINT, sig_hdl);   // 注册信号处理函数
    	signal(SIGTERM, sig_hdl);  // 注册信号处理函数

        session = ssh_new();
        if (session == null) {
            fprintf(stderr, "Failed to create SSH session.");
            exit(1);
        }

        ssh_options_set(session, SSH_OPTIONS_HOST, a->add);
        ssh_options_set(session, SSH_OPTIONS_USER, a->usr);

        rc = ssh_connect(session);
        if (rc != SSH_OK) {
            fprintf(stderr, "Error connecting to %s: %s", a->add, ssh_get_error(session));
            ssh_free(session);
            exit(1);
        }

        rc = ssh_userauth_password(session, null, a->upw);
        if (rc != SSH_AUTH_SUCCESS) {
            fprintf(stderr, "Authentication failed: %s", ssh_get_error(session));
            ssh_disconnect(session);
            ssh_free(session);
            exit(1);
        }

    	channel = ssh_channel_new(session);
		if(channel == NULL){
			return 1;
		}

		rc = ssh_channel_open_session(channel);
		if(rc != SSH_OK){
			ssh_channel_free(channel);
			return 1;
		}

    	rc = ssh_channel_request_pty(channel);
    	if (rc != SSH_OK) {
    		ssh_channel_close(channel);
    		ssh_channel_free(channel);
    		return 1;
    	}

    	char buffer[RMT_RDLEN];
    	int nbytes = 0;

#if 0
    	pthread_t threads;
    	mnrst nmr;
    	memset(&nmr, 0, sizeof(mnrst));
    	snprintf(nmr.nmpip, NMLEN, "%s", a->ipt);
    	nmr.channel = channel;
    	pthread_create(&threads, NULL, ipt_mnr, &nmr);
#endif
    	char command[1024];
		if (a->rfl == 1) {
			snprintf(command, sizeof(command), "echo '%s' | sudo -S %s", a->upw, a->cmd);
		} else if (a->rfl == 2) {
			snprintf(command, sizeof(command), "su -c '%s'", a->cmd);
		} else {
			snprintf(command, sizeof(command), "%s\n", a->cmd);
		}

    	rc = ssh_channel_request_exec(channel, command);
    	if (rc != SSH_OK) {
    		ssh_channel_close(channel);
    		ssh_channel_free(channel);
    		return 1;
    	}

    	phy_log(LOG_LEVEL_TRACE, "rmt_run:  open opt_fd %s\n", a->opt);
    	int opt_fd = open(a->opt, O_WRONLY | O_NONBLOCK);
		if (opt_fd < 0) {
			//fprintf(stderr, "Failed to open output named pipe.");
			phy_log(LOG_LEVEL_ERR, "rmt_run:  Failed to open output named pipe %s\n", a->opt);
			ssh_channel_close(channel);
			ssh_channel_free(channel);
			ssh_disconnect(session);
			ssh_free(session);
			exit(1);
		}
		phy_log(LOG_LEVEL_WARNING, "rmt_run:  ------------- opt_fd %s\n", a->opt);
		sleep(1);
    	while(1){
			memset(buffer, 0 ,RMT_RDLEN);
			nbytes = ssh_channel_read(channel, buffer, RMT_RDLEN, 0);
			if(nbytes > 0) {
				if (strstr(buffer, "password") != NULL || strstr(buffer, "Password") != NULL || strstr(buffer, "密码") != NULL || strstr(buffer,"[sudo]")!=NULL){
					if(a->rfl == 2){
						ssh_channel_write(channel, a->rpw, strlen(a->rpw));
						ssh_channel_write(channel, "\n", 1);
					}else if(a->rfl == 0){
						ssh_channel_write(channel, a->upw, strlen(a->upw));
						ssh_channel_write(channel, "\n", 1);
					}else{
						ssh_channel_write(channel, a->upw, strlen(a->upw));
						ssh_channel_write(channel, "\n", 1);
				    }
					continue;
				}
				if (strstr(buffer, "exit")){
					goto rtu;
				}
//				un_remove_str(buffer, rms);
				write(opt_fd, buffer, nbytes);
				phy_log(LOG_LEVEL_TRACE, "rmt_run:  %d ********* %s\n", ar->server_num, buffer);
			}else if(nbytes == 0){
rtu:
//				kill(a->pid, SIGKILL);
				ssh_channel_send_eof(channel);
				ssh_channel_close(channel);
				ssh_channel_free(channel);
				ssh_disconnect(session);
				ssh_free(session);
				phy_free(rms);
				exit(0);
			}
		}
		fprintf(stderr, "Failed to fork process.");

#undef RMT_RDLEN
#ifdef THREAD_PROCESS
		return 0;
#else
		return null;
#endif
}

RMT_THREAD_ENTRY(rmt_opt, args)
{
	rmt_args_t *a = NULL;
	a = (rmt_args_t *)(args);
#define BUF_SIZE 1024
	size_t     n;
	fd_set     rdset;
	int	fd;
	int ret;
	char       buf[BUF_SIZE*2];

	signal(SIGINT, sig_hdl);   // 注册信号处理函数
	signal(SIGTERM, sig_hdl);  // 注册信号处理函数
	signal(SIGKILL, sig_hdl);

	if (access(a->opt, F_OK))
	{
		phy_log(LOG_LEVEL_WARNING, "exec_ctl:  Fifo file \"%s\" not exist and will create it now.\n", a->opt);
		mkfifo(a->opt, 06666);
	}

	phy_log(LOG_LEVEL_TRACE, "exec_ctl:  Start open '%s'...", a->opt);

	if ( (fd = open(a->opt, O_RDONLY)) < 0)
	{
		phy_log(LOG_LEVEL_ERR, "exec_ctl:  Open fifo[%s] for read error: %s.", a->opt, strerror(errno));
#ifdef THREAD_PROCESS
		return 1;
#else
		return null;
#endif
	}

	while(1)
	{
		FD_ZERO(&rdset);
		FD_SET(fd, &rdset);
		ret = select(fd + 1, &rdset, NULL, NULL, NULL);
		if (ret == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				phy_log(LOG_LEVEL_WARNING, "exec_ctl: Select get error: %s\n", strerror(errno));
				break;
			}
		}else if (ret == 0){
			phy_log(LOG_LEVEL_TRACE, "exec_ctl:  %s\n", "Select get timeout.");
		}else{
			if (FD_ISSET(fd, &rdset))
			{
				memset(buf, 0, BUF_SIZE);
				n  = read(fd, buf,sizeof(buf) - 1);
				if (n < 0)
				{
					if(errno == EINTR){
						continue;
					}else{
						phy_log(LOG_LEVEL_WARNING, "exec_ctl: Read form fifo get error: %s\n", strerror(errno));
						break;
					}
				}else if (0 == n){
					phy_log(LOG_LEVEL_TRACE, "exec_ctl: Another side of fifo get closed and program will exit now.");
					continue;
				}else{
					writes_file(a->ofl, buf, n);
				}
			}
		}
	}
#ifdef THREAD_PROCESS
		return 0;
#else
		return null;
#endif
}

loc_thmtx lthmtx;
void loc_env_entry(const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl)
{
#ifdef THREAD_PROCESS
	pid_t* rthreads = NULL;
#else
	pthread_t* rthreads = NULL;
#endif

#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	//RTEnv新增
	//推送系统设置表格脚本
	char modpath[256] = {0};
	char tmpstr[256] = {0};
	char* results = NULL;
	char env_cmd[BUFLEN] = {0};

	memset(tmpstr, 0, 256);
	phy_snprintf(modpath, 256, "%s/envrt", rsrcdir);
//	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	phy_snprintf(tmpstr, 256, "cp -rp %s %s/; rm -f /tmp/numatopo.png", modpath, dstdir);
	forkpty_local(upw, upw, tmpstr, 0, &results, -1);
	phy_free(results);

	//静态表格信息
	memset(env_cmd, 0, BUFLEN);
	phy_snprintf(env_cmd, BUFLEN, "sudo %s/envrt/envrt_monitor.sh; sudo killall sar mpstat; sudo rm -f /tmp/sar.res /tmp/mpstat.res /tmp/envrt/numatopo.png; lstopo /tmp/envrt/numatopo.png; cp /tmp/envrt/numatopo.png /tmp", dstdir);
	forkpty_local(upw, upw, env_cmd, 0, &results, -1);
	FILE* fp = NULL;
	fp = fopen("/tmp/sta_table.txt", "w+");
	fprintf(fp, "%s", results);
	phy_free(results);
	fclose(fp);

	int i = 0;
	char* sfl = null;
	char* sub = null;
	loc_args_t* rarg;//线程参数
	char** arr = NULL;
	char** stmp;
	rarg = (loc_args_t*)malloc(sizeof(loc_args_t));

	snprintf(rarg->usr, SSTR, "%s", usr);
	snprintf(rarg->upw, SSTR, "%s", upw);//pwd
	snprintf(rarg->rpw, SSTR, "%s", rpw);

	rarg->rfl = rfl;//为0

	char mes[1280] = {0};
	phy_strarr_init(&arr);

	str_to_arr(cmdlist, "]", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		strncat(mes, "/tmp/rmt/opt", strlen("/tmp/rmt/opt") + 1);
		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
		i++;
	}
	send_message(EXECUT, RMTENV, RMTENV, mes);

	while(access("/tmp/rmt", F_OK))
	{
		sleep(1);
		phy_log(LOG_LEVEL_WARNING, "rmt not exist and will create it now.");

	}
	sleep(2);

#ifdef THREAD_PROCESS
	rthreads = (pid_t*)phy_calloc(rthreads, i, sizeof(pid_t));
#else
	rthreads = (pthread_t*)phy_calloc(rthreads, i, sizeof(pthread_t));
#endif
	i = 0;
	for (stmp = arr; NULL != *stmp; stmp++){
		sfl = get_str_between_two_words(*stmp, "||", NULL);//返回0/1序号，为1时才开启实时线程 //"|"符号与管道冲突
		snprintf(rarg->ipt, MSTR, "/tmp/rmt/ipt%d", i);
		snprintf(rarg->opt, MSTR, "/tmp/rmt/opt%d", i);
		sub = get_str_between_two_words(*stmp, NULL, "||");//实时命令
		snprintf(rarg->cmd, LSTR, "%s", sub);
		phy_free(sub);
		snprintf(rarg->ofl, MSTR, "/tmp/rmt/ofl%d", i);

//loc_thread
		loc_thread_args_t	thread_args;
		thread_args.server_num = i + 1;
		thread_args.args = NULL;
		thread_args.args = rarg;
		if(atoi(sfl) == 1){//字符串转整数
			rthreads[i] = loc_thread_start(loc_run, &thread_args);
#ifdef THREAD_PROCESS
			phy_log(LOG_LEVEL_TRACE, "loc_thread_start: child pid = %d.", rthreads[i]);
#else
			phy_log(LOG_LEVEL_TRACE, "loc_thread_start: child pthread = %ld.", rthreads[i]);
#endif
		}
		phy_free(sfl);
		i++;
	}
	lthmtx.num = i;
	lthmtx.rthreads = rthreads;
#ifdef RMT_OPT
	lthmtx.othreads = othreads;
#else
	lthmtx.othreads = NULL;
#endif
	lthmtx.rarg = rarg;
	phy_strarr_free(arr);
}


//#define RMT_OPT

rmt_thmtx thmtx;
void rmt_env_entry(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl)
{
#ifdef THREAD_PROCESS
	pid_t* rthreads = NULL;
#ifdef RMP_OPT
	pid_t* othreads = NULL;
#endif
#else
	pthread_t* rthreads = NULL;
#ifdef RMP_OPT
	pthread_t* othreads = NULL;
#endif
#endif

#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	//RTEnv新增
	//推送系统设置表格脚本
	char modpath[256] = {0};
	char tmpstr[256] = {0};
	char* results = NULL;
	char env_cmd[BUFLEN] = {0};

	memset(tmpstr, 0, 256);
	phy_snprintf(modpath, 256, "%s/envrt", rsrcdir);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/; rm -f /tmp/numatopo.png", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, upw, upw, tmpstr, 4, &results, -1);
	phy_free(results);

	//静态表格信息
	memset(env_cmd, 0, BUFLEN);
	phy_snprintf(env_cmd, BUFLEN, "sudo %s/envrt/envrt_monitor.sh; sudo killall sar mpstat;sudo rm -f /tmp/sar.res /tmp/mpstat.res /tmp/envrt/numatopo.png; lstopo /tmp/envrt/numatopo.png", dstdir);
	forkpty_cutlines(add, usr, upw, upw, env_cmd, 0, &results, -1);
	FILE* fp = NULL;
	fp = fopen("/tmp/sta_table.txt", "w+");
	fprintf(fp, "%s", results);
	phy_free(results);
	fclose(fp);

	//回传numatopo.png
	memset(tmpstr, 0, 256);
	phy_snprintf(tmpstr, 256, "scp %s@%s:/tmp/envrt/numatopo.png /tmp/", usr, add);
	forkpty_cutlines(add, usr, upw, upw, tmpstr, 4, &results, -1);
	phy_free(results);

	int i = 0;
	char* sfl = null;
	char* sub = null;
	rmt_args_t* rarg;//线程参数
	char** arr;
	char** stmp;
	rarg = (rmt_args_t*)malloc(sizeof(rmt_args_t));
	snprintf(rarg->add, SSTR, "%s", add);
	snprintf(rarg->usr, SSTR, "%s", usr);
	snprintf(rarg->upw, SSTR, "%s", upw);//pwd
	snprintf(rarg->rpw, SSTR, "%s", rpw);
//	snprintf(rarg->cmd, LSTR, "%s", cmd);
	rarg->rfl = rfl;//为0

	char mes[1280] = {0};
	phy_strarr_init(&arr);

	str_to_arr(cmdlist, "]", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
//		snprintf(mes, 1280, "%s", "/tmp/rmt/opt%d;/tmp/rmt/ipt%d;/tmp/rmt/ofl%d;", i);
		strncat(mes, "/tmp/rmt/opt", strlen("/tmp/rmt/opt") + 1);
		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
//		strncat(mes, "/tmp/rmt/ipt", strlen("/tmp/rmt/ipt"));
//		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
//		strncat(mes, "/tmp/rmt/ofl", strlen("/tmp/rmt/ofl"));
//		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
		i++;
	}
	send_message(EXECUT, RMTENV, RMTENV, mes);

//	phy_mkdir("/tmp/rmt");
//	delete_file("/tmp/rmt");
	while(access("/tmp/rmt", F_OK))
	{
		sleep(1);
		phy_log(LOG_LEVEL_WARNING, "rmt not exist and will create it now.");

	}
	sleep(2);
#ifdef RMT_OPT
#ifdef THREAD_PROCESS
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pid_t));
#else
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pthread_t));
#endif
#endif

#ifdef THREAD_PROCESS
	rthreads = (pid_t*)phy_calloc(rthreads, i, sizeof(pid_t));
#else
	rthreads = (pthread_t*)phy_calloc(rthreads, i, sizeof(pthread_t));
#endif
	i = 0;
	for (stmp = arr; NULL != *stmp; stmp++){
		sfl = get_str_between_two_words(*stmp, "||", NULL);//返回0/1序号，为1时才开启实时线程 //"|"符号与管道冲突
		snprintf(rarg->ipt, MSTR, "/tmp/rmt/ipt%d", i);
		snprintf(rarg->opt, MSTR, "/tmp/rmt/opt%d", i);
		sub = get_str_between_two_words(*stmp, NULL, "||");//实时命令
		snprintf(rarg->cmd, LSTR, "%s", sub);
		phy_free(sub);
		snprintf(rarg->ofl, MSTR, "/tmp/rmt/ofl%d", i);
#ifdef RMT_OPT
		mk_fifo(rarg->opt);
#endif
//rmt_opt
#ifdef RMT_OPT
		if(atoi(sfl) == 1){
			othreads[i] = rmt_thread_start(rmt_opt, (void*)rarg);
		}
#endif

//制定参数
//		if(strstr(rarg->cmd, "env_monitorRT.sh")){
//			rarg->rfl = 1;//sudo 命令
//		}
//rmt_thread
		rmt_thread_args_t	thread_args;
		thread_args.server_num = i + 1;
		thread_args.args = NULL;
		thread_args.args = rarg;
		if(atoi(sfl) == 1){//字符串转整数
			rthreads[i] = rmt_thread_start(rmt_run, &thread_args);
#ifdef THREAD_PROCESS
			phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: child pid = %d.", rthreads[i]);
#else
			phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: child pthread = %ld.", rthreads[i]);
#endif
		}
		phy_free(sfl);
//		rmt_run(&thread_args);
		i++;
//		break;
	}
	thmtx.num = i;
	thmtx.rthreads = rthreads;
#ifdef RMT_OPT
	thmtx.othreads = othreads;
#else
	thmtx.othreads = NULL;
#endif
	thmtx.rarg = rarg;
	phy_strarr_free(arr);
}

rmt_thmtx thmtx;
void rmt_exec_entry(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl)
{
#ifdef THREAD_PROCESS
	pid_t* rthreads = NULL;
#ifdef RMP_OPT
	pid_t* othreads = NULL;
#endif
#else
	pthread_t* rthreads = NULL;
#ifdef RMP_OPT
	pthread_t* othreads = NULL;
#endif
#endif

	int i = 0;
	char* sfl = null;
	char* sub = null;
	rmt_args_t* rarg;
	char** arr;
	char** stmp;
	rarg = (rmt_args_t*)malloc(sizeof(rmt_args_t));
	snprintf(rarg->add, SSTR, "%s", add);
	snprintf(rarg->usr, SSTR, "%s", usr);
	snprintf(rarg->upw, SSTR, "%s", upw);
	snprintf(rarg->rpw, SSTR, "%s", rpw);
//	snprintf(rarg->cmd, LSTR, "%s", cmd);
	rarg->rfl = rfl;

	char mes[1280] = {0};
	phy_strarr_init(&arr);

	str_to_arr(cmdlist, "]", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
//		snprintf(mes, 1280, "%s", "/tmp/rmt/opt%d;/tmp/rmt/ipt%d;/tmp/rmt/ofl%d;", i);
//		strncat(mes, "/tmp/rmt/opt", strlen("/tmp/rmt/opt") + 1);
		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
//		strncat(mes, "/tmp/rmt/ipt", strlen("/tmp/rmt/ipt"));
//		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
//		strncat(mes, "/tmp/rmt/ofl", strlen("/tmp/rmt/ofl"));
//		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
		i++;
	}
	send_message(EXECUT, RMTEXEC, RMTEXEC, mes);

	phy_log(LOG_LEVEL_ERR, "rmt_exec_entry: mes: %s.", mes);
//	phy_mkdir("/tmp/rmt");
//	delete_file("/tmp/rmt");
	while(access("/tmp/rmt", F_OK))
	{
		sleep(1);
		phy_log(LOG_LEVEL_WARNING, "rmt not exist and will create it now.");
	}
	sleep((i/10));
#ifdef RMT_OPT
#ifdef THREAD_PROCESS
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pid_t));
#else
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pthread_t));
#endif
#endif

#ifdef THREAD_PROCESS
	rthreads = (pid_t*)phy_calloc(rthreads, i, sizeof(pid_t));
#else
	rthreads = (pthread_t*)phy_calloc(rthreads, i, sizeof(pthread_t));
#endif

	thmtx.optl = (ffnm_t*)phy_calloc(thmtx.optl, i, sizeof(ffnm_t));
	thmtx.iptl = (ffnm_t*)phy_calloc(thmtx.iptl, i, sizeof(ffnm_t));
	i = 0;
	for (stmp = arr; NULL != *stmp; stmp++){
		sfl = get_str_between_two_words(*stmp, "||", NULL);
		snprintf(rarg->ipt, MSTR, "/tmp/rmt/ipt%d", i);
		snprintf(rarg->opt, MSTR, "/tmp/rmt/opt%d", i);
		snprintf(thmtx.optl[i].ffnm, MSTR, "%s", rarg->opt);
		snprintf(thmtx.iptl[i].ffnm, MSTR, "%s", rarg->ipt);
		sub = get_str_between_two_words(*stmp, NULL, "||");
		snprintf(rarg->cmd, LSTR, "%s", sub);
		phy_free(sub);
		snprintf(rarg->ofl, MSTR, "/tmp/rmt/ofl%d", i);
#ifdef RMT_OPT
		mk_fifo(rarg->opt);
#endif
//rmt_opt
#ifdef RMT_OPT
		if(atoi(sfl) == 1){
			othreads[i] = rmt_thread_start(rmt_opt, (void*)rarg);
		}
#endif
//rmt_thread
		rmt_thread_args_t	thread_args;
		thread_args.server_num = i + 1;
		thread_args.args = NULL;
		thread_args.args = rarg;
		if(atoi(sfl) == 1){
//			rmt_run(&thread_args);
			rthreads[i] = rmt_thread_start(rmt_run, &thread_args);
#ifdef THREAD_PROCESS
			phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: child pid = %d.", rthreads[i]);
#else
			phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: child pthread = %ld.", rthreads[i]);
#endif
		}
		phy_free(sfl);
		i++;
		usleep(1000);
	}
	thmtx.num = i;
	thmtx.rthreads = rthreads;
#ifdef RMT_OPT
	thmtx.othreads = othreads;
#else
	thmtx.othreads = NULL;
#endif
	thmtx.rarg = rarg;
	phy_strarr_free(arr);
}

void loc_env_exit()
{
	phy_log(LOG_LEVEL_TRACE, "loc_env_exit.");
	if(NULL != lthmtx.rthreads){
		int i;
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		sigprocmask(SIG_BLOCK, &set, NULL);
		for(i = 0; i< lthmtx.num; i++){
			if(lthmtx.rthreads[i]){
#ifdef THREAD_PROCESS
				phy_log(LOG_LEVEL_TRACE, "rmt_env_exit: kill pid: %d.",lthmtx.rthreads[i]);
#else
				phy_log(LOG_LEVEL_TRACE, "rmt_env_exit: kill pthread: %ld.",lthmtx.rthreads[i]);
#endif
				kill(lthmtx.rthreads[i], SIGTERM);
				lthmtx.rthreads[i] = 0;
			}
		}
		phy_free(lthmtx.rthreads);
	}
}

void rmt_env_exit()
{
	phy_log(LOG_LEVEL_TRACE, "rmt_exec_exit.");
	if(NULL != thmtx.rthreads){
		int i;
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		sigprocmask(SIG_BLOCK, &set, NULL);
		for(i = 0; i< thmtx.num; i++){
			if(thmtx.rthreads[i]){
#ifdef THREAD_PROCESS
				phy_log(LOG_LEVEL_TRACE, "rmt_exec_exit: kill pid: %d.",thmtx.rthreads[i]);
#else
				phy_log(LOG_LEVEL_TRACE, "rmt_exec_exit: kill pthread: %ld.",thmtx.rthreads[i]);
#endif
				kill(thmtx.rthreads[i], SIGTERM);
				thmtx.rthreads[i] = 0;
			}
		}
		phy_free(thmtx.rthreads);
	}
}

void rmt_exec_exit()
{
	phy_log(LOG_LEVEL_TRACE, "rmt_exec_exit.");
	if(NULL != thmtx.rthreads){
		int i;
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		sigprocmask(SIG_BLOCK, &set, NULL);
		for(i = 0; i< thmtx.num; i++){
			if(thmtx.rthreads[i]){
#ifdef THREAD_PROCESS
				phy_log(LOG_LEVEL_TRACE, "rmt_exec_exit: kill pid: %d.",thmtx.rthreads[i]);
#else
				phy_log(LOG_LEVEL_TRACE, "rmt_exec_exit: kill pthread: %ld.",thmtx.rthreads[i]);
#endif
				kill(thmtx.rthreads[i], SIGTERM);
				thmtx.rthreads[i] = 0;
				unlink(thmtx.optl[i].ffnm);

			}
		}
		phy_free(thmtx.rthreads);
		phy_free(thmtx.optl);
		phy_free(thmtx.iptl);
	}
}


loc_thmtx lthmtx_numa;
void loc_numa_entry(const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl)
{
#ifdef THREAD_PROCESS
	pid_t* rthreads = NULL;
#ifdef RMP_OPT
	pid_t* othreads = NULL;
#endif
#else
	pthread_t* rthreads = NULL;
#ifdef RMP_OPT
	pthread_t* othreads = NULL;
#endif
#endif

#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char modpath[256] = {0};
	char tmpstr[256] = {0};
	char* results = NULL;
	char numa_cmd[BUFLEN] = {0};

	memset(tmpstr, 0, 256);
	phy_snprintf(modpath, 256, "%s/numa", rsrcdir);
	phy_snprintf(tmpstr, 256, "cp -rp %s %s/", modpath, dstdir);
	forkpty_local(upw, upw, tmpstr, 0, &results, -1);
	phy_free(results);

	//静态表格信息
	memset(numa_cmd, 0, BUFLEN);
	phy_snprintf(numa_cmd, BUFLEN, "sudo killall pidstat; sudo rm -f /tmp/pidstat.res", dstdir);
	forkpty_local(upw, upw, numa_cmd, 0, &results, -1);
	phy_free(results);

	int i = 0;
	char* sfl = null;
	char* sub = null;
	loc_args_t* rarg;//线程参数
	char** arr;
	char** stmp;
	rarg = (loc_args_t*)malloc(sizeof(loc_args_t));
	snprintf(rarg->usr, SSTR, "%s", usr);
	snprintf(rarg->upw, SSTR, "%s", upw);//pwd
	snprintf(rarg->rpw, SSTR, "%s", rpw);
	rarg->rfl = rfl;//为0

	char mes[1280] = {0};
	phy_strarr_init(&arr);

	str_to_arr(cmdlist, "]", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		strncat(mes, "/tmp/rmt/opt", strlen("/tmp/rmt/opt") + 1);
		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
		i++;
	}
	send_message(EXECUT, RMTNUMA, RMTNUMA, mes);

	while(access("/tmp/rmt", F_OK))
	{
		sleep(1);
		phy_log(LOG_LEVEL_WARNING, "rmt not exist and will create it now.");

	}
	sleep(2);
#ifdef RMT_OPT
#ifdef THREAD_PROCESS
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pid_t));
#else
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pthread_t));
#endif
#endif

#ifdef THREAD_PROCESS
	rthreads = (pid_t*)phy_calloc(rthreads, i, sizeof(pid_t));
#else
	rthreads = (pthread_t*)phy_calloc(rthreads, i, sizeof(pthread_t));
#endif
	i = 0;
	for (stmp = arr; NULL != *stmp; stmp++){
		sfl = get_str_between_two_words(*stmp, "||", NULL);//返回0/1序号，为1时才开启实时线程 //"|"符号与管道冲突
		snprintf(rarg->ipt, MSTR, "/tmp/rmt/ipt%d", i);
		snprintf(rarg->opt, MSTR, "/tmp/rmt/opt%d", i);
		sub = get_str_between_two_words(*stmp, NULL, "||");//实时命令
		snprintf(rarg->cmd, LSTR, "%s", sub);
		phy_free(sub);
		snprintf(rarg->ofl, MSTR, "/tmp/rmt/ofl%d", i);
#ifdef RMT_OPT
		mk_fifo(rarg->opt);
#endif
//loc_opt
#ifdef RMT_OPT
		if(atoi(sfl) == 1){
			othreads[i] = loc_thread_start(loc_opt, (void*)rarg);
		}
#endif

//loc_thread
		loc_thread_args_t	thread_args;
		thread_args.server_num = i + 1;
		thread_args.args = NULL;
		thread_args.args = rarg;
		if(atoi(sfl) == 1){//字符串转整数
			rthreads[i] = loc_thread_start(loc_run, &thread_args);
#ifdef THREAD_PROCESS
			phy_log(LOG_LEVEL_TRACE, "loc_thread_start: child pid = %d.", rthreads[i]);
#else
			phy_log(LOG_LEVEL_TRACE, "loc_thread_start: child pthread = %ld.", rthreads[i]);
#endif
		}
		phy_free(sfl);;
		i++;
	}
	lthmtx_numa.num = i;
	lthmtx_numa.rthreads = rthreads;
#ifdef RMT_OPT
	lthmtx_numa.othreads = othreads;
#else
	lthmtx_numa.othreads = NULL;
#endif
	lthmtx_numa.rarg = rarg;
	phy_strarr_free(arr);
}

rmt_thmtx thmtx_numa;
void rmt_numa_entry(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl)
{
#ifdef THREAD_PROCESS
	pid_t* rthreads = NULL;
#ifdef RMP_OPT
	pid_t* othreads = NULL;
#endif
#else
	pthread_t* rthreads = NULL;
#ifdef RMP_OPT
	pthread_t* othreads = NULL;
#endif
#endif

#define resdir "/opt/phytune/server/results"
#define rsrcdir "/opt/phytune/agent/arm/modules/Performance/phyTune_core"
#define dstdir "/tmp"
#define tmpdir "/tmp/phy/agent"

	char modpath[256] = {0};
	char tmpstr[256] = {0};
	char* results = NULL;
	char numa_cmd[BUFLEN] = {0};

	memset(tmpstr, 0, 256);
	phy_snprintf(modpath, 256, "%s/numa", rsrcdir);
	phy_snprintf(tmpstr, 256, "rsync -azu %s %s@%s:%s/", modpath, usr, add, dstdir);
	forkpty_cutlines(add, usr, upw, upw, tmpstr, 4, &results, -1);
	phy_free(results);

	//静态表格信息
	memset(numa_cmd, 0, BUFLEN);
	phy_snprintf(numa_cmd, BUFLEN, "sudo killall pidstat; sudo rm -f /tmp/pidstat.res", dstdir);
	forkpty_cutlines(add, usr, upw, upw, numa_cmd, 0, &results, -1);
	phy_free(results);

	int i = 0;
	char* sfl = null;
	char* sub = null;
	rmt_args_t* rarg;//线程参数
	char** arr;
	char** stmp;
	rarg = (rmt_args_t*)malloc(sizeof(rmt_args_t));
	snprintf(rarg->add, SSTR, "%s", add);
	snprintf(rarg->usr, SSTR, "%s", usr);
	snprintf(rarg->upw, SSTR, "%s", upw);//pwd
	snprintf(rarg->rpw, SSTR, "%s", rpw);
//	snprintf(rarg->cmd, LSTR, "%s", cmd);
	rarg->rfl = rfl;//为0

	char mes[1280] = {0};
	phy_strarr_init(&arr);

	str_to_arr(cmdlist, "]", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
//		snprintf(mes, 1280, "%s", "/tmp/rmt/opt%d;/tmp/rmt/ipt%d;/tmp/rmt/ofl%d;", i);
		strncat(mes, "/tmp/rmt/opt", strlen("/tmp/rmt/opt") + 1);
		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
//		strncat(mes, "/tmp/rmt/ipt", strlen("/tmp/rmt/ipt"));
//		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
//		strncat(mes, "/tmp/rmt/ofl", strlen("/tmp/rmt/ofl"));
//		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
		i++;
	}
	send_message(EXECUT, RMTNUMA, RMTNUMA, mes);

//	phy_mkdir("/tmp/rmt");
//	delete_file("/tmp/rmt");
	while(access("/tmp/rmt", F_OK))
	{
		sleep(1);
		phy_log(LOG_LEVEL_WARNING, "rmt not exist and will create it now.");

	}
	sleep(2);
#ifdef RMT_OPT
#ifdef THREAD_PROCESS
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pid_t));
#else
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pthread_t));
#endif
#endif

#ifdef THREAD_PROCESS
	rthreads = (pid_t*)phy_calloc(rthreads, i, sizeof(pid_t));
#else
	rthreads = (pthread_t*)phy_calloc(rthreads, i, sizeof(pthread_t));
#endif
	i = 0;
	for (stmp = arr; NULL != *stmp; stmp++){
		sfl = get_str_between_two_words(*stmp, "||", NULL);//返回0/1序号，为1时才开启实时线程 //"|"符号与管道冲突
		snprintf(rarg->ipt, MSTR, "/tmp/rmt/ipt%d", i);
		snprintf(rarg->opt, MSTR, "/tmp/rmt/opt%d", i);
		sub = get_str_between_two_words(*stmp, NULL, "||");//实时命令
		snprintf(rarg->cmd, LSTR, "%s", sub);
		phy_free(sub);
		snprintf(rarg->ofl, MSTR, "/tmp/rmt/ofl%d", i);
#ifdef RMT_OPT
		mk_fifo(rarg->opt);
#endif
//rmt_opt
#ifdef RMT_OPT
		if(atoi(sfl) == 1){
			othreads[i] = rmt_thread_start(rmt_opt, (void*)rarg);
		}
#endif

//制定参数
//		if(strstr(rarg->cmd, "env_monitorRT.sh")){
//			rarg->rfl = 1;//sudo 命令
//		}
//rmt_thread
		rmt_thread_args_t	thread_args;
		thread_args.server_num = i + 1;
		thread_args.args = NULL;
		thread_args.args = rarg;
		if(atoi(sfl) == 1){//字符串转整数
			rthreads[i] = rmt_thread_start(rmt_run, &thread_args);
#ifdef THREAD_PROCESS
			phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: child pid = %d.", rthreads[i]);
#else
			phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: child pthread = %ld.", rthreads[i]);
#endif
		}
		phy_free(sfl);
//		rmt_run(&thread_args);
		i++;
//		break;
	}
	thmtx_numa.num = i;
	thmtx_numa.rthreads = rthreads;
#ifdef RMT_OPT
	thmtx_numa.othreads = othreads;
#else
	thmtx_numa.othreads = NULL;
#endif
	thmtx_numa.rarg = rarg;
	phy_strarr_free(arr);
}

void loc_numa_exit()
{
	phy_log(LOG_LEVEL_TRACE, "loc_numa_exit.");
	if(NULL != lthmtx_numa.rthreads){
		int i;
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		sigprocmask(SIG_BLOCK, &set, NULL);
		for(i = 0; i< lthmtx_numa.num; i++){
			if(lthmtx_numa.rthreads[i]){
#ifdef THREAD_PROCESS
				phy_log(LOG_LEVEL_TRACE, "loc_numa_exit: kill pid: %d.",lthmtx_numa.rthreads[i]);
#else
				phy_log(LOG_LEVEL_TRACE, "loc_numa_exit: kill pthread: %ld.",lthmtx_numa.rthreads[i]);
#endif
				kill(lthmtx_numa.rthreads[i], SIGTERM);
				lthmtx_numa.rthreads[i] = 0;
			}
		}
		phy_free(lthmtx_numa.rthreads);
	}
}


void rmt_numa_exit()
{
	phy_log(LOG_LEVEL_TRACE, "rmt_exec_exit.");
	if(NULL != thmtx_numa.rthreads){
		int i;
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		sigprocmask(SIG_BLOCK, &set, NULL);
		for(i = 0; i< thmtx_numa.num; i++){
			if(thmtx_numa.rthreads[i]){
#ifdef THREAD_PROCESS
				phy_log(LOG_LEVEL_TRACE, "rmt_exec_exit: kill pid: %d.",thmtx_numa.rthreads[i]);
#else
				phy_log(LOG_LEVEL_TRACE, "rmt_exec_exit: kill pthread: %ld.",thmtx_numa.rthreads[i]);
#endif
				kill(thmtx_numa.rthreads[i], SIGTERM);
				thmtx_numa.rthreads[i] = 0;
			}
		}
		phy_free(thmtx_numa.rthreads);
	}
}

void realtime_exec_entry(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl,mesexe mde)
{
#ifdef THREAD_PROCESS
	pid_t* rthreads = NULL;
#ifdef RMP_OPT
	pid_t* othreads = NULL;
#endif
#else
	pthread_t* rthreads = NULL;
#ifdef RMP_OPT
	pthread_t* othreads = NULL;
#endif
#endif

	int i = 0;
	char* sfl = null;
	char* sub = null;
	rmt_args_t* rarg;
	char** arr;
	char** stmp;
	rarg = (rmt_args_t*)malloc(sizeof(rmt_args_t));
	snprintf(rarg->add, SSTR, "%s", add);
	snprintf(rarg->usr, SSTR, "%s", usr);
	snprintf(rarg->upw, SSTR, "%s", upw);
	snprintf(rarg->rpw, SSTR, "%s", rpw);
//	snprintf(rarg->cmd, LSTR, "%s", cmd);
	rarg->rfl = rfl;

	char mes[1280] = {0};
	phy_strarr_init(&arr);

	str_to_arr(cmdlist, "]", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
//		snprintf(mes, 1280, "%s", "/tmp/rmt/opt%d;/tmp/rmt/ipt%d;/tmp/rmt/ofl%d;", i);
//		strncat(mes, "/tmp/rmt/opt", strlen("/tmp/rmt/opt") + 1);
		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
//		strncat(mes, "/tmp/rmt/ipt", strlen("/tmp/rmt/ipt"));
//		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
//		strncat(mes, "/tmp/rmt/ofl", strlen("/tmp/rmt/ofl"));
//		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
		i++;
	}

	if(fil_isexist("/tmp/kilflg") == true){
			return;
	}
	switch(mde){
		case IORTEXEC:
			send_message(EXECUT, IORTEXEC, IORTEXEC, mes);
		break;
		case SYSHITRTEXEC:
			send_message(EXECUT, SYSHITRTEXEC, SYSHITRTEXEC, mes);
		break;
		case SYSMISSRTEXEC:
			send_message(EXECUT, SYSMISSRTEXEC, SYSMISSRTEXEC, mes);
		break;
		case APIHITRTEXEC:
			send_message(EXECUT, APIHITRTEXEC, APIHITRTEXEC, mes);
		break;
		case APIMISSRTEXEC:
			send_message(EXECUT, APIMISSRTEXEC, APIMISSRTEXEC, mes);
		break;
		default:
		break;
	}


	phy_log(LOG_LEVEL_ERR, "rmt_exec_entry: mes: %s.", mes);
//	phy_mkdir("/tmp/rmt");
//	delete_file("/tmp/rmt");
	while(access("/tmp/rmt", F_OK))
	{
		sleep(1);
		phy_log(LOG_LEVEL_WARNING, "rmt not exist and will create it now.");
	}
	sleep((i/10));
#ifdef RMT_OPT
#ifdef THREAD_PROCESS
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pid_t));
#else
	othreads = (pid_t*)phy_calloc(othreads, i, sizeof(pthread_t));
#endif
#endif

#ifdef THREAD_PROCESS
	rthreads = (pid_t*)phy_calloc(rthreads, i, sizeof(pid_t));
#else
	rthreads = (pthread_t*)phy_calloc(rthreads, i, sizeof(pthread_t));
#endif

	thmtx.optl = (ffnm_t*)phy_calloc(thmtx.optl, i, sizeof(ffnm_t));
	thmtx.iptl = (ffnm_t*)phy_calloc(thmtx.iptl, i, sizeof(ffnm_t));
	i = 0;
	for (stmp = arr; NULL != *stmp; stmp++){
		sfl = get_str_between_two_words(*stmp, "||", NULL);
		snprintf(rarg->ipt, MSTR, "/tmp/rmt/ipt%d", i);
		snprintf(rarg->opt, MSTR, "/tmp/rmt/opt%d", i);
		snprintf(thmtx.optl[i].ffnm, MSTR, "%s", rarg->opt);
		snprintf(thmtx.iptl[i].ffnm, MSTR, "%s", rarg->ipt);
		sub = get_str_between_two_words(*stmp, NULL, "||");
		snprintf(rarg->cmd, LSTR, "%s", sub);
		phy_free(sub);
		snprintf(rarg->ofl, MSTR, "/tmp/rmt/ofl%d", i);
#ifdef RMT_OPT
		mk_fifo(rarg->opt);
#endif
//rmt_opt
#ifdef RMT_OPT
		if(atoi(sfl) == 1){
			othreads[i] = rmt_thread_start(rmt_opt, (void*)rarg);
		}
#endif
//rmt_thread
		rmt_thread_args_t	thread_args;
		thread_args.server_num = i + 1;
		thread_args.args = NULL;
		thread_args.args = rarg;
		if(atoi(sfl) == 1){
//			rmt_run(&thread_args);
			rthreads[i] = rmt_thread_start(rmt_run, &thread_args);
#ifdef THREAD_PROCESS
			phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: child pid = %d.", rthreads[i]);
#else
			phy_log(LOG_LEVEL_TRACE, "rmt_thread_start: child pthread = %ld.", rthreads[i]);
#endif
		}
		phy_free(sfl);
		i++;
		usleep(100000);
	}
	thmtx.num = i;
	thmtx.rthreads = rthreads;
#ifdef RMT_OPT
	thmtx.othreads = othreads;
#else
	thmtx.othreads = NULL;
#endif
	thmtx.rarg = rarg;
	phy_strarr_free(arr);
	if(fil_isexist("/tmp/kilflg") == true){
		return;
	}
}

void realtime_exec_entry_local(const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl,mesexe mde)
{
#ifdef THREAD_PROCESS
	pid_t* rthreads = NULL;
#else
	pthread_t* rthreads = NULL;
#endif

	int i = 0;
	char* sfl = null;
	char* sub = null;
	loc_args_t* rarg;
	char** arr;
	char** stmp;
	rarg = (loc_args_t*)malloc(sizeof(loc_args_t));
	snprintf(rarg->usr, SSTR, "%s", usr);
	snprintf(rarg->upw, SSTR, "%s", upw);
	snprintf(rarg->rpw, SSTR, "%s", rpw);
	rarg->rfl = rfl;

	char mes[1280] = {0};
	phy_strarr_init(&arr);

	str_to_arr(cmdlist, "]", &arr);
	for (stmp = arr; NULL != *stmp; stmp++){
		snprintf(mes + strlen(mes), 1280 - strlen(mes), "%d;", i);
		i++;
	}
	if(fil_isexist("/tmp/kilflg") == true){
		return;
	}
	switch(mde){
		case IORTEXEC:
			send_message(EXECUT, IORTEXEC, IORTEXEC, mes);
		break;
		case SYSHITRTEXEC:
			send_message(EXECUT, SYSHITRTEXEC, SYSHITRTEXEC, mes);
		break;
		case SYSMISSRTEXEC:
			send_message(EXECUT, SYSMISSRTEXEC, SYSMISSRTEXEC, mes);
		break;
		case APIHITRTEXEC:
			send_message(EXECUT, APIHITRTEXEC, APIHITRTEXEC, mes);
		break;
		case APIMISSRTEXEC:
			send_message(EXECUT, APIMISSRTEXEC, APIMISSRTEXEC, mes);
		break;
		default:
		break;
	}

	phy_log(LOG_LEVEL_ERR, "loc_exec_entry: mes: %s.", mes);
	while(access("/tmp/rmt", F_OK))
	{
		sleep(1);
		phy_log(LOG_LEVEL_WARNING, "rmt not exist and will create it now.");
	}
	sleep((i/10));

#ifdef THREAD_PROCESS
	rthreads = (pid_t*)phy_calloc(rthreads, i, sizeof(pid_t));
#else
	rthreads = (pthread_t*)phy_calloc(rthreads, i, sizeof(pthread_t));
#endif

	thmtx.optl = (ffnm_t*)phy_calloc(thmtx.optl, i, sizeof(ffnm_t));
	thmtx.iptl = (ffnm_t*)phy_calloc(thmtx.iptl, i, sizeof(ffnm_t));
	i = 0;
	for (stmp = arr; NULL != *stmp; stmp++){
		sfl = get_str_between_two_words(*stmp, "||", NULL);
		snprintf(rarg->ipt, MSTR, "/tmp/rmt/ipt%d", i);
		snprintf(rarg->opt, MSTR, "/tmp/rmt/opt%d", i);
		snprintf(thmtx.optl[i].ffnm, MSTR, "%s", rarg->opt);
		snprintf(thmtx.iptl[i].ffnm, MSTR, "%s", rarg->ipt);
		sub = get_str_between_two_words(*stmp, NULL, "||");
		snprintf(rarg->cmd, LSTR, "%s", sub);
		phy_free(sub);
		snprintf(rarg->ofl, MSTR, "/tmp/rmt/ofl%d", i);

//loc_thread
		loc_thread_args_t	thread_args;
		thread_args.server_num = i + 1;
		thread_args.args = NULL;
		thread_args.args = rarg;
		if(atoi(sfl) == 1){
//			loc_run(&thread_args);
			rthreads[i] = loc_thread_start(loc_run, &thread_args);
#ifdef THREAD_PROCESS
			phy_log(LOG_LEVEL_TRACE, "loc_thread_start: child pid = %d.", rthreads[i]);
#else
			phy_log(LOG_LEVEL_TRACE, "loc_thread_start: child pthread = %ld.", rthreads[i]);
#endif
		}
		phy_free(sfl);
		i++;
		usleep(100000);
	}
	thmtx.num = i;
	thmtx.rthreads = rthreads;
#ifdef RMT_OPT
	thmtx.othreads = othreads;
#else
	thmtx.othreads = NULL;
#endif
	thmtx.rarg = (rmt_args_t*)rarg;
	phy_strarr_free(arr);
	if(fil_isexist("/tmp/kilflg") == true){
		return;
	}
}
