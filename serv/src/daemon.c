#include "../src/daemon.h"

#include <pthread.h>
#include <sys/types.h>

#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include "channel.h"
#include "common.h"
//#include "server/phy_server.h"
#include "log.h"
#include "phy_tty.h"
#include "poller.h"

static int	parent_pid = -1;
static FILE	*fpid = NULL;
static int	fdpid = -1;
int	sig_parent_pid = -1;
int	sig_exiting = 0;

//char	*CONFIG_FILE		= "/root/eclipse-workspace/Intelligent_testing_server/conf/server.cnf";//NULL;
//char	*CONFIG_LOG_TYPE_STR	= NULL;
//int		CONFIG_LOG_TYPE		= LOG_TYPE_UNDEFINED;
//char	*CONFIG_LOG_FILE	= NULL;
//int		CONFIG_LOG_FILE_SIZE	= 1;
//int		CONFIG_ALLOW_ROOT	= 0;
//int		CONFIG_TIMEOUT		= 3;
const char	*get_signal_name(int sig);

extern char *CONFIG_PID_FILE;


#define SIG_PARENT_PROCESS		(sig_parent_pid == (int)getpid())

#define SIG_CHECKED_FIELD(siginfo, field)		(NULL == siginfo ? -1 : (int)siginfo->field)
#define SIG_CHECKED_FIELD_TYPE(siginfo, field, type)	(NULL == siginfo ? (type)-1 : siginfo->field)
#define SIG_PARENT_PROCESS				(sig_parent_pid == (int)getpid())
////////////////////////////////////////////////////
#define PHY_THREAD_HANDLE	pid_t
#define PHY_THREAD_HANDLE_NULL	0
#define PHY_THREAD_ERROR	-1
//PHY_THREAD_HANDLE	phy_thread_start(PHY_THREAD_ENTRY_POINTER(handler), phy_thread_args_t *thread_args);
#define PHY_THREAD_ENTRY_POINTER(pointer_name) \
	unsigned int (* pointer_name)(void *)

#define PHY_THREAD_ENTRY(entry_name, arg_name)	\
	unsigned entry_name(void *arg_name)

PHY_THREAD_LOCAL static char		*my_psk			= NULL;
PHY_THREAD_LOCAL static size_t		my_psk_len		= 0;

#if 1
int	phy_fork()
{
	fflush(stdout);
	fflush(stderr);
	return fork();
}

int	phy_child_fork()
{
	pid_t		pid;
	sigset_t	mask, orig_mask;

	/* block SIGTERM, SIGINT and SIGCHLD during fork to avoid deadlock (we've seen one in __unregister_atfork()) */
	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, &orig_mask);

	pid = phy_fork();

	sigprocmask(SIG_SETMASK, &orig_mask, NULL);

	/* ignore SIGCHLD to avoid problems with exiting scripts in phy_execute() and other cases */
	if (0 == pid)
		signal(SIGCHLD, SIG_DFL);

	return pid;
}
#endif

#if 1
PHY_THREAD_HANDLE phy_thread_start(PHY_THREAD_ENTRY_POINTER(handler), phy_thread_args_t *thread_args)
{
	PHY_THREAD_HANDLE	thread = PHY_THREAD_HANDLE_NULL;
	if (0 == (thread = phy_child_fork()))	/* child process */
	{
		(*handler)(thread_args);
		phy_thread_exit(EXIT_SUCCESS);
	}
	else if (-1 == thread)
	{
		phy_error("failed to fork: %s", phy_strerror(errno));
		thread = (PHY_THREAD_HANDLE)PHY_THREAD_ERROR;
	}
	return thread;
}
#endif


int	MAIN_SERVER_ENTRY(int flags)
{
	phy_thread_start(phy_poller, NULL);
	phy_channel();
	phy_thread_start(phy_channel, NULL);
#if AGENTFL_SYNCER
	phy_thread_start(agents_synchronizer, NULL);
#endif
	return 0;
}

void phy_tls_free_on_signal(void)
{
	if (NULL != my_psk)
		phy_guaranteed_memset(my_psk, 0, my_psk_len);
}

int	create_pid_file(const char *pidfile)
{
	int		fd;
	phy_stat_t	buf;
	struct flock	fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = getpid();

	/* check if pid file already exists */
	if (0 == phy_stat(pidfile, &buf))
	{
		if (-1 == (fd = open(pidfile, O_WRONLY | O_APPEND)))
		{
			phy_error("cannot open PID file [%s]: %s", pidfile, phy_strerror(errno));
			return FAIL;
		}

		if (-1 == fcntl(fd, F_SETLK, &fl))
		{
			close(fd);
			phy_error("Is this process already running? Could not lock PID file [%s]: %s",
					pidfile, phy_strerror(errno));
			return FAIL;
		}

		close(fd);
	}

	/* open pid file */
	if (NULL == (fpid = fopen(pidfile, "w")))
	{
		phy_error("cannot create PID file [%s]: %s", pidfile, phy_strerror(errno));
		return FAIL;
	}

	/* lock file */
	if (-1 != (fdpid = fileno(fpid)))
	{
		fcntl(fdpid, F_SETLK, &fl);
		fcntl(fdpid, F_SETFD, FD_CLOEXEC);
	}

	/* write pid to file */
	fprintf(fpid, "%d", (int)getpid());
	fflush(fpid);

	return SUCCEED;
}

void	exit_with_failure(void)
{
#if defined(HAVE_POLARSSL) || defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
	phy_tls_free_on_signal();
#endif
	exit(EXIT_FAILURE);
}
#if 0
const char	*get_signal_name(int sig)
{
	switch (sig)
	{
		case SIGALRM:	return "SIGALRM";
		case SIGILL:	return "SIGILL";
		case SIGFPE:	return "SIGFPE";
		case SIGSEGV:	return "SIGSEGV";
		case SIGBUS:	return "SIGBUS";
		case SIGQUIT:	return "SIGQUIT";
		case SIGINT:	return "SIGINT";
		case SIGTERM:	return "SIGTERM";
		case SIGPIPE:	return "SIGPIPE";
		case SIGUSR1:	return "SIGUSR1";
		default:	return "unknown";
	}
}
#endif

#if 0
void	child_signal_handler(int sig, siginfo_t *siginfo, void *context)
{
	SIG_CHECK_PARAMS(sig, siginfo, context);

	if (!SIG_PARENT_PROCESS)
		exit_with_failure();

	if (0 == sig_exiting)
	{
		sig_exiting = 1;
		phy_log(LOG_LEVEL_CRIT, "One child process died (PID:%d,exitcode/signal:%d). Exiting ...", SIG_CHECKED_FIELD(siginfo, si_pid), SIG_CHECKED_FIELD(siginfo, si_status));

#if defined(HAVE_POLARSSL) || defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
		phy_tls_free_on_signal();
#endif
		server_on_exit();
	}
}
#endif

void child_signal_handler(int sig, siginfo_t *siginfo, void *context)
{
	while(1){
		int status;
		pid_t pid = waitpid(-1, &status, WNOHANG);

		if(pid <= 0){
			break;
		}

		if(WIFEXITED(status)){
			phy_log(LOG_LEVEL_CRIT, "子进程 %d 正常退出，状态码 %d\n", pid, WEXITSTATUS(status));
		}else if(WIFSIGNALED(status)){
			phy_log(LOG_LEVEL_CRIT, "子进程 %d 被信号 %d 终止\n", pid, WTERMSIG(status));
		}
	}
}

void	drop_pid_file(const char *pidfile)
{
	struct flock	fl;

	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	fl.l_pid = phy_get_thread_id();

	/* unlock file */
	if (-1 != fdpid)
		fcntl(fdpid, F_SETLK, &fl);

	/* close pid file */
	phy_fclose(fpid);

	unlink(pidfile);
}

void	daemon_stop(void)
{
	/* this function is registered using atexit() to be called when we terminate */
	/* there should be nothing like logging or calls to exit() beyond this point */

	if (parent_pid != (int)getpid())
		return;
	drop_pid_file(CONFIG_PID_FILE);
}

void 	phy_set_child_signal_handler(void)
{
	struct sigaction	phan;
	sig_parent_pid = (int)getpid();

	sigemptyset(&phan.sa_mask);
	phan.sa_flags = SA_SIGINFO | SA_NOCLDSTOP;

	phan.sa_sigaction = child_signal_handler;
	sigaction(SIGCHLD, &phan, NULL);
}

void pipe_signal_handler(int sig, siginfo_t *siginfo, void *context)
{
	SIG_CHECK_PARAMS(sig, siginfo, context);

	printf("Got signal [signal:%d(%s),sender_pid:%d]. Ignoring ...",
			sig, get_signal_name(sig),
			SIG_CHECKED_FIELD(siginfo, si_pid));
}

void	user1_signal_handler(int sig, siginfo_t *siginfo, void *context)
{
	SIG_CHECK_PARAMS(sig, siginfo, context);

	printf("Got signal [signal:%d(%s),sender_pid:%d,sender_uid:%d,value_int:%d(0x%08x)].",
			sig, get_signal_name(sig),
			SIG_CHECKED_FIELD(siginfo, si_pid),
			SIG_CHECKED_FIELD(siginfo, si_uid),
			SIG_CHECKED_FIELD(siginfo, si_value.sival_int),
			SIG_CHECKED_FIELD(siginfo, si_value.sival_int));
}

void	terminate_signal_handler(int sig, siginfo_t *siginfo, void *context)
{
	SIG_CHECK_PARAMS(sig, siginfo, context);

	if (!SIG_PARENT_PROCESS)
	{
//		printf(sig_parent_pid == SIG_CHECKED_FIELD(siginfo, si_pid) || SIGINT == sig ? 4 : 3,
		phy_log(sig_parent_pid == SIG_CHECKED_FIELD(siginfo, si_pid) || SIGINT == sig ? 4 : 3,
				"Got signal [signal:%d(%s),sender_pid:%d,sender_uid:%d,"
				"reason:%d]. %s ...",
				sig, get_signal_name(sig),
				SIG_CHECKED_FIELD(siginfo, si_pid),
				SIG_CHECKED_FIELD(siginfo, si_uid),
				SIG_CHECKED_FIELD(siginfo, si_code),
				SIGINT == sig ? "Ignoring" : "Exiting");

		/* ignore interrupt signal in children - the parent */
		/* process will send terminate signals instead      */
		if (SIGINT == sig)
			return;
		exit_with_failure();
	}
	else
	{
		if (0 == sig_exiting)
		{
			sig_exiting = 1;
//			printf(sig_parent_pid == SIG_CHECKED_FIELD(siginfo, si_pid) ? LEVEL_DEBUG : LEVEL_WARNING,
			phy_log(sig_parent_pid == SIG_CHECKED_FIELD(siginfo, si_pid) ? LEVEL_DEBUG : LEVEL_WARNING,
					"Got signal [signal:%d(%s),sender_pid:%d,sender_uid:%d,"
					"reason:%d]. Exiting ...",
					sig, get_signal_name(sig),
					SIG_CHECKED_FIELD(siginfo, si_pid),
					SIG_CHECKED_FIELD(siginfo, si_uid),
					SIG_CHECKED_FIELD(siginfo, si_code));

#if defined(HAVE_POLARSSL) || defined(HAVE_GNUTLS) || defined(HAVE_OPENSSL)
			phy_tls_free_on_signal();
#endif
			server_on_exit();
		}
	}
}

void log_fatal_signal(int sig, siginfo_t *siginfo, void *context)
{
	SIG_CHECK_PARAMS(sig, siginfo, context);

	printf("Got signal [signal:%d(%s),reason:%d,refaddr:%p]. Crashing ...", \
			sig, get_signal_name(sig), \
			SIG_CHECKED_FIELD(siginfo, si_code), \
			SIG_CHECKED_FIELD_TYPE(siginfo, si_addr, void *));
}

void fatal_signal_handler(int sig, siginfo_t *siginfo, void *context)
{
//	log_fatal_signal(sig, siginfo, context);
//	phy_log_fatal_info(context, PHY_FATAL_LOG_FULL_INFO);
	exit_with_failure();
}

void	alarm_signal_handler(int sig, siginfo_t *siginfo, void *context)
{
	SIG_CHECK_PARAMS(sig, siginfo, context);

	phy_alarm_flag_set();	/* set alarm flag */
}

void	phy_set_common_signal_handlers(void)
{
	struct sigaction	phan;

	sig_parent_pid = (int)getpid();

	sigemptyset(&phan.sa_mask);
	phan.sa_flags = SA_SIGINFO;

	phan.sa_sigaction = terminate_signal_handler;
	sigaction(SIGINT, &phan, NULL);
	sigaction(SIGQUIT, &phan, NULL);
	sigaction(SIGTERM, &phan, NULL);

	phan.sa_sigaction = fatal_signal_handler;
	sigaction(SIGILL, &phan, NULL);
	sigaction(SIGFPE, &phan, NULL);
	sigaction(SIGSEGV, &phan, NULL);
	sigaction(SIGBUS, &phan, NULL);

	phan.sa_sigaction = alarm_signal_handler;
	sigaction(SIGALRM, &phan, NULL);
}

void	set_daemon_signal_handlers(void)
{
	struct sigaction	phan;

	sig_parent_pid = (int)getpid();

	sigemptyset(&phan.sa_mask);
	phan.sa_flags = SA_SIGINFO;

	phan.sa_sigaction = user1_signal_handler;
	sigaction(SIGUSR1, &phan, NULL);

	phan.sa_sigaction = pipe_signal_handler;
	sigaction(SIGPIPE, &phan, NULL);
}

int	daemon_start(int allow_root, const char *user, unsigned int flags)
{
	pid_t		pid;
	struct passwd	*pwd;

	if (0 == allow_root && 0 == getuid())	/* running as root? */
	{
		if (0 != (flags & PHY_TASK_FLAG_FOREGROUND))
		{
			phy_error("cannot run as root!");
			exit(EXIT_FAILURE);
		}

		if (NULL == user)
			user = "root";

		pwd = getpwnam(user);

		if (NULL == pwd)
		{
			phy_error("user %s does not exist", user);
			phy_error("cannot run as root!");
			exit(EXIT_FAILURE);
		}

		if (0 == pwd->pw_uid)
		{
			phy_error("User=%s contradicts AllowRoot=0", user);
			phy_error("cannot run as root!");
			exit(EXIT_FAILURE);
		}

		if (-1 == setgid(pwd->pw_gid))
		{
			phy_error("cannot setgid to %s: %s", user, phy_strerror(errno));
			exit(EXIT_FAILURE);
		}

		if (-1 == setuid(pwd->pw_uid))
		{
			phy_error("cannot setuid to %s: %s", user, phy_strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	umask(0002);

	if (0 == (flags & PHY_TASK_FLAG_FOREGROUND))
	{
		if (0 != (pid = phy_fork()))
			exit(EXIT_SUCCESS);

		setsid();

		signal(SIGHUP, SIG_IGN);

		if (0 != (pid = phy_fork()))
			exit(EXIT_SUCCESS);

		if (-1 == chdir("/"))	/* this is to eliminate warning: ignoring return value of chdir */
			assert(0);

		phy_redirect_stdio(LOG_TYPE_FILE == CONFIG_LOG_TYPE ? CONFIG_LOG_FILE : NULL);
	}

	if (FAIL == create_pid_file(CONFIG_PID_FILE))
		exit(EXIT_FAILURE);

	atexit(daemon_stop);

	parent_pid = (int)getpid();

#if 1
//	system("rm -rf /tmp/phy/messchannel/*");
	phy_set_common_signal_handlers();
	set_daemon_signal_handlers();
	phy_set_child_signal_handler();
	return MAIN_SERVER_ENTRY(flags);
#endif
}
