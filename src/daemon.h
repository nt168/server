#ifndef DAEMON_H
#define DAEMON_H
#include "threads.h"

#define LOG_TYPE_UNDEFINED	0
#define LOG_TYPE_SYSTEM		1
#define LOG_TYPE_FILE		2
#define LOG_TYPE_CONSOLE	3
#	define PHY_DEV_NULL	"/dev/null"
#define PHY_MESSAGE_BUF_SIZE	1024

extern int	CONFIG_LOG_TYPE;
extern char	*CONFIG_LOG_FILE;

//#	define phy_stat(path, buf)		stat(path, buf)
int	phy_fork();
//int	phy_child_fork();

#if 1
typedef struct
{
	int		server_num;
	int		process_num;
	unsigned char	process_type;
	void		*args;
}phy_thread_args_t;
#endif

#define phy_thread_exit(status) \
		_exit((int)(status)); \
		return ((unsigned)(status))

extern unsigned char	program_type;
int	daemon_start(int allow_root, const char *user, unsigned int flags);
int	phy_child_fork();

#define SIG_CHECK_PARAMS(sig, siginfo, context)											\
		if (NULL == siginfo)												\
			printf("received [signal:%d(%s)] with NULL siginfo", sig, get_signal_name(sig));	\
		if (NULL == context)												\
			printf("received [signal:%d(%s)] with NULL context", sig, get_signal_name(sig))

void phy_set_common_signal_handlers(void);

#endif
