#ifndef PHY_THREADS_H
#define PHY_THREADS_H

#include "common.h"

int	phy_fork(void);
//void	phy_child_fork(pid_t *pid);

#define PHY_THREAD_ERROR	-1

#define PHY_THREAD_HANDLE	pid_t
#define PHY_THREAD_HANDLE_NULL	0

#define PHY_THREAD_WAIT_EXIT	1

#define PHY_THREAD_ENTRY_POINTER(pointer_name) \
	unsigned (* pointer_name)(void *)

#define PHY_THREAD_ENTRY(entry_name, arg_name)	\
	unsigned entry_name(void *arg_name)

/* Calling _exit() to terminate child process immediately is important. See PHY-5732 for details. */
#define phy_thread_exit(status) \
	_exit((int)(status)); \
	return ((unsigned)(status))

#define phy_sleep(sec) sleep((sec))

#define phy_thread_kill(h) kill(h, SIGUSR2)
#define phy_thread_kill_fatal(h) kill(h, SIGHUP)


typedef struct
{
	unsigned char	process_type;
//	press_type  process_type;
	int		server_num;
	int		process_num;
	uint32_t threads_num;
	uint32_t pressure_value;
	uint32_t duration;
	uint32_t bind_core;
//	void		*args;
	const char* exepath;
	const char* args;
	const char* process_description;
}phy_thread_args_t;

int	phy_thread_wait(PHY_THREAD_HANDLE thread);
void phy_threads_wait(PHY_THREAD_HANDLE *threads, const int *threads_flags, int threads_num, int ret);

#endif	/* PHY_THREADS_H */
