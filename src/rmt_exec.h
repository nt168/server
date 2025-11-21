#ifndef RMT_EXEC_H
#define RMT_EXEC_H

#include "common.h"
#include "messtype.h"
#include "phy_tty.h"

int	rmt_fork();
int	rmt_child_fork();

#define RMT_THREAD_ERROR	-1
#define LOC_THREAD_ERROR -1

#define THREAD_PROCESS
#ifdef THREAD_PROCESS
#define RMT_THREAD_HANDLE	pid_t
#define LOC_THREAD_HANDLE	pid_t

#define LOC_THREAD_ENTRY_POINTER(pointer_name) \
	unsigned (* pointer_name)(void *)

#define RMT_THREAD_ENTRY_POINTER(pointer_name) \
	unsigned (* pointer_name)(void *)

#define LOC_THREAD_ENTRY(entry_name, arg_name)	\
	unsigned entry_name(void *arg_name)

#define RMT_THREAD_ENTRY(entry_name, arg_name)	\
	unsigned entry_name(void *arg_name)
#else

#define RMT_THREAD_HANDLE	pthread_t
#define RMT_THREAD_ENTRY_POINTER(pointer_name) \
		void* (* pointer_name)(void *)

#define RMT_THREAD_ENTRY(entry_name, arg_name)	\
	void* entry_name(void *arg_name)
#endif

#define RMT_THREAD_HANDLE_NULL	0

#define LOC_THREAD_HANDLE_NULL	0

#define loc_thread_exit(status) \
	_exit((int)(status)); \
	return ((unsigned)(status))


#define rmt_thread_exit(status) \
	_exit((int)(status)); \
	return ((unsigned)(status))

#define rmt_sleep(sec) sleep((sec))

#define rmt_thread_kill(h) kill(h, SIGTERM);



//const char* add, const char* usr, const char* upw, const char* rpw, const char* cmdlist, const char* cpulist, const char* ipt, const char* opt, int rfl

#define SSTR 20
#define MSTR 64
#define LSTR 768

typedef struct{
	char usr[SSTR];
	char upw[SSTR];
	char rpw[SSTR];
	char cmd[LSTR];
	int  ncp;
	char ipt[MSTR];
	char opt[MSTR];
	char ofl[MSTR];
	int  rfl;
	int  tot;
}loc_args_t;

typedef struct
{
	int		server_num;
	int		process_num;
	unsigned char	process_type;
	void		*args;
}loc_thread_args_t;

typedef struct{
	char add[SSTR];
	char usr[SSTR];
	char upw[SSTR];
	char rpw[SSTR];
	char cmd[LSTR];
	int  ncp;
	char ipt[MSTR];
	char opt[MSTR];
	char ofl[MSTR];
	int  rfl;
}rmt_args_t;

typedef struct
{
	int		server_num;
	int		process_num;
	unsigned char	process_type;
	void		*args;
}rmt_thread_args_t;

typedef struct{
	char ffnm[MSTR];
}ffnm_t;

typedef struct
{
	int num;
#ifdef THREAD_PROCESS
	pid_t* othreads;
	pid_t* rthreads;
#else
	pthread_t* othreads;
	pthread_t* rthreads;
#endif
	ffnm_t* iptl;
	ffnm_t* optl;
	loc_args_t* rarg;
}loc_thmtx;

typedef struct
{
	int num;
#ifdef THREAD_PROCESS
	pid_t* othreads;
	pid_t* rthreads;
#else
	pthread_t* othreads;
	pthread_t* rthreads;
#endif
	ffnm_t* iptl;
	ffnm_t* optl;
	rmt_args_t* rarg;
}rmt_thmtx;

RMT_THREAD_HANDLE	rmt_thread_start(RMT_THREAD_ENTRY_POINTER(handler), void* thread_args);//rmt_thread_args_t *thread_args);
LOC_THREAD_HANDLE   loc_thread_start(LOC_THREAD_ENTRY_POINTER(handler), void* thread_args);
int	rmt_thread_wait(RMT_THREAD_HANDLE thread);

long int rmt_get_thread_id();

LOC_THREAD_ENTRY(loc_run, args);
RMT_THREAD_ENTRY(rmt_run, args);
RMT_THREAD_ENTRY(rmt_opt, args);

void rmt_exec(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmd, const char* ipt, const char* opt, int rfl, int pid);
void rmt_exec_gtx(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmd, const char* cpulist, int rfl);
void rmt_env_entry(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl);
void rmt_numa_entry(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl);
void rmt_exec_entry(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl);
void loc_env_entry(const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl);
void loc_numa_entry(const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl);
void realtime_exec_entry(const char* add, const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl,mesexe mde);
void exec_ctl(const char* fds, int cfl, const char* cmd, int *pid);
bool exec_cmd(const char* ipt, const char* cmd, size_t len);
void realtime_exec_entry_local(const char* usr, const char* upw, const char* rpw, const char* cmdlist, int rfl,mesexe mde);
void rmt_env_exit();
void rmt_numa_exit();
void loc_env_exit();
void loc_numa_exit();
void rmt_exec_exit();
void sig_hdl(int sig);
void sch_hdl(int sig);

#endif
