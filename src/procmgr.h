#ifndef PROCMNGER_H
#define PROCMNGER_H
#include <sys/queue.h>
#include <pthread.h>
#include "common.h"

typedef struct pitem{
	int pid;
	int fd_in, fd_out;
	void (*signal_handler)(int);
	TAILQ_ENTRY(pitem) entries;
}pitem;

typedef struct procmgr{
	pthread_mutex_t lock;
	TAILQ_HEAD(tailhead, pitem)head;
	int running_procs;
}procmgr;

#endif
