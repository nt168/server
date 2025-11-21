#include "procmgr.h"
void procmgr_init(procmgr * manager)
{
	pthread_mutex_init(&manager->lock, NULL);
	TAILQ_INIT(&manager->head);
	manager->running_procs = 0;
}

void procmgr_cleanup(procmgr * manager)
{
	pthread_mutex_destroy(&manager->lock);
}

void procmgr_add(procmgr* manager, int pid, int fd_in, int fd_out, void(*handler)(int))
{
	pitem *new_item = malloc(sizeof(pitem));
	if(new_item == NULL){
		return;
	}

	new_item->pid = pid;
	new_item->fd_in = fd_in;
	new_item->fd_out = fd_out;
	new_item->signal_handler = handler;

	pthread_mutex_lock(&manager->lock);
	TAILQ_INSERT_TAIL(&(manager->head), new_item, entries);
	manager->running_procs++;
	pthread_mutex_unlock(&manager->lock);
}

void procmgr_del(procmgr* manager, int pid, int fd_in, int fd_out, void(*handler)(int))
{

}
