#ifndef SHMLST_H
#define SHMLST_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <semaphore.h>
#include "common.h"

#define SHM_NAME "/shm_list"
#define SEM_NAME "/shm_mutx"
#define SHM_RMT "/shm_rmt"
#define SEM_RMT "/sem_rmt"

#define SHM_RMTI "/shm_rmti"
#define SEM_RMTI "/sem_rmti"

#define RMTSHML 10*1024*1024
#define INITIAL_CAPACITY 10
#define CAPACITY_INCREMENT 10
#define DATLEN 1460
#define ADDLEN 20

typedef struct {
	size_t len;
	char  dat[0];
}shmst;

typedef enum
{
	SERV_LOOPER,
	SERV_QUEUE,
	SERV_MESS,
	SERV_REGISTER,
	SERV_OTHER,
} svtp;

typedef enum
{
	TASK_INSERT,
	TASK_ENVCK,
	TASK_PERF,
	TASK_SELECT,
	TASK_LISTENER,
	TASK_REPLY,
} tktp;

typedef struct {
	svtp stp;
	tktp ttp;
    char add[ADDLEN];
    char dat[DATLEN];
    int  port;
} rgdt;
// Node structure
typedef struct// ddl
{
    rgdt   data;              // Node data
    struct ddl* next;
    struct ddl* prev;
} node;

typedef struct shmlst
{
    node* entr;
    node* tail;
    node* curr;
    node* pos;
    sem_t mutex;
    size_t num;
    size_t used;
    size_t scal;
} shmlst;

shmlst* create_list();
int expend_list(shmlst** lst);
shmlst* insert_list(rgdt data);
int print_list();
bool create_shm(const char* shm_nam, const char* sem_nam, size_t len);
bool shm_write(const char* shm_nam, const char* sem_nam, void* dat, size_t len);
bool shm_read(const char* shm_nam, const char* sem_nam, void** dat, size_t* len);
void shm_free(const char* shm_nam, const char* sem_nam);
#endif
