#ifndef FILEBROWSER_H
#define FILEBROWSER_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <semaphore.h>
#include "common.h"



#define mshmnm "/phyTune_shm"
#define msemnm "/phyTune_sem"

//#define flptln 2048
#define flptln 512
#define flnmln 128
#define urln 64
#define dtln 20
#define pmln 20
typedef struct filst{
	bool enbl;
	bool cope;
	char fpms[pmln];
	int  lknu;
	char usr[dtln];
	char grp[dtln];
	size_t siz;
	char date[dtln];
	char fltp[pmln];
	char flnm[urln];
	char flpt[flptln];
}filst;

typedef struct vplst{
	void* data;
	struct vplst* next;
}vplst;

typedef struct vphd{
	vplst* cur;
	vplst* dlt;
	size_t len;
}vphd;

typedef struct mshm{
	bool flg;

}mshm;

typedef struct fltp{
	char flg;
	char* des;//des[dtln];
}fltp;

char* filnm2str(vphd *head);
void filst2mem(vphd *head, void** ret, size_t* len);
void frelst(vphd *head);
void lst_free(vphd *head);
void mdf_dirnm(vphd *head);
void fil_filter(vphd** head, const char* usr, const char* pms);
void lst_print(vphd *head);
vphd* lst_filebrowser(const char* add, const char* usr, const char* pwd, const char* dftpt);
vphd* lst_filebrowser_local(const char* usr, const char* pwd, const char* dftpt);
#endif
