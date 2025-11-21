#ifndef SCANNER_H
#define SCANNER_H
#include "common.h"
#include "log.h"
#include "ntmp.h"
#include "nttabs.h"
#include "phy_def.h"
#include "phy_tty.h"
#include "phy_sql/phy_sql.h"

typedef struct hwst{
	char itm[128];
	char dat[128];
	bool ish;
}hwst;

//typedef struct spo{
//	size_t 	x;
//	size_t 	y;
//	char* dat;
//}spo;

void hwst_prt(void* dat);
lvh* par_res_simp(const char* dat);
void scanner(const char* add);
void scan_init();
void init_ntmp();
void scan_start(const char* add);
void scan_samp();
void scan_pmus();
char* routex(ddlhx *dh, const char* pre, const char* typ, const char* key, const char* skey);
#endif
