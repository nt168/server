#ifndef OPTIM_H
#define OPTIM_H

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "phy_tty.h"
#include "phy_sql/phy_sql.h"
#include "log.h"
#include "hashmap.h"
#include "channel.h"

//////////////////////

//int load_conf(const char* conf);
void load_conf_extp(const char* exn, const char* ver, const char* itm, ddlhx** dh);
void load_conf_ext(const char* conf, ddlhx** dh);
int load_conf(const char* conf);
int gene_conf(const char* conf);
void ropt_load(const char* workdir);

void  load_getexe(const char* name, char** pth);
void load_getexe_pls(const char* dir, const char* exn, const char* itm, const char* fnm, char** pth);
void  load_init();
void  load_ldconf(const char* workdir);
void  load_deploy();
void  load_prepro();
void  load_result();
void  load_getexe_ext(const char* dir, const char* exn, const char* ver, const char* fnm, char** pth);
void  load_get_version_rmt(const char* add, const char* exenm, char** ver);
void  load_get_deps_rmt(const char* add, const char* exnm, char** mes);
//void  load_deploy_conf(const char* exnm, const char* ver, ddlhx** dh);
//void  load_deploy_conf(const char* exnm, const char* ver, ddlhx** dh);
void  load_load_conf(const char* exn, const char* ver, const char* itm, ddlhx** dh);
void  load_set_cnf(const char* exn, const char* itm, const char* cntpth);
uint64_t load_deploy_conf_pls(const char* exnm, const char* ver);
void  load_set_depcnf(const char* cnt);
void  load_deploy_conf_plss(const char* exnm, const char* ver, uint64_t *val);
void  load_get_envinfo_rmt(const char* add, const char* exnm, char** inf);
//uint64_t load_conf();
void load_mes(ddlhx* dh, mesopt ofl);
void load_run_prepro(const char* add, const char* exn, const char* ver);
void  load_run(const char* add, const char* dte, const char* msg, bool flg);
void  load_runt(const char* add, const char* dte, const char* msg, bool flg);
#endif
